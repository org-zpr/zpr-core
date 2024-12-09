//! Fastpath operations.
//!
//! General rule: no fastpath operation may block.
//! This implies that all functions here must be non-async.

use crate::adapter_tables::AltEntry;
use crate::assembly::{Assembly, PhMode};
use crate::classifier::{self, ClassifierResult};
use crate::config;
use crate::counters::CounterType;
use crate::defs::Direction;
use crate::km::Codec;
use crate::km_noise::NOISE_PADLEN;
use crate::logging::targets::DATAPATH;
use crate::net_defs;
use crate::packet::{BufferPacket, Packet, PacketBuffer};
use crate::queues::TryEnqueueError;
use crate::zdp;
use crate::zdp_ll;
use crate::{compress, km};
use blake3;
use bytes::{Buf, BufMut};
use std::time::SystemTime;
use tracing::{debug, error, info, warn};
use zerocopy::FromBytes;
use zpr;
use zpr_ext::std::mem::{drop_guard, DropGuard};
use zpr_ext::std::num::NonZeroExt;
use zpr_ext::zerocopy::*;

/// Drop a packet and count the drop with the given reason.
pub fn drop_and_count(asm: &Assembly, pkt: BufferPacket, reason: impl Into<CounterType>) {
    let reason = reason.into();
    debug!(target: DATAPATH, "dropping packet because {reason}");
    asm.buffer_stack.put_buffer(pkt.destroy());
    asm.counters[reason.into()].increment();
}

/// Add the ZPI header to a packet.
pub fn encap_zpi(
    _asm: &Assembly,
    _link_id: zpr::LinkId,
    zpi: zpr::Zpi,
    pkt: &mut Packet<impl PacketBuffer>,
) {
    pkt.alloc_zeroed_header::<zdp::ZdpZpiHeader>().zpi = zpi;
}

/// Offer a packet to be captured by the packet capture facility.
/// The packet must be a complete ZDP message.
/// Despite the &mut borrow, the packet will return materially unchanged.
/// (It will have a link-layer header temporarily added to it.)
pub fn maybe_capture(asm: &Assembly, dir: Direction, pkt: &mut Packet<impl PacketBuffer>) {
    maybe_capture_batch(asm, dir, [pkt])
}

/// Batch packet capture.
pub fn maybe_capture_batch<'a, PktBuf: PacketBuffer + 'a>(
    asm: &'a Assembly,
    dir: Direction,
    pkts: impl IntoIterator<Item = &'a mut Packet<PktBuf>>,
) {
    if !asm.flow_control.program_exists() {
        return;
    }

    let capture_time = SystemTime::now();

    let mut num_captured: usize = 0;
    let mut num_filtered: usize = 0;

    let mut pkts_iter = pkts.into_iter();

    // Preallocate buffers according to size hint.
    let desired_bufs = pkts_iter.size_hint().0;
    let mut bufs = Vec::new();
    let acquired_bufs = asm.buffer_stack.try_get_buffers(desired_bufs, &mut bufs);
    // If we got shortchanged, don't bother later checking again.
    let out_of_bufs = acquired_bufs < desired_bufs;

    for pkt in &mut pkts_iter {
        // Clones packet into capture queue after adding direction to beginning of packet
        let ll_hdr = pkt.alloc_zeroed_header::<zdp_ll::ZdpLinkP2P>();
        ll_hdr.direction = zdp_ll::encode_direction(dir);

        // FIXME: ideally, take an RCU reference to the program once on function entry
        let caplen = asm.flow_control.check_packet(pkt.body()) as usize;
        if caplen > 0 {
            match bufs.pop().or_else(|| {
                if out_of_bufs {
                    None
                } else {
                    asm.buffer_stack.try_get_buffer()
                }
            }) {
                Some(buf) => {
                    let orig_len = pkt.body().len();
                    let pkt_clone: BufferPacket =
                        pkt.clone_prefix_into(buf, std::cmp::min(caplen, orig_len));
                    // remove direction indicator from beginning of packet
                    pkt.advance(std::mem::size_of::<zdp_ll::ZdpLinkP2P>());

                    // Checks to see if the packet enqueue was successful
                    match asm
                        .capture_queue
                        .try_enqueue_packet(pkt_clone, capture_time, orig_len)
                    {
                        Ok(()) => num_captured += 1,

                        Err(TryEnqueueError::Full(ret_packet)) => {
                            asm.buffer_stack.put_buffer(ret_packet.destroy());
                            // No sense to try enqueuing more packets; exit the loop early.
                            break;
                        }
                    };
                }

                None => {
                    // remove direction indicator from beginning of packet
                    pkt.advance(std::mem::size_of::<zdp_ll::ZdpLinkP2P>());
                    // No sense to try acquiring more buffers; exit the loop early.
                    break;
                }
            }
        } else {
            num_filtered += 1;
            // remove direction indicator from beginning of packet
            pkt.advance(std::mem::size_of::<zdp_ll::ZdpLinkP2P>());
        }
    }

    // If we exited early, there are remaining packets we won't be capturing.
    let num_dropped = pkts_iter.count();

    // Return any remaining buffers.
    asm.buffer_stack.put_buffers(bufs.into_iter());

    match dir {
        Direction::Inbound => {
            asm.counters[CounterType::InCapPacksWrite].increase_by(num_captured as u64);
            asm.counters[CounterType::InCapPacksDrop].increase_by(num_dropped as u64);
            asm.counters[CounterType::InCapPacksFilt].increase_by(num_filtered as u64);
        }

        Direction::Outbound => {
            asm.counters[CounterType::OutCapPacksWrite].increase_by(num_captured as u64);
            asm.counters[CounterType::OutCapPacksDrop].increase_by(num_dropped as u64);
            asm.counters[CounterType::OutCapPacksFilt].increase_by(num_filtered as u64);
        }
    }
}

/// Encrypt a ZDP packet according to its ZPI header (which is not encrypted).
pub fn encrypt_null(pkt: &mut Packet<impl PacketBuffer>) {
    // RFC 6.5 § 5.25.2
    pkt.put(
        net_defs::inet_checksum(&pkt.body()[std::mem::size_of::<zdp::ZdpZpiHeader>()..]).as_slice(),
    );
}

/// Slap an HMAC onto the end of the packet.
pub fn encrypt_hmac(send_hmac_key: [u8; 32], pkt: &mut Packet<impl PacketBuffer>) {
    let mut link_mac = [0u8; zdp::ZDP_PACKET_MAC_SIZE];
    link_mac[..zdp::ZDP_PACKET_MAC_SIZE].copy_from_slice(
        &blake3::keyed_hash(&send_hmac_key, pkt.body()).as_bytes()[..zdp::ZDP_PACKET_MAC_SIZE],
    );
    pkt.put(&link_mac[..zdp::ZDP_PACKET_MAC_SIZE]);
}

pub fn encrypt_full(
    _asm: &Assembly,
    codec: &dyn Codec,
    pkt: &mut Packet<impl PacketBuffer>,
) -> Result<(), km::EncryptionError> {
    // TODO: Could do some length checks here on the packet body.  Is it too short? Too long? Etc.

    let zpi_hdr_len = std::mem::size_of::<zdp::ZdpZpiHeader>(); // = 1

    let mut enc_buf = [0u8; config::PACKET_BUFFER_SIZE];
    let encr_len = pkt.body().len() - zpi_hdr_len; // Everything except the ZPI byte

    match codec.encrypt_transport_stateless(
        &pkt.body()[zpi_hdr_len..encr_len + zpi_hdr_len],
        &mut enc_buf,
    ) {
        Ok(len) => {
            pkt.shrink_by(encr_len); // remove cleartext body, leavign ZPI
            pkt.put(&enc_buf[0..len]); // copy ciphertext body over
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[allow(dead_code)]
pub enum DecryptError {
    BadStructure,
    UnknownZpi,
    DecryptionFailure,
    MicvFailure,
    BadChecksum,
}

impl From<DecryptError> for CounterType {
    fn from(value: DecryptError) -> Self {
        match value {
            DecryptError::BadStructure => Self::BadStructure,
            DecryptError::UnknownZpi => Self::UnknownZpi,
            DecryptError::DecryptionFailure => Self::DecryptionFailure,
            DecryptError::MicvFailure => Self::MicvFailure,
            DecryptError::BadChecksum => Self::BadChecksum,
        }
    }
}

/// Decrypt a ZDP packet according to its ZPI header (which is not removed).
pub fn decrypt_null(pkt: &mut Packet<impl PacketBuffer>) -> Result<(), DecryptError> {
    // RFC 6.5 § 5.25.2
    if !net_defs::validate_inet_checksum(&pkt.body()[std::mem::size_of::<zdp::ZdpZpiHeader>()..]) {
        return Err(DecryptError::BadChecksum);
    }

    pkt.shrink_by(2); // remove checksum

    Ok(())
}

/// Check and remove the link-2-link HMAC on the (presumed) transit packet.
pub fn decrypt_hmac(
    recv_hmac_key: [u8; 32],
    pkt: &mut Packet<impl PacketBuffer>,
) -> Result<(), DecryptError> {
    if pkt.body().len() < zdp::ZDP_PACKET_MAC_SIZE {
        return Err(DecryptError::BadStructure);
    }

    let mut link_mac = [0u8; zdp::ZDP_PACKET_MAC_SIZE];

    link_mac.copy_from_slice(&pkt.body()[pkt.body().len() - zdp::ZDP_PACKET_MAC_SIZE..]);
    pkt.shrink_by(zdp::ZDP_PACKET_MAC_SIZE);

    if &blake3::keyed_hash(&recv_hmac_key, &pkt.body()).as_bytes()[..zdp::ZDP_PACKET_MAC_SIZE]
        != &link_mac[..zdp::ZDP_PACKET_MAC_SIZE]
    {
        return Err(DecryptError::MicvFailure);
    }

    Ok(())
}

/// Decrypt a ZDP packet according to its ZPI header (which is not removed).
pub fn decrypt_full(
    _asm: &Assembly,
    codec: &dyn Codec,
    padlen: usize,
    pkt: &mut Packet<impl PacketBuffer>,
) -> Result<(), DecryptError> {
    if pkt.body().len() < 1 {
        return Err(DecryptError::BadStructure);
    }
    let encr_len = pkt.body().len() - 1;
    if encr_len < padlen {
        return Err(DecryptError::BadStructure);
    }

    let mut decr_buf = [0u8; config::PACKET_BUFFER_SIZE];

    match codec.decrypt_transport_stateless(&pkt.body()[1..encr_len + 1], &mut decr_buf) {
        Ok(len) => {
            // Copy the decrypted data back into the message -- do not overwrite ZPI.
            pkt.shrink_by(encr_len); // remove ciphertext body, leave ZPI
            pkt.put(&decr_buf[0..len]); // copy over cleartext body
        }
        Err(e) => {
            error!(target: DATAPATH, "decryption failed: {}", e);
            return Err(DecryptError::DecryptionFailure);
        }
    }
    Ok(())
}

fn substrate_egress_common(
    asm: &Assembly,
    link_id: zpr::LinkId,
    pkt: &mut BufferPacket,
) -> Result<Option<zpr::SubstrateAddr>, km::EncryptionError> {
    // TODO: should we add ZDP header here also??

    let zdp_hdr = match zdp::ZdpBaseHeader::ref_from_prefix(&pkt.body()) {
        Ok((zdp_hdr, _)) => zdp_hdr,
        Err(_) => {
            error!(target: DATAPATH, "egress: link {}: failed to parse the ZDP header", link_id);
            return Err(km::EncryptionError::ParseError);
        }
    };

    let transit = zdp_hdr.packet_type == zdp::ZdpPacketType::TransitPacket;

    // Get the security association for this link and extrant the correct ZPI.
    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Ok(None);
    };

    // If this is key management we do not use transport security.
    // TODO: Not quite correct.  We ought to be able to use an existing
    //       security association for re-keying.  But for the intitial
    //       SA exchange, the node goes into transport mode as it consumes
    //       the message from the adapter.  But we need to send that initial
    //       message back under ZIP-0.
    //
    //       See https://github.com/org-zpr/zpr-core/issues/444
    let transport_sa;
    if zdp_hdr.packet_type == zdp::ZdpPacketType::KeyManagement {
        debug!(target: DATAPATH, "link {link_id}: KM message detected, using ZPI=0 ignoring security association");
        transport_sa = None;
    } else {
        transport_sa = peer_state.get_established_transport_association();
    }

    let real_zpi;
    match transport_sa {
        Some(ref transport_sa) => {
            if transit {
                real_zpi = transport_sa.send_zpis.hmac;
            } else {
                real_zpi = transport_sa.send_zpis.encr;
            }
            assert!(real_zpi != zpr::ZPI_0);
        }
        None => {
            real_zpi = zpr::ZPI_0;
        }
    }

    encap_zpi(asm, link_id, real_zpi, pkt);
    maybe_capture(asm, Direction::Outbound, pkt);

    match transport_sa {
        Some(ref transport_sa) => {
            if transit {
                encrypt_hmac(transport_sa.send_hmac_key, pkt);
            } else {
                match encrypt_full(asm, &*transport_sa.codec, pkt) {
                    Ok(()) => (),
                    Err(err) => return Err(err),
                }
            }
        }
        None => {
            encrypt_null(pkt);
        }
    }

    Ok(Some(peer_state.substrate_addr))
}

/// Egress a ZDP packet on the given link ID, according to the given ZPI.
/// The ZPI header will be added to the packet.
pub fn substrate_egress(asm: &Assembly, link_id: zpr::LinkId, mut pkt: BufferPacket) {
    let dest_sa = match substrate_egress_common(asm, link_id, &mut pkt) {
        Ok(Some(dest_sa)) => dest_sa,
        Ok(None) => {
            drop_and_count(asm, pkt, CounterType::PeerRemoved);
            return;
        }
        Err(err) => {
            error!(target: DATAPATH, "egress: link {}: encryption error: {}", link_id, err);
            drop_and_count(asm, pkt, CounterType::EncryptionFailure);
            return;
        }
    };

    match asm.substrate_egress.try_enqueue_packet(
        drop_guard(pkt, |p| drop_and_count(asm, p, CounterType::OutPacksSent)),
        dest_sa,
    ) {
        Ok(()) => (),
        Err(TryEnqueueError::Full(pkt)) => {
            drop_and_count(asm, pkt.into_inner(), CounterType::OutPacksErr)
        }
    }
}

/// A blocking/async version of `substrate_egress()`, for management path use.
/// Useful to ensure fairness under high load.
pub async fn substrate_egress_blocking(
    asm: &Assembly,
    link_id: zpr::LinkId,
    mut pkt: BufferPacket,
) {
    let dest_sa = match substrate_egress_common(asm, link_id, &mut pkt) {
        Ok(Some(dest_sa)) => dest_sa,
        Ok(None) => {
            drop_and_count(asm, pkt, CounterType::PeerRemoved);
            return;
        }
        Err(err) => {
            error!(target: DATAPATH, "egress: link {}: encryption error: {}", link_id, err);
            drop_and_count(asm, pkt, CounterType::EncryptionFailure);
            return;
        }
    };

    match asm
        .substrate_egress
        .enqueue_packet(
            drop_guard(pkt, |p| drop_and_count(asm, p, CounterType::OutPacksSent)),
            dest_sa,
        )
        .await
    {
        Ok(()) => (),
        Err(pkt) => {
            drop_and_count(asm, pkt.into_inner(), CounterType::OutPacksErr);
        }
    }
}

#[cfg(debug_assertions)]
/// This table is used to track whether a flow ever switches from one worker
/// to another (indicating potential for out-of-order packets) -- meaning
/// our packet steerer isn't steering correctly.  This is used only in debug mode.
const AGENT_PACKET_FLOW_TRACKER: std::sync::LazyLock<
    dashmap::DashMap<(zpr::LinkId, zpr::StreamId), usize>,
> = std::sync::LazyLock::new(|| dashmap::DashMap::new());

/// Process packets ingressing from the specified address.
pub fn substrate_ingress(
    asm: &Assembly,
    #[cfg_attr(not(debug_assertions), allow(unused_variables))] worker_index: usize,
    peer_sa: &zpr::SubstrateAddr,
    mut pkt: BufferPacket,
) {
    asm.counters[CounterType::InPacksRec].increment();

    pkt.metadata_mut().ingress_link_id = asm.peer_table.lookup_peer(peer_sa).unwrap_or_zero();

    // Read, but do not remove the ZPI header
    let Ok((zpi_hdr, _)) = zdp::ZdpZpiHeader::read_from_prefix(&pkt.body()) else {
        drop_and_count(asm, pkt, CounterType::BadStructure);
        return;
    };

    let peer_state = asm.peer_table.get(pkt.metadata().ingress_link_id);

    // If a ZPI is setup on this link, then we expect the message to use one of the valid
    // ZPI values.
    let secure;
    match peer_state {
        Some(state) => match state.get_established_transport_association() {
            Some(ref transport_sa) => {
                if zpi_hdr.zpi == transport_sa.recv_zpis.hmac {
                    match decrypt_hmac(transport_sa.recv_hmac_key, &mut pkt) {
                        Ok(()) => secure = true,
                        Err(err) => {
                            drop_and_count(asm, pkt, err);
                            return;
                        }
                    }
                } else if zpi_hdr.zpi == transport_sa.recv_zpis.encr {
                    // TODO: Put padlen in state somewhere too
                    match decrypt_full(asm, &*transport_sa.codec, NOISE_PADLEN, &mut pkt) {
                        Ok(()) => secure = true,
                        Err(err) => {
                            drop_and_count(asm, pkt, err);
                            return;
                        }
                    }
                } else {
                    // We have an SA and ZPI does not match.
                    warn!(
                        target: DATAPATH,
                        "ingress: link {}: unexpected ZPI value {} (expected {:?})",
                        pkt.metadata().ingress_link_id,
                        zpi_hdr.zpi,
                        transport_sa.recv_zpis
                    );
                    drop_and_count(asm, pkt, CounterType::UnknownZpi);
                    return;
                }
            }
            None => {
                // Either no security association on link, or it is not yet established.
                warn!(target: DATAPATH, "INSECURE, no SA on link {}", pkt.metadata().ingress_link_id);
                secure = false;
            }
        },
        None => {
            // No link in peer table
            warn!(
                target: DATAPATH,
                "INSECURE, no link in peer table for {}",
                pkt.metadata().ingress_link_id
            );
            secure = false;
        }
    };

    if !secure {
        // Not under a security assocation, which means only ZPI 0 is allowed.
        if zpi_hdr.zpi != zpr::ZPI_0 && pkt.metadata().ingress_link_id != zpr::LINK_ID_UNKNOWN {
            warn!(
                target: DATAPATH,
                "ingress: {}: ZPI {} not allowed on unestablished SA",
                pkt.metadata().ingress_link_id,
                zpi_hdr.zpi
            );
            drop_and_count(asm, pkt, CounterType::UnknownZpi);
            return;
        }
        warn!(
            target: DATAPATH,
            "INSECURE, decrypting null packet from {}",
            pkt.metadata().ingress_link_id
        );
        match decrypt_null(&mut pkt) {
            Ok(()) => (),
            Err(err) => {
                drop_and_count(asm, pkt, err);
                return;
            }
        }
    }

    // Watch out -- may not be secure
    maybe_capture(asm, Direction::Inbound, &mut pkt);

    // now pop the ZPI off the packet. We've already checked it.
    if zdp::ZdpZpiHeader::read_from_buf(&mut pkt).is_err() {
        drop_and_count(asm, pkt, CounterType::BadStructure);
        return;
    }

    // If we weren't able to match this packet to an existing link,
    // send it off to be processed as a potential new link.
    if pkt.metadata().ingress_link_id == zpr::LINK_ID_UNKNOWN {
        match asm
            .mgmt_dispatch
            .try_dispatch_mgmt_packet_with_addr(peer_sa, pkt)
        {
            Ok(()) => (),
            Err(TryEnqueueError::Full(pkt)) => {
                drop_and_count(asm, pkt, CounterType::QueueBackpressure)
            }
        }
        return;
    }

    let Ok(base_hdr) = zdp::ZdpBaseHeader::read_from_buf(&mut pkt) else {
        return drop_and_count(asm, pkt, CounterType::BadStructure);
    };

    // In ZPI zero only KM messages are allowed (well, and APR ARP which we don't support yet)
    // Can be overridden (FOR TESTING ONLY) in the flags.
    if !secure && base_hdr.packet_type != zdp::ZdpPacketType::KeyManagement {
        warn!(
            target: DATAPATH,
            "ingress: link {}: ZPI 0 only allows key management messages, not {:?}",
            pkt.metadata().ingress_link_id,
            base_hdr.packet_type
        );
        drop_and_count(asm, pkt, CounterType::OtherError);
        return;
    }

    // enqueue non-transit packets with the management processor
    if base_hdr.packet_type != zdp::ZdpPacketType::TransitPacket {
        // TODO: should we peel off the ZDP header here??
        // (instead of this silly code to restore it?)
        *pkt.alloc_zeroed_header() = base_hdr;
        match asm.mgmt_dispatch.try_dispatch_mgmt_packet_with_link(pkt) {
            Ok(()) => (),
            Err(TryEnqueueError::Full(pkt)) => {
                drop_and_count(asm, pkt, CounterType::QueueBackpressure)
            }
        }
        return;
    }

    let Ok(per_flow_hdr) = zdp::ZdpPerFlowHeader::read_from_buf(&mut pkt) else {
        return drop_and_count(asm, pkt, CounterType::BadStructure);
    };

    let ingress_stream_id: zpr::StreamId = per_flow_hdr.stream_id.into();
    pkt.metadata_mut().ingress_stream_id = ingress_stream_id;

    // in debug builds, track which worker this agent traffic came in on
    // ensure a given flow isn't hopping between workers (potentially
    // resulting in out-of-order packets)
    #[cfg(debug_assertions)]
    if let Some(old_index) = AGENT_PACKET_FLOW_TRACKER.insert(
        (
            pkt.metadata().ingress_link_id,
            pkt.metadata().ingress_stream_id,
        ),
        worker_index,
    ) {
        if old_index != worker_index {
            asm.counters[CounterType::AgentPacketsOutOfOrder].increment();
        }
    }

    forward(asm, pkt);
}

/// Send a compressed agent packet to the agent.
/// The packet will be decompressed according to the given stream ID.
pub fn agent_input(
    asm: &Assembly,
    tether_id: zpr::StreamId, // TODO: should we keep this in metadata? or per-flow header?
    mut pkt: BufferPacket,
) {
    // extract A2A MAC
    let Ok(a2a_hdr) = zdp::ZdpA2aHeader::read_from_buf(&mut pkt) else {
        drop_and_count(asm, pkt, CounterType::BadStructure);
        return;
    };

    if a2a_hdr.a2a_said != 0 {
        todo!("A2A SAID");
    }

    let a2a_mac_size = zdp::ZDP_A2A_MAC_SIZE; // TODO: checksum may be shorter depending on A2A SA

    if pkt.body().len() < a2a_mac_size {
        drop_and_count(asm, pkt, CounterType::BadStructure);
        return;
    }
    let mut a2a_mac = [0u8; zdp::ZDP_A2A_MAC_SIZE];
    a2a_mac[..a2a_mac_size].copy_from_slice(&pkt.body()[pkt.body().len() - a2a_mac_size..]);
    pkt.shrink_by(a2a_mac_size);

    // lookup PEP in DLT and expand compressed packet
    let Some(pep) = asm.dlt.get(tether_id) else {
        drop_and_count(asm, pkt, CounterType::UnknownStreamId);
        return;
    };

    compress::expand(pep.compression_mode, &pep.five_tuple, &mut pkt);

    // check A2A MAC
    // TODO: use actual A2A SAID & keyed hash
    if blake3::hash(pkt.body()).as_bytes()[..a2a_mac_size] != a2a_mac[..a2a_mac_size] {
        return drop_and_count(asm, pkt, CounterType::MicvFailure);
    }

    // send out decapsulated packet
    match asm.agent_input.try_enqueue_packet(drop_guard(pkt, |p| {
        drop_and_count(asm, p, CounterType::InPacksSent)
    })) {
        Ok(()) => (),
        Err(TryEnqueueError::Full(pkt)) => {
            drop_and_count(asm, pkt.into_inner(), CounterType::InPacksDrop)
        }
    }
}

/// Process uncompressed packet from the agent.
/// The packet will be compressed, or trigger a Bind request.
pub fn agent_output(asm: &Assembly, mut pkt: BufferPacket) {
    pkt.metadata_mut().ingress_link_id = zpr::LOCAL_AGENT_LINK_ID;

    // determine five tuple
    let classification = match classifier::classify(&mut pkt) {
        Ok(cls) => cls,
        Err(_why) => {
            drop_and_count(asm, pkt, CounterType::InPacksDrop);
            return;
        }
    };

    match classification {
        ClassifierResult::OK | ClassifierResult::UnclassifiedL4 => (),

        ClassifierResult::FirstFragment | ClassifierResult::SubsequentFragment => {
            // TODO: handle fragments!
            drop_and_count(asm, pkt, CounterType::InPacksDrop);
            return;
        }

        ClassifierResult::NonIP => {
            // should never happen; TUN doesn't deal in non-IP
            drop_and_count(asm, pkt, CounterType::InPacksDrop);
            return;
        }
    }

    agent_output_post_classify(asm, pkt, /* allow_bind_request */ true);
}

/// Post-classification portion of `agent_output` function.  Used for
/// re-injecting already-classified packets e.g.  which were held awaiting
/// bind.  `allow_bind_request` should be true for "real" packets; false for
/// packets re-injected from mgmt plane after fulfilling a bind request (so
/// as to prevent the theoretical possibility of a packet loop).
pub fn agent_output_post_classify(asm: &Assembly, mut pkt: BufferPacket, allow_bind_request: bool) {
    let five_tuple = *pkt.metadata().five_tuple(); // TODO: convince borrow checker we don't need to copy this out

    // lookup five tuple in ALT
    match asm.alt.get(&five_tuple) {
        Some(entry) => match &*entry {
            AltEntry::Active(pep) => {
                // compute A2A MAC
                // TODO: use actual A2A SAID & keyed hash
                let a2a_said: zpr::A2aSaid = 0;
                let a2a_mac_size = zdp::ZDP_A2A_MAC_SIZE; // TODO: may be smaller depending on A2A SAID
                let mut a2a_mac = [0u8; zdp::ZDP_A2A_MAC_SIZE];
                // SECURITY: truncating BLAKE3 is safe
                a2a_mac[..a2a_mac_size]
                    .copy_from_slice(&blake3::hash(pkt.body()).as_bytes()[..a2a_mac_size]);

                // compress packet
                compress::compress(
                    pep.compression_mode,
                    five_tuple.l3_type,
                    five_tuple.l4_protocol,
                    &mut pkt,
                );

                // append A2A MAC
                pkt.put(&a2a_mac[..a2a_mac_size]);
                pkt.alloc_zeroed_header::<zdp::ZdpA2aHeader>().a2a_said = a2a_said;

                pkt.metadata_mut().ingress_stream_id = pep.tether_id;

                // forward packet on
                forward(asm, pkt);
            }

            AltEntry::Pending(_) => {
                // Bind request pending; drop this packet
                drop_and_count(asm, pkt, CounterType::DroppedAwaitingBind);
            }
        },

        None => {
            if !allow_bind_request {
                // avoid the (all-but purely theoretical) chance of a packet loop,
                // when this is called from bind setup code
                drop_and_count(asm, pkt, CounterType::OtherError);
                return;
            }

            // issue bind request
            info!(target: DATAPATH, "issuing bind request for {five_tuple}");
            match asm.adapter_manager.try_request_tether_id(pkt) {
                Ok(()) => (),
                Err(TryEnqueueError::Full(pkt)) => {
                    drop_and_count(asm, pkt, CounterType::QueueBackpressure)
                }
            }
        }
    }
}

const fn adapter_next_hop_link(ingress_link_id: zpr::LinkId) -> zpr::LinkId {
    // this optimization is checked by the static asserts below
    // this allows us to avoid an unpredictable branch on every packet
    (ingress_link_id % 2) + 1
}

const _: () = assert!(adapter_next_hop_link(zpr::LOCAL_AGENT_LINK_ID) == zpr::DOCK_LINK_ID);
const _: () = assert!(adapter_next_hop_link(zpr::DOCK_LINK_ID) == zpr::LOCAL_AGENT_LINK_ID);

/// Forward compressed packet.
pub fn forward(asm: &Assembly, mut pkt: BufferPacket) {
    let egress_link_id;
    let egress_stream_id;

    match asm.ph_mode {
        PhMode::Adapter => {
            egress_link_id = adapter_next_hop_link(pkt.metadata().ingress_link_id);
            egress_stream_id = pkt.metadata().ingress_stream_id;
        }

        PhMode::Node => {
            let Some(ingress_peer_state) = asm.peer_table.get(pkt.metadata().ingress_link_id)
            else {
                drop_and_count(asm, pkt, CounterType::UnknownPeer);
                return;
            };

            let Some(pep) = ingress_peer_state.pft.get(pkt.metadata().ingress_stream_id) else {
                drop_and_count(asm, pkt, CounterType::UnknownStreamId);
                return;
            };

            // TODO: policy enforcement

            egress_link_id = pep.next_hop.0;
            egress_stream_id = pep.next_hop.1;
        }
    }

    if egress_link_id == zpr::LOCAL_AGENT_LINK_ID {
        agent_input(asm, egress_stream_id, pkt);
    } else {
        let per_flow_hdr = pkt.alloc_zeroed_header::<zdp::ZdpPerFlowHeader>();
        per_flow_hdr.stream_id = egress_stream_id.into();

        let base_hdr = pkt.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
        base_hdr.packet_type = zdp::ZdpPacketType::TransitPacket;

        substrate_egress(asm, egress_link_id, pkt);
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::config::PACKET_BUFFER_SIZE;

    #[test]
    fn test_encrypt_decrypt_null() {
        let mut buf = [0u8; PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 64);

        pkt.put(&b"this is a test of encrypt zero"[..]);

        let orig_len = pkt.body().len();

        encrypt_null(&mut pkt);

        assert!(pkt.body().len() == orig_len + 2); // did add checksum

        let res = decrypt_null(&mut pkt);
        assert!(res.is_ok());

        assert!(pkt.body().len() == orig_len); // did remove checksum
    }

    #[test]
    fn test_add_and_check_hmac() {
        let mut buf = [0u8; PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 64);

        pkt.put(&b"this is a test of hmac"[..]);
        let key: [u8; 32] = [6u8; 32];

        let orig_len = pkt.body().len();

        encrypt_hmac(key, &mut pkt);

        assert!(pkt.body().len() == orig_len + zdp::ZDP_PACKET_MAC_SIZE); // did add hmac

        let res = decrypt_hmac(key, &mut pkt);
        assert!(res.is_ok());

        assert!(pkt.body().len() == orig_len); // did remove hmac
    }

    #[test]
    fn test_add_and_check_hmac_fail() {
        let mut buf = [0u8; PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 64);

        pkt.put(&b"this is a test of hmac"[..]);
        let key: [u8; 32] = [6u8; 32];

        let orig_len = pkt.body().len();

        encrypt_hmac(key, &mut pkt);

        assert!(pkt.body().len() == orig_len + zdp::ZDP_PACKET_MAC_SIZE); // did add hmac

        let wrong_key: [u8; 32] = [7u8; 32];

        let res = decrypt_hmac(wrong_key, &mut pkt);
        assert!(res.is_err());
    }
}
