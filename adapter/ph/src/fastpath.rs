//! Fastpath operations.
//!
//! General rule: no fastpath operation may block.
//! This implies that all functions here must be non-async.

use crate::adapter_tables::AltEntry;
use crate::assembly::{Assembly, PhMode};
use crate::classifier::{self, ClassifierResult};
use crate::config;
use crate::counters_enum::CounterType;
use crate::defs::Direction;
use crate::km::Codec;
use crate::km_noise::NOISE_PADLEN;
use crate::net_defs;
use crate::packet::Packet;
use crate::peer_table::PeerState;
use crate::queues::TryEnqueueError;
use crate::zdp::{self, ZdpBaseHeader, ZDP_BASE_HEADER_OFFSET};
use crate::zdp_ll;
use crate::zpr;
use crate::{compress, km};
use blake3;
use bytes::{Buf, BufMut};
use std::time::SystemTime;
use tracing::{error, info, warn};
use zerocopy::FromBytes;
use zpr_ext::std::mem::{drop_guard, DropGuard};
use zpr_ext::zerocopy::*;

/// Drop a packet and count the drop with the given reason.
pub fn drop_and_count<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    pkt: Packet<'pktbuf>,
    reason: impl Into<CounterType>,
) {
    let reason = reason.into();
    eprintln!("{}: dropping packet because {}", asm.system_name, reason);
    asm.buffer_stack.put_buffer(pkt.destroy());
    asm.counters[reason.into()].increment();
}

/// Add the ZPI header to a packet.
pub fn encap_zpi<'pktbuf>(
    _asm: &Assembly<'pktbuf>,
    _link_id: zpr::LinkId,
    zpi: zpr::Zpi,
    pkt: &mut Packet<'pktbuf>,
) {
    pkt.alloc_zeroed_header::<zdp::ZdpZpiHeader>().zpi = zpi;
}

pub enum DecapZpiError {
    BadStructure,
    UnknownZpi,
}

impl From<DecapZpiError> for CounterType {
    fn from(value: DecapZpiError) -> Self {
        match value {
            DecapZpiError::BadStructure => Self::BadStructure,
            DecapZpiError::UnknownZpi => Self::UnknownZpi,
        }
    }
}

/// Remove the ZPI header from a packet.
/// Returns the ZPI value, or an error if it's invalid for the given link.
pub fn decap_zpi<'pktbuf>(
    _asm: &Assembly<'pktbuf>,
    _link_id: zpr::LinkId,
    pkt: &mut Packet<'pktbuf>,
) -> Result<zpr::Zpi, DecapZpiError> {
    let zpi_hdr = zdp::ZdpZpiHeader::read_from_buf(pkt).ok_or(DecapZpiError::BadStructure)?;
    let zpi = zpi_hdr.zpi as zpr::Zpi;

    if zpi == zpr::ZPI_0 {
        Ok(zpi)
    } else {
        // TODO: lookup in table
        Err(DecapZpiError::UnknownZpi)
    }
}

/// Offer a packet to be captured by the packet capture facility.
/// The packet must be a complete ZDP message.
/// Despite the &mut borrow, the packet will return materially unchanged.
/// (It will have a link-layer header temporarily added to it.)
pub fn maybe_capture<'pktbuf>(asm: &Assembly<'pktbuf>, dir: Direction, pkt: &mut Packet<'pktbuf>) {
    maybe_capture_batch(asm, dir, [pkt])
}

/// Batch packet capture.
pub fn maybe_capture_batch<'a, 'pktbuf: 'a>(
    asm: &'a Assembly<'pktbuf>,
    dir: Direction,
    pkts: impl IntoIterator<Item = &'a mut Packet<'pktbuf>>,
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
                    let pkt_clone: Packet =
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
pub fn encrypt_null<'pktbuf>(pkt: &mut Packet<'pktbuf>) {
    // RFC 6.5 § 5.25.2
    pkt.put(
        net_defs::inet_checksum(&pkt.body()[std::mem::size_of::<zdp::ZdpZpiHeader>()..]).as_slice(),
    );
}

pub fn encrypt_hmac<'pktbuf>(_send_hmac_key: [u8; 32], _pkt: &mut Packet<'pktbuf>) {
    // Run the blake hash key'd with the `send_hmac_key` on the correct parts of the packet
    // and write the (truncated) hash value to the correct header location.

    info!("encrypt_hmac: not implemented - NOP");
}

pub fn encrypt_full<'pktbuf>(
    _asm: &Assembly<'pktbuf>,
    codec: &dyn Codec,
    pkt: &mut Packet<'pktbuf>,
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
}

impl From<DecryptError> for CounterType {
    fn from(value: DecryptError) -> Self {
        match value {
            DecryptError::BadStructure => Self::BadStructure,
            DecryptError::UnknownZpi => Self::UnknownZpi,
            DecryptError::DecryptionFailure => Self::DecryptionFailure,
            DecryptError::MicvFailure => Self::MicvFailure,
        }
    }
}

/// Decrypt a ZDP packet according to its ZPI header (which is not removed).
pub fn decrypt_null<'pktbuf>(pkt: &mut Packet<'pktbuf>) -> Result<(), DecryptError> {
    // RFC 6.5 § 5.25.2
    if !net_defs::validate_inet_checksum(&pkt.body()[std::mem::size_of::<zdp::ZdpZpiHeader>()..]) {
        return Err(DecryptError::MicvFailure);
    }

    pkt.shrink_by(2); // remove checksum

    Ok(())
}

/// Decrypt a ZDP packet according to its ZPI header (which is not removed).
pub fn decrypt_hmac<'pktbuf>(
    _recv_hmac_key: [u8; 32],
    _pkt: &mut Packet<'pktbuf>,
) -> Result<(), DecryptError> {
    info!("decrypt_hmac: not implemented -- NOP");
    Ok(())
}

/// Decrypt a ZDP packet according to its ZPI header (which is not removed).
pub fn decrypt_full<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    codec: &dyn Codec,
    padlen: usize,
    pkt: &mut Packet<'pktbuf>,
) -> Result<(), DecryptError> {
    if pkt.body().len() < 1 {
        return Err(DecryptError::BadStructure);
    }
    let encr_len = pkt.body().len() - 1;
    if encr_len < padlen {
        return Err(DecryptError::BadStructure);
    }

    let decr_buf = asm.buffer_stack.try_get_buffer().unwrap();

    match codec.decrypt_transport_stateless(&pkt.body()[1..encr_len + 1], decr_buf) {
        Ok(len) => {
            // Copy the decrypted data back into the message -- do not overwrite ZPI.
            pkt.shrink_by(encr_len); // remove ciphertext body, leave ZPI
            pkt.put(&decr_buf[0..len]); // copy over cleartext body
        }
        Err(e) => {
            error!("decryption failed: {}", e);
            return Err(DecryptError::DecryptionFailure);
        }
    }
    Ok(())
}

fn substrate_egress_common<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    pkt: &mut Packet<'pktbuf>,
) -> Result<Option<zpr::SubstrateAddr>, km::EncryptionError> {
    // TODO: should we add ZDP header here also??

    let zdp_hdr = match ZdpBaseHeader::ref_from_prefix(&pkt.body()[ZDP_BASE_HEADER_OFFSET..]) {
        Some(zdp_hdr) => zdp_hdr,
        None => {
            return Err(km::EncryptionError::ParseError);
        }
    };
    let transit = zdp_hdr.packet_type == zdp::ZdpPacketType::TransitPacket;

    // Get the security association for this link and extrant the correct ZPI.
    // TODO: Is there some way to avoid a clone here?
    let real_zpi;
    let transport_sa = match asm
        .peer_table
        .clone_established_transport_association(link_id)
    {
        Some(transport_sa) => {
            if transit {
                real_zpi = transport_sa.recv_zpis.hmac;
            } else {
                real_zpi = transport_sa.recv_zpis.encr;
            }
            assert!(real_zpi != zpr::ZPI_0);
            Some(transport_sa)
        }
        None => {
            real_zpi = zpr::ZPI_0;
            None
        }
    };

    encap_zpi(asm, link_id, real_zpi, pkt);
    maybe_capture(asm, Direction::Outbound, pkt);

    match transport_sa {
        Some(transport_sa) => {
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

    Ok(asm
        .peer_table
        .inspect(link_id, |peer_state: &PeerState| peer_state.substrate_addr))
}

/// Egress a ZDP packet on the given link ID, according to the given ZPI.
/// The ZPI header will be added to the packet.
pub fn substrate_egress<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    mut pkt: Packet<'pktbuf>,
) {
    let dest_sa = match substrate_egress_common(asm, link_id, &mut pkt) {
        Ok(Some(dest_sa)) => dest_sa,
        Ok(None) => {
            drop_and_count(asm, pkt, CounterType::PeerRemoved);
            return;
        }
        Err(err) => {
            error!("egress: link {}: encryption error: {}", link_id, err);
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
pub async fn substrate_egress_blocking<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    mut pkt: Packet<'pktbuf>,
) {
    let dest_sa = match substrate_egress_common(asm, link_id, &mut pkt) {
        Ok(Some(dest_sa)) => dest_sa,
        Ok(None) => {
            drop_and_count(asm, pkt, CounterType::PeerRemoved);
            return;
        }
        Err(err) => {
            error!("egress: link {}: encryption error: {}", link_id, err);
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

/// Process packets ingressing from the specified address.
pub fn substrate_ingress<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    peer_sa: &zpr::SubstrateAddr,
    mut pkt: Packet<'pktbuf>,
) {
    asm.counters[CounterType::InPacksRec].increment();

    eprintln!("{}: got packet from {}", asm.system_name, peer_sa);

    let Some(ingress_link_id) = asm.peer_table.lookup_peer(peer_sa) else {
        drop_and_count(asm, pkt, CounterType::UnknownPeer);
        return;
    };

    // Read, but do not remove the ZPI header
    let Some(zpi_hdr) = zdp::ZdpZpiHeader::read_from_prefix(&pkt.body()) else {
        drop_and_count(asm, pkt, CounterType::BadStructure);
        return;
    };

    // If a ZPI is setup on this link, then we expect the message to use one of the valid
    // ZPI values.
    let secure = match asm
        .peer_table
        .clone_established_transport_association(ingress_link_id)
    {
        Some(transport_sa) => {
            if zpi_hdr.zpi == transport_sa.recv_zpis.hmac {
                match decrypt_hmac(transport_sa.recv_hmac_key, &mut pkt) {
                    Ok(()) => true,
                    Err(err) => {
                        drop_and_count(asm, pkt, err);
                        return;
                    }
                }
            } else if zpi_hdr.zpi == transport_sa.recv_zpis.encr {
                // TODO: Put padlen in state somewhere too
                match decrypt_full(asm, &*transport_sa.codec, NOISE_PADLEN, &mut pkt) {
                    Ok(()) => true,
                    Err(err) => {
                        drop_and_count(asm, pkt, err);
                        return;
                    }
                }
            } else {
                // We have an SA and ZPI does not match.
                info!(
                    "ingress: link {}: unexpected ZPI value {} (expected {:?})",
                    ingress_link_id, zpi_hdr.zpi, transport_sa.recv_zpis
                );
                drop_and_count(asm, pkt, CounterType::UnknownZpi);
                return;
            }
        }
        None => {
            // Either no security associatio on link, or it is not yet established.
            error!(
                "ingress: link {}: no SA or link not in sa-state table",
                ingress_link_id
            );
            false
        }
    };

    if !secure {
        // Not under a security assocation  which means only ZPI 0 is allowed
        if zpi_hdr.zpi != zpr::ZPI_0 {
            info!(
                "ingress: link {}: ZPI {} not allowed on unestablished SA",
                ingress_link_id, zpi_hdr.zpi
            );
            drop_and_count(asm, pkt, CounterType::UnknownZpi);
            return;
        }
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

    // now pop the ZPI off the packet
    let _zpi = match decap_zpi(asm, ingress_link_id, &mut pkt) {
        Ok(zpi) => zpi,
        Err(err) => {
            drop_and_count(asm, pkt, err);
            return;
        }
    };

    let Some(base_hdr) = zdp::ZdpBaseHeader::read_from_buf(&mut pkt) else {
        return drop_and_count(asm, pkt, CounterType::BadStructure);
    };

    // In ZPI zero only KM messages are allowed (well, and APR ARP which we don't support yet)
    // Can be overridden (FOR TESTING ONLY) in the flags.
    if !secure && base_hdr.packet_type != zdp::ZdpPacketType::KeyManagement {
        if asm.flags.allow_insecure_zpi_zero {
            warn!("operating in insecure mode - allow_insecure_zpi_zero is ENABLED");
        } else {
            warn!(
                "ingress: link {}: ZPI 0 only allows key management messages, not {:?}",
                ingress_link_id, base_hdr.packet_type
            );
            drop_and_count(asm, pkt, CounterType::OtherError);
            return;
        }
    }

    // enqueue non-transit packets with the management processor
    if base_hdr.packet_type != zdp::ZdpPacketType::TransitPacket {
        // TODO: should we peel off the ZDP header here??
        // (instead of this silly code to restore it?)
        *pkt.alloc_zeroed_header() = base_hdr;

        eprintln!("{}: enqueueing!", asm.system_name);

        // because of how `inspect` works the borrow checker can't track
        // who consumes this when...
        let mut pkt = Some(pkt);

        if asm
            .peer_table
            .inspect(ingress_link_id, |peer_state| {
                // note: we know `pkt` is still `Some` as we're the first to get to it
                match peer_state
                    .mgmt_processor
                    .try_enqueue_packet(pkt.take().unwrap())
                {
                    Ok(()) => (),
                    Err(TryEnqueueError::Full(pkt)) => {
                        eprintln!("{}: queue backpressure!", asm.system_name);
                        drop_and_count(asm, pkt, CounterType::QueueBackpressure);
                    }
                }
            })
            .is_none()
        {
            // note: we know `pkt` is still `Some` as we know the above closure hasn't been executed
            drop_and_count(asm, pkt.take().unwrap(), CounterType::PeerRemoved);
        }
        return;
    }

    let Some(per_flow_hdr) = zdp::ZdpPerFlowHeader::read_from_buf(&mut pkt) else {
        return drop_and_count(asm, pkt, CounterType::BadStructure);
    };

    pkt.metadata_mut().flow_id = per_flow_hdr.stream_id.into(); // TODO: is this necessary?

    forward(asm, ingress_link_id, per_flow_hdr.stream_id.into(), pkt);
}

/// Send a compressed agent packet to the agent.
/// The packet will be decompressed according to the given stream ID.
pub fn agent_input<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    tether_id: zpr::StreamId, // TODO: should we keep this in metadata? or per-flow header?
    mut pkt: Packet<'pktbuf>,
) {
    // extract A2A MAC
    let Some(a2a_hdr) = zdp::ZdpA2aHeader::read_from_buf(&mut pkt) else {
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
    if asm
        .dlt
        .inspect(tether_id, |pep| {
            compress::expand(pep.compression_mode, &pep.five_tuple, &mut pkt)
        })
        .is_none()
    {
        drop_and_count(asm, pkt, CounterType::UnknownStreamId);
        return;
    }

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
pub fn agent_output<'pktbuf>(asm: &Assembly<'pktbuf>, mut pkt: Packet<'pktbuf>) {
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

    let five_tuple = *pkt.metadata().five_tuple(); // TODO: convince borrow checker we don't need to copy this out

    // lookup five tuple in ALT
    match asm.alt.inspect(&five_tuple, |entry| *entry) {
        Some(AltEntry::Active(pep)) => {
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

            // forward packet on
            forward(asm, zpr::AGENT_LINK_ID, pep.tether_id, pkt);
        }

        Some(AltEntry::Pending) => {
            // bind request pending; drop this packet
            drop_and_count(asm, pkt, CounterType::DroppedAwaitingBind);
        }

        None => {
            // issue bind request
            match asm.adapter_manager.try_request_tether_id(pkt) {
                Ok(()) => (),
                Err(TryEnqueueError::Full(pkt)) => {
                    drop_and_count(asm, pkt, CounterType::QueueBackpressure)
                }
            }
        }
    }
}

/// Forward compressed packet.
pub fn forward<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    ingress_stream_id: zpr::StreamId,
    mut pkt: Packet<'pktbuf>,
) {
    // TODO: node forwarding

    // adapter forwarding
    let egress_link =  // FIXME: this is a hack
        if ingress_link_id == zpr::AGENT_LINK_ID {
            0
        } else {
            match asm.ph_mode {
                PhMode::Adapter => zpr::AGENT_LINK_ID,
                PhMode::Node => (ingress_link_id + 1) % 2,
            }
        };

    if egress_link == zpr::AGENT_LINK_ID {
        agent_input(asm, ingress_stream_id, pkt);
    } else {
        let per_flow_hdr = pkt.alloc_zeroed_header::<zdp::ZdpPerFlowHeader>();
        per_flow_hdr.stream_id = ingress_stream_id.into();

        let base_hdr = pkt.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
        base_hdr.packet_type = zdp::ZdpPacketType::TransitPacket;

        substrate_egress(asm, egress_link, pkt);
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
}
