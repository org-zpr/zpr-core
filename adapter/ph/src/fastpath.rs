//! Fastpath operations.
//!
//! General rule: no fastpath operation may block.
//! This implies that all functions here must be non-async.

use crate::assembly::Assembly;
use crate::classifier::{self, ClassifierResult};
use crate::compress;
use crate::counters_enum::CounterType;
use crate::defs::Direction;
use crate::net_defs;
use crate::packet::Packet;
use crate::peer_table::PeerState;
use crate::queues::TryEnqueueError;
use crate::zdp;
use crate::zdp_ll;
use crate::zpr;
use bytes::{Buf, BufMut};
use std::mem::size_of;
use std::net::SocketAddr;
use std::time::SystemTime;
use zerocopy::{AsBytes, FromBytes};
use zpr_ext::std::mem::{drop_guard, DropGuard};
use zpr_ext::zerocopy::*;

/// Drop a packet and count the drop with the given reason.
pub fn drop_and_count<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    pkt: Packet<'pktbuf>,
    reason: impl Into<CounterType>,
) {
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
pub fn encrypt<'pktbuf>(
    _asm: &Assembly<'pktbuf>,
    _link_id: zpr::LinkId,
    pkt: &mut Packet<'pktbuf>,
) {
    let zpi_hdr =
        zdp::ZdpZpiHeader::ref_from_prefix(pkt.body()).expect("ZPI header must be present");
    let zpi = zpi_hdr.zpi as zpr::Zpi;

    if zpi == zpr::ZPI_0 {
        // RFC 6.5 § 5.25.2
        pkt.put(
            net_defs::inet_checksum(&pkt.body()[std::mem::size_of::<zdp::ZdpZpiHeader>()..])
                .as_slice(),
        );
    } else {
        todo!("encryption");
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
pub fn decrypt<'pktbuf>(
    _asm: &Assembly<'pktbuf>,
    _link_id: zpr::LinkId,
    pkt: &mut Packet<'pktbuf>,
) -> Result<(), DecryptError> {
    let zpi_hdr =
        zdp::ZdpZpiHeader::ref_from_prefix(pkt.body()).ok_or(DecryptError::BadStructure)?;
    let zpi = zpi_hdr.zpi as zpr::Zpi;

    if zpi == zpr::ZPI_0 {
        // RFC 6.5 § 5.25.2
        if !net_defs::validate_inet_checksum(
            &pkt.body()[std::mem::size_of::<zdp::ZdpZpiHeader>()..],
        ) {
            return Err(DecryptError::MicvFailure);
        }

        pkt.shrink(2); // remove checksum

        Ok(())
    } else {
        todo!("decryption");
    }
}

fn substrate_egress_common<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    zpi: zpr::Zpi,
    pkt: &mut Packet<'pktbuf>,
) -> Option<zpr::SubstrateAddr> {
    // TODO: should we add ZDP header here also??

    encap_zpi(asm, link_id, zpi, pkt);

    maybe_capture(asm, Direction::Outbound, pkt);

    encrypt(asm, link_id, pkt);

    asm.peer_table
        .inspect(link_id, |peer_state: &PeerState| peer_state.substrate_addr)
}

/// Egress a ZDP packet on the given link ID, according to the given ZPI.
/// The ZPI header will be added to the packet.
pub fn substrate_egress<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    zpi: zpr::Zpi,
    mut pkt: Packet<'pktbuf>,
) {
    let Some(dest_sa) = substrate_egress_common(asm, link_id, zpi, &mut pkt) else {
        drop_and_count(asm, pkt, CounterType::PeerRemoved);
        return;
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
    zpi: zpr::Zpi,
    mut pkt: Packet<'pktbuf>,
) {
    let Some(dest_sa) = substrate_egress_common(asm, link_id, zpi, &mut pkt) else {
        drop_and_count(asm, pkt, CounterType::PeerRemoved);
        return;
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
        Err(pkt) => drop_and_count(asm, pkt.into_inner(), CounterType::OutPacksErr),
    }
}

/// Process packets ingressing from the specified SA.
pub fn substrate_ingress<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    peer_sa: &SocketAddr,
    mut pkt: Packet<'pktbuf>,
) {
    asm.counters[CounterType::InPacksRec].increment();

    let Some(ingress_link_id) = asm.peer_table.lookup_peer(peer_sa) else {
        drop_and_count(asm, pkt, CounterType::UnknownPeer);
        return;
    };

    match decrypt(asm, ingress_link_id, &mut pkt) {
        Ok(()) => (),
        Err(err) => {
            drop_and_count(asm, pkt, err);
            return;
        }
    }

    maybe_capture(asm, Direction::Inbound, &mut pkt);

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

    // enqueue non-transit packets with the management processor
    if base_hdr.packet_type != zdp::ZdpPacketType::TransitPacket {
        // TODO: should we peel off the ZDP header here??
        // (instead of this silly code to restore it?)
        *pkt.alloc_zeroed_header() = base_hdr;

        match asm.mgmt_processor.try_enqueue_packet(ingress_link_id, pkt) {
            Ok(()) => (),
            Err(TryEnqueueError::Full(pkt)) => drop_and_count(asm, pkt, CounterType::InPacksDrop),
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
    stream_id: zpr::StreamId, // TODO: should we keep this in metadata? or per-flow header?
    mut pkt: Packet<'pktbuf>,
) {
    // "Check" A2A checksum
    pkt.advance(size_of::<zdp::ZdpSaidHeader>());
    pkt.shrink(size_of::<zdp::ZdpMicvEnd>());

    // lookup PEP in DLT and expand compressed packet
    if asm
        .dlt
        .inspect(stream_id, |pep| {
            compress::expand(pep.compression_mode, &pep.five_tuple, &mut pkt)
        })
        .is_none()
    {
        drop_and_count(asm, pkt, CounterType::UnknownStreamId);
        return;
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
            // TODO; handle fragments!
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

    match asm.alt.inspect(&five_tuple, |pep| {
        // compress packet
        compress::compress(
            pep.compression_mode,
            five_tuple.l3_type,
            five_tuple.l4_protocol,
            &mut pkt,
        );

        // "generate" A2A checksum
        pkt.alloc_zeroed_header::<zdp::ZdpSaidHeader>().a2a_said = 0;
        let micv: zdp::ZdpMicvEnd = zdp::ZdpMicvEnd { micv: 0 };
        pkt.put(micv.as_bytes());

        pep.stream_id
    }) {
        Some(stream_id) => {
            forward(asm, zpr::AGENT_LINK_ID, stream_id, pkt);
        }

        None => {
            // TODO: issue bind request!
            drop_and_count(asm, pkt, CounterType::OtherError);
            return;
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
    if ingress_link_id == zpr::AGENT_LINK_ID {
        // in from agent; out to dock

        let per_flow_hdr = pkt.alloc_zeroed_header::<zdp::ZdpPerFlowHeader>();
        per_flow_hdr.stream_id = ingress_stream_id.into();

        let base_hdr = pkt.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
        base_hdr.packet_type = zdp::ZdpPacketType::TransitPacket;

        substrate_egress(asm, asm.adapter_docking_session_id, zpr::ZPI_0, pkt);
    } else {
        // in from dock; out to agent
        agent_input(asm, ingress_stream_id, pkt);
    }
}
