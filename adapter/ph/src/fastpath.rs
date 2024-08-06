//! Fastpath operations.
//!
//! General rule: no fastpath operation may block.
//! This implies that all functions here must be non-async.

use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::defs::Direction;
use crate::packet::Packet;
use crate::queues::TryEnqueueError;
use crate::zdp;
use crate::zdp_ll;
use crate::zpr;
use bytes::Buf;
use std::time::SystemTime;
use zerocopy::FromBytes;
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
        let caplen = asm.flow_control.check_packet(pkt.body());
        if caplen > 0 {
            match bufs.pop().or_else(|| {
                if out_of_bufs {
                    None
                } else {
                    asm.buffer_stack.try_get_buffer()
                }
            }) {
                Some(buf) => {
                    let pkt_clone: Packet = pkt.clone_into(buf);
                    // remove direction indicator from beginning of packet
                    pkt.advance(std::mem::size_of::<zdp_ll::ZdpLinkP2P>());

                    // Checks to see if the packet enqueue was successful
                    match asm.capture_queue.try_enqueue_packet(
                        pkt_clone,
                        capture_time,
                        caplen, // TODO: pass full packet length instead, and only copy caplen bytes
                    ) {
                        Ok(()) => num_captured += 1,

                        Err(TryEnqueueError::Full(ret_packet)) => {
                            asm.buffer_stack.put_buffer(ret_packet.destroy());
                            // No sense to try enqueuing more packets; exit the loop early.
                            break;
                        }
                    };
                }

                None => {
                    // No sense to try acquiring more buffers; exit the loop early.
                    break;
                }
            }
        } else {
            num_filtered += 1;
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
        // TODO: MAC
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
        // TODO: MAC
        Ok(())
    } else {
        todo!("decryption");
    }
}

/// Egress a ZDP packet on the given link ID, according to the given ZPI.
/// The ZPI header will be added to the packet.
pub fn substrate_egress<'pktbuf>(asm: &Assembly<'pktbuf>, link_id: zpr::LinkId, zpi: zpr::Zpi, mut pkt: Packet<'pktbuf>) {
    encap_zpi(asm, link_id, zpi, &mut pkt);

    maybe_capture(asm, Direction::Outbound, &mut pkt);

    encrypt(asm, link_id, &mut pkt);

    if link_id != zpr::ADAPTER_DOCKING_SESSION_ID {
        todo!("link routing");
    }

    match asm
        .outbound_send
        .try_enqueue_packet(drop_guard(pkt, |p|
            drop_and_count(asm, p, CounterType::OutPacksSent)
        ))
    {
        Ok(()) => (),
        Err(TryEnqueueError::Full(pkt)) =>
            drop_and_count(asm, pkt.into_inner(), CounterType::OutPacksErr),
    }
}

/// Send a compressed agent packet to the agent.
/// The packet will be decompressed according to the given stream ID.
pub fn agent_input<'pktbuf>(asm: &Assembly<'pktbuf>, _stream_id: zpr::StreamId, pkt: Packet<'pktbuf>) {
    // TODO: decompress

    // send out decapsulated packet
    match asm.inbound_send
        .try_enqueue_packet(drop_guard(pkt, |p|
            drop_and_count(asm, p, CounterType::InPacksSent)
        ))
    {
        Ok(()) => (),
        Err(TryEnqueueError::Full(pkt)) =>
            drop_and_count(asm, pkt.into_inner(), CounterType::InPacksDrop),
    }
}
