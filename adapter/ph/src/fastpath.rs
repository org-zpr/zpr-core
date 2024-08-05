//! Fastpath operations.
//!
//! General rule: no fastpath operation may block.
//! This implies that all functions here must be non-async.

use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::defs::Direction;
use crate::packet::Packet;
use crate::queues::TryEnqueueError;
use crate::zdp_ll;
use bytes::Buf;
use std::time::SystemTime;

/// Offer a packet to be captured by the packet capture facility.
/// The packet must be a complete ZDP message.
/// Despite the &mut borrow, the packet will return materially unchanged.
/// (It will have a link-layer header temporarily added to it.)
pub fn maybe_capture<'a, 'pktbuf: 'a>(asm: &Assembly<'pktbuf>, dir: Direction, pkts: impl IntoIterator<Item = &'a mut Packet<'pktbuf>>) {
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
            match bufs.pop().or_else(|| if out_of_bufs { None } else { asm.buffer_stack.try_get_buffer() }) {
                Some(buf) => {
                    let pkt_clone: Packet = pkt.clone_into(buf);
                    // remove direction indicator from beginning of packet
                    pkt.advance(std::mem::size_of::<zdp_ll::ZdpLinkP2P>());

                    // Checks to see if the packet enqueue was successful
                    match asm.capture_queue.try_enqueue_packet(
                        pkt_clone,
                        capture_time,
                        caplen,  // TODO: pass full packet length instead, and only copy caplen bytes
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
