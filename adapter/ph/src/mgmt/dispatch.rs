//! Code which handles dispatching management packets from fastpath.

use super::core;
use crate::assembly::Assembly;
use crate::counters::ManagementCounterType;
use crate::km_multiplexor;
use crate::link_state::LinkType;
use crate::logging::targets::{KEY_MGMT, ZDP};
use crate::net_defs;
use crate::packet::Packet;
use crate::queues;
use crate::zdp;
use bytes::Buf;
use std::sync::Arc;
use tracing::error;
use zerocopy::FromBytes;
use zpr;
use zpr_ext::zerocopy::FromBytesExt;

/// Dispatch a management packet for a link that hasn't been established yet
///
/// This function does not block, and does not perform significant processing.
/// It merely dispatches the management packet to the correct queue.
pub fn dispatch_mgmt_packet_with_addr(
    asm: &Arc<Assembly>,
    peer_sa: zpr::SubstrateAddr,
    interface_addr: net_defs::ScopedIpAddr,
    pkt: &mut Packet,
) {
    match zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()) {
        Ok(base_hdr) if base_hdr.0.packet_type == zdp::ZdpPacketType::KeyManagement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());

            // TODO: once we have multi-node, how do we know whether this is a link or a
            // tether?
            let Some(ingress_link_id) = asm
                .start_tether(&peer_sa, &interface_addr, LinkType::NodeToAdapter)
                .ok()
            else {
                core::count_event(asm, pkt, ManagementCounterType::UnknownPeer);
                return;
            };

            pkt.metadata_mut().ingress_link_id = ingress_link_id.get();

            handle_key_management(asm, pkt);
        }
        _ => {
            core::count_event(asm, pkt, ManagementCounterType::UnknownPeer);
            return;
        }
    }
}

/// Dispatch the given management packet.
///
/// This function does not block, and does not perform significant processing.
/// It merely dispatches the management packet to the correct queue.
pub fn dispatch_mgmt_packet_with_link(asm: &Arc<Assembly>, pkt: &mut Packet) {
    match zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()) {
        Ok((base_hdr, _)) if base_hdr.packet_type == zdp::ZdpPacketType::KeyManagement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
            handle_key_management(asm, pkt);
        }

        Ok((base_hdr, _)) if base_hdr.packet_type == zdp::ZdpPacketType::Acknowledgement => {
            handle_acknowledgement(asm, pkt)
        }

        Ok((base_hdr, _)) if base_hdr.packet_type.is_response() => handle_response(asm, pkt),

        _ => {
            let Some(peer_state) = asm.peer_table.get(pkt.metadata().ingress_link_id) else {
                core::count_event(asm, pkt, ManagementCounterType::PeerRemoved);
                return;
            };

            pkt.metadata_mut().seq_num = 0; // TODO, get from ZDPR (upcoming PR)

            let mgmt_pkt = Packet::new_with_existing_metadata(pkt.buffer().clone());

            match peer_state.mgmt_processor.try_enqueue_packet(mgmt_pkt) {
                Ok(()) => (),
                Err(queues::TryEnqueueError::Full(_mgmt_pkt)) => {
                    core::count_event(asm, pkt, ManagementCounterType::QueueBackpressure);
                    return;
                }
            }
        }
    }
}

fn handle_acknowledgement(asm: &Assembly, pkt: &mut Packet) {
    let Ok(base_hdr) = zdp::ZdpBaseHeader::read_from_buf(pkt) else {
        core::count_event(asm, pkt, ManagementCounterType::BadStructure);
        return;
    };

    let sn = base_hdr.sequence_number.get();
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Some(peer_state) = asm.peer_table.get(ingress_link_id) else {
        core::count_event(asm, pkt, ManagementCounterType::PeerRemoved);
        return;
    };
    let mut sender = peer_state.zdpr_send.lock().unwrap();

    let seq_num = sender.reify_seq_num(sn);
    sender.process_ack(seq_num);

    // If at this point (after processing the ACK) we should not have our
    // retry timer running (because all outstanding packets have been
    // ACKed), we may be liable to restart the timer after possibly sending
    // unblocked packets.
    let old_retry_needed = sender.retry_needed();

    // We may now be unblocked and may have been blocked before;
    // try to send queued packets.
    while sender.unblock_needed() {
        let sn_pkt = sender.enqueue_next_blocked_packet();
        core::build_and_egress_packets(asm, ingress_link_id, std::iter::once(sn_pkt));
    }

    if sender.retry_needed() && !old_retry_needed {
        // We should activate / restart our retry timer.
        peer_state.zdpr_retry_timer_reset.notify_one();
    }
}

fn handle_response(asm: &Assembly, pkt: &mut Packet) {
    let Ok(base_hdr) = zdp::ZdpBaseHeader::read_from_buf(pkt) else {
        core::count_event(asm, pkt, ManagementCounterType::BadStructure);
        return;
    };

    let packet_type = base_hdr.packet_type;

    let Ok(txn_hdr) = zdp::ZdpTransactionHeader::read_from_buf(pkt) else {
        core::count_event(asm, pkt, ManagementCounterType::BadStructure);
        return;
    };
    let txn_id = txn_hdr.transaction_id.get();

    assert!(
        packet_type.is_response(),
        "stray mgmt request in handle_response()"
    );

    // Gets the designated sender, attempts to send the response, if not drops
    // the packet and increments corresponding counter
    let Some(peer_state) = asm.peer_table.get(pkt.metadata().ingress_link_id) else {
        core::count_event(asm, pkt, ManagementCounterType::UnexpectedMgmtResponse);
        return;
    };

    let mgmt_pkt = Packet::new_with_existing_metadata(pkt.buffer().clone());
    match peer_state
        .sync_req_state
        .forward_response(txn_id, (packet_type, mgmt_pkt))
    {
        Ok(()) => (),
        Err(_mgmt_pkt) => {
            core::count_event(asm, pkt, ManagementCounterType::UnexpectedMgmtResponse);
            return;
        }
    }
}

// ZPI and Base header is already gone by the time we get here.  So we expect
// to parse starting from the KeyManagement header.
fn handle_key_management(asm: &Arc<Assembly>, pkt: &mut Packet) {
    let Ok(km_hdr) = zdp::ZdpKeyManagementHeader::read_from_buf(pkt) else {
        error!(target: ZDP, "KeyManagement packet arrived with unparseable header");
        core::count_event(asm, pkt, ManagementCounterType::BadStructure);
        return;
    };

    if (km_hdr.is_noise() && asm.config.get().km_impl != zpr::KM_ID_NOISE)
        || (km_hdr.is_null() && asm.config.get().km_impl != zpr::KM_ID_NULL)
    {
        error!(
            target: KEY_MGMT,
            "KeyManagement packet type does not match KM implementation - type is {}",
            km_hdr.message_type
        );
        core::count_event(asm, pkt, ManagementCounterType::OtherError);
        return;
    }

    let km_msg_len = usize::from(km_hdr.message_length);
    if pkt.remaining() < km_msg_len {
        error!(target: KEY_MGMT, "KeyManagement packet arrived with truncated payload");
        core::count_event(asm, pkt, ManagementCounterType::BadStructure);
        return;
    }

    match km_multiplexor::handle_inbound_km_msg(
        asm,
        pkt.metadata().ingress_link_id,
        &pkt.body()[..km_msg_len],
    ) {
        Ok(()) => (),
        Err(e) => {
            error!(
                target: KEY_MGMT,
                "key management handling failed on link {}: {e:?}",
                pkt.metadata().ingress_link_id,
            );
            core::count_event(asm, pkt, ManagementCounterType::OtherError);
            return;
        }
    };
    return;
}
