//! Code which handles dispatching management packets from fastpath.

use super::core;
use crate::assembly::Assembly;
use crate::counters::CounterType;
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
                core::count_event(asm, pkt, CounterType::UnknownPeer);
                return;
            };

            pkt.metadata_mut().ingress_link_id = ingress_link_id.get();

            handle_key_management(asm, pkt);
        }
        _ => {
            core::count_event(asm, pkt, CounterType::UnknownPeer);
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

        Ok((base_hdr, _)) if base_hdr.packet_type.is_response() => handle_response(asm, pkt),

        _ => {
            let Some(peer_state) = asm.peer_table.get(pkt.metadata().ingress_link_id) else {
                core::count_event(asm, pkt, CounterType::PeerRemoved);
                return;
            };

            let mgmt_pkt = Packet::new_with_existing_metadata(pkt.buffer().clone());
            match peer_state.mgmt_processor.try_enqueue_packet(mgmt_pkt) {
                Ok(()) => (),
                Err(queues::TryEnqueueError::Full(_mgmt_pkt)) => {
                    core::count_event(asm, pkt, CounterType::QueueBackpressure);
                    return;
                }
            }
        }
    }
}

fn handle_response(asm: &Assembly, pkt: &mut Packet) {
    let Ok(base_hdr) = zdp::ZdpBaseHeader::read_from_buf(pkt) else {
        core::count_event(asm, pkt, CounterType::BadStructure);
        return;
    };

    let packet_type = base_hdr.packet_type;
    let seq_num = base_hdr.sequence_number.get() as u64; // TODO: reconstitute full seq num given expected seq num state

    assert!(
        packet_type.is_response(),
        "stray mgmt request in handle_response()"
    );

    // Gets the designated sender, attempts to send the response, if not drops
    // the packet and increments corresponding counter
    let Some(peer_state) = asm.peer_table.get(pkt.metadata().ingress_link_id) else {
        core::count_event(asm, pkt, CounterType::UnexpectedMgmtResponse);
        return;
    };

    let mgmt_pkt = Packet::new_with_existing_metadata(pkt.buffer().clone());
    match peer_state
        .sync_req_state
        .forward_response(seq_num, (packet_type, mgmt_pkt))
    {
        Ok(()) => (),
        Err(_mgmt_pkt) => {
            core::count_event(asm, pkt, CounterType::UnexpectedMgmtResponse);
            return;
        }
    }
}

// ZPI and Base header is already gone by the time we get here.  So we expect
// to parse starting from the KeyManagement header.
fn handle_key_management(asm: &Arc<Assembly>, pkt: &mut Packet) {
    let Ok(km_hdr) = zdp::ZdpKeyManagementHeader::read_from_buf(pkt) else {
        error!(target: ZDP, "KeyManagement packet arrived with unparseable header");
        core::count_event(asm, pkt, CounterType::BadStructure);
        return;
    };

    if !km_hdr.is_noise() {
        error!(
            target: KEY_MGMT,
            "KeyManagement packet not using NOISE - type is {}",
            km_hdr.message_type
        );
        core::count_event(asm, pkt, CounterType::OtherError);
        return;
    }

    let km_msg_len = usize::from(km_hdr.message_length);
    if pkt.remaining() < km_msg_len {
        error!(target: KEY_MGMT, "KeyManagement packet arrived with truncated payload");
        core::count_event(asm, pkt, CounterType::BadStructure);
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
            core::count_event(asm, pkt, CounterType::OtherError);
            return;
        }
    };
}
