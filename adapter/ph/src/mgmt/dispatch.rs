//! Code which handles dispatching management packets from fastpath.

use super::handlers::{HandleMgmtError, HandleMgmtResult}; // TODO: make our own error type
use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::fastpath;
use crate::km_multiplexor;
use crate::packet::Packet;
use crate::queues;
use crate::zdp;
use crate::zpr;
use bytes::Buf;
use tracing::error;
use zerocopy::FromBytes;
use zpr_ext::zerocopy::FromBytesExt;

/// Dispatch the given management packet.
///
/// This function does not block, and does not perform significant processing.
/// It merely dispatches the management packet to the correct queue.
pub fn dispatch_mgmt_packet<'pktbuf>(
    asm: &'static Assembly<'pktbuf>,
    ingress_link_id: Option<zpr::LinkId>,
    peer_sa: zpr::SubstrateAddr,
    mut pkt: Packet<'pktbuf>,
) {
    match zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()) {
        Some(base_hdr) if base_hdr.packet_type == zdp::ZdpPacketType::KeyManagement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());

            // TODO: once we have multi-node, how do we know whether this is a link or a
            // tether?
            let Some(ingress_link_id) =
                ingress_link_id.or_else(|| asm.accept_tether(&peer_sa).ok())
            else {
                return fastpath::drop_and_count(asm, pkt, CounterType::UnknownPeer);
            };

            match handle_key_management(asm, ingress_link_id, pkt) {
                Ok(()) => (),
                Err((err, pkt)) => fastpath::drop_and_count(asm, pkt, err),
            }
        }

        Some(base_hdr) if base_hdr.packet_type.is_response() => {
            let Some(ingress_link_id) = ingress_link_id else {
                return fastpath::drop_and_count(asm, pkt, CounterType::UnknownPeer);
            };

            match handle_response(asm, ingress_link_id, pkt) {
                Ok(()) => (),
                Err((err, pkt)) => fastpath::drop_and_count(asm, pkt, err),
            }
        }

        _ => {
            let Some(ingress_link_id) = ingress_link_id else {
                return fastpath::drop_and_count(asm, pkt, CounterType::UnknownPeer);
            };

            let Some(peer_state) = asm.peer_table.get(ingress_link_id) else {
                fastpath::drop_and_count(asm, pkt, CounterType::PeerRemoved);
                return;
            };

            match peer_state.mgmt_processor.try_enqueue_packet(pkt) {
                Ok(()) => (),
                Err(queues::TryEnqueueError::Full(pkt)) => {
                    fastpath::drop_and_count(asm, pkt, CounterType::QueueBackpressure);
                }
            }
        }
    }
}

fn handle_response<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    mut pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let Some(base_hdr) = zdp::ZdpBaseHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    let packet_type = base_hdr.packet_type;
    let seq_num = base_hdr.sequence_number.get() as u64; // TODO: reconstitute full seq num given expected seq num state

    assert!(
        packet_type.is_response(),
        "stray mgmt request in handle_response()"
    );

    // Gets the designated sender, attempts to send the response, if not drops
    // the packet and increments corresponding counter
    let Some(peer_state) = asm.peer_table.get(ingress_link_id) else {
        return Err((HandleMgmtError::UnexpectedMgmtResponse, pkt));
    };

    peer_state
        .sync_req_state
        .forward_response(seq_num, (packet_type, pkt))
        .map_err(|pkt| (HandleMgmtError::UnexpectedMgmtResponse, pkt))
}

// ZPI and Base header is already gone by the time we get here.  So we expect
// to parse starting from the KeyManagement header.
fn handle_key_management<'pktbuf>(
    asm: &'static Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    mut pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let Some(km_hdr) = zdp::ZdpKeyManagementHeader::read_from_buf(&mut pkt) else {
        error!("KeyManagement packet arrived with unparseable header");
        return Err((HandleMgmtError::BadStructure, pkt));
    };
    if !km_hdr.is_noise() {
        error!(
            "KeyManagement packet not using NOISE - type is {}",
            km_hdr.message_type
        );
        return Err((
            HandleMgmtError::UnknownKeyManagementType(km_hdr.message_type.into()),
            pkt,
        ));
    }
    let km_msg_len = usize::from(km_hdr.message_length);
    if pkt.remaining() < km_msg_len {
        error!("KeyManagement packet arrived with truncated payload");
        return Err((HandleMgmtError::BadStructure, pkt));
    }

    match km_multiplexor::handle_inbound_km_msg(asm, ingress_link_id, &pkt.body()[..km_msg_len]) {
        Ok(()) => (),
        Err(e) => {
            error!(
                "key management handling failed on link {}: {:?}",
                ingress_link_id, e
            );
            return Err((HandleMgmtError::KeyManagementError(format!("{:?}", e)), pkt));
        }
    };
    asm.buffer_stack.put_buffer(pkt.destroy());

    Ok(())
}
