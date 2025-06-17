//! Core management packet functions.
//!
//! These are low-level primitives; most code should use the higher-level
//! functions in `requests` instead.

use crate::assembly::Assembly;
use crate::config;
use crate::counters::CounterType;
use crate::packet::Packet;
use crate::zdp;
use thiserror::Error;
use tokio::time::sleep;
use tracing::*;
use zpr;
use zpr_ext::zerocopy::FromBytesExt;

/// Helper to allocate a new Packet with default parameters from the heap.
pub fn new_heap_packet() -> Packet {
    Packet::new(
        Box::new([0u8; config::PACKET_BUFFER_SIZE]),
        config::DEFAULT_MESSAGE_HEADROOM,
    )
}

pub fn count_event(
    asm: &Assembly,
    _pkt: &mut Packet, // for later support of per-packet event recording
    event: CounterType,
) {
    debug!(target: crate::logging::targets::MGMT_EVENTS, "packet event {event}");
    asm.counters[event].increment();
}

/// Send a unidirectional non-flow management message on the given link.
/// The packet should contain only the message body.
pub fn send_non_flow_mgmt(
    asm: &Assembly,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    packet: Packet,
) -> zpr::SeqNum {
    let seq_num = 0; // TODO, zpr-core/839
    send_mgmt_helper(asm, link_id, packet_type, None, None, packet);
    seq_num
}

/// Send a unidirectional per-flow management message on the given link.
/// The packet should contain only the message body.
#[allow(dead_code)]
pub fn send_per_flow_mgmt(
    asm: &Assembly,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: zpr::StreamId,
    packet: Packet,
) {
    send_mgmt_helper(asm, link_id, packet_type, Some(stream_id), None, packet)
}

pub fn send_per_flow_mgmt_response(
    asm: &Assembly,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: zpr::StreamId,
    sequence_number: zpr::SeqNum,
    packet: Packet,
) {
    send_mgmt_helper(
        asm,
        link_id,
        packet_type,
        Some(stream_id),
        Some(sequence_number),
        packet,
    )
}

fn send_mgmt_helper(
    asm: &Assembly,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: Option<zpr::StreamId>,
    sequence_number: Option<zpr::SeqNum>,
    mut packet: Packet,
) {
    debug_assert_eq!(stream_id.is_some(), packet_type.is_per_flow());

    if let Some(stream_id) = stream_id {
        let per_flow_hdr = packet.alloc_zeroed_header::<zdp::ZdpPerFlowHeader>();
        per_flow_hdr.stream_id = stream_id.into();
    }

    let hdr = packet.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
    hdr.packet_type = packet_type;

    if let Some(sequence_number) = sequence_number {
        // uses only suffix of sequence number
        hdr.sequence_number = (sequence_number as u16).into();
    }

    // It's possible (but unlikely) the MgmtSubstrateEgress queue fills up.
    // In that case, just ignore the error; act as if the packet was dropped
    // by the substrate due to congestion.
    let _ = asm
        .mgmt_substrate_egress
        .try_enqueue_packet(link_id, packet);
}

/// Sender function for per flow request management packet.
/// Requires the type of ZDP packet being sent as well as the type of the
/// expected response packet. Also requires stream_id of the packet.
/// pkt_fn allows the function to create the proper body of the ZDP packet to send
/// Returns the received packet without any ZdpHeader (just management response body) or an error
pub async fn send_sync_per_flow_req(
    asm: &Assembly,
    link_id: zpr::LinkId,
    zdp_request_type: zdp::ZdpPacketType,
    zdp_response_type: zdp::ZdpPacketType,
    stream_id: zpr::StreamId,
    pkt_fn: impl Fn(&mut Packet) + Send + 'static,
) -> Result<(zpr::StreamId, Packet), SyncReqError> {
    match send_sync_req_helper(
        asm,
        link_id,
        zdp_request_type,
        zdp_response_type,
        Some(stream_id),
        pkt_fn,
    )
    .await
    {
        Ok(mut pkt) => {
            let per_flow_hdr =
                zdp::ZdpPerFlowHeader::read_from_buf(&mut pkt).expect("too-short inbound packet"); // FIXME, return failure instead
            Ok((per_flow_hdr.stream_id.into(), pkt))
        }
        Err(err) => Err(err),
    }
}

#[derive(Debug, Error)]
pub enum SyncReqError {
    #[error("link closed")]
    LinkClosed,
    #[error("protocol error")]
    ProtocolError,
    #[error("timeout")]
    Timeout,
}

/// Helper for send management request function
/// Requires the type of ZDP packet being sent as well as the type of the
/// expected response packet. The Option determines whether the function is helping the per-flow or
/// non-per flow sender.
/// pkt_fn allows the function to create the proper body of the ZDP packet to send
/// Returns the received packet without the ZdpBaseHeader, but still any other Zdp header information
/// not included in the ZdpBaseHeader, or an error
async fn send_sync_req_helper(
    asm: &Assembly,
    link_id: zpr::LinkId,
    zdp_request_type: zdp::ZdpPacketType,
    zdp_response_type: zdp::ZdpPacketType,
    stream_id: Option<zpr::StreamId>,
    pkt_fn: impl Fn(&mut Packet) + 'static,
) -> Result<Packet, SyncReqError> {
    // acquire a permit to send a manamgement message
    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Err(SyncReqError::LinkClosed);
    };
    let permit = peer_state.sync_req_state.acquire_permit().await;
    let mut response_future = peer_state.sync_req_state.install_response_listener(&permit);

    for _i in 0..=config::DEFAULT_REQUEST_RETRY_COUNT {
        let mut packet = new_heap_packet();
        pkt_fn(&mut packet);

        send_mgmt_helper(
            asm,
            link_id,
            zdp_request_type,
            stream_id,
            Some(permit.seq_num()),
            packet,
        );

        tokio::select! {
            response = &mut response_future => {
                drop(permit);
                return match_received(asm, response.ok(), SyncReqError::LinkClosed, zdp_response_type);
            }
            _ = sleep(config::DEFAULT_REQUEST_RETRY_TIMER) => ()
        }
    }

    peer_state.sync_req_state.clear_response_listener(&permit);
    let response = response_future.hangup();
    drop(permit);

    match_received(asm, response, SyncReqError::Timeout, zdp_response_type)
}

/// Determines whether the message recieved in response to the request is
/// a) a packet and not an error, and b) the expected packet type
// TODO: rename/move this
fn match_received(
    asm: &Assembly,
    response: Option<(zdp::ZdpPacketType, Packet)>,
    err_type: SyncReqError,
    zdp_response_type: zdp::ZdpPacketType,
) -> Result<Packet, SyncReqError> {
    match response {
        Some((pkt_type, mut pkt)) => {
            if pkt_type != zdp_response_type {
                count_event(asm, &mut pkt, CounterType::BadMgmtResponse);
                return Err(SyncReqError::ProtocolError);
            }
            return Ok(pkt);
        }
        None => return Err(err_type),
    }
}
