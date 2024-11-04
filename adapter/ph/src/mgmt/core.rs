//! Core management packet functions.
//!
//! These are low-level primitives; most code should use the higher-level
//! functions in `requests` instead.

use crate::assembly::Assembly;
use crate::config;
use crate::counters::CounterType;
use crate::fastpath;
use crate::packet::{BufferPacket, Packet};
use crate::zdp;
use std::time::Duration;
use tokio::time::sleep;
use zpr;
use zpr_ext::std::mem::{drop_guard, DropGuard};
use zpr_ext::zerocopy::FromBytesExt;

/// Send a unidirectional non-flow management message on the given link.
/// The packet should contain only the message body.
pub async fn send_non_flow_mgmt(
    asm: &Assembly,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    packet: BufferPacket,
) {
    send_mgmt_helper(asm, link_id, packet_type, None, None, packet).await
}

/// Send a unidirectional per-flow management message on the given link.
/// The packet should contain only the message body.
#[allow(dead_code)]
pub async fn send_per_flow_mgmt(
    asm: &Assembly,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: zpr::StreamId,
    packet: BufferPacket,
) {
    send_mgmt_helper(asm, link_id, packet_type, Some(stream_id), None, packet).await
}

pub async fn send_non_flow_mgmt_response(
    asm: &Assembly,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    sequence_number: zpr::SeqNum,
    packet: BufferPacket,
) {
    send_mgmt_helper(
        asm,
        link_id,
        packet_type,
        None,
        Some(sequence_number),
        packet,
    )
    .await
}

pub async fn send_per_flow_mgmt_response(
    asm: &Assembly,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: zpr::StreamId,
    sequence_number: zpr::SeqNum,
    packet: BufferPacket,
) {
    send_mgmt_helper(
        asm,
        link_id,
        packet_type,
        Some(stream_id),
        Some(sequence_number),
        packet,
    )
    .await
}

async fn send_mgmt_helper(
    asm: &Assembly,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: Option<zpr::StreamId>,
    sequence_number: Option<zpr::SeqNum>,
    mut packet: BufferPacket,
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

    fastpath::substrate_egress_blocking(asm, link_id, packet).await;
}

/// Sender function for non-per flow request management packet.
/// Requires the type of ZDP packet being sent as well as the type of the
/// expected response packet.
/// pkt_fn allows the function to create the proper body of the ZDP packet to send
/// Returns the received packet without any ZdpHeader (just management response body) or an error
pub async fn send_sync_non_flow_req(
    asm: &Assembly,
    link_id: zpr::LinkId,
    zdp_request_type: zdp::ZdpPacketType,
    zdp_response_type: zdp::ZdpPacketType,
    pkt_fn: impl Fn(&mut BufferPacket) + Send + 'static,
) -> Result<BufferPacket, SyncReqError> {
    send_sync_req_helper(
        asm,
        link_id,
        zdp_request_type,
        zdp_response_type,
        None,
        pkt_fn,
    )
    .await
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
    pkt_fn: impl Fn(&mut BufferPacket /* FIXME: can relax to Packet<_> */) + Send + 'static,
) -> Result<(zpr::StreamId, BufferPacket), SyncReqError> {
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

pub enum SyncReqError {
    LinkClosed,
    ProtocolError,
    Timeout,
}

impl std::fmt::Display for SyncReqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(match self {
            Self::LinkClosed => "link closed",
            Self::ProtocolError => "protocol error",
            Self::Timeout => "timeout",
        })
    }
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
    pkt_fn: impl Fn(&mut BufferPacket /* FIXME: relax to Packet */) + 'static,
) -> Result<BufferPacket, SyncReqError> {
    // acquire a permit to send a manamgement message
    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Err(SyncReqError::LinkClosed);
    };
    let permit = peer_state.sync_req_state.acquire_permit().await;
    let mut response_future = peer_state.sync_req_state.install_response_listener(&permit);

    for _i in 0..=config::DEFAULT_REQUEST_RETRY_COUNT {
        let buf = drop_guard(asm.buffer_stack.get_buffer().await, |buf| {
            asm.buffer_stack.put_buffer(buf)
        });
        let mut packet = Packet::new_guarded(buf, config::DEFAULT_MESSAGE_HEADROOM);
        pkt_fn(&mut packet);

        send_mgmt_helper(
            asm,
            link_id,
            zdp_request_type,
            stream_id,
            Some(permit.seq_num()),
            packet.into_inner(),
        )
        .await;

        tokio::select! {
            response = &mut response_future => {
                drop(permit);
                return match_received(asm, response.ok(), SyncReqError::LinkClosed, zdp_response_type);
            }
            _ = sleep(Duration::from_secs(config::DEFAULT_REQUEST_RETRY_TIMER as u64)) => ()
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
    response: Option<(zdp::ZdpPacketType, BufferPacket)>,
    err_type: SyncReqError,
    zdp_response_type: zdp::ZdpPacketType,
) -> Result<BufferPacket, SyncReqError> {
    match response {
        Some((pkt_type, pkt)) => {
            if pkt_type != zdp_response_type {
                fastpath::drop_and_count(asm, pkt, CounterType::BadMgmtResponse);
                return Err(SyncReqError::ProtocolError);
            }
            return Ok(pkt);
        }
        None => return Err(err_type),
    }
}
