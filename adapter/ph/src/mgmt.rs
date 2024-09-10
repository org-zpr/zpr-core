//! Management packet functions.

use crate::adapter_tables;
use crate::assembly::{Assembly, PhMode};
use crate::config;
use crate::counters_enum::{self, CounterType};
use crate::defs::*;
use crate::dock_tables;
use crate::fastpath;
use crate::km_multiplexor;
use crate::packet::{self, Packet};
use crate::queues;
use crate::zdp;
use crate::zpr;
use bytes::{Buf, BufMut};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};
use zerocopy::FromBytes;
use zpr_ext::std::mem::{drop_guard, DropGuard};
use zpr_ext::zerocopy::{AsBytesExt, FromBytesExt};

/// Send a unidirectional non-flow management message on the given link.
/// The packet should contain only the message body.
pub async fn send_non_flow_mgmt<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    packet: Packet<'pktbuf>,
) {
    send_mgmt_helper(asm, link_id, packet_type, None, None, packet).await
}

/// Send a unidirectional per-flow management message on the given link.
/// The packet should contain only the message body.
#[allow(dead_code)]
pub async fn send_per_flow_mgmt<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: zpr::StreamId,
    packet: Packet<'pktbuf>,
) {
    send_mgmt_helper(asm, link_id, packet_type, Some(stream_id), None, packet).await
}

pub async fn send_non_flow_mgmt_response<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    sequence_number: zpr::SeqNum,
    packet: Packet<'pktbuf>,
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

pub async fn send_per_flow_mgmt_response<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: zpr::StreamId,
    sequence_number: zpr::SeqNum,
    packet: Packet<'pktbuf>,
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

async fn send_mgmt_helper<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: Option<zpr::StreamId>,
    sequence_number: Option<zpr::SeqNum>,
    mut packet: Packet<'pktbuf>,
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
pub async fn send_sync_non_flow_req<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    zdp_request_type: zdp::ZdpPacketType,
    zdp_response_type: zdp::ZdpPacketType,
    pkt_fn: impl Fn(&mut Packet<'_>) + Send + 'static,
) -> Result<Packet<'pktbuf>, SyncReqError> {
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
pub async fn send_sync_per_flow_req<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    zdp_request_type: zdp::ZdpPacketType,
    zdp_response_type: zdp::ZdpPacketType,
    stream_id: zpr::StreamId,
    pkt_fn: impl Fn(&mut Packet<'_>) + Send + 'static,
) -> Result<(zpr::StreamId, Packet<'pktbuf>), SyncReqError> {
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
async fn send_sync_req_helper<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    zdp_request_type: zdp::ZdpPacketType,
    zdp_response_type: zdp::ZdpPacketType,
    stream_id: Option<zpr::StreamId>,
    pkt_fn: impl Fn(&mut Packet<'_>) + 'static,
) -> Result<Packet<'pktbuf>, SyncReqError> {
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
fn match_received<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    response: Option<(zdp::ZdpPacketType, Packet<'pktbuf>)>,
    err_type: SyncReqError,
    zdp_response_type: zdp::ZdpPacketType,
) -> Result<Packet<'pktbuf>, SyncReqError> {
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

pub fn dispatch_mgmt_packet<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    mut pkt: Packet<'pktbuf>,
) {
    match zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()) {
        Some(base_hdr) if base_hdr.packet_type == zdp::ZdpPacketType::KeyManagement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
            match handle_key_management(asm, ingress_link_id, pkt) {
                Ok(()) => (),
                Err((err, pkt)) => fastpath::drop_and_count(asm, pkt, err),
            }
        }

        Some(base_hdr) if base_hdr.packet_type.is_response() => {
            match handle_response(asm, ingress_link_id, pkt) {
                Ok(()) => (),
                Err((err, pkt)) => fastpath::drop_and_count(asm, pkt, err),
            }
        }

        _ => {
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

/// send a Report message (RFC 6.5 § 6.3.13)
pub async fn send_report(asm: &Assembly<'_>, link_id: zpr::LinkId, report: &str) {
    // TODO this condition will need to be adjusted when we have complete ZPR packets
    // with the information at the end of the packet at well
    if packet::PACKET_BUFFER_MAX_BODY_SIZE - config::DEFAULT_MESSAGE_HEADROOM < report.len() {
        return;
    }
    let buf = asm.buffer_stack.get_buffer().await;
    let mut pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpReportHeader>();
    hdr.report_data_length = (report.len() as u16).into();
    pkt.put(report.as_bytes());
    send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Report, pkt).await;
}

/// send a Discard message (RFC 6.5 § 6.3.1)
pub async fn send_discard(asm: &Assembly<'_>, link_id: zpr::LinkId) {
    let buf = asm.buffer_stack.get_buffer().await;
    let pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
    send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Discard, pkt).await;
}

/// send a Hello Request and wait for the Response (RFC 6.5 § 6.3.4)
pub async fn send_hello_request<'a, 'pktbuf>(
    asm: &'a Assembly<'pktbuf>,
    link_id: zpr::LinkId,
) -> Result<(), ()> {
    let response = send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::HelloRequest,
        zdp::ZdpPacketType::HelloResponse,
        move |_packet| {},
    )
    .await;

    match response {
        Ok(mut hello_res) => {
            let Some(hdr) = zdp::ZdpHelloResponseHeader::read_from_buf(&mut hello_res) else {
                fastpath::drop_and_count(asm, hello_res, CounterType::BadStructure);
                return Err(());
            };
            let status = hdr.status;
            info!("Received HelloResponse, status: {}", status);
            asm.buffer_stack.put_buffer(hello_res.destroy());
            Ok(())
        }

        Err(err) => {
            warn!("{} error with HelloRequest", err);
            Err(())
        }
    }
}

pub enum BindAgentAddressError {
    SyncReqError(SyncReqError),
    BadStructure,
    BindAgentAddressError(Box<str>),
}

impl std::fmt::Display for BindAgentAddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::SyncReqError(err) => err.fmt(f),
            Self::BadStructure => write!(f, "bad structure"),
            Self::BindAgentAddressError(msg) => f.write_str(&*msg),
        }
    }
}

/// send a Bind Agent Address Request and wait for the Response (RFC 6.5 § 6.3.11)
pub async fn send_bind_agent_address_request<'a, 'pktbuf>(
    asm: &'a Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    compression_mode: zpr::CompressionMode,
    five_tuple: FiveTuple,
) -> Result<zpr::StreamId, BindAgentAddressError> {
    let response = send_sync_per_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::BindAgentAddressRequest,
        zdp::ZdpPacketType::BindAgentAddressResponse,
        0,
        move |mut req| {
            zdp::ZdpBindAgentAddressRequestHeader {
                ip_version: five_tuple.l3_type,
                compression_mode,
            }
            .write_to_buf(&mut req);

            match five_tuple.l3_type {
                zpr::L3Type::Ipv4 => {
                    req.put(five_tuple.src_address.read_as_v4().as_slice());
                    req.put(five_tuple.dst_address.read_as_v4().as_slice());
                }

                zpr::L3Type::Ipv6 => {
                    req.put(five_tuple.src_address.v6.as_slice());
                    req.put(five_tuple.dst_address.v6.as_slice());
                }

                other => panic!("bad L3 type: {}", other.0),
            }

            req.put_u8(five_tuple.l4_protocol);

            if compression_mode != 0 {
                todo!("L4 compression");
            }
        },
    )
    .await;

    match response {
        Ok((tether_id, mut resp)) => {
            let Some(hdr) = zdp::ZdpBindAgentAddressResponseHeader::read_from_buf(&mut resp) else {
                fastpath::drop_and_count(asm, resp, CounterType::BadStructure);
                return Err(BindAgentAddressError::BadStructure);
            };

            match hdr.status_code {
                zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_SUCCESS => {
                    asm.buffer_stack.put_buffer(resp.destroy());
                    Ok(tether_id)
                }

                zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_OTHER => {
                    if hdr.info_len as usize > resp.remaining() {
                        fastpath::drop_and_count(asm, resp, CounterType::BadStructure);
                        return Err(BindAgentAddressError::BadStructure);
                    }

                    let Ok(msg) = std::str::from_utf8(&resp.body()[..hdr.info_len as usize]) else {
                        fastpath::drop_and_count(asm, resp, CounterType::BadStructure);
                        return Err(BindAgentAddressError::BadStructure);
                    };
                    let msg: Box<str> = msg.into();

                    asm.buffer_stack.put_buffer(resp.destroy());
                    Err(BindAgentAddressError::BindAgentAddressError(msg))
                }

                _ => {
                    fastpath::drop_and_count(asm, resp, CounterType::BadStructure);
                    Err(BindAgentAddressError::BadStructure)
                }
            }
        }

        Err(err) => Err(BindAgentAddressError::SyncReqError(err)),
    }
}

/// Send a key management message out the given link.
pub async fn send_key_management<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    km_id: zpr::KmId,
    payload: &[u8],
) {
    let buf = asm.buffer_stack.get_buffer().await;
    let mut pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);

    let km_hdr = pkt.alloc_zeroed_header::<zdp::ZdpKeyManagementHeader>();
    km_hdr.message_type = km_id.into();
    km_hdr.message_length = (payload.len() as u16).into();

    pkt.put(payload);

    send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::KeyManagement, pkt).await;
}

pub enum HandleMgmtError {
    UnknownType(u8),
    UnexpectedMgmtResponse,
    BadStructure,
    UnknownKeyManagementType(u16),
    KeyManagementError(String),
}

impl From<HandleMgmtError> for counters_enum::CounterType {
    fn from(err: HandleMgmtError) -> Self {
        match err {
            HandleMgmtError::UnknownType(_type) => Self::UnknownType,
            HandleMgmtError::UnexpectedMgmtResponse => Self::UnexpectedMgmtResponse,
            HandleMgmtError::BadStructure => Self::BadStructure,
            HandleMgmtError::UnknownKeyManagementType(_type) => Self::OtherError,
            HandleMgmtError::KeyManagementError(_desc) => Self::OtherError,
        }
    }
}

pub type HandleMgmtResult<'pktbuf> = Result<(), (HandleMgmtError, Packet<'pktbuf>)>;

/// handle a Report message (RFC 6.5 § 6.3.13)
pub async fn handle_report<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    mut pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let Some(hdr) = zdp::ZdpReportHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    // TODO handle protocol errors i.e. if the body is shorter
    let report_data_length: usize = hdr.report_data_length.into();
    pkt.advance(std::mem::size_of::<zdp::ZdpReportHeader>());
    if pkt.body().len() >= report_data_length {
        info!(
            "{}: {}",
            ingress_link_id,
            std::str::from_utf8(&pkt.body()[..report_data_length]).unwrap()
        );
    }
    asm.buffer_stack.put_buffer(pkt.destroy());
    Ok(())
}

/// handle a Discard message (RFC 6.5 § 6.3.1)
pub async fn handle_discard<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    // TODO print to debug log, when implemented
    info!(
        "{}: Discard message received from {}",
        asm.system_name, ingress_link_id
    );
    asm.buffer_stack.put_buffer(pkt.destroy());
    Ok(())
}

/// handle a Hello Request (RFC 6.5 § 6.3.4)
pub async fn handle_hello_request<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    seq_num: zpr::SeqNum,
    pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpHelloResponseHeader>();
    hdr.status = 0.into();

    info!("{}: Received HelloRequest", asm.system_name);

    send_non_flow_mgmt_response(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::HelloResponse,
        seq_num,
        rsp_pkt,
    )
    .await;

    Ok(())
}

/// handle a Bind Agent Address Request (RFC 6.5 § 6.3.11)
pub async fn handle_bind_agent_address_request<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    _stream_id: zpr::StreamId, // ignored
    seq_num: zpr::SeqNum,
    mut pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let Some(hdr) = zdp::ZdpBindAgentAddressRequestHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    // TODO: handle as node: enter into DFT
    // TODO: disallow bind requests between nodes

    // read addresses (always present)
    let src_address;
    let dst_address;
    match hdr.ip_version {
        zpr::L3Type::Ipv4 => {
            let Some(src_addr) = <[u8; 4]>::read_from_buf(&mut pkt) else {
                return Err((HandleMgmtError::BadStructure, pkt));
            };
            src_address = src_addr.into();

            let Some(dst_addr) = <[u8; 4]>::read_from_buf(&mut pkt) else {
                return Err((HandleMgmtError::BadStructure, pkt));
            };
            dst_address = dst_addr.into();
        }

        zpr::L3Type::Ipv6 => {
            let Some(src_addr) = <[u8; 16]>::read_from_buf(&mut pkt) else {
                return Err((HandleMgmtError::BadStructure, pkt));
            };
            src_address = src_addr.into();

            let Some(dst_addr) = <[u8; 16]>::read_from_buf(&mut pkt) else {
                return Err((HandleMgmtError::BadStructure, pkt));
            };
            dst_address = dst_addr.into();
        }

        _ => {
            return Err((HandleMgmtError::BadStructure, pkt));
        }
    };

    // read IP Protocol (always present)
    if pkt.remaining() < 1 {
        return Err((HandleMgmtError::BadStructure, pkt));
    }
    let ip_protocol = pkt.get_u8();

    // read source port (optional)
    let src_port;
    if hdr.compression_mode & zpr::compression_mode::SOURCE_PORT_PRESENT != 0 {
        if pkt.remaining() < 2 {
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        src_port = pkt.get_u16();
    } else {
        src_port = 0;
    }

    // read destination port (optional)
    let dst_port;
    if hdr.compression_mode & zpr::compression_mode::DESTINATION_PORT_PRESENT != 0 {
        if pkt.remaining() < 2 {
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        dst_port = pkt.get_u16();
    } else {
        dst_port = 0;
    }

    let compression_mode = hdr.compression_mode;

    let five_tuple = FiveTuple::new(
        hdr.ip_version,
        src_address,
        dst_address,
        ip_protocol,
        src_port,
        dst_port,
    );

    // recycle request buffer for response
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);

    let ingress_tether_id;

    match asm.ph_mode {
        PhMode::Node => {
            // TODO: request visa

            // HACK: for now, we assume a visa which forwards through to the other adapter
            // AND ALSO we manually issue a bind request out to that adapter

            let egress_link_id = (ingress_link_id + 1) % 2;

            match send_bind_agent_address_request(asm, egress_link_id, compression_mode, five_tuple)
                .await
            {
                Ok(egress_tether_id) => {
                    // form PEP
                    // TODO: forwarding PEPs
                    let pep = dock_tables::DftPep {
                        next_hop: dock_tables::DftNextHop::Tether(egress_link_id, egress_tether_id),
                    };

                    match asm.peer_table.inspect(ingress_link_id, |peer_state| {
                        match peer_state.dft.insert(pep) {
                            Ok(tid) => {
                                // success; respond with tether ID
                                // TODO: maybe tick a counter somewhere?
                                zdp::ZdpBindAgentAddressResponseHeader {
                                    status_code:
                                        zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_SUCCESS,
                                    info_len: 0,
                                }
                                .write_to_buf(&mut rsp_pkt);

                                tid
                            }

                            Err(()) => {
                                // DFT full; respond with error message
                                // TODO: maybe tick a counter somewhere?
                                let message = "DFT full";

                                zdp::ZdpBindAgentAddressResponseHeader {
                                    status_code:
                                        zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_OTHER,
                                    info_len: message.len() as u8,
                                }
                                .write_to_buf(&mut rsp_pkt);

                                rsp_pkt.put(message.as_bytes());

                                0
                            }
                        }
                    }) {
                        Some(tid) => ingress_tether_id = tid,

                        None => {
                            // peer went away; don't bother responding
                            asm.buffer_stack.put_buffer(rsp_pkt.destroy());
                            return Ok(());
                        }
                    }

                    // WORKING: factor out message generation using Result<StreamId, Box<str>>
                }

                Err(err) => {
                    // unable to bind next-hop; respond with error message
                    // TODO: maybe tick a counter somewhere?
                    let message = format!("unable to bind next-hop: {}", err);

                    zdp::ZdpBindAgentAddressResponseHeader {
                        status_code: zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_OTHER,
                        info_len: message.len() as u8,
                    }
                    .write_to_buf(&mut rsp_pkt);

                    rsp_pkt.put(message.as_bytes());

                    ingress_tether_id = 0;
                }
            }
        }

        PhMode::Adapter => {
            // form PEP
            let pep = adapter_tables::DltPep {
                compression_mode,
                five_tuple,
            };

            // attempt to insert into DLT
            match asm.dlt.insert(pep) {
                Ok(tid) => {
                    // success; respond with tether ID
                    // TODO: maybe tick a counter somewhere?
                    zdp::ZdpBindAgentAddressResponseHeader {
                        status_code: zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_SUCCESS,
                        info_len: 0,
                    }
                    .write_to_buf(&mut rsp_pkt);

                    ingress_tether_id = tid;
                }

                Err(()) => {
                    // DLT full; respond with error message
                    // TODO: maybe tick a counter somewhere?
                    let message = "DLT full";

                    zdp::ZdpBindAgentAddressResponseHeader {
                        status_code: zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_OTHER,
                        info_len: message.len() as u8,
                    }
                    .write_to_buf(&mut rsp_pkt);

                    rsp_pkt.put(message.as_bytes());

                    ingress_tether_id = 0;
                }
            }
        }
    }

    // respond to requestor
    send_per_flow_mgmt_response(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::BindAgentAddressResponse,
        ingress_tether_id,
        seq_num,
        rsp_pkt,
    )
    .await;

    Ok(())
}

// ZPI and Base header is already gone by the time we get here.  So we expect
// to parse starting from the KeyManagement header.
pub fn handle_key_management<'pktbuf>(
    asm: &Assembly<'pktbuf>,
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
