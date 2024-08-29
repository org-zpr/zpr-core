//! Management packet functions.

use crate::adapter_tables;
use crate::assembly::{Assembly, PhMode};
use crate::config;
use crate::counters_enum::{self, CounterType};
use crate::defs::*;
use crate::dock_tables;
use crate::fastpath;
use crate::packet::{self, Packet};
use crate::sync_req;
use crate::zdp;
use crate::zpr;
use bytes::{Buf, BufMut};
use std::time::Duration;
use tokio::sync::oneshot::channel;
use tokio::time::sleep;
use zpr_ext::std::mem::{drop_guard, DropGuard};
use zpr_ext::zerocopy::{AsBytesExt, FromBytesExt};

/// Send a unidirectional non-flow management message on the given link.
/// The packet should contain only the message body.
pub async fn send_non_flow_mgmt<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    mut packet: Packet<'pktbuf>,
) {
    debug_assert!(!packet_type.is_per_flow());

    let hdr = packet.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
    hdr.packet_type = packet_type;

    fastpath::substrate_egress_blocking(
        asm,
        link_id,
        zpr::ZPI_0, // TODO
        packet,
    )
    .await;
}

/// Send a unidirectional per-flow management message on the given link.
/// The packet should contain only the message body.
pub async fn send_per_flow_mgmt<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: zpr::StreamId,
    mut packet: Packet<'pktbuf>,
) {
    debug_assert!(packet_type.is_per_flow());

    let per_flow_hdr = packet.alloc_zeroed_header::<zdp::ZdpPerFlowHeader>();
    per_flow_hdr.stream_id = stream_id.into();

    let hdr = packet.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
    hdr.packet_type = packet_type;

    fastpath::substrate_egress_blocking(
        asm,
        link_id,
        zpr::ZPI_0, // TODO
        packet,
    )
    .await;
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
) -> Result<Packet<'pktbuf>, sync_req::SyncReqError> {
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
) -> Result<(zpr::StreamId, Packet<'pktbuf>), sync_req::SyncReqError> {
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
    pkt_fn: impl Fn(&mut Packet<'_>) + Send + 'static,
) -> Result<Packet<'pktbuf>, sync_req::SyncReqError> {
    let Some(semaphore) = asm.peer_table.inspect(link_id, |peer_state| {
        peer_state.sync_req_state.semaphore.clone()
    }) else {
        return Err(sync_req::SyncReqError::LinkClosed);
    };
    let permit = semaphore.acquire_owned().await.unwrap(); // TODO error handling in case we don't get permit
    let (sender, mut receiver) = channel::<(Packet<'pktbuf>, zdp::ZdpPacketType)>();

    asm.peer_table.inspect(link_id, move |peer_state| {
        peer_state.sync_req_state.set_sender(Some(sender))
    });

    for _i in 0..=config::DEFAULT_REQUEST_RETRY_COUNT {
        let buf = drop_guard(asm.buffer_stack.get_buffer().await, |buf| {
            asm.buffer_stack.put_buffer(buf)
        });
        let mut packet = Packet::new_guarded(buf, config::DEFAULT_MESSAGE_HEADROOM);
        pkt_fn(&mut packet);

        // Determine if sending a non-flow or per-flow message
        match stream_id {
            Some(stream_id) => {
                send_per_flow_mgmt(
                    asm,
                    link_id,
                    zdp_request_type,
                    stream_id,
                    packet.into_inner(),
                )
                .await;
            }
            None => {
                send_non_flow_mgmt(asm, link_id, zdp_request_type, packet.into_inner()).await;
            }
        }
        tokio::select! {
            received_val = &mut receiver => {
                drop(permit);
                eprintln!("{}: received response from {} via channel!", asm.system_name, link_id);
                return match_received(asm, received_val, sync_req::SyncReqError::LinkClosed, zdp_response_type);
            }
            _ = sleep(Duration::from_secs(config::DEFAULT_REQUEST_RETRY_TIMER as u64)) => ()
        }
    }
    asm.peer_table.inspect(link_id, |peer_state| {
        peer_state.sync_req_state.set_sender(None)
    });
    receiver.close();
    drop(permit);
    match_received(
        asm,
        receiver.try_recv(),
        sync_req::SyncReqError::Timeout,
        zdp_response_type,
    )
}

/// Determines whether the message recieved in response to the request is
/// a) a packet and not an error, and b) the expected packet type
// TODO: rename/move this
fn match_received<'pktbuf, T>(
    asm: &Assembly<'pktbuf>,
    result: Result<(Packet<'pktbuf>, zdp::ZdpPacketType), T>,
    err_type: sync_req::SyncReqError,
    zdp_response_type: zdp::ZdpPacketType,
) -> Result<Packet<'pktbuf>, sync_req::SyncReqError> {
    match result {
        Ok(rec_tuple) => {
            if zdp_response_type != rec_tuple.1 {
                fastpath::drop_and_count(asm, rec_tuple.0, CounterType::BadMgmtResponse);
                return Err(sync_req::SyncReqError::ProtocolError);
            }
            return Ok(rec_tuple.0);
        }
        Err(_) => return Err(err_type),
    }
}

/// send a Report message (RFC 6.5 § 6.3.13)
pub async fn send_report<'pktbuf>(
    asm: &'pktbuf Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    report: &str,
) {
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
pub async fn send_discard<'pktbuf>(asm: &'pktbuf Assembly<'pktbuf>, link_id: zpr::LinkId) {
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
            eprintln!("Received HelloResponse, status: {}", status);
            asm.buffer_stack.put_buffer(hello_res.destroy());
            Ok(())
        }

        Err(err) => {
            eprintln!("{} error with HelloRequest", err);
            Err(())
        }
    }
}

pub enum BindAgentAddressError {
    SyncReqError(sync_req::SyncReqError),
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
    eprintln!(
        "{}: sending bind req for {} to {}",
        asm.system_name, five_tuple, link_id
    );

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

pub enum HandleMgmtError {
    UnknownType(u8),
    UnexpectedMgmtResponse,
    BadStructure,
}

impl From<HandleMgmtError> for counters_enum::CounterType {
    fn from(err: HandleMgmtError) -> Self {
        match err {
            HandleMgmtError::UnknownType(_type) => Self::UnknownType,
            HandleMgmtError::UnexpectedMgmtResponse => Self::UnexpectedMgmtResponse,
            HandleMgmtError::BadStructure => Self::BadStructure,
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
        // TODO printing to stderr blocks indefinitely, this is just temporary
        eprintln!(
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
    eprintln!(
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
    pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpHelloResponseHeader>();
    hdr.status = 0.into();

    eprintln!("{}: Received HelloRequest", asm.system_name);

    send_non_flow_mgmt(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::HelloResponse,
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

    eprintln!(
        "{}: handling bind req for {} from {}",
        asm.system_name, five_tuple, ingress_link_id
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
            eprintln!("{}: I'm an adapter!", asm.system_name);

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

    eprintln!(
        "{}: responding to {} with {} for {}!",
        asm.system_name, ingress_link_id, ingress_tether_id, five_tuple
    );

    // respond to requestor
    send_per_flow_mgmt(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::BindAgentAddressResponse,
        ingress_tether_id,
        rsp_pkt,
    )
    .await;

    Ok(())
}
