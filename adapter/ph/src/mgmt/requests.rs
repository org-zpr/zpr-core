//! Management requests.
#![allow(dead_code)]

use super::core;
use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::defs::*;
use crate::logging::targets::ZDP;
use crate::mgmt::core::SyncReqError;
use crate::zdp;
use bytes::{Buf, BufMut};
use std::net::IpAddr;
use thiserror::Error;
use tracing::*;
use zpr;
use zpr_ext::zerocopy::{FromBytesExt, IntoBytesExt};

/// send a Key Management message (RFC 6.5 § 6.2.8)
pub async fn send_key_management(
    asm: &Assembly,
    link_id: zpr::LinkId,
    km_id: zpr::KmId,
    payload: &[u8],
) {
    let mut pkt = core::new_heap_packet();

    let km_hdr = pkt.alloc_zeroed_header::<zdp::ZdpKeyManagementHeader>();
    km_hdr.message_type = km_id.into();
    km_hdr.message_length = (payload.len() as u16).into();

    pkt.put(payload);

    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::KeyManagement, pkt).await;
}

#[allow(dead_code)]
/// send a Discard message (RFC 6.5 § 6.3.1)
pub async fn send_discard(asm: &Assembly, link_id: zpr::LinkId) {
    let pkt = core::new_heap_packet();
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Discard, pkt).await;
}

/// send an Echo Request and wait for the Response (RFC 6.5 § 6.3.2)
pub async fn send_echo_request(asm: &Assembly, link_id: zpr::LinkId) -> Result<(), SyncReqError> {
    let mut echo = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::EchoRequest,
        zdp::ZdpPacketType::EchoResponse,
        move |_packet| {},
    )
    .await?;

    // TODO: Break these apart
    let Ok(_) = zdp::ZdpEchoHeader::read_from_buf(&mut echo) else {
        core::count_event(asm, &mut echo, CounterType::BadStructure);
        return Err(SyncReqError::ProtocolError);
    };
    Ok(())
}

/// send a Hello Request and wait for the Response (RFC 6.5 § 6.3.4)
pub async fn send_hello_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
) -> Result<zdp::ResponseCode, ()> {
    let response = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::HelloRequest,
        zdp::ZdpPacketType::HelloResponse,
        move |_packet| {},
    )
    .await;

    // TODO: Break these apart
    match response {
        Ok(mut hello_res) => {
            let Ok(hdr) = zdp::ZdpHelloResponseHeader::read_from_buf(&mut hello_res) else {
                core::count_event(asm, &mut hello_res, CounterType::BadStructure);
                return Err(());
            };
            let status = hdr.status;
            debug!(target: ZDP, "Received HelloResponse, status: {status:?}");
            Ok(status)
        }

        Err(err) => {
            warn!(target: ZDP, "{err} error with HelloRequest");
            Err(())
        }
    }
}

/// send a Register Agent Address Request (RFC 6.5 § 6.3.10)
pub async fn send_register_agent_address_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
    agent_addr: IpAddr,
) -> Result<zdp::ResponseCode, ()> {
    let response = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::RegisterAgentAddressRequest,
        zdp::ZdpPacketType::RegisterAgentAddressResponse,
        move |mut req| match agent_addr {
            IpAddr::V4(addr) => {
                zdp::ZdpRegisterAgentAddressRequestHeader {
                    ip_version: zpr::L3Type::Ipv4,
                }
                .write_to_buf(&mut req)
                .unwrap();
                req.put(&addr.octets()[..]);
            }

            IpAddr::V6(addr) => {
                zdp::ZdpRegisterAgentAddressRequestHeader {
                    ip_version: zpr::L3Type::Ipv6,
                }
                .write_to_buf(&mut req)
                .unwrap();
                req.put(&addr.octets()[..]);
            }
        },
    )
    .await;

    // TODO: Break these apart
    match response {
        Ok(mut register_res) => {
            let Ok(hdr) =
                zdp::ZdpRegisterAgentAddressResponseHeader::read_from_buf(&mut register_res)
            else {
                core::count_event(asm, &mut register_res, CounterType::BadStructure);
                return Err(());
            };
            debug!(
                target: ZDP,
                "Received RegisterAgentAddressResponse, status: {:?}",
                hdr.status_code
            );
            return Ok(hdr.status_code);
        }

        Err(err) => {
            warn!(target: ZDP, "{err} error with RegisterAgentAddressRequest");
            return Err(());
        }
    }
}

/// send a Terminate Request (RFC 6.5 § 6.3.3)
pub async fn send_terminate_request<'a, 'pktbuf>(
    asm: &Assembly,
    link_id: zpr::LinkId,
    reason: zdp::TerminateReason,
) -> Result<zdp::ResponseCode, ()> {
    let response = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::TerminateLinkRequest,
        zdp::ZdpPacketType::TerminateLinkResponse,
        move |mut req| {
            zdp::ZdpTerminateLinkRequestHeader {
                reason_code: reason,
                data_len: 0,
            }
            .write_to_buf(&mut req)
            .unwrap();
        },
    )
    .await;

    // TODO: Break these apart
    match response {
        Ok(mut terminate_res) => {
            let Ok(hdr) = zdp::ZdpTerminateLinkResponseHeader::read_from_buf(&mut terminate_res)
            else {
                core::count_event(asm, &mut terminate_res, CounterType::BadStructure);
                return Err(());
            };
            let resp_code = hdr.response_code;
            info!("Received TerminateLinkResponse, status: {:?}", resp_code);
            Ok(resp_code)
        }

        Err(err) => {
            warn!("{} error with TerminateLinkResponse", err);
            Err(())
        }
    }
}

/// send a Terminate Indication (RFC 6.5 § 6.3.3)
pub async fn send_terminate_indication<'a, 'pktbuf>(
    asm: &Assembly,
    link_id: zpr::LinkId,
    reason: zdp::TerminateReason,
) {
    let mut pkt = core::new_heap_packet();
    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpTerminateLinkIndicationHeader>();
    hdr.reason_code = reason;
    core::send_non_flow_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::TerminateLinkIndication,
        pkt,
    )
    .await;
}

#[derive(Debug, Error)]
pub enum BindAgentAddressError {
    #[error("{0}")]
    SyncReqError(core::SyncReqError),
    #[error("bad structure")]
    BadStructure,
    #[error("{0}")]
    BindAgentAddressError(Box<str>),
}

/// send a Bind Agent Address Request and wait for the Response (RFC 6.5 § 6.3.11)
pub async fn send_bind_agent_address_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
    compression_mode: zpr::CompressionMode,
    five_tuple: FiveTuple,
    packet_body: Vec<u8>,
) -> Result<zpr::StreamId, BindAgentAddressError> {
    let response = core::send_sync_per_flow_req(
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
            .write_to_buf(&mut req)
            .unwrap();

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

            req.put_slice(&packet_body);
        },
    )
    .await;

    match response {
        Ok((tether_id, mut resp)) => {
            let Ok(hdr) = zdp::ZdpBindAgentAddressResponseHeader::read_from_buf(&mut resp) else {
                core::count_event(asm, &mut resp, CounterType::BadStructure);
                return Err(BindAgentAddressError::BadStructure);
            };

            match hdr.status_code {
                zdp::ResponseCode::Success => Ok(tether_id),

                zdp::ResponseCode::Other => {
                    if hdr.info_len as usize > resp.remaining() {
                        core::count_event(asm, &mut resp, CounterType::BadStructure);
                        return Err(BindAgentAddressError::BadStructure);
                    }

                    let Ok(msg) = std::str::from_utf8(&resp.body()[..hdr.info_len as usize]) else {
                        core::count_event(asm, &mut resp, CounterType::BadStructure);
                        return Err(BindAgentAddressError::BadStructure);
                    };
                    let msg: Box<str> = msg.into();

                    Err(BindAgentAddressError::BindAgentAddressError(msg))
                }

                _ => {
                    core::count_event(asm, &mut resp, CounterType::BadStructure);
                    Err(BindAgentAddressError::BadStructure)
                }
            }
        }

        Err(err) => Err(BindAgentAddressError::SyncReqError(err)),
    }
}

#[allow(dead_code)]
/// send a Report message (RFC 6.5 § 6.3.13)
pub async fn send_report(asm: &Assembly, link_id: zpr::LinkId, report: &str) {
    // TODO this condition will need to be adjusted when we have complete ZPR packets
    // with the information at the end of the packet at well
    /*if packet::PACKET_BUFFER_MAX_BODY_SIZE - config::DEFAULT_MESSAGE_HEADROOM < report.len() {
        return;
    }*/  // CTP FIXME
    let mut pkt = core::new_heap_packet();
    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpReportHeader>();
    hdr.report_data_length = (report.len() as u16).into();
    pkt.put(report.as_bytes());
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Report, pkt).await;
}
