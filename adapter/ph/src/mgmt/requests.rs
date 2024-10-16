//! Management requests.

use super::core;
use crate::assembly::Assembly;
use crate::config;
use crate::counters::CounterType;
use crate::defs::*;
use crate::fastpath;
use crate::packet::{self, Packet};
use crate::zdp;
use crate::zpr;
use bytes::{Buf, BufMut};
use tracing::{info, warn};
use zpr_ext::zerocopy::{FromBytesExt, IntoBytesExt};

/// send a Key Management message (RFC 6.5 § 6.2.8)
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

    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::KeyManagement, pkt).await;
}

/// send a Discard message (RFC 6.5 § 6.3.1)
pub async fn send_discard(asm: &Assembly<'_>, link_id: zpr::LinkId) {
    let buf = asm.buffer_stack.get_buffer().await;
    let pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Discard, pkt).await;
}

#[allow(dead_code)]
/// send a Hello Request and wait for the Response (RFC 6.5 § 6.3.4)
pub async fn send_hello_request<'a, 'pktbuf>(
    asm: &'a Assembly<'pktbuf>,
    link_id: zpr::LinkId,
) -> Result<(), ()> {
    let response = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::HelloRequest,
        zdp::ZdpPacketType::HelloResponse,
        move |_packet| {},
    )
    .await;

    match response {
        Ok(mut hello_res) => {
            let Ok(hdr) = zdp::ZdpHelloResponseHeader::read_from_buf(&mut hello_res) else {
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
    SyncReqError(core::SyncReqError),
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
        },
    )
    .await;

    match response {
        Ok((tether_id, mut resp)) => {
            let Ok(hdr) = zdp::ZdpBindAgentAddressResponseHeader::read_from_buf(&mut resp) else {
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
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Report, pkt).await;
}
