//! Management packet functions.

use crate::adapter_tables;
use crate::assembly::{self, Assembly};
use crate::config;
use crate::counters_enum::{self, CounterType};
use crate::defs::*;
use crate::fastpath;
use crate::packet::{self, Packet};
use crate::zdp;
use crate::zpr;
use bytes::{Buf, BufMut};
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

pub async fn send_discard<'pktbuf>(asm: &'pktbuf Assembly<'pktbuf>, link_id: zpr::LinkId) {
    let buf = asm.buffer_stack.get_buffer().await;
    let pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
    send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Discard, pkt).await;
}

pub async fn send_hello_request<'a, 'pktbuf>(asm: &'a Assembly<'pktbuf>, link_id: zpr::LinkId) -> Result<(), ()>
{
    let response = asm
        .send_sync_non_flow_req(
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
    SyncReqError(assembly::SyncReqError),
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

pub async fn send_bind_agent_address_request<'a, 'pktbuf>(
    asm: &'a Assembly<'pktbuf>, link_id: zpr::LinkId,
    compression_mode: zpr::CompressionMode, five_tuple: FiveTuple,
) -> Result<zpr::StreamId, BindAgentAddressError> {
    let response = asm.send_sync_per_flow_req(
        link_id,
        zdp::ZdpPacketType::BindAgentAddressRequest,
        zdp::ZdpPacketType::BindAgentAddressResponse,
        0, move |mut req| {
            zdp::ZdpBindAgentAddressRequestHeader {
                ip_version: five_tuple.l3_type,
                compression_mode,
            }.write_to_buf(&mut req);

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
        }
    ).await;

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

        Err(err) =>
            Err(BindAgentAddressError::SyncReqError(err)),
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

pub async fn handle_discard<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    // TODO print to debug log, when implemented
    eprintln!("Discard message received from {}", ingress_link_id);
    asm.buffer_stack.put_buffer(pkt.destroy());
    Ok(())
}

pub async fn handle_hello_request<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpHelloResponseHeader>();
    hdr.status = 0.into();

    eprintln!("Received HelloRequest");

    send_non_flow_mgmt(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::HelloResponse,
        rsp_pkt,
    )
    .await;

    Ok(())
}

// RFC 6.5 § 6.3.11
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
    let mut src_port = 0;
    if hdr.compression_mode & zpr::compression_mode::SOURCE_PORT_PRESENT != 0 {
        if pkt.remaining() < 2 {
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        src_port = pkt.get_u16();
    }

    // read destination port (optional)
    let mut dst_port = 0;
    if hdr.compression_mode & zpr::compression_mode::DESTINATION_PORT_PRESENT != 0 {
        if pkt.remaining() < 2 {
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        dst_port = pkt.get_u16();
    }

    // form PEP
    let pep = adapter_tables::DltPep {
        compression_mode: hdr.compression_mode,
        five_tuple: FiveTuple::new(
            hdr.ip_version,
            src_address,
            dst_address,
            ip_protocol,
            src_port,
            dst_port,
        ),
    };

    // recycle request buffer for response
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);

    // attempt to insert into DLT
    let stream_id;
    match asm.dlt.insert(pep) {
        Ok(sid) => {
            // success; respond with stream ID
            // TODO: maybe tick a counter somewhere?
            zdp::ZdpBindAgentAddressResponseHeader {
                status_code: zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_SUCCESS,
                info_len: 0,
            }
            .write_to_buf(&mut rsp_pkt);

            stream_id = sid;
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

            stream_id = 0;
        }
    }

    // respond to requestor
    send_per_flow_mgmt(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::BindAgentAddressResponse,
        stream_id,
        rsp_pkt,
    )
    .await;

    Ok(())
}
