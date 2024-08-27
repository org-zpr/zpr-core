//! Management packet functions.

use crate::adapter_tables;
use crate::assembly::Assembly;
use crate::config;
use crate::counters_enum;
use crate::defs::*;
use crate::fastpath;
use crate::packet::{self, Packet};
use crate::zdp;
use crate::zpr;
use bytes::{Buf, BufMut};
use zerocopy::FromBytes;
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
    let Some(hdr) = zdp::ZdpReportHeader::ref_from_prefix(pkt.body()) else {
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
    eprintln!(
        "{}: Discard message received from {}",
        asm.system_name, ingress_link_id
    );
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

// RFC 6.5 § 6.3.11
pub async fn handle_bind_agent_address_request<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    _stream_id: zpr::StreamId, // ignored
    mut pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let Some(hdr) = zdp::ZdpBindAgentAddressRequestHeader::ref_from_prefix(pkt.body()) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    // TODO: handle as node: enter into DFT
    // TODO: disallow bind requests between nodes

    let ip_version = hdr.ip_version;
    let compression_mode = hdr.compression_mode;

    // read addresses (always present)
    let src_address;
    let dst_address;
    match ip_version {
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
    if compression_mode & zpr::compression_mode::SOURCE_PORT_PRESENT != 0 {
        if pkt.remaining() < 2 {
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        src_port = pkt.get_u16();
    }

    // read destination port (optional)
    let mut dst_port = 0;
    if compression_mode & zpr::compression_mode::SOURCE_PORT_PRESENT != 0 {
        if pkt.remaining() < 2 {
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        dst_port = pkt.get_u16();
    }

    // form PEP
    let pep = adapter_tables::DltPep {
        compression_mode: compression_mode,
        five_tuple: FiveTuple::new(
            ip_version,
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
