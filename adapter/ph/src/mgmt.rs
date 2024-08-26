//! Management packet functions.

use crate::assembly::Assembly;
use crate::config;
use crate::fastpath;
use crate::packet::{self, Packet};
use crate::zdp;
use crate::zpr;
use bytes::{Buf, BufMut};
use zerocopy::FromBytes;

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

pub async fn handle_report<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    mut pkt: Packet<'pktbuf>,
) {
    let hdr = zdp::ZdpReportHeader::ref_from_prefix(pkt.body()).expect("too-short inbound packet");
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
}

pub async fn handle_discard<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    pkt: Packet<'pktbuf>,
) {
    // TODO print to debug log, when implemented
    eprintln!("Discard message received from {}", ingress_link_id);
    asm.buffer_stack.put_buffer(pkt.destroy());
}

pub async fn handle_hello_request<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    pkt: Packet<'pktbuf>,
) {
    let mut send_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = send_pkt.alloc_zeroed_header::<zdp::ZdpHelloResponseHeader>();
    hdr.status = 0.into();
    send_non_flow_mgmt(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::HelloResponse,
        send_pkt,
    )
    .await;
    eprintln!("Received HelloRequest");
}

pub async fn handle_bind_agent_address_request<'pktbuf>(
    _asm: &Assembly<'pktbuf>,
    _ingress_link_id: zpr::LinkId,
    _stream_id: zpr::StreamId,
    mut _pkt: Packet<'pktbuf>,
) {
}
