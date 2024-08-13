//! Management packet functions.

use crate::assembly::Assembly;
use crate::config;
use crate::fastpath;
use crate::packet::{self, Packet};
use crate::zdp;
use crate::zpr;
use bytes::BufMut;
use zpr_ext::std::mem::DropGuard;

/// Send a unidirectional non-flow management message on the given link.
/// The packet should contain only the message body.
pub async fn send_non_flow_mgmt<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    mut packet: impl DropGuard<Packet<'pktbuf>>,
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
    mut packet: impl DropGuard<Packet<'pktbuf>>,
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
    // this condition will need to be adjusted when we have complete ZPR packets
    // with the information at the end of the packet at well
    if packet::PACKET_BUFFER_MAX_BODY_SIZE - config::DEFAULT_MESSAGE_HEADROOM < report.len() {
        return;
    }
    let buf = asm.buffer_stack.get_buffer_guarded().await;
    let mut pkt = Packet::new_guarded(buf, config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpReportHeader>();
    hdr.report_data_length = (report.len() as u16).into();
    pkt.put(report.as_bytes());
    send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Report, pkt).await;
}

pub async fn send_discard<'pktbuf>(asm: &'pktbuf Assembly<'pktbuf>, link_id: zpr::LinkId) {
    let buf = asm.buffer_stack.get_buffer_guarded().await;
    let pkt = Packet::new_guarded(buf, config::DEFAULT_MESSAGE_HEADROOM);
    send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Discard, pkt).await;
}
