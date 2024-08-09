//! Management packet functions.

use crate::assembly::Assembly;
use crate::fastpath;
use crate::packet::Packet;
use crate::zdp;
use crate::zpr;

/// Send a unidirectional non-flow management message on the given link.
/// The packet should contain only the message body.
pub fn send_non_flow_mgmt<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    link_id: zpr::LinkId,
    packet_type: zdp::ZdpPacketType,
    mut packet: Packet<'pktbuf>,
) {
    debug_assert!(!packet_type.is_per_flow());

    let hdr = packet.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
    hdr.packet_type = packet_type;

    fastpath::substrate_egress(
        asm,
        link_id,
        zpr::ZPI_0,  // TODO
        packet,
    );
}

/// Send a unidirectional per-flow management message on the given link.
/// The packet should contain only the message body.
pub fn send_per_flow_mgmt<'pktbuf>(
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

    fastpath::substrate_egress(
        asm,
        link_id,
        zpr::ZPI_0,  // TODO
        packet,
    );
}
