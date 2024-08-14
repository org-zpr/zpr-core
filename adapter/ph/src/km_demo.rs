//! Functions and constants here are to support the key management demo code
//! in the node and adapter.
//!
//! This will go away eventually.
//!

use bytes::BufMut;
use zerocopy::FromBytes;

use crate::config;
use crate::packet::*;
use crate::zdp::*;
use crate::zpr;

/// Headroom for headers when creating the ZDP packets.
pub const HEADROOM: usize = 128;

/// Location of the key management header in the ZDP packet.
pub const ZDP_KM_HDR_OFFSET: usize = ZDP_NON_PER_FLOW_MGMT_HEADER_OFFSET;

/// Location of the key management payload in the ZDP packet.
pub const ZDP_KM_DATA_OFFSET: usize =
    ZDP_KM_HDR_OFFSET + std::mem::size_of::<ZdpKeyManagementHeader>();

/// Location of the report header in the ZDP packet.
pub const ZDP_REPORT_HDR_OFFSET: usize = ZDP_NON_PER_FLOW_MGMT_HEADER_OFFSET;

/// Location of the report data in the ZDP packet.
pub const ZDP_REPORT_DATA_OFFSET: usize =
    ZDP_REPORT_HDR_OFFSET + std::mem::size_of::<ZdpReportHeader>();

/// Note no ZPI is added.
/// Creates a packet like: [ZdpBaseHeader]|[ZdpReportHeader]|<report_data>
pub fn build_zdp_report_packet<'buf>(
    pbuf: &'buf mut [u8; config::PACKET_BUFFER_SIZE],
    report_data: &[u8],
) -> Packet<'buf> {
    let mut pkt = Packet::new(pbuf, HEADROOM);

    let mlen = report_data.len() as u16;
    let report_hdr = pkt.alloc_zeroed_header::<ZdpReportHeader>();
    report_hdr.report_data_length = mlen.into();

    let zdp_hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
    zdp_hdr.packet_type = ZdpPacketType::Report;
    zdp_hdr.excess_length = 0;
    zdp_hdr.sequence_number = 0.into();

    // Do not add ZPI here - SA_ID is added by KM.

    pkt.put(&report_data[..]);
    pkt
}

/// Creates a packet like: [ZdpZpiHeader]|[ZdpBaseHeader]|[ZdpKeyManagementHeader]<km_payload>
pub fn build_zdp_km_noise_packet<'buf>(
    pbuf: &'buf mut [u8; config::PACKET_BUFFER_SIZE],
    km_payload: &[u8],
) -> Packet<'buf> {
    let mut pkt = Packet::new(pbuf, HEADROOM);
    pkt.put(&km_payload[..]);

    let km_hdr = pkt.alloc_zeroed_header::<ZdpKeyManagementHeader>();
    km_hdr.message_type = zpr::KM_ID_NOISE.into();
    km_hdr.message_length = (km_payload.len() as u16).into();

    let zdp_hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
    zdp_hdr.packet_type = ZdpPacketType::KeyManagement;

    pkt.alloc_zeroed_header::<ZdpZpiHeader>().zpi = 0;
    pkt
}

/// Parse a full ZDP packet as a ZDP Report Message, expecting the payload of that message
/// to be a string which is returned.
pub fn parse_zdp_report_pkt(pkt: &Packet) -> Result<String, String> {
    let zpi_hdr = ZdpZpiHeader::ref_from_prefix(&pkt.body());
    if zpi_hdr.is_none() {
        return Err(String::from(
            "error parsing ZPI header from decrypted payload",
        ));
    }
    let zdp_hdr = ZdpBaseHeader::ref_from_prefix(&pkt.body()[ZDP_BASE_HEADER_OFFSET..]);
    if zdp_hdr.is_none() {
        return Err(String::from(
            "parse report msg - error parsing ZDP header from decrypted payload",
        ));
    }
    let zdp_hdr = zdp_hdr.unwrap();
    if zdp_hdr.packet_type != ZdpPacketType::Report {
        return Err(String::from(format!(
            "parse report msg - expected REPORT packet, got {:?}",
            zdp_hdr.packet_type
        )));
    }
    let report_hdr = ZdpReportHeader::ref_from_prefix(&pkt.body()[ZDP_REPORT_HDR_OFFSET..]);
    if report_hdr.is_none() {
        return Err(String::from(
            "parse report msg - error parsing REPORT header from decrypted payload",
        ));
    }
    let report_hdr = report_hdr.unwrap();
    let strlen = usize::from(report_hdr.report_data_length);
    if ZDP_REPORT_DATA_OFFSET + strlen > pkt.body().len() {
        return Err(String::from(
            "parse report msg - report data length exceeds packet length",
        ));
    }
    match std::str::from_utf8(&pkt.body()[ZDP_REPORT_DATA_OFFSET..ZDP_REPORT_DATA_OFFSET + strlen])
    {
        Ok(s) => return Ok(String::from(s)),
        Err(e) => {
            return Err(String::from(format!(
                "parse report msg - error parsing report data: {:?}",
                e
            )));
        }
    }
}

/// Parse a ZDP packet as a ZDP Key Management Message.  Return a reference to
/// the KM payload (which can then be passed to the KM system).
pub fn parse_km_payload<'buf>(msg_buf: &'buf [u8]) -> Result<&'buf [u8], String> {
    let zdp_hdr = ZdpBaseHeader::ref_from_prefix(&msg_buf[ZDP_BASE_HEADER_OFFSET..]);
    if zdp_hdr.is_none() {
        return Err(String::from(
            "zdp/server - error parsing ZDP header from ZPI=0 message",
        ));
    }
    let zdp_hdr = zdp_hdr.unwrap();
    if zdp_hdr.packet_type != ZdpPacketType::KeyManagement {
        return Err(String::from(format!(
            "zdp/server - expected KM packet, got {:?}",
            zdp_hdr.packet_type
        )));
    }
    let km_hdr = ZdpKeyManagementHeader::ref_from_prefix(&msg_buf[ZDP_KM_HDR_OFFSET..]);
    if km_hdr.is_none() {
        return Err(String::from(
            "zdp/server - error parsing KM header from ZPI=0 message",
        ));
    }
    let km_hdr = km_hdr.unwrap();
    if !km_hdr.is_noise() {
        return Err(String::from(format!(
            "zdp/server - expected NOISE KM message, got {:?}",
            km_hdr.message_type.get()
        )));
    }
    let km_msg_len = usize::from(km_hdr.message_length);
    if msg_buf.len() < ZDP_KM_DATA_OFFSET + km_msg_len {
        return Err(String::from(format!(
            "zdp/server - KM message truncated: expected {} got {}",
            ZDP_KM_DATA_OFFSET + km_msg_len,
            msg_buf.len()
        )));
    }

    Ok(&msg_buf[ZDP_KM_DATA_OFFSET..ZDP_KM_DATA_OFFSET + km_msg_len])
}
