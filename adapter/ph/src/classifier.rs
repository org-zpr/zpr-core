#![allow(dead_code)]
use crate::net_defs::*;
use crate::packet;
use arrayref::array_ref;
use std::mem::size_of;
use zerocopy::byteorder::network_endian::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
use zpr::L3Type;

#[derive(Debug, PartialEq)]
pub enum ClassifierResult {
    OK,
    NonIP,
    UnclassifiedL4,
    FirstFragment,
    SubsequentFragment,
}

pub const IP_VERSION_MASK: u8 = 0xF0;
pub const IPV4_HEADER_LENGTH_MASK: u8 = 0x0F;

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct IPv4Header {
    pub vhl: u8,
    pub dscp: u8,
    pub total_length: U16,
    pub frag_id: [u8; 2],
    pub frag_offset: U16,
    pub ttl: u8,
    pub proto: u8,
    pub header_checksum: [u8; 2],
    pub src_address: [u8; 4],
    pub dst_address: [u8; 4],
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct IPv6Header {
    pub version_and_tc_upper: u8,
    pub tc_lower_and_fl_upper: u8,
    pub fl_lower: [u8; 2],
    pub payload_length: U16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_address: IpAddress,
    pub dst_address: IpAddress,
}

const NO_NEXT_HEADER: u8 = 59;

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct TCPHeader {
    pub src_port: U16,
    pub dst_port: U16,
    pub sequence_number: [u8; 4],
    pub acknowledgement_number: [u8; 4],
    pub data_offset_and_reserved: u8,
    pub flags: u8,
    pub window_size: [u8; 2],
    pub checksum: [u8; 2],
    pub urgent_pointer: [u8; 2],
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct UDPHeader {
    pub src_port: U16,
    pub dst_port: U16,
    pub length: [u8; 2],
    pub checksum: [u8; 2],
}

pub fn get_ip_version(body: &[u8]) -> u8 {
    (body[0] & IP_VERSION_MASK) >> 4
}

pub fn classify<PktBuf: packet::PacketBuffer>(
    packet: &mut packet::Packet<PktBuf>,
) -> Result<ClassifierResult, &'static str> {
    let (metadata, body) = packet.metadata_mut_and_body_mut();
    classify_zdp(metadata, body)
}

fn classify_zdp(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    classify_l3(metadata, body)
}

fn classify_l3(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    let ip_version = get_ip_version(body);

    match ip_version {
        4 => classify_ipv4(metadata, body),
        6 => classify_ipv6(metadata, body),
        _ => return Ok(ClassifierResult::NonIP),
    }
}

fn classify_ipv4(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    metadata.set_l3_type(L3Type::Ipv4);

    // Check that there's enough room in the packet data for the base header (no options)
    if size_of::<IPv4Header>() > body.len() {
        return Err("Packet length error");
    }

    let header_bytes = &body[..size_of::<IPv4Header>()];
    let ipv4_header = IPv4Header::ref_from_bytes(header_bytes).unwrap();

    let header_length = ipv4_header.vhl & IPV4_HEADER_LENGTH_MASK;
    let total_length = ipv4_header.total_length.get();
    if total_length as usize != body.len()
        || header_length < 5
        || u16::from(header_length * 4) > total_length
    {
        return Err("Packet length error");
    }

    metadata.set_addresses(
        IpAddress::new_from_v4(ipv4_header.src_address),
        IpAddress::new_from_v4(ipv4_header.dst_address),
    );

    const FRAGMENT_OFFSET_MASK: u16 = 0x1FFF;
    const MORE_FRAGMENTS_MASK: u16 = 0x2000;
    let frag_offset = ipv4_header.frag_offset.get();
    if frag_offset & FRAGMENT_OFFSET_MASK != 0 {
        metadata.set_l4_protocol(ipv4_header.proto);
        return Ok(ClassifierResult::SubsequentFragment);
    }

    let offset = usize::from(header_length * 4);
    let ret_code = classify_next_header(metadata, &body[offset..], ipv4_header.proto);

    if frag_offset & MORE_FRAGMENTS_MASK != 0 {
        return Ok(ClassifierResult::FirstFragment);
    }

    return ret_code;
}

fn classify_ipv6(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    metadata.set_l3_type(L3Type::Ipv6);

    // Check that there's enough room in the packet data for the base header (no options)
    if size_of::<IPv6Header>() > body.len() {
        return Err("Packet length error");
    }

    let header_bytes = &body[..size_of::<IPv6Header>()];
    let ipv6_header = IPv6Header::ref_from_bytes(header_bytes).unwrap();

    // reject IPv4-mapped IPv6 addresses (i.e. ::ffff/96) as we use this
    // range internally as the only means of distinguishing v6 from v4
    if ipv6_header.src_address.is_v4() || ipv6_header.dst_address.is_v4() {
        return Err("IPv4-mapped IPv6 addresses not allowed");
    }

    metadata.set_addresses(ipv6_header.src_address, ipv6_header.dst_address);

    let payload_length = ipv6_header.payload_length.get();
    if payload_length == 0 && ipv6_header.next_header == 0
    /* hop-by-hop */
    {
        // RFC 2675 § 3
        return Err("IPv6 jumbograms not supported");
    }
    if payload_length as usize != body.len() - size_of::<IPv6Header>() {
        return Err("Packet length error");
    }

    classify_next_header(
        metadata,
        &body[size_of::<IPv6Header>()..],
        ipv6_header.next_header,
    )
}

fn classify_next_header(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
    protocol: IpProtocol,
) -> Result<ClassifierResult, &'static str> {
    metadata.set_l4_protocol(protocol);
    // NOTE: this code does not make any attempt to reject packets which
    // carry a payload which is "unsupported" for the IP version, e.g.
    // ICMPv4 over IPv6, or IPv6 options over IPv4
    match protocol {
        0 => skip_v6_option(metadata, body),    // Hop-by-hop
        1 => classify_icmp(metadata, body),     // ICMP
        4 => classify_unclassified(metadata),   // IP in IP
        6 => classify_tcp(metadata, body),      // TCP
        17 => classify_udp(metadata, body),     // UDP
        43 => skip_v6_option(metadata, body),   // Routing
        44 => classify_frag(metadata, body),    // Fragment
        51 => skip_auth_header(metadata, body), // AH
        58 => classify_icmpv6(metadata, body),  // IPv6-ICMP
        60 => skip_v6_option(metadata, body),   // Dest opts
        _ => classify_unclassified(metadata),
    }
}

fn is_option_length_error(remaining_len: usize, next_header: u8, option_length: usize) -> bool {
    option_length > remaining_len
        || (next_header != NO_NEXT_HEADER && option_length + 8 > remaining_len)
}

fn skip_v6_option(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    // Almost all Ipv6 options start with protocol and length
    let next_header = body[0];
    // The length for these options is in muliples of 8 bytes, not including the first 8
    let option_length = (usize::from(body[1]) + 1) * 8;

    // Validate that there is enough room for this option
    // and that there is enough room for the next option if
    // there is one
    if is_option_length_error(body.len(), next_header, option_length) {
        return Err("Packet length error");
    }

    classify_next_header(metadata, &body[option_length..], next_header)
}

fn skip_auth_header(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    let next_header = body[0];
    // AH header is legacy v4 and therefore uses 4 octet multiples instead
    let option_length = (usize::from(body[1]) + 2) * 4;

    if is_option_length_error(body.len(), next_header, option_length) {
        return Err("Packet length error");
    }

    classify_next_header(metadata, &body[option_length..], next_header)
}

fn classify_frag(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    // Frag options have no length field and are always 8 bytes
    let next_header = body[0];
    let option_length: usize = 8;

    if is_option_length_error(body.len(), next_header, option_length) {
        return Err("Packet length error");
    }

    const FRAG_OFFSET_MASK: u16 = 0xFFF8;
    let frag_offset = U16::from_bytes(*array_ref!(body, 2, 2)).get();
    if frag_offset & FRAG_OFFSET_MASK != 0 {
        // Subsequent fragments can't be parsed further
        return Ok(ClassifierResult::SubsequentFragment);
    }

    classify_next_header(metadata, &body[option_length..], next_header)?;
    return Ok(ClassifierResult::FirstFragment);
}

fn classify_icmp(
    metadata: &mut packet::PacketMetadata,
    _body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    // TODO: check type and code
    metadata.set_src_port(0);
    metadata.set_dst_port(0);
    Ok(ClassifierResult::OK)
}

fn classify_icmpv6(
    metadata: &mut packet::PacketMetadata,
    _body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    // TODO: check type and code
    metadata.set_src_port(0);
    metadata.set_dst_port(0);
    Ok(ClassifierResult::OK)
}

fn classify_tcp(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    // Check that there's enough room in the packet data for the base header (no options)
    if size_of::<TCPHeader>() > body.len() {
        return Err("Packet length error");
    }

    let header_bytes = &body[..size_of::<TCPHeader>()];
    let tcp_header = TCPHeader::ref_from_bytes(header_bytes).unwrap();

    let data_offset = (tcp_header.data_offset_and_reserved >> 4) * 4;
    if data_offset < 20 || data_offset as usize > body.len() {
        return Err("Packet length error");
    }

    metadata.set_src_port(tcp_header.src_port.get());
    metadata.set_dst_port(tcp_header.dst_port.get());

    Ok(ClassifierResult::OK)
}

fn classify_udp(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
) -> Result<ClassifierResult, &'static str> {
    if size_of::<UDPHeader>() > body.len() {
        return Err("Packet length error");
    }

    let header_bytes = &body[..size_of::<UDPHeader>()];
    let udp_header = UDPHeader::ref_from_bytes(header_bytes).unwrap();

    metadata.set_src_port(udp_header.src_port.get());
    metadata.set_dst_port(udp_header.dst_port.get());

    Ok(ClassifierResult::OK)
}

fn classify_unclassified(
    metadata: &mut packet::PacketMetadata,
) -> Result<ClassifierResult, &'static str> {
    metadata.set_src_port(0);
    metadata.set_dst_port(0);
    Ok(ClassifierResult::UnclassifiedL4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use bytes::BufMut;
    use zerocopy::FromZeros;

    #[test]
    fn test_non_ip() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        let packet_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert_eq!(ClassifierResult::NonIP, classify(&mut packet).unwrap());

        let metadata = packet.metadata();
        assert_eq!(IpAddress::new_zeroed(), metadata.get_src_address());
        assert_eq!(IpAddress::new_zeroed(), metadata.get_dst_address());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_l4_protocol());
    }

    // Begin IPv4 tests

    #[test]
    fn test_v4_tcp_success() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data =
            [
                0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
                0x40, 0x06, 0x70, 0xC6, 0x01, 0x02, 0x03, 0x04,
                0x04, 0x03, 0x02, 0x01, 0x00, 0x14, 0x00, 0x50,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x50, 0x02, 0x20, 0x00, 0x85, 0x75, 0x00, 0x00,
            ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert_eq!(ClassifierResult::OK, classify(&mut packet).unwrap());

        let metadata = packet.metadata();
        assert_eq!(
            [0x04, 0x03, 0x02, 0x01],
            metadata.get_dst_address().read_as_v4()
        );
        assert_eq!(
            [0x01, 0x02, 0x03, 0x04],
            metadata.get_src_address().read_as_v4()
        );
        assert_eq!(0x14u16, metadata.get_src_port_hbo());
        assert_eq!(0x50u16, metadata.get_dst_port_hbo());
        assert_eq!(6u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_v4_tcp_first_frag() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data =
            [
                0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x20, 0x00,
                0x40, 0x06, 0x70, 0xC6, 0x01, 0x02, 0x03, 0x04,
                0x04, 0x03, 0x02, 0x01, 0x00, 0x14, 0x00, 0x50,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x50, 0x02, 0x20, 0x00, 0x85, 0x75, 0x00, 0x00,
            ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert_eq!(
            ClassifierResult::FirstFragment,
            classify(&mut packet).unwrap()
        );

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv4, metadata.get_l3_type());
        assert_eq!(
            [0x04, 0x03, 0x02, 0x01],
            metadata.get_dst_address().read_as_v4()
        );
        assert_eq!(
            [0x01, 0x02, 0x03, 0x04],
            metadata.get_src_address().read_as_v4()
        );
        assert_eq!(0x14u16, metadata.get_src_port_hbo());
        assert_eq!(0x50u16, metadata.get_dst_port_hbo());
        assert_eq!(6u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_v4_tcp_subsequent_frag() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data =
            [
                0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0xC0,
                0x40, 0x06, 0x70, 0xC6, 0x01, 0x02, 0x03, 0x04,
                0x04, 0x03, 0x02, 0x01, 0x00, 0x14, 0x00, 0x50,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x50, 0x02, 0x20, 0x00, 0x85, 0x75, 0x00, 0x00,
            ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert_eq!(
            ClassifierResult::SubsequentFragment,
            classify(&mut packet).unwrap()
        );

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv4, metadata.get_l3_type());
        assert_eq!(
            [0x04, 0x03, 0x02, 0x01],
            metadata.get_dst_address().read_as_v4()
        );
        assert_eq!(
            [0x01, 0x02, 0x03, 0x04],
            metadata.get_src_address().read_as_v4()
        );
        assert_eq!(0x0u16, metadata.get_src_port_hbo());
        assert_eq!(0x0u16, metadata.get_dst_port_hbo());
        assert_eq!(6u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_v4_truncated_l3() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data =
            [
                0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
                0x40, 0x06, 0x70, 0xC6, 0x01, 0x02, 0x03, 0x04,
            ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(IpAddress::new_zeroed(), metadata.get_src_address());
        assert_eq!(IpAddress::new_zeroed(), metadata.get_dst_address());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_v4_ihl_too_small() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data =
            [
                0x43, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
                0x40, 0x06, 0x70, 0xC6, 0x01, 0x02, 0x03, 0x04,
                0x04, 0x03, 0x02, 0x01, 0x00, 0x14, 0x00, 0x50,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x50, 0x02, 0x20, 0x00, 0x85, 0x75, 0x00, 0x00,
            ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv4, metadata.get_l3_type());
        assert_eq!(IpAddress::new_zeroed(), metadata.get_src_address());
        assert_eq!(IpAddress::new_zeroed(), metadata.get_dst_address());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_v4_ihl_too_big() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data =
            [
                0x4F, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
                0x40, 0x06, 0x70, 0xC6, 0x01, 0x02, 0x03, 0x04,
                0x04, 0x03, 0x02, 0x01, 0x00, 0x14, 0x00, 0x50,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x50, 0x02, 0x20, 0x00, 0x85, 0x75, 0x00, 0x00,
            ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv4, metadata.get_l3_type());
        assert_eq!(IpAddress::new_zeroed(), metadata.get_src_address());
        assert_eq!(IpAddress::new_zeroed(), metadata.get_dst_address());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_l4_protocol());
    }

    // Begin IPv6 tests

    #[test]
    fn test_v6_tcp_success() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x0d, 0x68, 0x4a, 0x00, 0x28, 0x06, 0x40,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xa9, 0xa0, 0x1f, 0x90, 0x02, 0x1b, 0x63, 0x8c,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x67, 0x5c,
            0x8e, 0xb9, 0x00, 0x00, 0x02, 0x04, 0x0b, 0x7c,
            0x04, 0x02, 0x08, 0x0a, 0x80, 0x1d, 0xa5, 0x22,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07
        ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert_eq!(ClassifierResult::OK, classify(&mut packet).unwrap());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_src_address()
        );
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_dst_address()
        );
        assert_eq!(43424u16, metadata.get_src_port_hbo());
        assert_eq!(8080u16, metadata.get_dst_port_hbo());
        assert_eq!(6u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_v6_first_fragment() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 128);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x02, 0x12, 0x89, 0x00, 0x50, 0x2c, 0x40,
            0x26, 0x07, 0xf0, 0x10, 0x03, 0xf9, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01,
            0x26, 0x07, 0xf0, 0x10, 0x03, 0xf9, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00,
            0x11, 0x00, 0x00, 0x01, 0xf8, 0x8e, 0xb4, 0x66,
            0x18, 0xdb, 0x18, 0xdb, 0x15, 0x0b, 0x79, 0x16,
            0x06, 0xfd, 0x14, 0xff, 0x07, 0x29, 0x08, 0x07,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x08,
            0x07, 0x74, 0x65, 0x73, 0x74, 0x41, 0x70, 0x70,
            0x08, 0x01, 0x31, 0x08, 0x07, 0x74, 0x65, 0x73,
            0x74, 0x41, 0x70, 0x70, 0x08, 0x09, 0xfd, 0x00,
            0x00, 0x01, 0x4f, 0x23, 0x68, 0xc7, 0x8e, 0x14,
            0x04, 0x19, 0x02, 0x27, 0x10, 0x15, 0xfd, 0x13,
            0x88, 0x68, 0x68, 0x68, 0x68, 0x68, 0x68, 0x68,
        ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert_eq!(
            ClassifierResult::FirstFragment,
            classify(&mut packet).unwrap()
        );

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(
            IpAddress {
                v6: [
                    0x26, 0x07, 0xf0, 0x10, 0x03, 0xf9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x11, 0x00, 0x00
                ]
            },
            metadata.get_dst_address()
        );
        assert_eq!(
            IpAddress {
                v6: [
                    0x26, 0x07, 0xf0, 0x10, 0x03, 0xf9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x10, 0x01
                ]
            },
            metadata.get_src_address()
        );
        assert_eq!(6363u16, metadata.get_dst_port_hbo());
        assert_eq!(6363u16, metadata.get_src_port_hbo());
        assert_eq!(17u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_v6_subsequent_fragment() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 128);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x02, 0x12, 0x89, 0x00, 0x18, 0x2c, 0x40,
            0x26, 0x07, 0xf0, 0x10, 0x03, 0xf9, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01,
            0x26, 0x07, 0xf0, 0x10, 0x03, 0xf9, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00,
            0x11, 0x00, 0x05, 0xa9, 0xf8, 0x8e, 0xb4, 0x66,
            0x68, 0x68, 0x68, 0x68, 0x68, 0x68, 0x68, 0x68,
            0x68, 0x68, 0x68, 0x68, 0x68, 0x68, 0x68, 0x68,
        ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert_eq!(
            ClassifierResult::SubsequentFragment,
            classify(&mut packet).unwrap()
        );

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(
            IpAddress {
                v6: [
                    0x26, 0x07, 0xf0, 0x10, 0x03, 0xf9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x11, 0x00, 0x00
                ]
            },
            metadata.get_dst_address()
        );
        assert_eq!(
            IpAddress {
                v6: [
                    0x26, 0x07, 0xf0, 0x10, 0x03, 0xf9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x10, 0x01
                ]
            },
            metadata.get_src_address()
        );
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(44u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_v6_with_routing_option() {
        // This packet presents an interesting problem of the inner IP being the "correct" one
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 128);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x0f, 0xbb, 0x74, 0x00, 0x60, 0x2b, 0x3f,
            0xfc, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x29, 0x06, 0x04, 0x02, 0x02, 0x00, 0x00, 0x00,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x1f, 0x90, 0xa9, 0xa0, 0xba, 0x31, 0x1e, 0x8d,
            0x02, 0x1b, 0x63, 0x8d, 0xa0, 0x12, 0x70, 0xf8,
            0x8a, 0xf5, 0x00, 0x00, 0x02, 0x04, 0x07, 0x94,
            0x04, 0x02, 0x08, 0x0a, 0x80, 0x1d, 0xa5, 0x22,
            0x80, 0x1d, 0xa5, 0x22, 0x01, 0x03, 0x03, 0x07,
        ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert_eq!(
            ClassifierResult::UnclassifiedL4,
            classify(&mut packet).unwrap()
        );

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_dst_address()
        );
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x02
                ]
            },
            metadata.get_src_address()
        );
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(41u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_option_length_error_v6() {
        // This packet presents an interesting problem of the inner IP being the "correct" one
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 128);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x0f, 0xbb, 0x74, 0x00, 0x38, 0x2b, 0x3f,
            0xfc, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x29, 0x06, 0x04, 0x02, 0x02, 0x00, 0x00, 0x00,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_dst_address()
        );
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x02
                ]
            },
            metadata.get_src_address()
        );
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(43u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_header_length_error_v6() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        let packet_data = [0x60u8, 5u8, 4u8, 3u8, 2u8, 1u8, 0u8];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(IpAddress::new_zeroed(), metadata.get_src_address());
        assert_eq!(IpAddress::new_zeroed(), metadata.get_dst_address());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_ipv4_mapped_src_error_v6() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x0d, 0x68, 0x4a, 0x00, 0x28, 0x06, 0x40,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xa9, 0xa0, 0x1f, 0x90, 0x02, 0x1b, 0x63, 0x8c,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x67, 0x5c,
            0x8e, 0xb9, 0x00, 0x00, 0x02, 0x04, 0x0b, 0x7c,
            0x04, 0x02, 0x08, 0x0a, 0x80, 0x1d, 0xa5, 0x22,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07
        ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());
    }

    #[test]
    fn test_ipv4_mapped_dst_error_v6() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x0d, 0x68, 0x4a, 0x00, 0x28, 0x06, 0x40,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x05, 0x06, 0x07, 0x08,
            0xa9, 0xa0, 0x1f, 0x90, 0x02, 0x1b, 0x63, 0x8c,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x67, 0x5c,
            0x8e, 0xb9, 0x00, 0x00, 0x02, 0x04, 0x0b, 0x7c,
            0x04, 0x02, 0x08, 0x0a, 0x80, 0x1d, 0xa5, 0x22,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07
        ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());
    }

    #[test]
    fn test_payload_length_error_v6() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x0d, 0x68, 0x4a, 0x01, 0x28, 0x06, 0x40,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xa9, 0xa0, 0x1f, 0x90, 0x02, 0x1b, 0x63, 0x8c,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x67, 0x5c,
            0x8e, 0xb9, 0x00, 0x00, 0x02, 0x04, 0x0b, 0x7c,
            0x04, 0x02, 0x08, 0x0a, 0x80, 0x1d, 0xa5, 0x22,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07
        ];
        packet.put_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_src_address()
        );
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_dst_address()
        );
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_jumbo_reject_v6() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x0d, 0x68, 0x4a, 0x00, 0x00, 0x00, 0x40,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x06, 0x00, 0xC2, 0x04, 0x00, 0x01, 0x00, 0x00,
        ];
        packet.put_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_src_address()
        );
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_dst_address()
        );
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_smalljumbo_reject_v6() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x0d, 0x68, 0x4a, 0x00, 0x00, 0x00, 0x40,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x06, 0x00, 0xC2, 0x04, 0x00, 0x00, 0x01, 0x00,
        ];
        packet.put_slice(&packet_data);
        packet.put_bytes(0, 256);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_src_address()
        );
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_dst_address()
        );
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_empty_packet_v6() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x0d, 0x68, 0x4a, 0x00, 0x00, 0xFE, 0x40,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x06, 0x00, 0xC2, 0x04, 0x00, 0x00, 0x01, 0x00,
        ];
        packet.put_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_src_address()
        );
        assert_eq!(
            IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_dst_address()
        );
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_l4_protocol());
    }

    // Begin TCP tests

    #[test]
    fn test_tcp_truncated() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data = [
                0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00,
                0x40, 0x06, 0x70, 0xC6, 0x01, 0x02, 0x03, 0x04,
                0x04, 0x03, 0x02, 0x01, 0x00, 0x14, 0x00, 0x50,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv4, metadata.get_l3_type());
        assert_eq!(
            [0x04, 0x03, 0x02, 0x01],
            metadata.get_dst_address().read_as_v4()
        );
        assert_eq!(
            [0x01, 0x02, 0x03, 0x04],
            metadata.get_src_address().read_as_v4()
        );
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(6u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_tcp_data_offset_too_small() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data = [
                0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
                0x40, 0x06, 0x70, 0xC6, 0x01, 0x02, 0x03, 0x04,
                0x04, 0x03, 0x02, 0x01, 0x00, 0x14, 0x00, 0x50,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x30, 0x02, 0x20, 0x00, 0x85, 0x75, 0x00, 0x00,
            ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv4, metadata.get_l3_type());
        assert_eq!(
            [0x04, 0x03, 0x02, 0x01],
            metadata.get_dst_address().read_as_v4()
        );
        assert_eq!(
            [0x01, 0x02, 0x03, 0x04],
            metadata.get_src_address().read_as_v4()
        );
        assert_eq!(0x0u16, metadata.get_src_port_hbo());
        assert_eq!(0x0u16, metadata.get_dst_port_hbo());
        assert_eq!(6u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_tcp_data_offset_too_big() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data = [
                0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
                0x40, 0x06, 0x70, 0xC6, 0x01, 0x02, 0x03, 0x04,
                0x04, 0x03, 0x02, 0x01, 0x00, 0x14, 0x00, 0x50,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x30, 0x02, 0x30, 0x00, 0x85, 0x75, 0x00, 0x00,
            ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv4, metadata.get_l3_type());
        assert_eq!(
            [0x04, 0x03, 0x02, 0x01],
            metadata.get_dst_address().read_as_v4()
        );
        assert_eq!(
            [0x01, 0x02, 0x03, 0x04],
            metadata.get_src_address().read_as_v4()
        );
        assert_eq!(0x0u16, metadata.get_src_port_hbo());
        assert_eq!(0x0u16, metadata.get_dst_port_hbo());
        assert_eq!(6u8, metadata.get_l4_protocol());
    }

    // Begin UDP tests

    #[test]
    fn test_udp_truncated() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        #[rustfmt::skip]
        let packet_data = [
                0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00,
                0x40, 0x06, 0x70, 0xC6, 0x01, 0x02, 0x03, 0x04,
                0x04, 0x03, 0x02, 0x01, 0x00, 0x14, 0x00, 0x50,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert!(classify(&mut packet).is_err());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv4, metadata.get_l3_type());
        assert_eq!(
            [0x04, 0x03, 0x02, 0x01],
            metadata.get_dst_address().read_as_v4()
        );
        assert_eq!(
            [0x01, 0x02, 0x03, 0x04],
            metadata.get_src_address().read_as_v4()
        );
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(6u8, metadata.get_l4_protocol());
    }

    // Begin ICMP tests

    #[test]
    fn test_icmp() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET);
        #[rustfmt::skip]
        let packet_data = [
            0x45, 0x00, 0x00, 0x54, 0x22, 0x7C, 0x40, 0x00,
            0x40, 0x01, 0x07, 0x73, 0x0A, 0x89, 0x04, 0x30,
            0x01, 0x01, 0x01, 0x01, 0x08, 0x00, 0x2A, 0xD4,
            0x48, 0x4A, 0x00, 0x01, 0x8F, 0xA8, 0x23, 0x67,
            0x00, 0x00, 0x00, 0x00, 0x0F, 0xFE, 0x03, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
        ];
        packet.put_slice(&packet_data);

        assert_eq!(ClassifierResult::OK, classify(&mut packet).unwrap());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv4, metadata.get_l3_type());
        assert_eq!([10, 137, 4, 48], metadata.get_src_address().read_as_v4());
        assert_eq!(
            [0x01, 0x01, 0x01, 0x01],
            metadata.get_dst_address().read_as_v4()
        );
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(1u8, metadata.get_l4_protocol());
    }

    #[test]
    fn test_icmpv6() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET);
        #[rustfmt::skip]
        let packet_data = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3A, 0xFF,
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0C, 0xBB, 0x7E, 0xA4, 0x55, 0xF1, 0x07, 0x9F,
            0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0xFF, 0xF1, 0x00, 0x01,
            0x87, 0x00, 0x1A, 0xE5, 0x00, 0x00, 0x00, 0x00,
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0C, 0xBB, 0x7E, 0xA4, 0x55, 0xF1, 0x00, 0x01,
            0x01, 0x01, 0xE4, 0x60, 0x17, 0xD8, 0x9A, 0x4B,
        ];
        packet.put_slice(&packet_data);

        assert_eq!(ClassifierResult::OK, classify(&mut packet).unwrap());

        let metadata = packet.metadata();
        assert_eq!(L3Type::Ipv6, metadata.get_l3_type());
        assert_eq!(
            IpAddress::from([
                0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0xBB, 0x7E, 0xA4, 0x55, 0xF1,
                0x07, 0x9F,
            ]),
            metadata.get_src_address()
        );
        assert_eq!(
            IpAddress::from([
                0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xF1,
                0x00, 0x01,
            ]),
            metadata.get_dst_address()
        );
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(58u8, metadata.get_l4_protocol());
    }
}
