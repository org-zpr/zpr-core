use crate::config;
use crate::packet;
use std::mem::size_of;
use zerocopy::{ByteOrder, FromBytes, FromZeroes, NetworkEndian};
use zerocopy_derive::{FromBytes, FromZeroes, KnownLayout};

#[derive(Debug, PartialEq)]
pub enum ClassifierResult {
    OK,
    NonIP,
    UnclassifiedL4,
    LengthError,
}

const IP_VERSION_MASK: u8 = 0xF0;
const IPV4_HEADER_LENGTH_MASK: u8 = 0x0F;

#[derive(FromZeroes, FromBytes, KnownLayout)]
#[repr(C)]
struct IPv4Header {
    pub vhl: u8,
    pub dscp: u8,
    pub total_length: [u8; 2],
    pub frag_id: u16,
    pub frag_offset: u16,
    pub ttl: u8,
    pub proto: u8,
    pub header_checksum: u16,
    pub src_address: [u8; 4],
    pub dst_address: [u8; 4],
}

#[derive(FromZeroes, FromBytes, KnownLayout)]
#[repr(C)]
struct IPv6Header {
    pub version_and_tc_lower: u8,
    pub tc_upper_and_fl_lower: u8,
    pub fl_upper: u16,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_address: packet::IpAddress,
    pub dst_address: packet::IpAddress,
}

#[derive(FromZeroes, FromBytes, KnownLayout)]
#[repr(C)]
struct TCPHeader {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub data_offset_and_reserved: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

#[derive(FromZeroes, FromBytes, KnownLayout)]
#[repr(C)]
struct UDPHeader {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub length: u16,
    pub checksum: u16,
}

pub fn classify(packet: &mut packet::Packet) -> ClassifierResult {
    let offset = 0;
    let (metadata, body) = packet.metadata_mut_and_body();
    classify_zdp(metadata, body, offset)
}

pub fn classify_zdp(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
    offset: usize,
) -> ClassifierResult {
    classify_l3(metadata, body, offset)
}

pub fn classify_l3(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
    offset: usize,
) -> ClassifierResult {
    let ip_version = (body[offset] & IP_VERSION_MASK) >> 4;

    match ip_version {
        4 => classify_ipv4(metadata, body, offset),
        6 => classify_ipv6(metadata, body, offset),
        _ => return ClassifierResult::NonIP,
    }
}

pub fn classify_ipv4(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
    mut offset: usize,
) -> ClassifierResult {
    // Check that there's enough room in the packet data for the base header (no options)
    if usize::from(size_of::<IPv4Header>() + offset) > metadata.get_length() {
        return ClassifierResult::LengthError;
    }

    let end_of_header = offset + size_of::<IPv4Header>();
    let header_bytes = &body[offset..end_of_header];
    let ipv4_header = IPv4Header::ref_from(header_bytes).unwrap();

    let header_length = ipv4_header.vhl & IPV4_HEADER_LENGTH_MASK;
    let total_length = NetworkEndian::read_u16(&ipv4_header.total_length);
    if usize::from(total_length) + offset != metadata.get_length()
        || header_length < 5
        || u16::from(header_length * 4) > total_length
    {
        return ClassifierResult::LengthError;
    }

    let protocol = ipv4_header.proto;
    metadata.set_protocol(protocol);
    metadata.set_src_address_v4(ipv4_header.src_address);
    metadata.set_dst_address_v4(ipv4_header.dst_address);

    offset += usize::from(header_length * 4);
    classify_l4(metadata, body, offset, protocol)
}

pub fn classify_ipv6(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
    offset: usize,
) -> ClassifierResult {
    // Check that there's enough room in the packet data for the base header (no options)
    if usize::from(size_of::<IPv6Header>() + offset) > metadata.get_length() {
        return ClassifierResult::LengthError;
    }

    let end_of_header = offset + size_of::<IPv6Header>();
    let header_bytes = &body[offset..end_of_header];
    let ipv6_header = IPv6Header::ref_from(header_bytes).unwrap();

    let protocol = ipv6_header.next_header;
    metadata.set_protocol(protocol);
    metadata.set_src_address_v6(ipv6_header.src_address);
    metadata.set_dst_address_v6(ipv6_header.dst_address);

    // TODO: IPv6 options parsing
    classify_l4(metadata, body, end_of_header, protocol)
}

pub fn classify_l4(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
    offset: usize,
    protocol: u8,
) -> ClassifierResult {
    match protocol {
        6 => return classify_tcp(metadata, body, offset),
        17 => return classify_udp(metadata, body, offset),
        _ => return ClassifierResult::UnclassifiedL4,
    }
}

pub fn classify_tcp(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
    offset: usize,
) -> ClassifierResult {
    // Check that there's enough room in the packet data for the base header (no options)
    if usize::from(size_of::<TCPHeader>() + offset) > metadata.get_length() {
        return ClassifierResult::LengthError;
    }

    let end_of_header = offset + size_of::<TCPHeader>();
    let header_bytes = &body[offset..end_of_header];
    let tcp_header = TCPHeader::ref_from(header_bytes).unwrap();

    let data_offset = (tcp_header.data_offset_and_reserved >> 4) * 4;
    if data_offset < 20 || usize::from(data_offset) + offset > metadata.get_length() {
        return ClassifierResult::LengthError;
    }

    metadata.set_src_port(tcp_header.src_port);
    metadata.set_dst_port(tcp_header.dst_port);

    ClassifierResult::OK
}

pub fn classify_udp(
    metadata: &mut packet::PacketMetadata,
    body: &[u8],
    offset: usize,
) -> ClassifierResult {
    if usize::from(size_of::<UDPHeader>() + offset) > metadata.get_length() {
        return ClassifierResult::LengthError;
    }

    let end_of_header = offset + size_of::<UDPHeader>();
    let header_bytes = &body[offset..end_of_header];
    let udp_header = UDPHeader::ref_from(header_bytes).unwrap();

    metadata.set_src_port(udp_header.src_port);
    metadata.set_dst_port(udp_header.dst_port);

    ClassifierResult::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_ip() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        let packet_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert_eq!(ClassifierResult::NonIP, classify(&mut packet));

        let metadata = packet.metadata();
        assert_eq!(packet::IpAddress::new_zeroed(), metadata.get_src_address());
        assert_eq!(packet::IpAddress::new_zeroed(), metadata.get_dst_address());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_protocol());
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

        assert_eq!(ClassifierResult::OK, classify(&mut packet));

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
        assert_eq!(6u8, metadata.get_protocol());
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

        assert_eq!(ClassifierResult::LengthError, classify(&mut packet));

        let metadata = packet.metadata();
        assert_eq!(packet::IpAddress::new_zeroed(), metadata.get_src_address());
        assert_eq!(packet::IpAddress::new_zeroed(), metadata.get_dst_address());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_protocol());
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

        assert_eq!(ClassifierResult::LengthError, classify(&mut packet));

        let metadata = packet.metadata();
        assert_eq!(packet::IpAddress::new_zeroed(), metadata.get_src_address());
        assert_eq!(packet::IpAddress::new_zeroed(), metadata.get_dst_address());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_protocol());
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

        assert_eq!(ClassifierResult::LengthError, classify(&mut packet));

        let metadata = packet.metadata();
        assert_eq!(packet::IpAddress::new_zeroed(), metadata.get_src_address());
        assert_eq!(packet::IpAddress::new_zeroed(), metadata.get_dst_address());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_protocol());
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

        assert_eq!(ClassifierResult::OK, classify(&mut packet));

        let metadata = packet.metadata();
        assert_eq!(
            packet::IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_src_address()
        );
        assert_eq!(
            packet::IpAddress {
                v6: [
                    0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]
            },
            metadata.get_dst_address()
        );
        assert_eq!(43424u16, metadata.get_src_port_hbo());
        assert_eq!(8080u16, metadata.get_dst_port_hbo());
        assert_eq!(6u8, metadata.get_protocol());
    }

    #[test]
    fn test_length_error_v6() {
        let mut buf: [u8; config::PACKET_BUFFER_SIZE] = [0; config::PACKET_BUFFER_SIZE];
        let mut packet = packet::Packet::new(&mut buf, packet::PACKET_BUFFER_MIN_BODY_OFFSET + 64);
        let packet_data = [0x60u8, 5u8, 4u8, 3u8, 2u8, 1u8, 0u8];
        packet.alloc_zeroed_headroom(packet_data.len());
        packet.body_mut().copy_from_slice(&packet_data);

        assert_eq!(ClassifierResult::LengthError, classify(&mut packet));

        let metadata = packet.metadata();
        assert_eq!(packet::IpAddress::new_zeroed(), metadata.get_src_address());
        assert_eq!(packet::IpAddress::new_zeroed(), metadata.get_dst_address());
        assert_eq!(0u16, metadata.get_src_port_hbo());
        assert_eq!(0u16, metadata.get_dst_port_hbo());
        assert_eq!(0u8, metadata.get_protocol());
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

        assert_eq!(ClassifierResult::LengthError, classify(&mut packet));

        let metadata = packet.metadata();
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
        assert_eq!(6u8, metadata.get_protocol());
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

        assert_eq!(ClassifierResult::LengthError, classify(&mut packet));

        let metadata = packet.metadata();
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
        assert_eq!(6u8, metadata.get_protocol());
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

        assert_eq!(ClassifierResult::LengthError, classify(&mut packet));

        let metadata = packet.metadata();
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
        assert_eq!(6u8, metadata.get_protocol());
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

        assert_eq!(ClassifierResult::LengthError, classify(&mut packet));

        let metadata = packet.metadata();
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
        assert_eq!(6u8, metadata.get_protocol());
    }
}
