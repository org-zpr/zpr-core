//! ZDP Header Compression (RFC 6.5 § 5.26)

use crate::classifier;
use crate::defs::FiveTuple;
use crate::prelude::*;
use bytes::Buf;
use internet_checksum;
use zerocopy::*;
use zpr::packet_info::compression_mode::*;
use zpr_ext::bytes::BufExt;
use zpr_utils::net_defs;

const ZDP_V4_FRAG_INFO_PRESENT: u8 = 0b00001000;

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
struct CompressedIPv6Header {
    pub version_and_tc_upper: u8,
    pub tc_lower_and_fl_upper: u8,
    pub fl_lower: [u8; 2],
    pub hop_limit: u8,
}

fn compress_ipv4(
    compression_mode: CompressionMode,
    l4_protocol: net_defs::IpProtocol,
    pkt: &mut Packet,
) {
    let hdr = classifier::IPv4Header::ref_from_prefix(pkt.body())
        .unwrap()
        .0;
    let hl = hdr.vhl & classifier::IPV4_HEADER_LENGTH_MASK;
    let dscp = hdr.dscp;
    let frag_flags = hdr.frag_offset.get() >> 13; // fragmentation flags
    let frag_id = hdr.frag_id;
    let frag_offset = hdr.frag_offset & 0x1fff; // ignores fragmentation flags; NOTE/TODO: spec deviation
    let ttl = hdr.ttl;

    pkt.advance(std::mem::size_of::<classifier::IPv4Header>());

    compress_l4(compression_mode, l4_protocol, pkt);

    pkt.push_header(&ttl);

    let frag_info_present = frag_offset.get() != 0;
    if frag_info_present {
        pkt.push_header(&frag_offset);
    }

    pkt.push_header(&frag_id);

    let hl_zdpflags = (hl << 4)
        | (if frag_info_present {
            ZDP_V4_FRAG_INFO_PRESENT
        } else {
            0
        })
        | (frag_flags as u8);

    pkt.push_header(&[hl_zdpflags, dscp]);
}

fn expand_ipv4(compression_mode: CompressionMode, five_tuple: &FiveTuple, pkt: &mut Packet) {
    let hl_zdpflags_tos = pkt.get_array::<2>();
    let hl_zdpflags = hl_zdpflags_tos[0];
    let tos = hl_zdpflags_tos[1];

    let hl = hl_zdpflags >> 4;
    let frag_info_present = (hl_zdpflags & ZDP_V4_FRAG_INFO_PRESENT) != 0;
    let frag_flags = hl_zdpflags & 0x07;

    let frag_id = pkt.get_array::<2>();

    let mut frag_offset;
    if frag_info_present {
        frag_offset = pkt.get_u16();
    } else {
        frag_offset = 0u16;
    }
    frag_offset |= (frag_flags as u16) << 13; // NOTE/TODO: spec deviation

    let ttl = pkt.get_u8();

    expand_l4(compression_mode, five_tuple, pkt);

    let body_len = pkt.body().len();

    let hdr = pkt.alloc_zeroed_header::<classifier::IPv4Header>();
    hdr.vhl = (4 << 4) | hl;
    hdr.dscp = tos;
    hdr.total_length = ((body_len + std::mem::size_of::<classifier::IPv4Header>()) as u16).into();
    hdr.frag_id = frag_id;
    hdr.frag_offset = frag_offset.into();
    hdr.ttl = ttl;
    hdr.proto = five_tuple.l4_protocol;
    hdr.src_address = five_tuple.src_address.read_as_v4();
    hdr.dst_address = five_tuple.dst_address.read_as_v4();

    let header_len = (hl as usize) << 2;
    let csum = internet_checksum::checksum(&pkt.body()[..header_len]);
    classifier::IPv4Header::mut_from_prefix(pkt.body_mut())
        .unwrap()
        .0
        .header_checksum = csum;
}

fn compress_ipv6(
    compression_mode: CompressionMode,
    l4_protocol: net_defs::IpProtocol,
    pkt: &mut Packet,
) {
    let hdr = classifier::IPv6Header::ref_from_prefix(pkt.body())
        .unwrap()
        .0;
    let version_and_tc_upper = hdr.version_and_tc_upper;
    let tc_lower_and_fl_upper = hdr.tc_lower_and_fl_upper;
    let fl_lower = hdr.fl_lower;
    let hop_limit = hdr.hop_limit;

    pkt.advance(std::mem::size_of::<classifier::IPv6Header>());

    compress_l4(compression_mode, l4_protocol, pkt);

    let chdr = pkt.alloc_zeroed_header::<CompressedIPv6Header>();
    chdr.version_and_tc_upper = version_and_tc_upper;
    chdr.tc_lower_and_fl_upper = tc_lower_and_fl_upper;
    chdr.fl_lower = fl_lower;
    chdr.hop_limit = hop_limit;
}

fn expand_ipv6(compression_mode: CompressionMode, five_tuple: &FiveTuple, pkt: &mut Packet) {
    let chdr = CompressedIPv6Header::ref_from_prefix(pkt.body()).unwrap().0;
    let version_and_tc_upper = chdr.version_and_tc_upper;
    let tc_lower_and_fl_upper = chdr.tc_lower_and_fl_upper;
    let fl_lower = chdr.fl_lower;
    let hop_limit = chdr.hop_limit;

    pkt.advance(std::mem::size_of::<CompressedIPv6Header>());

    expand_l4(compression_mode, five_tuple, pkt);

    let body_len = pkt.body().len();

    let hdr = pkt.alloc_zeroed_header::<classifier::IPv6Header>();
    hdr.version_and_tc_upper = version_and_tc_upper;
    hdr.tc_lower_and_fl_upper = tc_lower_and_fl_upper;
    hdr.fl_lower = fl_lower;
    hdr.payload_length = (body_len as u16).into(); // NOTE: we do not allow jumbo payloads
    hdr.next_header = five_tuple.l4_protocol;
    hdr.hop_limit = hop_limit;
    hdr.src_address = five_tuple.src_address;
    hdr.dst_address = five_tuple.dst_address;
}

fn compress_l4(
    compression_mode: CompressionMode,
    l4_protocol: net_defs::IpProtocol,
    pkt: &mut Packet,
) {
    match l4_protocol {
        net_defs::ip_number::TCP => compress_tcp(compression_mode, pkt),
        net_defs::ip_number::UDP => compress_udp(compression_mode, pkt),
        _ => (), // no compression defined for other protocols
    }
}

fn expand_l4(compression_mode: CompressionMode, five_tuple: &FiveTuple, pkt: &mut Packet) {
    // NOTE: "PRESENT" CompressionMode bits indicate that the corresponding field
    // is present _in the traffic classifier_, which means it should be _absent_
    // in the compressed packet.  (Hence the checks herein look as if they are backward.)

    match five_tuple.l4_protocol {
        net_defs::ip_number::TCP => expand_tcp(compression_mode, five_tuple, pkt),
        net_defs::ip_number::UDP => expand_udp(compression_mode, five_tuple, pkt),
        _ => (), // no compression defined for other protocols
    }
}

fn compress_tcp(compression_mode: CompressionMode, pkt: &mut Packet) {
    let src_port = pkt.get_u16();
    let dst_port = pkt.get_u16();

    // remove checksum
    // NOTE: we expect classifier to have filtered out packets
    // with incorrect checksums
    pkt.body_mut().copy_within(
        ..(std::mem::offset_of!(classifier::TCPHeader, checksum) - 4),
        2,
    );
    pkt.advance(2);

    if compression_mode & DESTINATION_PORT_PRESENT == 0 {
        pkt.push_u16(dst_port);
    }

    if compression_mode & SOURCE_PORT_PRESENT == 0 {
        pkt.push_u16(src_port);
    }
}

fn expand_tcp(compression_mode: CompressionMode, five_tuple: &FiveTuple, pkt: &mut Packet) {
    let src_port = if compression_mode & SOURCE_PORT_PRESENT != 0 {
        five_tuple.src_port
    } else {
        pkt.get_u16()
    };

    let dst_port = if compression_mode & DESTINATION_PORT_PRESENT != 0 {
        five_tuple.dst_port
    } else {
        pkt.get_u16()
    };

    // make space for checksum
    pkt.alloc_zeroed_headroom(2);
    pkt.body_mut().copy_within(
        2..(2 + std::mem::offset_of!(classifier::TCPHeader, checksum) - 4),
        0,
    );

    pkt.push_u16(dst_port);
    pkt.push_u16(src_port);

    // zero out checksum for computation
    classifier::TCPHeader::mut_from_prefix(pkt.body_mut())
        .unwrap()
        .0
        .checksum = [0u8; 2];

    // recompute checksum
    let csum = net_defs::inet_l4_checksum(
        five_tuple.l3_type.0,
        &five_tuple.src_address,
        &five_tuple.dst_address,
        net_defs::ip_number::TCP,
        pkt.body(),
    );
    classifier::TCPHeader::mut_from_prefix(pkt.body_mut())
        .unwrap()
        .0
        .checksum = csum;
}

fn compress_udp(compression_mode: CompressionMode, pkt: &mut Packet) {
    let src_port = pkt.get_u16();
    let dst_port = pkt.get_u16();

    // remove length
    // NOTE: we do not support v6 jumbograms (whose length field is 0);
    // the classifier should filter these out (as it does
    // UDPs packet whose length is incorrect)
    pkt.advance(2);

    // leave checksum

    if compression_mode & DESTINATION_PORT_PRESENT == 0 {
        pkt.push_u16(dst_port);
    }

    if compression_mode & SOURCE_PORT_PRESENT == 0 {
        pkt.push_u16(src_port);
    }
}

fn expand_udp(compression_mode: CompressionMode, five_tuple: &FiveTuple, pkt: &mut Packet) {
    let src_port = if compression_mode & SOURCE_PORT_PRESENT != 0 {
        five_tuple.src_port
    } else {
        pkt.get_u16()
    };

    let dst_port = if compression_mode & DESTINATION_PORT_PRESENT != 0 {
        five_tuple.dst_port
    } else {
        pkt.get_u16()
    };

    // leave checksum in place

    let payload_len = pkt.body().len() - 2; // - 2 accounts for checksum

    pkt.push_u16((payload_len + std::mem::size_of::<classifier::UDPHeader>()) as u16);
    pkt.push_u16(dst_port);
    pkt.push_u16(src_port);
}

/// Compress a packet.  Does not inspect payload length, so trailers (e.g. A2A MAC) may be present.
pub fn compress(
    compression_mode: CompressionMode,
    l3_type: L3Type,
    l4_protocol: net_defs::IpProtocol,
    pkt: &mut Packet,
) {
    match l3_type {
        L3Type::Ipv4 => compress_ipv4(compression_mode, l4_protocol, pkt),
        L3Type::Ipv6 => compress_ipv6(compression_mode, l4_protocol, pkt),
        _ => (), // no compression defined for non-IP packets
    }
}

/// Expand a packet.  Fills payload length from body length, so trailers (e.g. A2A MAC) must not be present.
pub fn expand(compression_mode: CompressionMode, five_tuple: &FiveTuple, pkt: &mut Packet) {
    match five_tuple.l3_type {
        L3Type::Ipv4 => expand_ipv4(compression_mode, five_tuple, pkt),
        L3Type::Ipv6 => expand_ipv6(compression_mode, five_tuple, pkt),
        _ => (), // no compression defined for non-IP packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier;
    use crate::config;
    use crate::packet::Packet;
    use bytes::BufMut;

    #[test]
    fn test_round_trip() {
        for &(desc, body) in TEST_CASES {
            let buf = Box::new([0u8; config::PACKET_BUFFER_SIZE]);
            let mut pkt = Packet::new(buf, 256);
            pkt.put(body);

            let (metadata, pkt_body) = pkt.metadata_mut_and_body_mut();
            let cls_res = match classifier::classify(metadata.five_tuple_mut(), pkt_body) {
                Ok(cls_res) => cls_res,
                Err(err) => panic!("{desc}: classify() failed: {err:?}"),
            };
            assert!(
                cls_res == classifier::ClassifierResult::OK
                    || cls_res == classifier::ClassifierResult::UnclassifiedL4
            );
            let ft = *pkt.metadata().five_tuple();

            for compression_mode in [
                CompressionMode::default(),
                SOURCE_PORT_PRESENT,
                DESTINATION_PORT_PRESENT,
                SOURCE_PORT_PRESENT | DESTINATION_PORT_PRESENT,
            ] {
                compress(compression_mode, ft.l3_type, ft.l4_protocol, &mut pkt);
                expand(compression_mode, &ft, &mut pkt);
                assert_eq!(
                    pkt.body(),
                    body,
                    "{desc}; compression mode 0x{compression_mode:02x}",
                );
            }
        }
    }

    const TEST_CASES: &[(&str, &[u8])] = &[
        (
            "ICMP Echo (ping) request",
            &[
                0x45, 0x00, 0x00, 0x54, 0x46, 0xa2, 0x40, 0x00, 0x40, 0x01, 0x70, 0xb3, 0xc0, 0xa8,
                0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, 0x08, 0x00, 0x5d, 0x2e, 0xf6, 0xae, 0x00, 0x01,
                0x3c, 0xa0, 0xcc, 0x66, 0x00, 0x00, 0x00, 0x00, 0xda, 0x47, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            ],
        ),
        (
            "ICMPv6 Neighbor Soliciation",
            &[
                0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x0c, 0xbb, 0x7e, 0xa4, 0x55, 0xf1, 0x07, 0x9f, 0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xf1, 0x00, 0x01, 0x87, 0x00,
                0x1a, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0c, 0xbb, 0x7e, 0xa4, 0x55, 0xf1, 0x00, 0x01, 0x01, 0x01, 0xe4, 0x60, 0x17, 0xd8,
                0x9a, 0x4b,
            ],
        ),
        (
            "TCP mid-stream (TLS)",
            &[
                0x45, 0x00, 0x00, 0x4c, 0xc8, 0xa2, 0x40, 0x00, 0x2e, 0x06, 0xd7, 0x29, 0x17, 0x60,
                0x7c, 0x44, 0xc0, 0xa8, 0x58, 0x93, 0x01, 0xbb, 0xad, 0x18, 0xea, 0xfb, 0x7d, 0x53,
                0x23, 0xea, 0x6b, 0x90, 0x80, 0x18, 0x01, 0xf5, 0x5c, 0x7a, 0x00, 0x00, 0x01, 0x01,
                0x08, 0x0a, 0x49, 0xad, 0x26, 0x25, 0x74, 0xcf, 0x24, 0x4a, 0x17, 0x03, 0x03, 0x00,
                0x13, 0x3e, 0xf1, 0x3e, 0x45, 0xbc, 0x66, 0x69, 0xe7, 0xf1, 0x28, 0xb4, 0x60, 0x8a,
                0xaf, 0x1f, 0xef, 0x77, 0xe1, 0x56,
            ],
        ),
        (
            "UDP (NTP)",
            &[
                0x45, 0xb8, 0x00, 0x4c, 0x73, 0xb2, 0x40, 0x00, 0x35, 0x11, 0xe8, 0x2c, 0x47, 0xa2,
                0x88, 0x2c, 0xc0, 0xa8, 0x58, 0x93, 0x00, 0x7b, 0x00, 0x7b, 0x00, 0x38, 0x48, 0xcd,
                0x24, 0x03, 0x00, 0xe9, 0x00, 0x00, 0x02, 0xc1, 0x00, 0x00, 0x0c, 0xe8, 0xd0, 0x5a,
                0x90, 0x35, 0xed, 0x51, 0xb0, 0xa6, 0x40, 0x7f, 0x0b, 0xdf, 0x9d, 0x36, 0x66, 0xa5,
                0x07, 0x76, 0xe4, 0xb9, 0xed, 0x51, 0xb8, 0xac, 0x9f, 0x31, 0x21, 0x57, 0xed, 0x51,
                0xb8, 0xac, 0x9f, 0x3a, 0xb1, 0x67,
            ],
        ),
        (
            "TCPv6 mid-stream (SSH)",
            &[
                0x61, 0x06, 0x93, 0x47, 0x00, 0x54, 0x06, 0x40, 0xfd, 0x58, 0x97, 0x1a, 0xa5, 0xca,
                0x00, 0x00, 0xf6, 0x4d, 0x30, 0xff, 0xfe, 0x62, 0x06, 0x5e, 0xfd, 0x58, 0x97, 0x1a,
                0xa5, 0xca, 0x00, 0x00, 0xf6, 0x09, 0xbf, 0x26, 0x40, 0x3f, 0xa5, 0x6d, 0x00, 0x16,
                0x88, 0xf8, 0x9a, 0x8a, 0x13, 0x71, 0xa5, 0x52, 0x4d, 0x8b, 0x80, 0x18, 0x01, 0xf5,
                0xf8, 0x89, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x81, 0x81, 0x87, 0x22, 0xd4, 0xa6,
                0x96, 0xb2, 0xbf, 0x5a, 0x00, 0xd8, 0x79, 0xac, 0xdb, 0x79, 0xe8, 0xef, 0x8d, 0x6f,
                0x2c, 0x10, 0xe2, 0x9d, 0xa4, 0x4a, 0x55, 0x18, 0xc0, 0x59, 0x66, 0xfd, 0x0a, 0x49,
                0x02, 0xca, 0xce, 0x64, 0x26, 0x43, 0x74, 0x7a, 0x47, 0x76, 0xa2, 0x44, 0x0d, 0xf4,
                0x89, 0x78, 0xe1, 0x77, 0x75, 0xfa, 0x87, 0x27, 0x45, 0xe2, 0xcb, 0xbb,
            ],
        ),
        (
            "MDNSv6 query",
            &[
                0x60, 0x0f, 0x82, 0xc9, 0x00, 0x5d, 0x11, 0xff, 0xfd, 0x58, 0x97, 0x1a, 0xa5, 0xca,
                0x00, 0x00, 0xe6, 0x60, 0x17, 0xff, 0xfe, 0xd8, 0x9a, 0x4b, 0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x14, 0xe9,
                0x14, 0xe9, 0x00, 0x5d, 0xc0, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x04, 0x5f, 0x73, 0x6d, 0x62, 0x04, 0x5f, 0x74, 0x63, 0x70,
                0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x04, 0x5f, 0x69,
                0x70, 0x70, 0xc0, 0x11, 0x00, 0x0c, 0x00, 0x01, 0x05, 0x5f, 0x69, 0x70, 0x70, 0x73,
                0xc0, 0x11, 0x00, 0x0c, 0x00, 0x01, 0x08, 0x5f, 0x77, 0x65, 0x62, 0x64, 0x61, 0x76,
                0x73, 0xc0, 0x11, 0x00, 0x0c, 0x00, 0x01, 0x07, 0x5f, 0x77, 0x65, 0x62, 0x64, 0x61,
                0x76, 0xc0, 0x11, 0x00, 0x0c, 0x00, 0x01,
            ],
        ),
    ];
}
