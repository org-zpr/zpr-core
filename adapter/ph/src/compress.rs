//! ZDP Header Compression (RFC 6.5 § 5.26)

use crate::classifier;
use crate::defs::FiveTuple;
use crate::packet::Packet;
use bytes::Buf;
use std::net::{Ipv4Addr, Ipv6Addr};
use zerocopy::*;
use zpr::packet_info::{CompressionMode, L3Type};
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

fn compress_addrs_v4(pkt: &mut Packet) {
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

fn expand_addrs_v4(pkt: &mut Packet, proto: u8, src_address: Ipv4Addr, dst_address: Ipv4Addr) {
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

    let body_len = pkt.body().len();

    let hdr = pkt.alloc_zeroed_header::<classifier::IPv4Header>();
    hdr.vhl = (4 << 4) | hl;
    hdr.dscp = tos;
    hdr.total_length = ((body_len + std::mem::size_of::<classifier::IPv4Header>()) as u16).into();
    hdr.frag_id = frag_id;
    hdr.frag_offset = frag_offset.into();
    hdr.ttl = ttl;
    hdr.proto = proto;
    hdr.src_address = src_address.octets();
    hdr.dst_address = dst_address.octets();

    let header_len = (hl as usize) << 2;
    let csum = net_defs::inet_checksum(&pkt.body()[..header_len]);
    classifier::IPv4Header::mut_from_prefix(pkt.body_mut())
        .unwrap()
        .0
        .header_checksum = csum;
}

fn compress_addrs_v6(pkt: &mut Packet) {
    let hdr = classifier::IPv6Header::ref_from_prefix(pkt.body())
        .unwrap()
        .0;
    let version_and_tc_upper = hdr.version_and_tc_upper;
    let tc_lower_and_fl_upper = hdr.tc_lower_and_fl_upper;
    let fl_lower = hdr.fl_lower;
    let hop_limit = hdr.hop_limit;

    pkt.advance(std::mem::size_of::<classifier::IPv6Header>());

    let chdr = pkt.alloc_zeroed_header::<CompressedIPv6Header>();
    chdr.version_and_tc_upper = version_and_tc_upper;
    chdr.tc_lower_and_fl_upper = tc_lower_and_fl_upper;
    chdr.fl_lower = fl_lower;
    chdr.hop_limit = hop_limit;
}

fn expand_addrs_v6(
    pkt: &mut Packet,
    next_header: u8,
    src_address: Ipv6Addr,
    dst_address: Ipv6Addr,
) {
    let chdr = CompressedIPv6Header::ref_from_prefix(pkt.body()).unwrap().0;
    let version_and_tc_upper = chdr.version_and_tc_upper;
    let tc_lower_and_fl_upper = chdr.tc_lower_and_fl_upper;
    let fl_lower = chdr.fl_lower;
    let hop_limit = chdr.hop_limit;

    pkt.advance(std::mem::size_of::<CompressedIPv6Header>());

    let body_len = pkt.body().len();

    let hdr = pkt.alloc_zeroed_header::<classifier::IPv6Header>();
    hdr.version_and_tc_upper = version_and_tc_upper;
    hdr.tc_lower_and_fl_upper = tc_lower_and_fl_upper;
    hdr.fl_lower = fl_lower;
    hdr.payload_length = (body_len as u16).into(); // NOTE: we do not allow jumbo payloads
    hdr.next_header = next_header;
    hdr.hop_limit = hop_limit;
    hdr.src_address = net_defs::IpAddress {
        v6: src_address.octets(),
    };
    hdr.dst_address = net_defs::IpAddress {
        v6: dst_address.octets(),
    };
}

/// Compress a packet.  Does not inspect payload length, so trailers (e.g. A2A MAC) may be present.
pub fn compress(
    compression_mode: CompressionMode,
    l3_type: L3Type,
    _l4_protocol: net_defs::IpProtocol,
    pkt: &mut Packet,
) {
    match l3_type {
        L3Type::Ipv4 => compress_addrs_v4(pkt),
        L3Type::Ipv6 => compress_addrs_v6(pkt),
        other => panic!("bad L3 type: {}", other.0),
    }

    if compression_mode != 0 {
        todo!("L4 compression");
    }
}

/// Expand a packet.  Fills payload length from body length, so trailers (e.g. A2A MAC) must not be present.
pub fn expand(compression_mode: CompressionMode, five_tuple: &FiveTuple, pkt: &mut Packet) {
    match five_tuple.l3_type {
        L3Type::Ipv4 => expand_addrs_v4(
            pkt,
            five_tuple.l4_protocol,
            five_tuple.src_address.read_as_v4().into(),
            five_tuple.dst_address.read_as_v4().into(),
        ),
        L3Type::Ipv6 => expand_addrs_v6(
            pkt,
            five_tuple.l4_protocol,
            five_tuple.src_address.into(),
            five_tuple.dst_address.into(),
        ),
        other => panic!("bad L3 type: {}", other.0),
    }

    if compression_mode != 0 {
        todo!("L4 compression");
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
        for &body in TEST_CASES {
            let buf = Box::new([0u8; config::PACKET_BUFFER_SIZE]);
            let mut pkt = Packet::new(buf, 256);
            pkt.put(body);

            let (metadata, pkt_body) = pkt.metadata_mut_and_body_mut();
            let cls_res = classifier::classify(metadata.five_tuple_mut(), pkt_body).unwrap();
            assert!(
                cls_res == classifier::ClassifierResult::OK
                    || cls_res == classifier::ClassifierResult::UnclassifiedL4
            );
            let ft = *pkt.metadata().five_tuple();

            let compression_mode: CompressionMode = 0; // TODO: iterate through compression modes
            compress(compression_mode, ft.l3_type, ft.l4_protocol, &mut pkt);
            expand(compression_mode, &ft, &mut pkt);

            assert_eq!(pkt.body(), body);
        }
    }

    const TEST_CASES: &[&[u8]] = &[
        // ICMP Echo (ping) request
        &[
            0x45, 0x00, 0x00, 0x54, 0x46, 0xa2, 0x40, 0x00, 0x40, 0x01, 0x70, 0xb3, 0xc0, 0xa8,
            0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, 0x08, 0x00, 0x5d, 0x2e, 0xf6, 0xae, 0x00, 0x01,
            0x3c, 0xa0, 0xcc, 0x66, 0x00, 0x00, 0x00, 0x00, 0xda, 0x47, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ],
        // ICMPv6 Neighbor Soliciation
        &[
            0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0c, 0xbb, 0x7e, 0xa4, 0x55, 0xf1, 0x07, 0x9f, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xf1, 0x00, 0x01, 0x87, 0x00,
            0x1a, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0c, 0xbb, 0x7e, 0xa4, 0x55, 0xf1, 0x00, 0x01, 0x01, 0x01, 0xe4, 0x60, 0x17, 0xd8,
            0x9a, 0x4b,
        ],
    ];
}
