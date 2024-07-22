//! ZDP Header Compression (RFC 6.5 § 5.26)

#![allow(dead_code)]

use crate::classifier;
use crate::net_defs;
use crate::packet::Packet;
use bytes::Buf;
use std::net::{Ipv4Addr, Ipv6Addr};
use zerocopy::FromBytes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes, Unaligned};

const COMPRESSED_IPV4_FLAG_HAS_FRAG_OFFSET: u8 = 1; // IPv4 "evil bit"

#[derive(AsBytes, FromZeroes, FromBytes, Unaligned)]
#[repr(packed)]
pub struct CompressedIPv4Header {
    pub hl_flags: u8,
    pub dscp: u8,
    pub frag_id: [u8; 2],
    pub ttl: u8,
}

#[derive(AsBytes, FromZeroes, FromBytes, Unaligned)]
#[repr(packed)]
pub struct CompressedIPv6Header {
    pub version_and_tc_upper: u8,
    pub tc_lower_and_fl_upper: u8,
    pub fl_lower: [u8; 2],
    pub hop_limit: u8,
}

pub fn compress_addrs(pkt: &mut Packet) {
    match classifier::get_ip_version(pkt.body()) {
        4 => compress_addrs_v4(pkt),
        6 => compress_addrs_v6(pkt),
        _ => (),
    }
}

pub fn compress_addrs_v4(pkt: &mut Packet) {
    let hdr = classifier::IPv4Header::ref_from_prefix(pkt.body()).unwrap();
    let hl = hdr.vhl & 0x0f;
    let mut flags = hdr.frag_offset[0] >> 5;
    let dscp = hdr.dscp;
    let frag_id = hdr.frag_id;
    let ttl = hdr.ttl;
    let frag_offset = [hdr.frag_offset[0] & 0x1f, hdr.frag_offset[1]];

    pkt.advance(std::mem::size_of::<classifier::IPv4Header>());

    // clear "evil bit" if set, as we're going to use it
    flags &= !COMPRESSED_IPV4_FLAG_HAS_FRAG_OFFSET;

    if frag_offset != [0u8, 0u8] {
        flags |= COMPRESSED_IPV4_FLAG_HAS_FRAG_OFFSET;
        *pkt.alloc_zeroed_header::<[u8; 2]>() = frag_offset;
    }

    let chdr = pkt.alloc_zeroed_header::<CompressedIPv4Header>();
    chdr.hl_flags = (hl << 4) | (flags << 1);
    chdr.dscp = dscp;
    chdr.frag_id = frag_id;
    chdr.ttl = ttl;
}

pub fn expand_addrs_v4(pkt: &mut Packet, proto: u8, src_address: Ipv4Addr, dst_address: Ipv4Addr) {
    let chdr = CompressedIPv4Header::ref_from_prefix(pkt.body()).unwrap();
    let hl = chdr.hl_flags >> 4;
    let mut flags = (chdr.hl_flags & 0x0f) >> 1;
    let dscp = chdr.dscp;
    let frag_id = chdr.frag_id;
    let ttl = chdr.ttl;
    let mut frag_offset = [0u8; 2];

    pkt.advance(std::mem::size_of::<CompressedIPv4Header>());

    if flags & COMPRESSED_IPV4_FLAG_HAS_FRAG_OFFSET != 0 {
        pkt.copy_to_slice(&mut frag_offset);
    }

    flags &= !COMPRESSED_IPV4_FLAG_HAS_FRAG_OFFSET;

    let body_len = pkt.body().len();

    let hdr = pkt.alloc_zeroed_header::<classifier::IPv4Header>();
    hdr.vhl = (4u8 << 4) | hl;
    hdr.dscp = dscp;
    hdr.total_length =
        ((body_len + std::mem::size_of::<classifier::IPv4Header>()) as u16).to_be_bytes();
    hdr.frag_id = frag_id;
    hdr.frag_offset = [(flags << 5) | frag_offset[0], frag_offset[1]];
    hdr.ttl = ttl;
    hdr.proto = proto;
    hdr.src_address = src_address.octets();
    hdr.dst_address = dst_address.octets();

    // TODO FIXME: header checksum
}

pub fn compress_addrs_v6(pkt: &mut Packet) {
    let hdr = classifier::IPv6Header::ref_from_prefix(pkt.body()).unwrap();
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

pub fn expand_addrs_v6(
    pkt: &mut Packet,
    next_header: u8,
    src_address: Ipv6Addr,
    dst_address: Ipv6Addr,
) {
    let chdr = CompressedIPv6Header::ref_from_prefix(pkt.body()).unwrap();
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
    hdr.payload_length = (body_len as u16).to_be_bytes(); // TODO FIXME: set to zero for Jumbo Payload
    hdr.next_header = next_header;
    hdr.hop_limit = hop_limit;
    hdr.src_address = net_defs::IpAddress {
        v6: src_address.octets(),
    };
    hdr.dst_address = net_defs::IpAddress {
        v6: dst_address.octets(),
    };
}
