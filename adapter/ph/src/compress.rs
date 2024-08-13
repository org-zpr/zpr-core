//! ZDP Header Compression (RFC 6.5 § 5.26)

#![allow(dead_code)]

use crate::classifier;
use crate::net_defs;
use crate::packet::Packet;
use bytes::Buf;
use std::net::{Ipv4Addr, Ipv6Addr};
use zerocopy::FromBytes;
use zerocopy::{AsBytes, FromZeroes, Unaligned};

#[derive(AsBytes, FromZeroes, FromBytes, Unaligned)]
#[repr(packed)]
pub struct CompressedIPv4Header {
    pub vhl: u8,
    pub dscp: u8,
    pub frag_id: [u8; 2],
    pub frag_offset: [u8; 2],
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
    let vhl = hdr.vhl;
    let dscp = hdr.dscp;
    let frag_id = hdr.frag_id;
    let frag_offset = hdr.frag_offset;
    let ttl = hdr.ttl;

    pkt.advance(std::mem::size_of::<classifier::IPv4Header>());

    let chdr = pkt.alloc_zeroed_header::<CompressedIPv4Header>();
    chdr.vhl = vhl;
    chdr.dscp = dscp;
    chdr.frag_id = frag_id;
    chdr.frag_offset = frag_offset;
    chdr.ttl = ttl;
}

pub fn expand_addrs_v4(pkt: &mut Packet, proto: u8, src_address: Ipv4Addr, dst_address: Ipv4Addr) {
    let chdr = CompressedIPv4Header::ref_from_prefix(pkt.body()).unwrap();
    let vhl = chdr.vhl;
    let dscp = chdr.dscp;
    let frag_id = chdr.frag_id;
    let frag_offset = chdr.frag_offset;
    let ttl = chdr.ttl;

    pkt.advance(std::mem::size_of::<CompressedIPv4Header>());

    let body_len = pkt.body().len();

    let hdr = pkt.alloc_zeroed_header::<classifier::IPv4Header>();
    hdr.vhl = vhl;
    hdr.dscp = dscp;
    hdr.total_length =
        ((body_len + std::mem::size_of::<classifier::IPv4Header>()) as u16).to_be_bytes();
    hdr.frag_id = frag_id;
    hdr.frag_offset = frag_offset;
    hdr.ttl = ttl;
    hdr.proto = proto;
    hdr.src_address = src_address.octets();
    hdr.dst_address = dst_address.octets();

    let header_len = ((vhl & 0x0f) as usize) << 2;
    let csum = net_defs::inet_checksum(&pkt.body()[..header_len]);
    classifier::IPv4Header::mut_from_prefix(pkt.body_mut())
        .unwrap()
        .header_checksum = csum;
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
    hdr.payload_length = (body_len as u16).to_be_bytes(); // NOTE: we do not allow jumbo payloads
    hdr.next_header = next_header;
    hdr.hop_limit = hop_limit;
    hdr.src_address = net_defs::IpAddress {
        v6: src_address.octets(),
    };
    hdr.dst_address = net_defs::IpAddress {
        v6: dst_address.octets(),
    };
}
