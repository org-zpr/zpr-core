//! Common definitions that have no more specific place to live.

use crate::net_defs;

/// Packet direction with respect to an interface.
/// Primary use is for constructing libpcap link-layer header.
#[derive(Copy, Clone)]
pub enum Direction {
    // Do not change the values!  They are used directly to form the link-layer header.
    Inbound = 0,
    Outbound = 1,
}

/// IP 5-tuple used for hashing.
#[derive(PartialEq, Eq, Hash)]
pub struct FiveTuple {
    src_ip: net_defs::IpAddress,
    dst_ip: net_defs::IpAddress,
    proto: net_defs::IpProtocol,
    src_port: u16,
    dst_port: u16,
}
