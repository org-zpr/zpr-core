//! Common definitions that have no more specific place to live.

use crate::net_defs;
use zerocopy::*;
use zpr;

/// Packet direction with respect to an interface.
/// Primary use is for constructing libpcap link-layer header.
#[derive(Copy, Clone)]
pub enum Direction {
    // Do not change the values!  They are used directly to form the link-layer header.
    Inbound = 0,
    Outbound = 1,
}

/// IP 5-tuple used for hashing.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FiveTuple {
    pub src_address: net_defs::IpAddress,
    pub dst_address: net_defs::IpAddress,
    pub l3_type: zpr::L3Type,
    pub l4_protocol: net_defs::IpProtocol,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FiveTuple {
    pub fn new(
        l3_type: zpr::L3Type,
        src_address: net_defs::IpAddress,
        dst_address: net_defs::IpAddress,
        l4_protocol: net_defs::IpProtocol,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            src_address,
            dst_address,
            l3_type,
            l4_protocol,
            src_port,
            dst_port,
        }
    }

    #[allow(dead_code)]
    pub fn reverse(&self) -> FiveTuple {
        Self {
            src_address: self.dst_address,
            dst_address: self.src_address,
            l3_type: self.l3_type,
            l4_protocol: self.l4_protocol,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

impl std::fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "({}, {}, {}, {}, {}, {})",
            self.l3_type,
            self.src_address,
            self.dst_address,
            self.l4_protocol,
            self.src_port,
            self.dst_port
        )
    }
}
