//! Common definitions that have no more specific place to live.

use crate::net_defs;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

/// Packet direction with respect to an interface.
/// Primary use is for constructing libpcap link-layer header.
#[derive(Copy, Clone)]
pub enum Direction {
    // Do not change the values!  They are used directly to form the link-layer header.
    Inbound = 0,
    Outbound = 1,
}

/// IP 5-tuple used for hashing.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct FiveTuple {
    pub src_address: net_defs::IpAddress,
    pub dst_address: net_defs::IpAddress,
    pub protocol: net_defs::IpProtocol,
    pub padding: [u8; 1],
    pub src_port: u16,
    pub dst_port: u16,
}

impl FiveTuple {
    pub fn new(
        src_address: net_defs::IpAddress,
        dst_address: net_defs::IpAddress,
        protocol: net_defs::IpProtocol,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            src_address,
            dst_address,
            protocol,
            padding: [0],
            src_port,
            dst_port,
        }
    }

    pub fn reverse(&self) -> FiveTuple {
        Self {
            src_address: self.dst_address,
            dst_address: self.src_address,
            protocol: self.protocol,
            padding: [0],
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

impl std::fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "({}, {}, {}, {}, {})",
            self.src_address, self.dst_address, self.protocol, self.src_port, self.dst_port
        )
    }
}
