use std::net::{IpAddr, Ipv6Addr};

/// Default prefix length for local tun IPv6 ZPR addresses.
pub const ZPRNET_PREFIX_LEN: u8 = 32;

// Well-known addresses.

pub const ZPR_INTERNAL_NETWORK: Ipv6Addr = Ipv6Addr::new(0xfd5a, 0x5052, 0, 0, 0, 0, 0, 0);
pub const ZPR_TEMP_LOCAL_ADDRESS: Ipv6Addr = Ipv6Addr::new(0xfc00, 0x5a, 0x50, 0x52, 0, 0, 0, 1);

pub const DEFAULT_TETHER_PORT: u16 = 5000;
pub const DEFAULT_LINK_PORT: u16 = 5001;

pub const VISA_SERVICE_ADDR: IpAddr =
    IpAddr::V6(Ipv6Addr::from_bits(ZPR_INTERNAL_NETWORK.to_bits() | 1));
pub const VISA_SERVICE_PROTO: u8 = 6 /* TCP */;
pub const VISA_SERVICE_PORT: u16 = 5002;
