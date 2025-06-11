//! Standard network constants.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub mod ethertype {
    //! Ethertype / IEEE 802 numbers

    pub const IP: u16 = 0x0800;
    pub const IPV6: u16 = 0x86dd;
}

pub const IPV6_ADDRESS_SIZE: usize = 16;

pub const IPADDRESS_ZERO: IpAddress = IpAddress {
    v6: [0; IPV6_ADDRESS_SIZE],
};

/// "Flat" (non-enum) representation of an IPv4 or IPv6 address, used
/// internally to represent ZPR addresses.
#[derive(
    FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Hash, Debug, PartialEq, Eq,
)]
#[repr(transparent)]
pub struct IpAddress {
    pub v6: [u8; IPV6_ADDRESS_SIZE],
}

impl IpAddress {
    pub const fn new_from_v4(v4_address: [u8; 4]) -> Self {
        // Uses standard v4 to v6 conversion
        Self {
            v6: [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0xff,
                0xff,
                v4_address[0],
                v4_address[1],
                v4_address[2],
                v4_address[3],
            ],
        }
    }

    pub const fn read_as_v4(&self) -> [u8; 4] {
        [self.v6[12], self.v6[13], self.v6[14], self.v6[15]]
    }

    pub const fn is_v4(&self) -> bool {
        self.v6[0] == 0
            && self.v6[1] == 0
            && self.v6[2] == 0
            && self.v6[3] == 0
            && self.v6[4] == 0
            && self.v6[5] == 0
            && self.v6[6] == 0
            && self.v6[7] == 0
            && self.v6[8] == 0
            && self.v6[9] == 0
            && self.v6[10] == 0xff
            && self.v6[11] == 0xff
    }

    pub const fn new_from_std_v4(addr: &Ipv4Addr) -> Self {
        Self::new_from_v4(addr.octets())
    }

    pub const fn new_from_std_v6(addr: &Ipv6Addr) -> Self {
        Self { v6: addr.octets() }
    }

    pub const fn new_from_std(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => Self::new_from_std_v4(v4),
            IpAddr::V6(v6) => Self::new_from_std_v6(v6),
        }
    }

    pub const fn is_v6_unicast_link_local(&self) -> bool {
        self.v6[0] == 0xfe && self.v6[1] & 0xC0 == 0x80
    }
}

impl From<Ipv4Addr> for IpAddress {
    fn from(addr: Ipv4Addr) -> Self {
        Self::new_from_std_v4(&addr)
    }
}

impl From<[u8; 4]> for IpAddress {
    fn from(addr: [u8; 4]) -> Self {
        Self::new_from_v4(addr)
    }
}

impl From<Ipv6Addr> for IpAddress {
    fn from(addr: Ipv6Addr) -> Self {
        Self::new_from_std_v6(&addr)
    }
}

impl From<[u8; 16]> for IpAddress {
    fn from(addr: [u8; 16]) -> Self {
        Self { v6: addr }
    }
}

impl From<IpAddr> for IpAddress {
    fn from(addr: IpAddr) -> Self {
        Self::new_from_std(&addr)
    }
}

impl TryFrom<Vec<u8>> for IpAddress {
    type Error = Vec<u8>;

    fn try_from(octets: Vec<u8>) -> Result<Self, Self::Error> {
        match octets.len() {
            4 => Ok(IpAddress::from(
                <[u8; 4]>::try_from(octets.as_slice()).expect("Bad IP length"),
            )),
            16 => Ok(IpAddress::from(
                <[u8; 16]>::try_from(octets.as_slice()).expect("Bad IP length"),
            )),
            _ => Err(octets),
        }
    }
}

impl TryFrom<IpAddress> for Ipv4Addr {
    type Error = ();

    fn try_from(addr: IpAddress) -> Result<Self, Self::Error> {
        if addr.is_v4() {
            Ok(addr.read_as_v4().into())
        } else {
            Err(())
        }
    }
}

impl From<IpAddress> for Ipv6Addr {
    fn from(addr: IpAddress) -> Self {
        addr.v6.into()
    }
}

impl From<IpAddress> for IpAddr {
    fn from(addr: IpAddress) -> Self {
        if addr.is_v4() {
            IpAddr::V4(addr.read_as_v4().into())
        } else {
            IpAddr::V6(addr.v6.into())
        }
    }
}

impl From<&IpAddress> for IpAddr {
    fn from(addr: &IpAddress) -> Self {
        IpAddr::from(*addr)
    }
}

impl std::fmt::Display for IpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        Ipv6Addr::from(*self).fmt(f)
    }
}

/// Like `std::net::IpAddr`, but includes IPv6 scope ID field, needed to
/// distinguish link-local addresses from one another.  Used to represent
/// the portion of a substrate address (i.e. `std::net::SocketAddr`) needed
/// for routing.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScopedIpAddr {
    V4(Ipv4Addr),
    V6(ScopedIpv6Addr),
}

impl ScopedIpAddr {
    #[allow(dead_code)]
    pub fn ip(&self) -> IpAddr {
        match self {
            ScopedIpAddr::V4(v4) => IpAddr::V4(*v4),
            ScopedIpAddr::V6(v6) => IpAddr::V6(v6.ip),
        }
    }
}

impl std::fmt::Display for ScopedIpAddr {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopedIpAddr::V4(v4) => v4.fmt(fmt),
            ScopedIpAddr::V6(v6) => v6.fmt(fmt),
        }
    }
}

impl From<IpAddr> for ScopedIpAddr {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => ScopedIpAddr::V4(v4),
            IpAddr::V6(v6) => ScopedIpAddr::V6(v6.into()),
        }
    }
}

impl From<Ipv4Addr> for ScopedIpAddr {
    fn from(addr: Ipv4Addr) -> Self {
        ScopedIpAddr::V4(addr)
    }
}

impl From<ScopedIpv6Addr> for ScopedIpAddr {
    fn from(addr: ScopedIpv6Addr) -> Self {
        ScopedIpAddr::V6(addr)
    }
}

impl From<Ipv6Addr> for ScopedIpAddr {
    fn from(addr: Ipv6Addr) -> Self {
        ScopedIpAddr::V6(addr.into())
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScopedIpv6Addr {
    ip: Ipv6Addr,
    scope_id: u32,
}

impl ScopedIpv6Addr {
    pub fn new(ip: Ipv6Addr, scope_id: u32) -> Self {
        Self { ip, scope_id }
    }

    pub fn ip(&self) -> &Ipv6Addr {
        &self.ip
    }

    pub fn scope_id(&self) -> u32 {
        self.scope_id
    }

    #[allow(dead_code)]
    pub fn set_ip(&mut self, new_ip: Ipv6Addr) {
        self.ip = new_ip
    }

    #[allow(dead_code)]
    pub fn set_scope_id(&mut self, new_scope_id: u32) {
        self.scope_id = new_scope_id
    }
}

impl std::fmt::Display for ScopedIpv6Addr {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.ip.fmt(fmt)?;
        if self.scope_id != 0 {
            write!(fmt, "%{}", self.scope_id)?;
        }
        Ok(())
    }
}

impl From<Ipv6Addr> for ScopedIpv6Addr {
    fn from(ip: Ipv6Addr) -> Self {
        Self { ip, scope_id: 0 }
    }
}

pub trait SocketAddrExt {
    fn scoped_ip(&self) -> ScopedIpAddr;
}

impl SocketAddrExt for std::net::SocketAddr {
    fn scoped_ip(&self) -> ScopedIpAddr {
        match self {
            std::net::SocketAddr::V4(v4) => ScopedIpAddr::V4(*v4.ip()),
            std::net::SocketAddr::V6(v6) => {
                ScopedIpAddr::V6(ScopedIpv6Addr::new(*v6.ip(), v6.scope_id()))
            }
        }
    }
}

pub type IpVersion = u8;

pub fn ip_version(pkt: &[u8]) -> IpVersion {
    pkt[0] >> 4
}

pub fn ip_ethertype(ip_version: IpVersion) -> u16 {
    match ip_version {
        4 => ethertype::IP,
        6 => ethertype::IPV6,
        _ => 0,
    }
}

pub type IpProtocol = u8;

pub mod ip_number {
    use super::IpProtocol;

    pub const HOPOPT: IpProtocol = 0;
    pub const ICMP: IpProtocol = 1;
    pub const IPINIP: IpProtocol = 4;
    pub const TCP: IpProtocol = 6;
    pub const UDP: IpProtocol = 17;
    pub const IPV6_ROUTE: IpProtocol = 43;
    pub const IPV6_FRAG: IpProtocol = 44;
    pub const AH: IpProtocol = 51;
    pub const IPV6_ICMP: IpProtocol = 58;
    pub const IPV6_OPTS: IpProtocol = 60;
}

/// RFC 1071 Internet Checksum.  The input data must be non-empty, and
/// length at most ~128 KiB.
pub fn inet_checksum(data: &[u8]) -> [u8; 2] {
    // NOTE: This benchmarks about twice as fast as the `internet-checksum` crate,
    // and is many fewer lines of code.

    fn inet_checksum_helper(extra_sum: u16, data16: &[u16]) -> u16 {
        let mut sum = extra_sum as u32;

        for &x in data16 {
            sum += x as u32;
        }

        // reduce to form ones-complement sum
        sum = (sum & 0xffff) + (sum >> 16);
        sum += sum >> 16;

        // Internet checksum is bitwise negated
        !sum as u16
    }

    if data.is_empty() {
        return [0xffu8; 2];
    }

    // Longer than this, our 32-bit temporary sum would overflow.
    debug_assert!(data.len() <= ((u32::MAX / (u16::MAX as u32)) * 2) as usize);

    // Split into the aligned and unaligned case.  We could sum 32 bits at a
    // time instead, but we're mostly summing short spans, so having only
    // one unaligned case shortens the branch logic here.
    if (&data[0] as *const u8 as *const u16).is_aligned() ^ (data.len() % 2 == 1) {
        let first_byte = if data.len() % 2 == 0 { 0 } else { data[0] };
        let extra_sum = u16::from_ne_bytes([0, first_byte]);

        // SAFETY: we have verified alignment and length
        let data16 = unsafe {
            std::slice::from_raw_parts(
                &data[data.len() % 2] as *const u8 as *const u16,
                data.len() / 2,
            )
        };

        inet_checksum_helper(extra_sum, data16).to_ne_bytes()
    } else {
        let first_byte = if data.len() % 2 == 0 { data[0] } else { 0 };
        let extra_sum = u16::from_ne_bytes([data[data.len() - 1], first_byte]);

        // SAFETY: we are compensating for alignment
        let data16 = unsafe {
            std::slice::from_raw_parts(
                &data[1 - data.len() % 2] as *const u8 as *const u16,
                (data.len() - 1) / 2,
            )
        };
        // NOTE: purposefully to_le_bytes(), to compensate for misalignment
        inet_checksum_helper(extra_sum, data16)
            .swap_bytes()
            .to_ne_bytes()
    }
}

pub fn validate_inet_checksum(data: &[u8]) -> bool {
    inet_checksum(data) == [0u8; 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vec_to_ip_address_v4() {
        let v4_octets = [0x01, 0x02, 0x03, 0x04];
        let vec_octets = Vec::from(v4_octets);
        assert_eq!(
            IpAddress::from(v4_octets),
            IpAddress::try_from(vec_octets)
                .expect("IpAddress::try_from(Vec<u8>) did not work as expected")
        );
    }

    #[test]
    fn test_vec_to_ip_address_v6() {
        let v6_octets = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let vec_octets = Vec::from(v6_octets);
        assert_eq!(
            IpAddress::from(v6_octets),
            IpAddress::try_from(vec_octets)
                .expect("IpAddress::try_from(Vec<u8>) did not work as expected")
        );
    }

    #[test]
    fn test_vec_to_ip_address_invalid() {
        let invalid_octets = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let vec_octets = Vec::from(invalid_octets);
        assert_eq!(true, IpAddress::try_from(vec_octets).is_err());
    }

    #[test]
    fn test_checksum_empty() {
        assert_eq!(inet_checksum(&[]), [0xffu8; 2]);
    }

    #[test]
    fn test_checksum() {
        for buf in TEST_DATA {
            let mut v = Vec::new();
            v.extend_from_slice(buf);
            assert_eq!(inet_checksum(v.as_slice()), [0u8; 2]);
        }
    }

    #[test]
    fn test_checksum_order() {
        for buf in TEST_DATA {
            let mut v = Vec::new();
            v.extend_from_slice(&buf[..buf.len() - 2]);
            assert_eq!(inet_checksum(v.as_slice()), buf[buf.len() - 2..]);
        }
    }

    #[test]
    fn test_checksum_unaligned() {
        for buf in TEST_DATA {
            let mut v = Vec::new();
            v.push(0);
            v.extend_from_slice(buf);
            assert_eq!(inet_checksum(&v[1..]), [0u8; 2]);
        }
    }

    #[test]
    fn test_checksum_order_unaligned() {
        for buf in TEST_DATA {
            let mut v = Vec::new();
            v.push(0);
            v.extend_from_slice(&buf[..buf.len() - 2]);
            assert_eq!(inet_checksum(v.as_slice()), buf[buf.len() - 2..]);
        }
    }

    #[test]
    fn test_checksum_max_len() {
        assert_eq!(inet_checksum(&[0xffu8; (1 << 17) + 2]), [0u8; 2]);
    }

    #[test]
    #[should_panic]
    fn test_checksum_over_max_len() {
        let _ = inet_checksum(&[0xffu8; (1 << 17) + 3]);
    }

    // NOTE: because of how these sequences are stored in the object file,
    // they are arbitrarily aligned.  In order to ensure a specific
    // alignment, copy them into a Vec before using.  Memory allocated to a
    // Vec is all-but-guaranteed to be aligned at least to the system word size.
    const TEST_DATA: &[&[u8]] = &[
        // IP headers from the wild
        &[
            0x45, 0x00, 0x00, 0x5b, 0xd7, 0xbe, 0x40, 0x00, 0x40, 0x06, 0x6a, 0x45, 0xc0, 0xa8,
            0x58, 0x93, 0x8e, 0xfa, 0x50, 0x63,
        ],
        &[
            0x45, 0x00, 0x04, 0x02, 0x03, 0xe5, 0x00, 0x00, 0x78, 0x06, 0x6a, 0x4c, 0x8e, 0xfb,
            0x28, 0x8e, 0xc0, 0xa8, 0x58, 0x93,
        ],
        &[
            0x45, 0x00, 0x01, 0x88, 0x03, 0xe6, 0x00, 0x00, 0x78, 0x06, 0x6c, 0xc5, 0x8e, 0xfb,
            0x28, 0x8e, 0xc0, 0xa8, 0x58, 0x93,
        ],
        // odd length
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0xf9, 0xf6],
    ];
}
