use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const IPV4_ADDRESS_SIZE: usize = 4;
pub const IPV6_ADDRESS_SIZE: usize = 16;

/// "Flat" (non-enum) representation of an IPv4 or IPv6 address, used
/// internally to represent ZPR addresses.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Default,
    Hash,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct IpAddress {
    pub v6: [u8; IPV6_ADDRESS_SIZE],
}

// Implement our own Debug in order to prety print addresses in logs.
impl std::fmt::Debug for IpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_v4() {
            write!(f, "IpAddress(V4: {self})")
        } else {
            write!(f, "IpAddress(V6: {self})")
        }
    }
}

impl IpAddress {
    /// All-zeros address
    pub const UNSPECIFIED: Self = IpAddress {
        v6: [0; IPV6_ADDRESS_SIZE],
    };

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
}
