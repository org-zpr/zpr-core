//! Standard network constants.

use arrayref::array_ref;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zerocopy::FromZeroes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes, KnownLayout, Unaligned};

pub mod ethertype {
    //! Ethertype / IEEE 802 numbers

    pub const IP: u16 = 0x0800;
    pub const IPV6: u16 = 0x86dd;
}

pub const IPV6_ADDRESS_SIZE: usize = 16;

#[derive(
    AsBytes, FromZeroes, FromBytes, KnownLayout, Unaligned, Copy, Clone, Hash, Debug, PartialEq, Eq,
)]
#[repr(transparent)]
pub struct IpAddress {
    pub v6: [u8; IPV6_ADDRESS_SIZE],
}

impl IpAddress {
    pub fn new_from_v4(v4_address: [u8; 4]) -> Self {
        // Uses standard v4 to v6 conversion
        let mut addr = Self::new_zeroed();
        addr.v6[12..16].copy_from_slice(&v4_address);
        addr.v6[10] = 0xff;
        addr.v6[11] = 0xff;
        addr
    }

    pub fn read_as_v4(&self) -> [u8; 4] {
        *array_ref!(self.v6, 12, 4)
    }
}

impl From<Ipv4Addr> for IpAddress {
    fn from(addr: Ipv4Addr) -> Self {
        Self::new_from_v4(addr.octets())
    }
}

impl From<Ipv6Addr> for IpAddress {
    fn from(addr: Ipv6Addr) -> Self {
        Self { v6: addr.octets() }
    }
}

impl From<IpAddr> for IpAddress {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => v4.into(),
            IpAddr::V6(v6) => v6.into(),
        }
    }
}

impl From<IpAddress> for Ipv6Addr {
    fn from(addr: IpAddress) -> Self {
        addr.v6.into()
    }
}

impl std::fmt::Display for IpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        Ipv6Addr::from(*self).fmt(f)
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
