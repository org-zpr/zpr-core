//! Standard network constants.

use zerocopy::FromZeroes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes, KnownLayout, Unaligned};

pub mod ethertype {
    //! Ethertype / IEEE 802 numbers

    pub const IP: u16 = 0x0800;
    pub const IPV6: u16 = 0x86dd;
}

pub const IPV6_ADDRESS_SIZE: usize = 16;

#[derive(
    AsBytes, FromZeroes, FromBytes, KnownLayout, Unaligned, Copy, Clone, Hash, Debug, PartialEq,
)]
#[repr(transparent)]
pub struct IpAddress {
    pub v6: [u8; IPV6_ADDRESS_SIZE],
}

#[allow(dead_code)]
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

/// RFC 1071 Internet Checksum.  The input data must be non-empty, length at
/// most 64 KiB, and length a multiple of 4.
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

    // We can easily make this strong assumption, as this
    // checksum is only used over IP headers, which are guaranteed
    // to be multiples of 4 bytes.
    debug_assert_eq!(data.len() % 4, 0);

    // Longer than this, our 32-bit temporary sum would overflow.
    debug_assert!(data.len() <= 65536);

    // No need to support empty case.
    debug_assert!(data.len() > 0);

    // Split into the aligned and unaligned case.  We could sum 32 bits at a
    // time instead, but we're mostly summing short spans, so having only
    // one unaligned case shortens the branch logic here.
    if (&data[0] as *const u8 as *const u16).is_aligned() {
        // SAFETY: we have verified alignment and length
        let data16 = unsafe {
            std::slice::from_raw_parts(&data[0] as *const u8 as *const u16, data.len() / 2)
        };
        inet_checksum_helper(0, data16).to_be_bytes()
    } else {
        let extra_sum = u16::from_ne_bytes([data[data.len() - 1], data[0]]);
        // SAFETY: we are compensating for alignment
        let data16 = unsafe {
            std::slice::from_raw_parts(&data[1] as *const u8 as *const u16, data.len() / 2 - 1)
        };
        // NOTE: purposefully to_le_bytes(), to compensate for misalignment
        inet_checksum_helper(extra_sum, data16).to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        for buf in TEST_DATA {
            let mut v = Vec::new();
            v.extend_from_slice(buf);
            assert_eq!(inet_checksum(v.as_slice()), [0u8; 2]);
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

    // NOTE: because of how these sequences are stored in the object file,
    // they are arbitrarily aligned.  In order to ensure a specific
    // alignment, copy them into a Vec before using.  Memory allocated to a
    // Vec is all-but-guaranteed to be aligned at least to the system word size.
    const TEST_DATA: &[&[u8]] = &[
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
    ];
}
