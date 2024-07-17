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
