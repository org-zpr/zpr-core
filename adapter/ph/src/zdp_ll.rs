//! ZDP libpcap link-layer

use crate::defs::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpLinkP2P {
    pub direction: u8,
}

pub fn encode_direction(dir: Direction) -> u8 {
    (dir as usize) as u8
}
