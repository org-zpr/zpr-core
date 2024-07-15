#![allow(dead_code)]

use open_enum::open_enum;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes, Unaligned};

#[open_enum]
#[derive(Copy, Clone, FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(u8)]
pub enum ZdpPacketType {
    CompressedAgentPacket = 0,
    UncompressedAgentPacket = 1,
}

#[open_enum]
#[derive(Copy, Clone, FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(u8)]
pub enum ZdpD2DAlgorithm {
    NOP = 0,
    Blake2b256 = 1,
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
pub struct ZdpAbbreviatedHeader {
    pub packet_type: ZdpPacketType,
    pub sequence_number: u16,
    pub stream_id: u32,
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
pub struct ZdpHeader {
    pub abbreviated_header: ZdpAbbreviatedHeader,
    pub d2d_algorithm: ZdpD2DAlgorithm,
    pub mac: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<ZdpHeader>() == 24);
