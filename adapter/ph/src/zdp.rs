use open_enum::open_enum;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};


#[open_enum]
#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(u8)]
pub enum ZdpPacketType {
    CompressedAgentPacket = 0,
    UncompressedAgentPacket = 1
}

#[open_enum]
#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(u8)]
pub enum ZdpD2DAlgorithm {
    NOP = 0,
    Blake2b256 = 1
}

#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(C, packed)]
pub struct ZdpAbbreviatedHeader {
    packet_type: ZdpPacketType,
    sequence_number: u16,
    stream_id: u32
}

#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(C, packed)]
pub struct ZdpHeader {
    abbreviated_header: ZdpAbbreviatedHeader,
    d2d_algorithm: ZdpD2DAlgorithm,
    mac: [u8; 16]
}

const _: () = assert!(core::mem::size_of::<ZdpHeader>() == 24);
