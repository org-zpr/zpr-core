use std::mem::size_of;
use zerocopy::{AsBytes, FromBytes};
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};
use crate::config;

// This contains all state of a packet which is moving through the system.
// TODO: possible we want to keep this stuff on the heap

pub struct Packet<'buf> {
    pub buf: &'buf mut [u8; config::PACKET_BUFFER_SIZE]
}

pub fn packet_body_buffer(buf: &mut [u8; config::PACKET_BUFFER_SIZE]) -> &mut [u8] {
    &mut buf[size_of::<PacketMetadata>()..]
}

#[derive(AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct PacketMetadata {
    pub len: usize
}

impl<'buf> Packet<'buf> {

    // packet metadata
    pub fn metadata(&self) -> &PacketMetadata {
        let opt = PacketMetadata::ref_from(&self.buf[..size_of::<PacketMetadata>()]);
        unsafe {
            // SAFETY: we know this fits in PACKET_BUFFER_SIZE
            opt.unwrap_unchecked()
        }
    }

    pub fn metadata_mut(&mut self) -> &mut PacketMetadata {
        let opt = PacketMetadata::mut_from(&mut self.buf[..size_of::<PacketMetadata>()]);
        unsafe {
            // SAFETY: we know this fits in PACKET_BUFFER_SIZE
            opt.unwrap_unchecked()
        }
    }

    pub fn body(&self) -> &[u8] {
        &self.buf[size_of::<PacketMetadata>()..size_of::<PacketMetadata>()+self.metadata().len]
    }

    // flowhash is different for different flows, but not necessarily vice-versa.
    // Ideally this is a high-entropy value useful for load balancing.
    // Must be cheap to query.
    pub fn flowhash(&self) -> u32 { 0 /* TODO */ }
}
