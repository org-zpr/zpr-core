use std::mem::{size_of, size_of_val};
use bytes::buf;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};
use crate::config;

// This contains all state of a packet which is moving through the system.
// TODO: possible we want to keep this stuff on the heap

pub struct Packet<'buf> {
    buf: &'buf mut [u8; config::PACKET_BUFFER_SIZE]
}

#[derive(AsBytes, FromZeroes, FromBytes)]
#[repr(packed)]
pub struct PacketMetadata {
    offset: usize,  // packet offset (must be >= PACKET_BODY_BUFFER_MIN_OFFSET)
    len: usize,  // packet length
    pub flow_id: u32  // flow ID for load-balancing purposes; not otherwise meaningful
}

pub const PACKET_BUFFER_MIN_BODY_OFFSET: usize = size_of::<PacketMetadata>();

#[allow(dead_code)]
pub const PACKET_BODY_BUFFER_MAX_SIZE: usize = config::PACKET_BUFFER_SIZE - PACKET_BUFFER_MIN_BODY_OFFSET;


#[allow(dead_code)]
impl<'buf> Packet<'buf> {
    // Initialize a buffer as a packet buffer.
    // `headroom` indicates room to keep free at packet start for possible extension.
    pub fn new(buf: &'buf mut [u8; config::PACKET_BUFFER_SIZE], headroom: usize) -> Self {
        Self::new_with_existing_data(buf, PACKET_BUFFER_MIN_BODY_OFFSET + headroom, 0)
    }

    #[must_use]
    pub fn destroy(self) -> &'buf mut [u8; config::PACKET_BUFFER_SIZE] {
        self.buf
    }

    // Initialize a buffer with existing packet data as a packet buffer.
    // `offset` is offset of data within buffer.
    // It must be at least equal to PACKET_BODY_BUFFER_MIN_OFFSET.
    pub fn new_with_existing_data(buf: &'buf mut [u8; config::PACKET_BUFFER_SIZE], offset: usize, len: usize) -> Self {
        assert!(offset >= PACKET_BUFFER_MIN_BODY_OFFSET);
        assert!(offset + len < size_of_val(buf));
        let mut pkt = Packet { buf };
        let md = pkt.metadata_mut();
        md.offset = offset;
        md.len = len;
        md.flow_id = 0;
        pkt
    }

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
        let offset = self.metadata().offset;
        let len = self.metadata().len;
        &self.buf[offset..offset+len]
    }

    pub fn body_mut(&mut self) -> &mut [u8] {
        let offset = self.metadata().offset;
        let len = self.metadata().len;
        &mut self.buf[offset..offset+len]
    }

    // Space available for extension of the start of the packet.
    pub fn headroom_available(&self) -> usize {
        self.metadata().offset - PACKET_BUFFER_MIN_BODY_OFFSET
    }

    // Extend the start of the packet into available headroom.
    pub fn alloc_zeroed_headroom(&mut self, cnt: usize) {
        assert!(cnt <= self.headroom_available());
        let md = self.metadata_mut();
        md.offset -= cnt;
        md.len += cnt;
        let offset = md.offset;
        self.buf[offset..offset+cnt].fill(0);
    }

    pub fn alloc_zeroed_header<T: AsBytes + FromBytes + FromZeroes>(&mut self) -> &mut T {
        self.alloc_zeroed_headroom(size_of::<T>());
        T::mut_from_prefix(self.body_mut()).unwrap()
    }

    // flowhash is different for different flows, but not necessarily vice-versa.
    // Ideally this is a high-entropy value useful for load balancing.
    // Must be cheap to query.
    pub fn flowhash(&self) -> u32 { self.metadata().flow_id }
}

impl<'buf> buf::Buf for Packet<'buf> {
    fn remaining(&self) -> usize {
        self.metadata().len
    }

    // NOTE: This isn't super useful for us, as the contract of `chunk()`
    // permits returning less than what's available (even though we do not).
    // Most internal users should use `body()` instead.
    fn chunk(&self) -> &[u8] {
        self.body()
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining());
        self.metadata_mut().offset += cnt;
        self.metadata_mut().len -= cnt;
    }
}

unsafe impl<'buf> buf::BufMut for Packet<'buf> {
    fn remaining_mut(&self) -> usize {
        let md = self.metadata();
        size_of_val(self.buf) - (md.offset + md.len)
    }

    fn chunk_mut(&mut self) -> &mut buf::UninitSlice {
        let offset = self.metadata().offset;
        let len = self.metadata().len;
        buf::UninitSlice::new(&mut self.buf[offset+len..])
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining_mut());
        self.metadata_mut().len += cnt;
    }
}
