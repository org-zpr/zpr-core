//! This module contains all state of a packet which is moving through the system.

use crate::config;
use crate::net_defs::*;
use bytes::buf;
use std::mem::{size_of, size_of_val};
use zerocopy::{AsBytes, ByteOrder, FromBytes, FromZeroes, NetworkEndian};
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};
use zpr_ext::std::mem::DropGuard;

/** Exclusive handle to an in-use packet buffer.
 *
 * Via this handle, a buffer is divided into four sections in this order:
 *
 * - metadata
 * - headroom
 * - packet body
 * - tailroom
 *
 * Metadata is of a fixed size and contains information about the
 * buffer layout itself, as well as packet classification data.
 *
 * The packet body resides between headroom and tailroom.  It can be
 * extended into either of these, but not beyond.  The size of these
 * is defined when the `Packet` handle is created.
 */

pub struct Packet<'buf> {
    buf: &'buf mut [u8; config::PACKET_BUFFER_SIZE],
}

#[derive(AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct PacketMetadata {
    offset: usize,    // packet offset (must be >= PACKET_BODY_BUFFER_MIN_OFFSET)
    len: usize,       // packet length
    pub flow_id: u32, // flow ID for load-balancing purposes; not otherwise meaningful
    src_address: IpAddress,
    dst_address: IpAddress,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _padding: [u8; 7],
}

#[allow(dead_code)]
impl PacketMetadata {
    pub fn set_addresses(&mut self, src_addr: IpAddress, dst_addr: IpAddress) {
        self.src_address = src_addr;
        self.dst_address = dst_addr;
    }

    pub fn set_src_port(&mut self, sport: [u8; 2]) {
        self.src_port = NetworkEndian::read_u16(&sport)
    }

    pub fn set_dst_port(&mut self, dport: [u8; 2]) {
        self.dst_port = NetworkEndian::read_u16(&dport)
    }

    pub fn set_protocol(&mut self, proto: u8) {
        self.protocol = proto
    }

    pub fn get_src_address(&self) -> IpAddress {
        self.src_address
    }

    pub fn get_dst_address(&self) -> IpAddress {
        self.dst_address
    }

    pub fn get_src_port_hbo(&self) -> u16 {
        self.src_port
    }

    pub fn get_dst_port_hbo(&self) -> u16 {
        self.dst_port
    }

    pub fn get_protocol(&self) -> u8 {
        self.protocol
    }
}

const _: () = assert!(
    size_of::<PacketMetadata>() <= config::PACKET_BUFFER_SIZE,
    "Metadata must be shorter than the packet buffer"
);

pub const PACKET_BUFFER_MIN_BODY_OFFSET: usize = size_of::<PacketMetadata>();

/// The maximum size packet body which can be referenced by a `Packet`.
#[allow(dead_code)]
pub const PACKET_BUFFER_MAX_BODY_SIZE: usize =
    config::PACKET_BUFFER_SIZE - PACKET_BUFFER_MIN_BODY_OFFSET;

#[allow(dead_code)]
impl<'buf> Packet<'buf> {
    /// Initialize a buffer as a packet buffer, returning an exclusive handle to it.
    /// `headroom` indicates room to keep free at packet start for possible extension.
    pub fn new(buf: &'buf mut [u8; config::PACKET_BUFFER_SIZE], headroom: usize) -> Self {
        Self::new_with_existing_data(buf, PACKET_BUFFER_MIN_BODY_OFFSET + headroom, 0)
    }

    /// Same as `new()`, but accepts a `DropGuard`-protected buffer, and produces
    /// a `DropGuard`-protected packet buffer, so manually calling `destroy()`
    /// is unnecessary.
    pub fn new_guarded<B: DropGuard<&'buf mut [u8; config::PACKET_BUFFER_SIZE]>>(
        buf: B,
        headroom: usize,
    ) -> impl DropGuard<Self> {
        buf.map(move |b| Self::new(b, headroom), |p| p.destroy())
    }

    /// Consumes a packet handle, returning the underlying buffer.
    #[must_use]
    pub fn destroy(self) -> &'buf mut [u8; config::PACKET_BUFFER_SIZE] {
        self.buf
    }

    /// Initialize a buffer with existing packet data as a packet buffer.
    /// `offset` is offset of data within buffer.
    /// It must be at least equal to `PACKET_BUFFER_MIN_BODY_OFFSET`.
    pub fn new_with_existing_data(
        buf: &'buf mut [u8; config::PACKET_BUFFER_SIZE],
        offset: usize,
        len: usize,
    ) -> Self {
        assert!(offset >= PACKET_BUFFER_MIN_BODY_OFFSET);
        assert!(len <= size_of_val(buf));
        assert!(offset <= size_of_val(buf) - len);
        let mut pkt = Packet { buf };
        let md = pkt.metadata_mut();
        md.offset = offset;
        md.len = len;
        md.flow_id = 0;
        pkt
    }

    /// Copy this packet's metadata, data and layout into a new buffer, returning a handle for it.
    pub fn clone_into<'other>(
        &self,
        buf: &'other mut [u8; config::PACKET_BUFFER_SIZE],
    ) -> Packet<'other> {
        self.clone_prefix_into_with_headroom(buf, self.headroom_available(), self.body().len())
    }

    /// Like `clone_into()`, but only copy a prefix of the packet's data.
    pub fn clone_prefix_into<'other>(
        &self,
        buf: &'other mut [u8; config::PACKET_BUFFER_SIZE],
        len: usize,
    ) -> Packet<'other> {
        self.clone_prefix_into_with_headroom(buf, self.headroom_available(), len)
    }

    /// Copy this packet's metadata and data into a new buffer, returning a handle for it.
    /// The packet body will be positioned to leave the specified amount of headroom in the new buffer.
    pub fn clone_into_with_headroom<'other>(
        &self,
        buf: &'other mut [u8; config::PACKET_BUFFER_SIZE],
        headroom: usize,
    ) -> Packet<'other> {
        self.clone_prefix_into_with_headroom(buf, headroom, self.body().len())
    }

    fn clone_prefix_into_with_headroom<'other>(
        &self,
        buf: &'other mut [u8; config::PACKET_BUFFER_SIZE],
        headroom: usize,
        len: usize,
    ) -> Packet<'other> {
        let body = self.body();
        assert!(len <= body.len());
        assert!(headroom <= size_of_val(buf) - len - PACKET_BUFFER_MIN_BODY_OFFSET);
        buf[..size_of::<PacketMetadata>()]
            .copy_from_slice(&self.buf[..size_of::<PacketMetadata>()]);
        let offset = PACKET_BUFFER_MIN_BODY_OFFSET + headroom;
        buf[offset..offset + len].copy_from_slice(body);
        let mut pkt = Packet { buf };
        pkt.metadata_mut().offset = offset;
        pkt.metadata_mut().len = len;
        pkt
    }

    /// Returns a reference to the packet metadata.
    pub fn metadata(&self) -> &PacketMetadata {
        let opt = PacketMetadata::ref_from(&self.buf[..size_of::<PacketMetadata>()]);
        unsafe {
            // SAFETY: we know this fits in PACKET_BUFFER_SIZE
            opt.unwrap_unchecked()
        }
    }

    /// Returns a mutable reference to the packet metadata.
    pub fn metadata_mut(&mut self) -> &mut PacketMetadata {
        let opt = PacketMetadata::mut_from(&mut self.buf[..size_of::<PacketMetadata>()]);
        unsafe {
            // SAFETY: we know this fits in PACKET_BUFFER_SIZE
            opt.unwrap_unchecked()
        }
    }

    /// Returns a reference to the packet body.
    pub fn body(&self) -> &[u8] {
        let offset = self.metadata().offset;
        let len = self.metadata().len;
        &self.buf[offset..offset + len]
    }

    /// Returns a mutable reference to the packet body.
    pub fn body_mut(&mut self) -> &mut [u8] {
        let offset = self.metadata().offset;
        let len = self.metadata().len;
        &mut self.buf[offset..offset + len]
    }

    /// Returns mutable references to both the packet metadata and body.
    pub fn metadata_mut_and_body_mut(&mut self) -> (&mut PacketMetadata, &mut [u8]) {
        let (md, bd) = self.buf.split_at_mut(size_of::<PacketMetadata>());
        let opt = PacketMetadata::mut_from(md);
        let md = unsafe {
            // SAFETY: we know this fits in PACKET_BUFFER_SIZE
            opt.unwrap_unchecked()
        };
        let offset = md.offset - size_of::<PacketMetadata>();
        let len = md.len;
        (md, &mut bd[offset..offset + len])
    }

    /// Returns the amount of space available for extension of the start of the packet.
    pub fn headroom_available(&self) -> usize {
        self.metadata().offset - PACKET_BUFFER_MIN_BODY_OFFSET
    }

    /// Extend the start of the packet into available headroom by the given amount,
    /// and return a reference to that space.  The space allocated will be zeroed.
    pub fn alloc_zeroed_headroom(&mut self, cnt: usize) -> &mut [u8] {
        assert!(cnt <= self.headroom_available());
        let md = self.metadata_mut();
        md.offset -= cnt;
        md.len += cnt;
        let hdr = &mut self.body_mut()[..cnt];
        hdr.fill(0);
        hdr
    }

    /// Extend the start of the packet into available headroom enough to
    /// hold a structure of the given type, and return a reference to the space.
    /// The structure allocated will be zeroed.
    pub fn alloc_zeroed_header<T: AsBytes + FromBytes + FromZeroes>(&mut self) -> &mut T {
        T::mut_from(self.alloc_zeroed_headroom(size_of::<T>())).unwrap()
    }

    /// `flowhash()` is different for different flows, but not necessarily vice-versa.
    /// Ideally this is a high-entropy value useful for load balancing.
    /// Must be cheap to query.
    pub fn flowhash(&self) -> u32 {
        self.metadata().flow_id
    }
}

impl<'buf> buf::Buf for Packet<'buf> {
    //! Reading from a `Packet` using the `Buf` interface consumes data
    //! from the front of the packet.

    /// This is simply the packet size.
    fn remaining(&self) -> usize {
        self.metadata().len
    }

    /// Provides a reference to a portion of the remaining packet.
    /// NOTE: This isn't super useful for us, as the contract of `chunk()`
    /// permits returning less than what's available (even though we do not).
    /// Most internal users should use `body()` instead.
    fn chunk(&self) -> &[u8] {
        self.body()
    }

    /// Discards the indicated number of bytes from the start of the packet.
    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining());
        self.metadata_mut().offset += cnt;
        self.metadata_mut().len -= cnt;
    }
}

unsafe impl<'buf> buf::BufMut for Packet<'buf> {
    //! Writing to a `Packet` using the `BufMut` interface appends data
    //! into the tailroom and the end of the packet.

    /// This indicates how much tailroom is remaining.
    fn remaining_mut(&self) -> usize {
        let md = self.metadata();
        size_of_val(self.buf) - (md.offset + md.len)
    }

    /// Provides a reference to a portion of the remaining tailroom.
    fn chunk_mut(&mut self) -> &mut buf::UninitSlice {
        let offset = self.metadata().offset;
        let len = self.metadata().len;
        buf::UninitSlice::new(&mut self.buf[offset + len..])
    }

    /// Asserts that the indicated amount of tailroom has been initialized,
    /// and grows the packet to include it as part of the body.
    unsafe fn advance_mut(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining_mut());
        self.metadata_mut().len += cnt;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, BufMut};

    #[test]
    fn lifetime_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let pkt = Packet::new(&mut buf, 0);
        let ptr_buf = pkt.destroy().as_ptr();
        assert_eq!(ptr_buf, (&buf).as_ptr());
    }

    #[test]
    fn basic_headroom_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let pkt = Packet::new(&mut buf, 123);
        assert_eq!(pkt.headroom_available(), 123);
    }

    #[test]
    fn max_headroom_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let new_coke = Packet::new(&mut buf, PACKET_BUFFER_MAX_BODY_SIZE);
        assert_eq!(new_coke.headroom_available(), PACKET_BUFFER_MAX_BODY_SIZE);
    }

    #[test]
    #[should_panic]
    fn too_much_headroom_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        Packet::new(&mut buf, PACKET_BUFFER_MAX_BODY_SIZE + 1);
    }

    #[test]
    #[should_panic]
    fn way_too_much_headroom_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        Packet::new(&mut buf, usize::MAX);
    }

    #[test]
    #[should_panic]
    fn existing_data_way_too_large_offset() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        Packet::new_with_existing_data(&mut buf, usize::MAX, 0);
    }

    #[test]
    #[should_panic]
    fn existing_data_way_too_large_len() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        Packet::new_with_existing_data(&mut buf, PACKET_BUFFER_MIN_BODY_OFFSET, usize::MAX);
    }

    #[test]
    #[should_panic]
    fn existing_data_too_small_offset() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        Packet::new_with_existing_data(&mut buf, std::mem::size_of::<PacketMetadata>() - 1, 0);
    }

    #[test]
    fn existing_data() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let offset = PACKET_BUFFER_MIN_BODY_OFFSET + 123;
        let data = [1, 2, 3, 4, 5, 6, 7, 8].as_slice();
        buf[offset..offset + 8].copy_from_slice(data);
        let pkt = Packet::new_with_existing_data(&mut buf, PACKET_BUFFER_MIN_BODY_OFFSET + 123, 8);
        assert_eq!(pkt.body(), data);
    }

    #[test]
    fn clone_headroom_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let pkt = Packet::new(&mut buf, 123);
        let mut buf2 = [0u8; config::PACKET_BUFFER_SIZE];
        let pkt2 = pkt.clone_into(&mut buf2);
        assert_eq!(pkt2.headroom_available(), 123);
    }

    #[test]
    fn clone_adjusted_headroom_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let pkt = Packet::new(&mut buf, 123);
        let mut buf2 = [0u8; config::PACKET_BUFFER_SIZE];
        let pkt2 = pkt.clone_into_with_headroom(&mut buf2, 456);
        assert_eq!(pkt2.headroom_available(), 456);
    }

    #[test]
    fn clone_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let offset = PACKET_BUFFER_MIN_BODY_OFFSET + 123;
        let data = [1, 2, 3, 4, 5, 6, 7, 8].as_slice();
        buf[offset..offset + 8].copy_from_slice(data);
        let mut pkt =
            Packet::new_with_existing_data(&mut buf, PACKET_BUFFER_MIN_BODY_OFFSET + 123, 8);
        pkt.metadata_mut().flow_id = 100;
        let mut buf2 = [0u8; config::PACKET_BUFFER_SIZE];
        let pkt2 = pkt.clone_into_with_headroom(&mut buf2, 456);
        assert_eq!(pkt.metadata().flow_id, pkt2.metadata().flow_id);
        assert_eq!(*pkt.body(), *pkt2.body());
    }

    #[test]
    fn alloc_headroom_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 123);
        let hdr = pkt.alloc_zeroed_headroom(123);
        for &mut x in hdr {
            assert_eq!(x, 0);
        }
    }

    #[test]
    #[should_panic]
    fn alloc_too_much_headroom_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 123);
        pkt.alloc_zeroed_headroom(124);
    }

    #[test]
    #[should_panic]
    fn alloc_way_too_much_headroom_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 0);
        pkt.alloc_zeroed_headroom(usize::MAX);
    }

    #[test]
    fn write_header_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 4);
        let data: [u8; 4] = [1, 2, 3, 4];
        *pkt.alloc_zeroed_header() = data;
        assert_eq!(pkt.body()[..4], data);
    }

    #[test]
    fn buf_read_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let offset = PACKET_BUFFER_MIN_BODY_OFFSET + 123;
        let data = [1, 2, 3, 4, 5, 6, 7, 8].as_slice();
        buf[offset..offset + 8].copy_from_slice(data);
        let mut pkt =
            Packet::new_with_existing_data(&mut buf, PACKET_BUFFER_MIN_BODY_OFFSET + 123, 8);
        assert_eq!(pkt.get_u64(), 0x0102030405060708u64);
    }

    #[test]
    fn buf_read_twice_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let offset = PACKET_BUFFER_MIN_BODY_OFFSET + 123;
        let data = [1, 2, 3, 4, 5, 6, 7, 8].as_slice();
        buf[offset..offset + 8].copy_from_slice(data);
        let mut pkt =
            Packet::new_with_existing_data(&mut buf, PACKET_BUFFER_MIN_BODY_OFFSET + 123, 8);
        assert_eq!(pkt.get_u32(), 0x01020304u32);
        assert_eq!(pkt.get_u32(), 0x05060708u32);
    }

    #[test]
    #[should_panic]
    fn buf_read_too_much_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let offset = PACKET_BUFFER_MIN_BODY_OFFSET + 123;
        let data = [1, 2, 3, 4, 5, 6, 7].as_slice();
        buf[offset..offset + 8].copy_from_slice(data);
        let mut pkt =
            Packet::new_with_existing_data(&mut buf, PACKET_BUFFER_MIN_BODY_OFFSET + 123, 8);
        let _ = pkt.get_u64();
    }

    #[test]
    fn buf_write_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 0);
        pkt.put_u64(0x0102030405060708u64);
        assert_eq!(pkt.body()[..8], [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn buf_write_twice_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 0);
        pkt.put_u32(0x01020304u32);
        pkt.put_u32(0x05060708u32);
        assert_eq!(pkt.body()[..8], [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    #[should_panic]
    fn buf_write_no_tail_room_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, PACKET_BUFFER_MAX_BODY_SIZE);
        pkt.put_u8(1);
    }
}
