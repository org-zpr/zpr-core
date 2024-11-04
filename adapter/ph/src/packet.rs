//! This module contains all state of a packet which is moving through the system.
//!
//! A [Packet] is a lightweight wrapper around a byte buffer. Creator of the packet
//! is responsible for allocating the buffer and keeping it around for as long as
//! the packet is needed.
//!
//! For usage examples see the [Packet] documentation.

use crate::config;
use crate::defs::*;
use crate::net_defs::*;
use bytes::buf;
use std::mem::{size_of, size_of_val};
use zerocopy::*;
use zpr;
use zpr::L3Type;
use zpr_ext::std::mem::DropGuard;

/// Exclusive handle to an in-use packet buffer.
///
/// Via this handle, a buffer is divided into four sections in this order:
///
/// - metadata
/// - headroom
/// - packet body
/// - tailroom
///
/// *Metadata* is of a fixed size and may contain information about the
/// buffer layout itself, as well as packet classification data. Access is
/// via the [Packet::metadata] series of functions. Note that the metadata
/// properties must be set manually. See, for example the [crate::classifier] module
/// which takes a [Packet] and sets various metadata fields.
///
/// *Headroom* is space in the buffer which is set aside when the packet is
/// created (see [Packet::new]).  It is useful for when you need to slap
/// headers or other front matter onto the packet.  Use the `alloc_*` series
/// of functions or `push_header()` to push strucutres onto the packet body
/// by taking bytes from the headroom.
///
/// The packet *body* resides between headroom and tailroom.  It can be
/// extended into either of these, but not beyond.  The size of these
/// is defined when the `Packet` handle is created.
///
/// Note that a packet is [bytes::BufMut] and [bytes::Buf] so, for example, you can use the
/// `put` method on Packet to append data to the packet body. Note that to get
/// this (and other interesting) functionality you must have the correct traits in
/// scope.
///
///
/// # Examples
///
/// Read ZDP data from a socket, put it in a packet:
///
///```
/// use std::net::UdpSocket;
///
/// use ph::{packet, config};
/// use bytes::BufMut;
///
/// fn reader() -> std::io::Result<()> {
///
///     let sock = UdpSocket::bind("0.0.0.0:31337")?;
///
///     // Read from socket:
///     let mut sock_buf = [0u8; 4096];
///     let (read_len, source_addr) = sock.recv_from(&mut sock_buf)?;
///
///     // We need a backing byte buffer for the packet.  This would tupically be allocated
///     // from a buffer pool.
///     let pkt_buf = Box::new([0u8; config::PACKET_BUFFER_SIZE]);
///
///     // Create the packet. Since we are reading this packet with
///     // full (ZDP) headers already on it and we don't plan on pushing
///     // anything on to the front, we don't need any headroom so
///     // we set it to 0.
///     let mut pkt = packet::Packet::new(pkt_buf, 0);
///
///     // Write (copy) the received data into the packet.
///     pkt.put(&sock_buf[..read_len]);
///     Ok(())
/// }
///```
///
/// > Note that a [tokio::net::UdpSocket] does support writing into a [bytes::BufMut] directly,
/// > so you can skip the intermediate buffer (`sock_buf` in the above example) and have the
/// > socket write directly into a [Packet].
///
///
/// Create a ZDP report message in a packet and send it out a socket:
///
/// ```
/// use std::net::UdpSocket;
///
/// use ph::packet;
/// use ph::zdp::*;
/// use ph::config;
///
/// use bytes::BufMut;
/// use zerocopy::FromBytes;
///
///
/// fn writer() -> std::io::Result<()> {
///     let sock = UdpSocket::bind("0.0.0.0:31337")?;
///
///     // We need a backing byte buffer for the packet.
///     let mut pkt_buf = [0u8; config::PACKET_BUFFER_SIZE];
///
///     // Create the packet. Reserve 128 bytes for adding headers.
///     let mut pkt = packet::Packet::new(&mut pkt_buf, 128);
///
///     let payload = b"here is a payload";
///
///     // Write the payload to the packet body.
///     pkt.put(&payload[..]);
///
///     // Now we add the headers. We work backwards from the inner-most header
///     // to the outer-most.  In our case we want the final packet to look
///     // like this:
///     //
///     //  [ ZdpZpiHeader ] | [ ZdpBaseHeader ] | [ ZdpReportHeader ] | [ payload ]
///     //   (outer)                                          (inner)
///     //
///     // So we start with the ZdpReportHeader.
///
///     // Take sizeof(ZdpReportHeader) bytes from the headroom. The
///     // return value from the alloc call here is a *mutable* reference
///     // to the header structure that writes directly into the buffer.
///     let report_hdr = pkt.alloc_zeroed_header::<ZdpReportHeader>();
///     let msg_len = payload.len() as u16;
///     report_hdr.report_data_length = msg_len.into();
///
///     // Next the ZdpHeader. No need to set values that are zero since
///     // the `alloc` function returns zero'd memory.
///     let zdp_hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
///     zdp_hdr.packet_type = ZdpPacketType::Report;
///     zdp_hdr.sequence_number = 22.into();
///
///     // Finally the ZpiHeader
///     let zpi_hdr = pkt.alloc_zeroed_header::<ZdpZpiHeader>().zpi = 5;
///
///     // Packet is ready, so send it out the socket. Calling `body()` now
///     // returns a slice of the buffer starting at the last header we
///     // pushed, which is our ZpiHeader.
///     let _ = sock.send(&pkt.body())?;
///     Ok(())
/// }
/// ```

/// A generic packet type, backed by any sort of buffer.
///
/// Use this type in functions which operate only on the contents of a packet,
/// and do not interact with the buffer stack in any way.
pub struct Packet<PktBuf> {
    buf: PktBuf,
}

/// Blanket trait capturing all the traits needed to act as a packet backing buffer.
pub trait PacketBuffer:
    std::ops::DerefMut<Target = [u8; config::PACKET_BUFFER_SIZE]> + Send
{
}
impl<PktBuf: std::ops::DerefMut<Target = [u8; config::PACKET_BUFFER_SIZE]> + Send> PacketBuffer
    for PktBuf
{
}

/// A `Packet` backed specifically by a `Buffer` from the buffer stack.
///
/// Use this type in any code which moves a packet through the packet processing
/// pipeline (ultimately starting from, or ending with, the buffer stack).
pub type BufferPacket = Packet<crate::buffer_stack::Buffer<{ config::PACKET_BUFFER_SIZE }>>;

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct PacketMetadata {
    offset: usize, // packet offset (must be >= PACKET_BODY_BUFFER_MIN_OFFSET)
    len: usize,    // packet length

    /// which link this packet arrived on
    pub ingress_link_id: zpr::LinkId,

    /// which stream ID this packet is associated with
    pub ingress_stream_id: zpr::StreamId,

    five_tuple: FiveTuple,

    _padding: [u8; 2],
}

#[allow(dead_code)]
impl PacketMetadata {
    pub fn set_l3_type(&mut self, l3_type: L3Type) {
        self.five_tuple.l3_type = l3_type;
    }

    pub fn set_addresses(&mut self, src_addr: IpAddress, dst_addr: IpAddress) {
        self.five_tuple.src_address = src_addr;
        self.five_tuple.dst_address = dst_addr;
    }

    pub fn set_src_port(&mut self, sport: u16) {
        self.five_tuple.src_port = sport;
    }

    pub fn set_dst_port(&mut self, dport: u16) {
        self.five_tuple.dst_port = dport;
    }

    pub fn set_l4_protocol(&mut self, proto: IpProtocol) {
        self.five_tuple.l4_protocol = proto
    }

    pub fn get_l3_type(&self) -> L3Type {
        self.five_tuple.l3_type
    }

    pub fn get_src_address(&self) -> IpAddress {
        self.five_tuple.src_address
    }

    pub fn get_dst_address(&self) -> IpAddress {
        self.five_tuple.dst_address
    }

    pub fn get_src_port_hbo(&self) -> u16 {
        self.five_tuple.src_port
    }

    pub fn get_dst_port_hbo(&self) -> u16 {
        self.five_tuple.dst_port
    }

    pub fn get_l4_protocol(&self) -> IpProtocol {
        self.five_tuple.l4_protocol
    }

    pub fn five_tuple(&self) -> &FiveTuple {
        &self.five_tuple
    }
}

impl std::fmt::Debug for PacketMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "5-tuple: {}\nFlow Id: {}, arrived on: {}, length: {}\n",
            self.five_tuple, self.ingress_stream_id, self.ingress_link_id, self.len
        )
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
impl<PktBuf: PacketBuffer> Packet<PktBuf> {
    /// Initialize a buffer as a packet buffer, returning an exclusive handle to it.
    /// `headroom` indicates room to keep free at packet start for possible extension.
    pub fn new(buf: PktBuf, headroom: usize) -> Self {
        Self::new_with_existing_data(buf, PACKET_BUFFER_MIN_BODY_OFFSET + headroom, 0)
    }

    /// Same as `new()`, but accepts a `DropGuard`-protected buffer, and produces
    /// a `DropGuard`-protected packet buffer, so manually calling `destroy()`
    /// is unnecessary.
    pub fn new_guarded<B: DropGuard<PktBuf> + Send>(
        buf: B,
        headroom: usize,
    ) -> impl DropGuard<Self> + Send {
        buf.map(move |b| Self::new(b, headroom), |p| p.destroy())
    }

    /// Consumes a packet handle, returning the underlying buffer.
    #[must_use]
    pub fn destroy(self) -> PktBuf {
        self.buf
    }

    /// Initialize a buffer with existing packet data as a packet buffer.
    /// `offset` is offset of data within buffer.
    /// It must be at least equal to `PACKET_BUFFER_MIN_BODY_OFFSET`.
    pub fn new_with_existing_data(buf: PktBuf, offset: usize, len: usize) -> Self {
        assert!(offset >= PACKET_BUFFER_MIN_BODY_OFFSET);
        assert!(len <= size_of_val(&*buf));
        assert!(offset <= size_of_val(&*buf) - len);
        let mut pkt = Packet { buf };
        let md = pkt.metadata_mut();
        md.offset = offset;
        md.len = len;
        md.ingress_link_id = 0;
        md.ingress_stream_id = 0;
        pkt
    }

    /// Copy this packet's metadata, data and layout into a new buffer, returning a handle for it.
    pub fn clone_into<OtherPktBuf: PacketBuffer>(&self, buf: OtherPktBuf) -> Packet<OtherPktBuf> {
        self.clone_prefix_into_with_headroom(buf, self.headroom_available(), self.body().len())
    }

    /// Like `clone_into()`, but only copy a prefix of the packet's data.
    pub fn clone_prefix_into<OtherPktBuf: PacketBuffer>(
        &self,
        buf: OtherPktBuf,
        len: usize,
    ) -> Packet<OtherPktBuf> {
        self.clone_prefix_into_with_headroom(buf, self.headroom_available(), len)
    }

    /// Copy this packet's metadata and data into a new buffer, returning a handle for it.
    /// The packet body will be positioned to leave the specified amount of headroom in the new buffer.
    pub fn clone_into_with_headroom<OtherPktBuf: PacketBuffer>(
        &self,
        buf: OtherPktBuf,
        headroom: usize,
    ) -> Packet<OtherPktBuf> {
        self.clone_prefix_into_with_headroom(buf, headroom, self.body().len())
    }

    /// Like `clone_into_with_headroom()`, but only copy a prefix of the packet's data.
    pub fn clone_prefix_into_with_headroom<OtherPktBuf: PacketBuffer>(
        &self,
        mut buf: OtherPktBuf,
        headroom: usize,
        len: usize,
    ) -> Packet<OtherPktBuf> {
        let body = self.body();
        assert!(len <= body.len());
        assert!(headroom <= size_of_val(&*buf) - len - PACKET_BUFFER_MIN_BODY_OFFSET);
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
        let opt = PacketMetadata::ref_from_bytes(&self.buf[..size_of::<PacketMetadata>()]);
        unsafe {
            // SAFETY: we know this fits in PACKET_BUFFER_SIZE
            opt.unwrap_unchecked()
        }
    }

    /// Returns a mutable reference to the packet metadata.
    pub fn metadata_mut(&mut self) -> &mut PacketMetadata {
        let opt = PacketMetadata::mut_from_bytes(&mut self.buf[..size_of::<PacketMetadata>()]);
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
        let opt = PacketMetadata::mut_from_bytes(md);
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
    pub fn alloc_zeroed_header<T: FromBytes + IntoBytes + KnownLayout + Unaligned>(
        &mut self,
    ) -> &mut T {
        let res = T::mut_from_bytes(self.alloc_zeroed_headroom(size_of::<T>()))
            .map_err(Into::<SizeError<_, _>>::into);
        unsafe {
            // SAFETY: we know we've allocated exactly the right number of bytes
            res.unwrap_unchecked()
        }
    }

    /// Copy the given data as a header into the packet's headroom.
    /// (Avoids needlessly zeroing the allocated headroom.)
    pub fn push_header<T: IntoBytes + Immutable>(&mut self, header: &T) {
        let cnt = size_of::<T>();
        assert!(cnt <= self.headroom_available());
        let md = self.metadata_mut();
        md.offset -= cnt;
        md.len += cnt;
        let res = header.write_to_prefix(&mut self.body_mut()[..cnt]);
        unsafe {
            // SAFETY: we know we've allocated exactly the right number of bytes
            res.unwrap_unchecked()
        };
    }

    /// Shrink the packet by `cnt` bytes (removing data from the tail).
    pub fn shrink_by(&mut self, cnt: usize) {
        let md = self.metadata_mut();
        assert!(cnt <= md.len);
        md.len -= cnt;
    }

    /// `flowhash()` is different for different flows, but not necessarily vice-versa.
    /// Ideally this is a high-entropy value useful for load balancing.
    /// Must be cheap to query.
    pub fn flowhash(&self) -> u32 {
        self.metadata().ingress_stream_id
    }

    pub fn dump_packet_buffer(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> Result<(), std::fmt::Error> {
        // TODO This is a super hacky and inefficient way to do this
        for i in 0..self.metadata().len {
            if i % 16 == 0 {
                write!(f, "\n{:04x} ", i)?;
            } else if i % 8 == 0 {
                write!(f, " ")?;
            }
            write!(f, " {:02x}", self.buf[i])?;
        }
        writeln!(f, "")
    }
}

impl<PktBuf: PacketBuffer> buf::Buf for Packet<PktBuf> {
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

unsafe impl<PktBuf: PacketBuffer> buf::BufMut for Packet<PktBuf> {
    //! Writing to a `Packet` using the `BufMut` interface appends data
    //! into the tailroom and the end of the packet.

    /// This indicates how much tailroom is remaining.
    fn remaining_mut(&self) -> usize {
        let md = self.metadata();
        size_of_val(&*self.buf) - (md.offset + md.len)
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

impl<PktBuf: PacketBuffer> std::fmt::Debug for Packet<PktBuf> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "\n=== Begin dumping packet info ===")?;
        self.metadata().fmt(f)?;
        self.dump_packet_buffer(f)?;
        writeln!(f, "===  End dumping packet info  ===\n")
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
        pkt.metadata_mut().ingress_stream_id = 100;
        let mut buf2 = [0u8; config::PACKET_BUFFER_SIZE];
        let pkt2 = pkt.clone_into_with_headroom(&mut buf2, 456);
        assert_eq!(
            pkt.metadata().ingress_stream_id,
            pkt2.metadata().ingress_stream_id
        );
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
        assert_eq!(pkt.body(), [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn buf_write_twice_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 0);
        pkt.put_u32(0x01020304u32);
        pkt.put_u32(0x05060708u32);
        assert_eq!(pkt.body(), [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    #[should_panic]
    fn buf_write_no_tail_room_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, PACKET_BUFFER_MAX_BODY_SIZE);
        pkt.put_u8(1);
    }

    #[test]
    fn shrink_by_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 0);
        pkt.put_u64(0x0102030405060708u64);
        pkt.shrink_by(2);
        assert_eq!(pkt.body(), [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    #[should_panic]
    fn shrink_by_too_much_test() {
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 0);
        pkt.put_u64(0x0102030405060708u64);
        pkt.shrink_by(10);
    }
}
