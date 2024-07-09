use crate::config;
use bytes::buf;
use std::mem::{size_of, size_of_val};
use zerocopy::{AsBytes, ByteOrder, FromBytes, FromZeroes, NetworkEndian};
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes, KnownLayout, Unaligned};

// This contains all state of a packet which is moving through the system.
// TODO: possible we want to keep this stuff on the heap

pub struct Packet<'buf> {
    buf: &'buf mut [u8; config::PACKET_BUFFER_SIZE],
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
    pub fn set_from_v4(&mut self, v4_address: [u8; 4]) {
        self.v6[12..16].copy_from_slice(&v4_address);
        self.v6[10] = 0xff;
        self.v6[11] = 0xff
    }

    pub fn read_as_v4(&self) -> &[u8] {
        &self.v6[12..16]
    }
}

pub fn v4_to_v6_address(v4_address: [u8; 4]) -> IpAddress {
    // Uses standard v4 to v6 conversion
    let mut v6_address = IpAddress::new_zeroed();
    v6_address.set_from_v4(v4_address);
    v6_address
}

#[derive(AsBytes, FromZeroes, FromBytes)]
#[repr(packed)]
pub struct PacketMetadata {
    offset: usize,    // packet offset (must be >= PACKET_BODY_BUFFER_MIN_OFFSET)
    len: usize,       // packet length
    pub flow_id: u32, // flow ID for load-balancing purposes; not otherwise meaningful
    src_address: IpAddress,
    dst_address: IpAddress,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _padding: [u8; 3],
}

#[allow(dead_code)]
impl PacketMetadata {
    pub fn set_src_port(&mut self, sport: [u8; 2]) {
        self.src_port = NetworkEndian::read_u16(&sport)
    }

    pub fn set_dst_port(&mut self, dport: [u8; 2]) {
        self.dst_port = NetworkEndian::read_u16(&dport)
    }

    pub fn set_protocol(&mut self, proto: u8) {
        self.protocol = proto
    }

    pub fn set_addresses(&mut self, src_addr: IpAddress, dst_addr: IpAddress) {
        self.src_address = src_addr;
        self.dst_address = dst_addr;
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

#[allow(dead_code)]
pub const PACKET_BODY_BUFFER_MAX_SIZE: usize =
    config::PACKET_BUFFER_SIZE - PACKET_BUFFER_MIN_BODY_OFFSET;

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
    pub fn new_with_existing_data(
        buf: &'buf mut [u8; config::PACKET_BUFFER_SIZE],
        offset: usize,
        len: usize,
    ) -> Self {
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
        &self.buf[offset..offset + len]
    }

    pub fn body_mut(&mut self) -> &mut [u8] {
        let offset = self.metadata().offset;
        let len = self.metadata().len;
        &mut self.buf[offset..offset + len]
    }

    pub fn metadata_and_body_mut(&mut self) -> (&PacketMetadata, &mut [u8]) {
        let (md, bd) = self.metadata_mut_and_body_mut();
        (md as &_, bd)
    }

    pub fn metadata_mut_and_body(&mut self) -> (&mut PacketMetadata, &[u8]) {
        let (md, bd) = self.metadata_mut_and_body_mut();
        (md, bd as &_)
    }

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
        self.buf[offset..offset + cnt].fill(0);
    }

    pub fn alloc_zeroed_header<T: AsBytes + FromBytes + FromZeroes>(&mut self) -> &mut T {
        self.alloc_zeroed_headroom(size_of::<T>());
        T::mut_from_prefix(self.body_mut()).unwrap()
    }

    // flowhash is different for different flows, but not necessarily vice-versa.
    // Ideally this is a high-entropy value useful for load balancing.
    // Must be cheap to query.
    pub fn flowhash(&self) -> u32 {
        self.metadata().flow_id
    }
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
        buf::UninitSlice::new(&mut self.buf[offset + len..])
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining_mut());
        self.metadata_mut().len += cnt;
    }
}
