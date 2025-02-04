//! Simple PCAP writing functionality.
//!
//! Uses tokio for I/O, so e.g. writing over a network socket
//! won't block the runtime.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Represents an open PCAP writer.
pub struct PcapWriter<W: AsyncWrite> {
    writer: BufWriter<W>,
}

// see <https://wiki.wireshark.org/Development/LibpcapFileFormat> for format details

const PCAP_HDR_MAGIC_NUMBER: u32 = 0xa1b2c3d4;
const PCAP_HDR_VERSION_MAJOR: u16 = 2;
const PCAP_HDR_VERSION_MINOR: u16 = 4;

/// Maximum size packet which may be captured.
pub const MAX_SNAPLEN: usize = 1 << 18;

#[derive(IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct PcapHdr {
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct PcaprecHdr {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

impl PcaprecHdr {
    pub fn new(timestamp: SystemTime, incl_len: usize, orig_len: usize) -> Self {
        let ts = timestamp.duration_since(UNIX_EPOCH).unwrap_or_default();

        Self {
            ts_sec: ts.as_secs() as u32,
            ts_usec: ts.subsec_micros() as u32,
            incl_len: std::cmp::min(incl_len, u32::MAX as usize) as u32,
            orig_len: std::cmp::min(orig_len, u32::MAX as usize) as u32,
        }
    }
}

/// A packet to be written out.
#[allow(dead_code)]
pub struct PcapPacket<'a> {
    pub timestamp: SystemTime,
    pub orig_len: usize,
    pub data: &'a [u8],
}

/// Link type values, which indicate the type of packets being written.
/// See <https://www.tcpdump.org/linktypes.html> for protocol details.
pub mod linktype {
    #![allow(dead_code)]

    /// BSD loopback encapsulation
    pub const NULL: u32 = 0;

    /// IEEE 802.3 Ethernet
    pub const ETHERNET: u32 = 1;

    /// PPP
    pub const PPP: u32 = 9;

    /// raw IP (IPv4 or IPv6)
    pub const RAW: u32 = 101;

    /// user-defined
    pub const USER0: u32 = 147;
    pub const USER1: u32 = 148;
    pub const USER2: u32 = 149;
    pub const USER3: u32 = 150;
    pub const USER4: u32 = 151;
    pub const USER5: u32 = 152;
    pub const USER6: u32 = 153;
    pub const USER7: u32 = 154;
    pub const USER8: u32 = 155;
    pub const USER9: u32 = 156;
    pub const USER10: u32 = 157;
    pub const USER11: u32 = 158;
    pub const USER12: u32 = 159;
    pub const USER13: u32 = 160;
    pub const USER14: u32 = 161;
    pub const USER15: u32 = 162;
}

impl<W: AsyncWrite + Unpin> PcapWriter<W> {
    /// "Open" a new PCAP writer, using the specified async writer as the destination.
    pub async fn open(writer: W, linktype: u32) -> io::Result<Self> {
        let mut writer = BufWriter::new(writer);

        let hdr = PcapHdr {
            magic_number: PCAP_HDR_MAGIC_NUMBER,
            version_major: PCAP_HDR_VERSION_MAJOR,
            version_minor: PCAP_HDR_VERSION_MINOR,
            thiszone: 0,
            sigfigs: 0,
            snaplen: MAX_SNAPLEN as u32,
            network: linktype,
        };

        writer.write_all(hdr.as_bytes()).await?;

        Ok(Self { writer })
    }

    /// Write a packet to the PCAP writer.
    #[allow(dead_code)]
    pub async fn write(&mut self, packet: &PcapPacket<'_>) -> io::Result<()> {
        self.write_preformatted(
            &PcaprecHdr::new(packet.timestamp, packet.data.len(), packet.orig_len),
            &packet.data,
        )
        .await
    }

    /// Write a packet to the PCAP writer, with preformatted header.
    ///
    /// If `data` is longer than `hdr.incl_len`, it will be truncated.
    /// If `data` is shorter than `hdr.incl_len`, `incl_len` will be adjusted to match.
    pub async fn write_preformatted(&mut self, hdr: &PcaprecHdr, data: &[u8]) -> io::Result<()> {
        let data_len_u32 = std::cmp::min(data.len(), u32::MAX as usize) as u32;

        let hdr = PcaprecHdr {
            incl_len: std::cmp::min(hdr.incl_len, data_len_u32),
            ..*hdr
        };

        self.writer.write_all(hdr.as_bytes()).await?;
        self.writer.write_all(&data[..hdr.incl_len as usize]).await
    }

    /// Write a raw PCAP packet to the PCAP writer.
    ///
    /// The first 16 bytes of `pcap_data` should be a `PcaprecHdr`.
    /// The remainder should be the packet to be recorded.
    ///
    /// `incl_len` and the packet data length are adjusted as per
    /// `write_preformatted()`.
    pub async fn write_raw(&mut self, pcap_data: &[u8]) -> io::Result<()> {
        let Ok((hdr, data)) = PcaprecHdr::ref_from_prefix(pcap_data) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad pcap data"));
        };

        self.write_preformatted(hdr, data).await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.writer.flush().await
    }

    pub async fn close(mut self) -> io::Result<W> {
        self.writer.flush().await?;
        Ok(self.writer.into_inner())
    }
}
