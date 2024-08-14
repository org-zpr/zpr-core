//! Simple PCAP writing functionality.
//!
//! Uses tokio for I/O, so e.g. writing over a network socket
//! won't block the runtime.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use zerocopy::AsBytes;

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

#[derive(AsBytes)]
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

#[derive(AsBytes)]
#[repr(C)]
struct PcaprecHdr {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

/// A packet to be written out.
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
    pub async fn write(&mut self, packet: &PcapPacket<'_>) -> io::Result<()> {
        if packet.data.len() > MAX_SNAPLEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too large",
            ));
        }

        let ts = packet
            .timestamp
            .duration_since(UNIX_EPOCH)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

        let hdr = PcaprecHdr {
            ts_sec: ts.as_secs() as u32,
            ts_usec: ts.subsec_micros() as u32,
            incl_len: packet.data.len() as u32,
            orig_len: packet.orig_len as u32,
        };

        self.writer.write_all(hdr.as_bytes()).await?;
        self.writer.write_all(packet.data).await?;

        Ok(())
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.writer.flush().await
    }

    pub async fn close(mut self) -> io::Result<W> {
        self.writer.flush().await?;
        Ok(self.writer.into_inner())
    }
}
