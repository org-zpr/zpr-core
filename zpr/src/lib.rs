//! ZPR concepts, excluding the ZDP protocol.

pub mod rpc_commands;

use open_enum::open_enum;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Substrate Address
pub type SubstrateAddr = std::net::SocketAddr;

/// ZPR Parameter Index
pub type Zpi = u8;

/// ZPI 0, used for keying and early ZARP.
pub const ZPI_0: Zpi = 0;

/// Proposed value to allow easily distinguishing packets with plaintext payloads.
pub const ZPI_ENCRYPTED_HEADER_FLAG: Zpi = 0x80;

/// Message sequence numbers.  Note this is the _abstract_ sequence number.
/// The physical sequence number included in message headers is a suffix of this.
pub type SeqNum = u64;

/// The Security Association ID must fit no more than 8 bits.  Note that it shares
/// space with the ZPI.
pub type SaId = u8;

/// Link or Docking Session ID
pub type LinkId = u32;

/// Link ID used to refer to a packet not associated with a link (typically a link setup packet).
pub const LINK_ID_UNKNOWN: LinkId = 0;

/// Link ID used to refer to a node or adapter's local agent.
pub const LOCAL_AGENT_LINK_ID: LinkId = 1;

/// Link ID used on an adapter to refer to the dock to which it's connected.
pub const DOCK_LINK_ID: LinkId = 2;

/// Stream ID
pub type StreamId = u32;

/// Reserved for node-to-node / control-plane traffic.
pub const NODE_TO_NODE_STREAM_ID: StreamId = 0;

/// Adapter-to-Adapter SAID.
pub type A2aSaid = u8;

/// Within a ZDP Key Management packet, indicates the Key Managenent algorithm identifier.
pub type KmId = u16;

/// Key Management Identifier indicating "experimental" algorithm.
pub const KM_ID_EXPERIMENTAL: KmId = 255;

/// Key Management Identifier indicating IKEv2 algorithm.
pub const KM_ID_IKEV2: KmId = 1;

/// Key Management Identifier indicating Noise algorithm.
pub const KM_ID_NOISE: KmId = 2;

/// ZPR agent packet L3 type (RFC 6.5 § 6.3.11)
#[open_enum]
#[derive(Copy, Clone, Debug, FromBytes, Hash, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum L3Type {
    Ipv4 = 4,
    Ipv6 = 6,
}

impl std::fmt::Display for L3Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match *self {
            Self::Ipv4 => write!(f, "IPv4"),
            Self::Ipv6 => write!(f, "IPv6"),
            other => write!(f, "[unknown L3 type {}]", other.0),
        }
    }
}

/// Bitmask indicating how an agent packet is compressed.
pub type CompressionMode = u8;

/// CompressionMode constants (RFC 6.5 § 6.3.11)
pub mod compression_mode {
    use super::CompressionMode;

    pub const DESTINATION_PORT_PRESENT: CompressionMode = 0x20;
    pub const SOURCE_PORT_PRESENT: CompressionMode = 0x40;
    //pub const IP_PROTOCOL_PRESENT: CompressionMode = 0x80; // FIXME: this seems unused; I have a Q out to Frank about it
}
