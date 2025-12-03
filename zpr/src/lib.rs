//! ZPR concepts, excluding the ZDP protocol.

pub mod rpc_commands;
pub mod vsapi_types;
pub mod vsapi_types_writers;

capnp::generated_code!(pub mod cli_capnp);
pub mod admin_api {
    pub use super::cli_capnp as v1;
}

capnp::generated_code!(pub mod policy_capnp);
pub mod policy {
    pub use super::policy_capnp as v1;
}

capnp::generated_code!(pub mod vs_capnp);
pub mod vsapi {
    pub use super::vs_capnp as v1;
}

use open_enum::open_enum;
use std::net::{IpAddr, Ipv6Addr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Substrate Address
pub type SubstrateAddr = std::net::SocketAddr;

/// Default prefix length for local tun IPv6 ZPR addresses.
pub const ZPRNET_PREFIX_LEN: u8 = 32;

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

/// Link ID used to refer to a node or adapter's local actor.
pub const LOCAL_ACTOR_LINK_ID: LinkId = 1;

/// Link ID used on an adapter to refer to the dock to which it's connected,
/// or on a node to refer to the node's internal dock.
pub const DOCK_LINK_ID: LinkId = 2;

/// Stream ID
pub type StreamId = u32;

/// Forwarding entry used both for forwarding next-hops and looking up forwarding next-hops
#[derive(Clone)]
pub struct ForwardingEntry(pub LinkId, pub StreamId);

/// Visa ID
// TODO: Generate from Thrift instead?
pub type VisaId = i32;

// TODO: Get rid of this?
pub const SPECIAL_VISA_ID: VisaId = 0;

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

/// Key Management Identifier indicating Null algorithm.
pub const KM_ID_NULL: KmId = 0;

/// ZPR actor packet L3 type (RFC 6.5 § 6.3.11)
#[open_enum]
#[derive(
    Copy, Clone, Debug, Default, FromBytes, Hash, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(u8)]
pub enum L3Type {
    Ipv4 = 4,
    Ipv6 = 6,
}

impl L3Type {
    pub fn new_from_addr(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => L3Type::Ipv4,
            IpAddr::V6(_) => L3Type::Ipv6,
        }
    }
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

/// Trait for that from which an L3Type can be derived.
#[allow(dead_code)]
pub trait L3TypeDeriveable {
    fn l3_type(&self) -> L3Type;
}

/// Derive L3Type from an IP address.
impl L3TypeDeriveable for IpAddr {
    fn l3_type(&self) -> L3Type {
        match self {
            IpAddr::V4(_) => L3Type::Ipv4,
            IpAddr::V6(_) => L3Type::Ipv6,
        }
    }
}

/// Bitmask indicating how an actor packet is compressed.
pub type CompressionMode = u8;

/// CompressionMode constants (RFC 6.5 § 6.3.11)
pub mod compression_mode {
    use super::CompressionMode;

    pub const DESTINATION_PORT_PRESENT: CompressionMode = 0x20;
    pub const SOURCE_PORT_PRESENT: CompressionMode = 0x40;
    //pub const IP_PROTOCOL_PRESENT: CompressionMode = 0x80; // FIXME: this seems unused; I have a Q out to Frank about it
}

/// Traffic classification specification type.
#[open_enum]
#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum Tcst {
    Ip5Tuple = 0,
}

impl std::fmt::Display for Tcst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match *self {
            Self::Ip5Tuple => write!(f, "IP 5-Tuple"),
            other => write!(f, "[unknown TCST {}]", other.0),
        }
    }
}

// Well-known DNs.

const DN_CN_DER_PREFIX_LEN: usize = 13;

const fn encode_dn_cn_as_der<const DER_LEN: usize>(cn: &str) -> [u8; DER_LEN] {
    let mut der = [0u8; DER_LEN];

    der[0] = 0x30; // SEQUENCE
    der[1] = (cn.len() + 11) as u8; // length

    der[2] = 0x31; // SET
    der[3] = (cn.len() + 9) as u8; // length

    der[4] = 0x30; // SEQUENCE
    der[5] = (cn.len() + 7) as u8; // length

    der[6] = 0x06; // OBJECT IDENTIFIER
    der[7] = 3; // length = 3
    der[8] = 2 * 40 + 5; // 2.5
    der[9] = 4; // .4
    der[10] = 3; // .3 -> commonName

    der[11] = 0x0C; // UTF8STRING
    der[12] = cn.len() as u8; // length

    let mut i = 0;
    while i < cn.len() {
        der[13 + i] = cn.as_bytes()[i];
        i += 1;
    }

    der
}

macro_rules! dn_cn_der {
    ($cn:expr) => {
        encode_dn_cn_as_der::<{ DN_CN_DER_PREFIX_LEN + $cn.len() }>($cn)
    };
}

pub const VISA_SERVICE_CN: &str = "vs.zpr";
pub const VISA_SERVICE_DN: &[u8] = &dn_cn_der!(VISA_SERVICE_CN);

// Well-known addresses.

pub const ZPR_INTERNAL_NETWORK: Ipv6Addr = Ipv6Addr::new(0xfd5a, 0x5052, 0, 0, 0, 0, 0, 0);
pub const ZPR_TEMP_LOCAL_ADDRESS: Ipv6Addr = Ipv6Addr::new(0xfc00, 0x5a, 0x50, 0x52, 0, 0, 0, 1);

pub const DEFAULT_TETHER_PORT: u16 = 5000;
pub const DEFAULT_LINK_PORT: u16 = 5001;

pub const VISA_SERVICE_ADDR: IpAddr =
    IpAddr::V6(Ipv6Addr::from_bits(ZPR_INTERNAL_NETWORK.to_bits() | 1));
pub const VISA_SERVICE_PROTO: u8 = 6 /* TCP */;
pub const VISA_SERVICE_PORT: u16 = 5002;
