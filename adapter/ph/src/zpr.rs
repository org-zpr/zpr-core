//! ZPR concepts, excluding the ZDP protocol.
#![allow(dead_code)]

/// ZPR Parameter Index
pub type Zpi = u8;

/// ZPI 0, used for keying and early ZARP.
pub const ZPI_0: Zpi = 0;

/// The Security Association ID must fit no more than 8 bits.  Note that it shares
/// space with the ZPI.
pub type SaId = u8;

/// Link or Docking Session ID
pub type LinkId = u32;

/// Link ID used to refer to a node or adapter's local agent.
pub const AGENT_LINK_ID: LinkId = 0;

/// Link ID used by an adapter to refer to its docking session.
pub const ADAPTER_DOCKING_SESSION_ID: LinkId = 1;

/// Stream ID
pub type StreamId = u32;

/// Reserved for node-to-node / control-plane traffic.
pub const NODE_TO_NODE_STREAM_ID: StreamId = 0;

/// Within a ZDP Key Management packet, indicates the Key Managenent algorithm identifier.
pub type KmId = u16;

/// Key Management Identifier indicating "experimental" algorithm.
pub const KM_ID_EXPERIMENTAL: KmId = 255;

/// Key Management Identifier indicating IKEv2 algorithm.
pub const KM_ID_IKEV2: KmId = 1;

/// Key Management Identifier indicating Noise algorithm.
pub const KM_ID_NOISE: KmId = 2;
