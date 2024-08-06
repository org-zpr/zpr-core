//! ZPR concepts, excluding the ZDP protocol.
#![allow(dead_code)]

/// ZPR Parameter Index
pub type Zpi = u8;

/// ZPI 0, used for keying and early ZARP.
pub const ZPI_0: Zpi = 0;

/// Link or Docking Session ID
pub type LinkId = u32;

/// Link ID used by an adapter to refer to its docking session.
pub const ADAPTER_DOCKING_SESSION_ID: LinkId = 0;

/// Stream ID
pub type StreamId = u32;

/// Reserved for node-to-node / control-plane traffic.
pub const NODE_TO_NODE_STREAM_ID: StreamId = 0;
