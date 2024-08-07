//! Static system configuration.

/// Size of a packet buffer.
pub const PACKET_BUFFER_SIZE: usize = 4096 * 3;

/// Size of headroom necessary for most messages.
pub const DEFAULT_MESSAGE_HEADROOM: usize = 256;

pub const DEFAULT_REQUEST_RETRY_COUNT: usize = 3;
pub const DEFAULT_REQUEST_RETRY_TIMER: usize = 1;
