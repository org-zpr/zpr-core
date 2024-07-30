// Static system configuration.

// Size of a packet buffer.
pub const PACKET_BUFFER_SIZE: usize = 4096 * 3;

// Size of headroom necessary for Report messages
pub const REPORT_HEADROOM: usize = 256; // Not sure if config is best place, perhaps in zdp.rs?
