use crate::config;

// This contains all state of a packet which is moving through the system.
// TODO: possible we want to keep this stuff on the heap

pub struct Packet<'buf> {
    pub len: usize,
    pub buf: &'buf mut [u8; config::PACKET_BUFFER_SIZE],
}

impl<'buf> Packet<'buf> {
    // flowhash is different for different flows, but not necessarily vice-versa.
    // Ideally this is a high-entropy value useful for load balancing.
    // Must be cheap to query.
    pub fn flowhash(&self) -> u32 {
        0 /* TODO */
    }
}
