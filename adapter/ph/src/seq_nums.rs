use enum_map::{Enum, EnumMap};
use std::sync::atomic::*;
use zpr::SeqNum;

/// Generates outgoing sequence numbers.
pub struct SeqNumGenerator {
    next: AtomicU64,
}

impl SeqNumGenerator {
    /// Initialize a new sequence number generator.
    ///
    /// The first sequence number output will be 0.
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
        }
    }

    /// Generate and return the next sequence number.
    pub fn generate_seq_num(&self) -> SeqNum {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

/// Truncate a sequence number to 16 bits for sending over the ether.
pub fn truncate_seq_num(sn: SeqNum) -> u16 {
    (sn & 0xFFFF) as u16
}

#[derive(Enum)]
pub enum SeqNumTrackerStat {
    /// how many packets were rejected due to being "too old" (and therefore possibly duplicates)
    TooOld,
    /// how many packets were rejected due to being known duplicates
    Duplicate,
    /// how many packets were never receieved in time to be validated and processed
    Lost,
    /// how many packets were received and processed with a sequence number
    /// earlier than the latest seen at the time
    OutOfOrder,
}

/// Tracks incoming sequence numbers.
///
/// Both reifies truncated sequence numbers into full sequence numbers,
/// and tracks which have been seen to detect duplicate messages.
pub struct SeqNumTracker {
    highest_seen: SeqNum,
    window: u64,
    stats: EnumMap<SeqNumTrackerStat, u64>,
}

impl SeqNumTracker {
    const WINDOW_SIZE: usize = 64;

    /// Create a new sequence number tracker.
    ///
    /// Initialized to accept sequence numbers starting at 0,
    /// and to reject (consider as old/already received) all
    /// earlier sequence numbers.
    pub fn new() -> Self {
        Self {
            highest_seen: SeqNum::MAX,
            window: u64::MAX,
            stats: Default::default(),
        }
    }

    /// Query the highest sequence number seen so far.
    /// (Useful for explicitly synchronizing.)
    pub fn highest_seen(&self) -> SeqNum {
        self.highest_seen
    }

    /// Query the ratio of messages which have been missed
    /// within the reception window.
    pub fn drop_rate(&self) -> f32 {
        (self.window.count_zeros() as f32) / (Self::WINDOW_SIZE as f32)
    }

    /// Reinitialize the tracker such that the given sequence number
    /// is considered the latest seen, and all prior are considered
    /// already received also.
    pub fn resynchronize(&mut self, highest_seen: SeqNum) {
        self.highest_seen = highest_seen;
        self.window = u64::MAX;
    }

    /// Reify the truncated sequence number into an offset relative to the
    /// reference sequence number, under the assumption that it is within a
    /// window centered on the highest seen value thus far.
    fn reify_seq_num_relative(reference: SeqNum, sn: u16) -> i64 {
        (sn.wrapping_sub((reference & 0xFFFF) as u16)
            .wrapping_add(0x8000) as i64)
            - 0x8000
    }

    /// Process the truncated sequence number of a received packet.
    ///
    /// The truncated sequence number is reified into a full sequence number
    /// according to the current window position.  If this packet
    /// is sufficiently recent and hasn't already been seen, this full
    /// sequence number is returned and the packet can be safely processed.
    /// Else, `None` is returned, and the packet should be ignored,
    /// as it may be a duplicate.
    pub fn process_seq_num(&mut self, sn: u16) -> Option<SeqNum> {
        let offset = Self::reify_seq_num_relative(self.highest_seen, sn);

        if offset <= -(Self::WINDOW_SIZE as i64) {
            // Too old!  Reject.
            self.stats[SeqNumTrackerStat::TooOld] += 1;
            return None;
        }

        if offset > 0 {
            // Newer than any we've seen prior; accept, shift the window, and mark.
            self.highest_seen = self.highest_seen.wrapping_add(offset as SeqNum);

            if offset >= Self::WINDOW_SIZE as i64 {
                self.stats[SeqNumTrackerStat::Lost] += self.window.count_zeros() as u64;
                self.window = 0;
            } else {
                self.stats[SeqNumTrackerStat::Lost] +=
                    (self.window >> ((Self::WINDOW_SIZE as i64) - offset)).count_zeros() as u64;
                self.window <<= offset;
            }
            self.window |= 1;

            return Some(self.highest_seen);
        }

        if (self.window >> -offset) & 1 != 0 {
            // Already seen.  Reject.
            self.stats[SeqNumTrackerStat::Duplicate] += 1;
            return None;
        }

        // Old, but within our window.  Accept and mark.
        self.stats[SeqNumTrackerStat::OutOfOrder] += 1;
        self.window |= 1 << -offset;
        return Some(self.highest_seen.wrapping_sub((-offset) as SeqNum));
    }

    /// Fetch & reset the specified stat.
    pub fn fetch_reset_stat(&mut self, stat: SeqNumTrackerStat) -> u64 {
        std::mem::take(&mut self.stats[stat])
    }
}
