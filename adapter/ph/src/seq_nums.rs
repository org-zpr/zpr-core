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

#[derive(Clone, Copy, Debug, Enum, strum::EnumIter)]
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
    #[allow(dead_code)]
    pub fn highest_seen(&self) -> SeqNum {
        self.highest_seen
    }

    /// Query the ratio of messages which have been missed
    /// within the reception window.
    #[allow(dead_code)]
    pub fn drop_rate(&self) -> f32 {
        (self.window.count_zeros() as f32) / (Self::WINDOW_SIZE as f32)
    }

    /// Reinitialize the tracker such that the given sequence number
    /// is considered the latest seen, and all prior are considered
    /// already received also.
    #[allow(dead_code)]
    pub fn resynchronize(&mut self, highest_seen: SeqNum) {
        self.highest_seen = highest_seen;
        self.window = u64::MAX;
    }

    /// Reify the truncated sequence number into an offset relative to the
    /// reference sequence number, under the assumption that it is within a
    /// window centered on the highest seen value thus far.
    fn reify_seq_num_relative(reference: SeqNum, sn: u16) -> i64 {
        // We operate under the assumption that the difference between the
        // true sequence number and `reference` is in the range [-2^15, 2^15).

        // Under that assumption, we can subtract the truncated versions
        // of both to produce a 16-bit 2s-complement value representing
        // this difference.
        let diff = sn.wrapping_sub(reference as u16);

        // Convert the 16-bit 2s-complement value into a 64-bit signed value.
        (diff as i16) as i64
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
                self.stats[SeqNumTrackerStat::Lost] += (self.window.count_zeros() as u64)
                    + ((offset as u64) - (Self::WINDOW_SIZE as u64));
                self.window = 0;
            } else {
                self.stats[SeqNumTrackerStat::Lost] += (offset as u64)
                    - ((self.window >> ((Self::WINDOW_SIZE as i64) - offset)).count_ones() as u64);
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

#[cfg(test)]
mod tests {
    use super::{truncate_seq_num, SeqNumTracker, SeqNumTrackerStat as Stat};
    use enum_map::{enum_map, EnumMap};

    fn fetch_reset_all_stats(snt: &mut SeqNumTracker) -> EnumMap<Stat, u64> {
        EnumMap::from_fn(|s| snt.fetch_reset_stat(s))
    }

    #[test]
    fn basic_tracking() {
        let mut snt = SeqNumTracker::new();

        for i in 0..5 {
            assert_eq!(snt.process_seq_num(truncate_seq_num(i)), Some(i));
        }

        assert_eq!(snt.highest_seen(), 4);
        assert_eq!(fetch_reset_all_stats(&mut snt), enum_map! { _ => 0 });
    }

    #[test]
    fn offset_sn() {
        let mut snt = SeqNumTracker::new();

        snt.resynchronize(0x123456); // wrap the truncated SN

        for i in 0x123457..0x12345c {
            assert_eq!(snt.process_seq_num(truncate_seq_num(i)), Some(i));
        }

        assert_eq!(snt.highest_seen(), 0x12345b);
        assert_eq!(fetch_reset_all_stats(&mut snt), enum_map! { _ => 0 });
    }

    #[test]
    fn wrap_tsn() {
        let mut snt = SeqNumTracker::new();

        snt.resynchronize(0x12fffd); // wrap the truncated SN

        for i in 0x12fffe..0x130003 {
            assert_eq!(snt.process_seq_num(truncate_seq_num(i)), Some(i));
        }

        assert_eq!(snt.highest_seen(), 0x130002);
        assert_eq!(fetch_reset_all_stats(&mut snt), enum_map! { _ => 0 });
    }

    #[test]
    fn too_old_basic() {
        let mut snt = SeqNumTracker::new();

        assert_eq!(snt.process_seq_num(0), Some(0));
        assert_eq!(snt.process_seq_num(0xF000), None);
        assert_eq!(snt.highest_seen(), 0);
        assert_eq!(snt.process_seq_num(1), Some(1));

        assert_eq!(
            fetch_reset_all_stats(&mut snt),
            enum_map! { Stat::TooOld => 1, _ => 0 }
        );
    }

    #[test]
    fn too_old_wrapping() {
        let mut snt = SeqNumTracker::new();
        snt.resynchronize(0x15000);

        assert_eq!(snt.process_seq_num(0x5001), Some(0x15001));
        assert_eq!(snt.process_seq_num(0x3000), None);
        assert_eq!(snt.highest_seen(), 0x15001);
        assert_eq!(snt.process_seq_num(0xF000), None);
        assert_eq!(snt.highest_seen(), 0x15001);
        assert_eq!(snt.process_seq_num(0x5002), Some(0x15002));

        assert_eq!(
            fetch_reset_all_stats(&mut snt),
            enum_map! { Stat::TooOld => 2, _ => 0 }
        );
    }

    #[test]
    fn skip_basic() {
        let mut snt = SeqNumTracker::new();

        assert_eq!(snt.process_seq_num(0), Some(0));
        assert_eq!(snt.process_seq_num(0x1000), Some(0x1000));
        assert_eq!(snt.highest_seen(), 0x1000);
        assert_eq!(snt.process_seq_num(0x1001), Some(0x1001));

        // note, the 62 unreceived packets still in the new window aren't lost yet
        assert_eq!(
            fetch_reset_all_stats(&mut snt),
            enum_map! { Stat::Lost => 0xFFF - 62, _ => 0 }
        );
    }

    #[test]
    fn skip_wrapping() {
        let mut snt = SeqNumTracker::new();
        snt.resynchronize(0x8FFF);

        assert_eq!(snt.process_seq_num(0x9000), Some(0x9000));
        assert_eq!(snt.process_seq_num(0xB000), Some(0xB000));
        assert_eq!(snt.highest_seen(), 0xB000);
        assert_eq!(snt.process_seq_num(0x1000), Some(0x11000));
        assert_eq!(snt.highest_seen(), 0x11000);

        // note, the 63 unreceived packets still in the new window aren't lost yet
        assert_eq!(
            fetch_reset_all_stats(&mut snt),
            enum_map! { Stat::Lost => 0x7FFE - 63, _ => 0 }
        );
    }

    #[test]
    fn out_of_order() {
        let mut snt = SeqNumTracker::new();

        assert_eq!(snt.process_seq_num(truncate_seq_num(0)), Some(0));
        assert_eq!(snt.process_seq_num(truncate_seq_num(2)), Some(2));
        assert_eq!(snt.process_seq_num(truncate_seq_num(1)), Some(1));
        assert_eq!(snt.process_seq_num(truncate_seq_num(4)), Some(4));
        assert_eq!(snt.process_seq_num(truncate_seq_num(3)), Some(3));
        assert_eq!(snt.highest_seen(), 4);

        assert_eq!(
            fetch_reset_all_stats(&mut snt),
            enum_map! { Stat::OutOfOrder => 2, _ => 0 }
        );
    }

    #[test]
    fn duplicate_basic() {
        let mut snt = SeqNumTracker::new();

        assert_eq!(snt.process_seq_num(0xFFFF), None);

        for i in 0..5 {
            assert_eq!(snt.process_seq_num(truncate_seq_num(i)), Some(i));
        }

        for i in 0..5 {
            assert_eq!(snt.process_seq_num(truncate_seq_num(i)), None);
            assert_eq!(snt.highest_seen(), 4);
        }

        assert_eq!(
            fetch_reset_all_stats(&mut snt),
            enum_map! { Stat::Duplicate => 6, _ => 0 }
        );
    }

    #[test]
    fn duplicate_skip() {
        let mut snt = SeqNumTracker::new();

        for i in 0..5 {
            assert_eq!(snt.process_seq_num(truncate_seq_num(i)), Some(i));
        }

        assert_eq!(snt.process_seq_num(0x1000), Some(0x1000));

        for i in 0..5 {
            assert_eq!(
                snt.process_seq_num(truncate_seq_num(0xfff - i)),
                Some(0xfff - i)
            );
        }

        for i in 0..5 {
            assert_eq!(
                snt.process_seq_num(truncate_seq_num(0x1001 + i)),
                Some(0x1001 + i)
            );
        }

        assert_eq!(
            fetch_reset_all_stats(&mut snt),
            enum_map! { Stat::Lost => 0x1000 - 63, Stat::OutOfOrder => 5, _ => 0 }
        );
    }

    #[test]
    fn test_clear_stats() {
        let mut snt = SeqNumTracker::new();

        // Out of order
        snt.process_seq_num(1);
        snt.process_seq_num(0);

        // Duplicate
        snt.process_seq_num(0);

        // Too old
        snt.process_seq_num(0xF000);

        // Lose a packet
        snt.process_seq_num(66);

        assert_eq!(fetch_reset_all_stats(&mut snt), enum_map! { _ => 1 });
        assert_eq!(fetch_reset_all_stats(&mut snt), enum_map! { _ => 0 });
    }

    #[test]
    fn test_reify() {
        assert_eq!(SeqNumTracker::reify_seq_num_relative(0x2000, 0x2000), 0);
        assert_eq!(SeqNumTracker::reify_seq_num_relative(0x2000, 0x2001), 1);
        assert_eq!(SeqNumTracker::reify_seq_num_relative(0x2000, 0x1FFF), -1);
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0x2000, 0x3000),
            0x1000
        );
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0x2000, 0x1000),
            -0x1000
        );
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0x2000, 0x9000),
            0x7000
        );
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0x2000, 0xF000),
            -0x3000
        );
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0x2000, 0xB000),
            -0x7000
        );
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0x2000, 0xA000),
            -0x8000
        );

        assert_eq!(SeqNumTracker::reify_seq_num_relative(0xE000, 0xE000), 0);
        assert_eq!(SeqNumTracker::reify_seq_num_relative(0xE000, 0xDFFF), -1);
        assert_eq!(SeqNumTracker::reify_seq_num_relative(0xE000, 0xE001), 1);
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0xE000, 0xD000),
            -0x1000
        );
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0xE000, 0xF000),
            0x1000
        );
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0xE000, 0x7000),
            -0x7000
        );
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0xE000, 0x1000),
            0x3000
        );
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0xE000, 0x5000),
            0x7000
        );
        assert_eq!(
            SeqNumTracker::reify_seq_num_relative(0xE000, 0x6000),
            -0x8000
        );
    }
}
