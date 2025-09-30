#![allow(dead_code)]

//! Reliable ZDP logic.
//!
//! `Sender` and `Receiver` encapsulate the sending and receiving logic
//! respectively of a reliable ZDP session.  Each side of a ZDP link will
//! have both its own `Sender` and `Receiver` state corresponding to the two
//! directions of traffic.
//!
//! These structures encapsulate only the logic involved in maintaining
//! session state.  The mechanics of sending/receiving packets and managing
//! timeouts live elsewhere.

use enum_map::{Enum, EnumMap};
use std::collections::VecDeque;
use std::task::{Context, Poll, Waker};
use zpr::SeqNum;

/// Reify the truncated sequence number relative to the reference sequence
/// number, under the assumption that it is within a window centered on the
/// highest seen value thus far.
fn reify_seq_num(reference: SeqNum, sn: u16) -> SeqNum {
    // We operate under the assumption that the difference between the
    // true sequence number and `reference` is in the range [-2^15, 2^15).

    // Under that assumption, we can subtract the truncated versions
    // of both to produce a 16-bit 2s-complement value representing
    // this difference.
    let diff = sn.wrapping_sub(reference as u16);

    // Convert the 16-bit 2s-complement value into a 64-bit signed value
    // and add back to the reference.
    reference.wrapping_add_signed((diff as i16) as i64)
}

/// Truncate a sequence number to 16 bits for sending over the ether.
pub fn truncate_seq_num(sn: SeqNum) -> u16 {
    (sn & 0xFFFF) as u16
}

/// ID of a packet which was queued for sending (but maybe not yet sent).
pub type QueuedPacketId = u64;

pub enum EnqueueResult<'a, Pkt> {
    Sent(SeqNum, &'a mut Pkt),
    Queued(QueuedPacketId),
}

/// State of the sending side of a reliable ZDP session.
///
/// `Pkt` is any abstract representation of a packet which the
/// caller can use to recreate a packet (provided also the sequence number).
pub struct Sender<Pkt> {
    /// The window size the receiver is willing to accept.
    window_size: usize,

    /// The sequence number of the most recent packet sent.
    last_sent: SeqNum,

    /// A queue representing the window of outstanding packets, indexed by
    /// sequence number.  The rightmost entry (if any) is the most recent
    /// packet sent (with sequence number `last_sent`).  Packets which have
    /// been acknowledged are marked `None`.  The contiguous prefix of
    /// oldest packets which have been acknowledged are removed entirely.
    /// Thus the maximum length of this deque is exactly the window size.
    unacked: VecDeque<Option<(Pkt, Waker)>>,

    /// The ID of the most recent packet queued waiting to be sent.
    last_enqueued: QueuedPacketId,

    /// A queue containing packets blocked waiting to be sent, indexed by
    /// packet ID.  The rightmost entry (if any) is the most recent packet
    /// enqueued (with packet ID `last_enqueued`).  Packets which have been
    /// canceled are marked `None`.  Packets are moved to the `sent` queue
    /// upon being sent, as are any preceding packets which have been canceled.
    blocked: VecDeque<Option<(Pkt, Waker)>>,

    /// A queue containing packets which had been queued but have now been
    /// sent, indexed by packet ID.  The rightmost entry (if any) is the
    /// most recent packet to have been unblocked (with packet ID
    /// `last_enqueued - blocked.len()`).  The sole purpose of this queue is
    /// to allow asynchronous awaiters to resolve packet IDs into sequence
    /// numbers.  It therefore contains as `None` placeholders packets which
    /// were canceled and never sent.  (However, any such prefix of canceled
    /// packets are always immediately removed.)
    sent: VecDeque<Option<SeqNum>>,
}

// Individual sent packets conceptually follow the following state machine.
//
// States:
//
//   BLOCKED: This packet is waiting to be sent on the wire.
//
//   CANCELED: This packet was cancelled by the caller while blocked.
//
//   UNACKED: This packet has been sent and we are waiting for the
//     remote to acknowledge receipt.  The caller should periodically
//     resend packets which are in this state.
//
//   ACKED: This packet has been acknowledged by the remote.
//
//   FORGOTTEN: We no longer have any record of this packet.
//
// Events:
//
//   ENQUEUE: The caller requests to enqueue a packet.
//
//   CANCEL: The caller requests to cancel a packet.
//
//   ACK: An acknowledgement is received for the packet.
//
//   UNBLOCK: There is now room in the window for this packet.
//
//   AGED: This packet is now the oldest packet which is not FORGOTTEN.
//
// Transitions:
//
//   new -[ENQUEUE]> BLOCKED: The window is full.
//
//   new -[ENQUEUE]> UNACKED: The window is not full.
//
//   BLOCKED -[CANCEL]> CANCELED
//
//   BLOCKED -[UNBLOCK]> UNACKED
//
//   UNACKED -[ACK]> ACKED
//
//   ACKED -[AGED]> FORGOTTEN
//
//   CANCELED -[AGED]> FORGOTTEN
//
//
// It can be seen from the above that the number of packets in UNACKED or
// ACKED is bounded by the window size.  However, the number of packets in
// BLOCKED and CANCELED (and trivially, in FORGOTTEN) are not bounded.
//
// `Waker` objects may be registered for notification when a packet leaves
// the BLOCKED and UNACKED states.  By waiting on exit of the BLOCKED state,
// the caller may implement basic flow control.  By waiting on exit of the
// UNACKED state, the caller may track forward progress of the channel.
//
// Packets which are initially BLOCKED are assigned a `QueuedPacketId` which
// may be used to refer to this packet for the rest of its lifetime.
// Packets which are initially UNACKED are likewise assigned a `SeqNum`.
// (Packets which were BLOCKED and became UNACKED are also assigned a
// `SeqNum` which the caller may look up based on the packet's
// `QueuedPacketId` while the packet is UNACKED in order to register for
// notification when the packet leaves UNACKED.  If the caller performs this
// lookup in ACKED it is simply informed that the packet has already been
// acknowledged.)

impl<Pkt> Sender<Pkt> {
    /// The maximum window size supported by the sender.
    pub const MAX_WINDOW_SIZE: usize = usize::MAX;

    // herein, all references to "offset" are relative to `last_sent`

    /// Create a new `Sender`.
    ///
    /// The window size is initially 1.  The first sequence number which
    /// will be used is 0.  `retry_needed()` will always initially return false
    /// (that is, no retry timer should be initially scheduled).
    pub fn new() -> Self {
        let window_size = 1;
        Self {
            window_size,
            last_sent: SeqNum::MAX,
            unacked: VecDeque::with_capacity(window_size),
            last_enqueued: QueuedPacketId::MAX,
            blocked: VecDeque::new(),
            sent: VecDeque::new(),
        }
    }

    /// Adjust the window size the sender will use.
    ///
    /// If adjusted down, outstanding unacknowledged packets outside the
    /// window will still be retried until they are acknowledged.  However
    /// the sender will remain blocked until no such packets remain.
    ///
    /// The window size must be at least 1.  If the provided window size is greater
    /// than the maximum, it is clamped to the maximum.
    pub fn adjust_window_size(&mut self, window_size: usize) {
        assert!(window_size >= 1);
        let window_size = std::cmp::min(Self::MAX_WINDOW_SIZE, window_size);

        self.window_size = window_size;
        if window_size >= self.unacked.len() {
            self.unacked.reserve_exact(window_size - self.unacked.len());
        }
    }

    /// Returns true whenever the sender is unable to send new packets
    /// due to the window being full.
    pub fn is_blocked(&self) -> bool {
        self.unacked.len() >= self.window_size
    }

    /// Returns whether there are queued unsent packets.
    pub fn has_blocked_packets(&self) -> bool {
        !self.blocked.is_empty()
    }

    /// Returns whether the given queued packet has been sent.
    pub fn is_sent(&self, id: QueuedPacketId) -> bool {
        let offset = id.wrapping_sub(self.last_enqueued) as i64;
        -offset >= self.blocked.len() as i64
    }

    /// Returns whether the given sent packet has been acknowledged.
    pub fn is_acked(&self, sn: SeqNum) -> bool {
        let offset = sn.wrapping_sub(self.last_sent) as i64;

        if offset > 0 {
            return false;
        }

        if -offset >= self.unacked.len() as i64 {
            return true;
        }

        let idx = (self.unacked.len() as i64 + offset - 1) as usize;
        self.unacked[idx].is_none()
    }

    /// Implementation of `Future::poll` to wait for send of a given packet.
    pub fn poll_send(&mut self, cx: &mut Context<'_>, id: QueuedPacketId) -> Poll<Option<SeqNum>> {
        let offset = id.wrapping_sub(self.last_enqueued) as i64;
        assert!(
            offset <= 0,
            "poll of packet which has not yet been enqueued"
        );

        if -offset >= self.blocked.len() as i64 {
            return Poll::Ready(self.lookup_seq_num(id));
        }

        let idx = (self.blocked.len() as i64 + offset - 1) as usize;
        match self.blocked[idx] {
            None => panic!("poll of cancelled packet"),

            Some((_, ref mut waker)) => {
                *waker = cx.waker().clone();
                Poll::Pending
            }
        }
    }

    /// Implementation of `Future::poll` to wait for acknowledgement
    /// of a given packet.
    pub fn poll_ack(&mut self, cx: &mut Context<'_>, sn: SeqNum) -> Poll<()> {
        let offset = sn.wrapping_sub(self.last_sent) as i64;
        assert!(offset <= 0, "poll of packet which has not yet been sent");

        if -offset >= self.unacked.len() as i64 {
            return Poll::Ready(());
        }

        let idx = (self.unacked.len() as i64 + offset - 1) as usize;
        match self.unacked[idx] {
            None => Poll::Ready(()),

            Some((_, ref mut waker)) => {
                *waker = cx.waker().clone();
                Poll::Pending
            }
        }
    }

    /// Implementation of `Future::poll` to wait for acknowledgement
    /// of a given packet which may not yet be sent.
    pub fn poll_send_and_ack(&mut self, cx: &mut Context<'_>, id: QueuedPacketId) -> Poll<()> {
        match self.poll_send(cx, id) {
            Poll::Ready(Some(sn)) => self.poll_ack(cx, sn),
            Poll::Ready(None) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Attempt to enqueue the given packet.
    ///
    /// If the sender is blocked (window is full), it is placed in the
    /// local send queue and `EnqueueResult::Queued(id)` is returned, where
    /// `id` can be used to identify the packet before it is sent.  (Note,
    /// this identifier is _not_ the sequence number: packets are only assigned
    /// a sequence number once sent.)
    ///
    /// If the sender is not blocked, a sequence number is assigned and the
    /// packet is enqueued.  `EnqueueResult::Sent(sn, pkt)` is returned,
    /// where `sn` is the packet's sequence number, and `pkt` is a mutable
    /// reference to the packet.  The sender should use these to actually
    /// send a packet on the wire.
    ///
    /// Upon return, `retry_needed()` will always return true: callers
    /// should therefore schedule a timer to retry sending packets if one is
    /// not already scheduled.
    pub fn enqueue_packet(&mut self, packet: Pkt) -> EnqueueResult<'_, Pkt> {
        if self.is_blocked() {
            self.last_enqueued = self.last_enqueued.wrapping_add(1);
            self.blocked
                .push_back(Some((packet, Waker::noop().clone())));
            return EnqueueResult::Queued(self.last_enqueued);
        }

        self.unacked
            .push_back(Some((packet, Waker::noop().clone())));
        let sn = self.last_sent.wrapping_add(1);
        self.last_sent = sn;

        EnqueueResult::Sent(
            sn,
            &mut self.unacked.back_mut().unwrap().as_mut().unwrap().0,
        )
    }

    /// Attempt to cancel the specified queued packet.
    ///
    /// If the packet has not yet been sent, it is returned as `Some(pkt)`.
    ///
    /// Else, `None` is returned.
    pub fn cancel_packet(&mut self, id: QueuedPacketId) -> Option<Pkt> {
        let offset = id.wrapping_sub(self.last_enqueued) as i64;
        assert!(
            offset <= 0,
            "cancel of packet which has not yet been enqueued"
        );

        if -offset >= self.blocked.len() as i64 {
            // already sent
            return None;
        }

        let idx = (self.blocked.len() as i64 + offset - 1) as usize;

        let (pkt, waker) = self.blocked[idx].take()?;

        if idx == 0 {
            self.clean_blocked_queue();
        }

        // TODO: move wake up to caller? to minimize time under lock
        waker.wake();
        Some(pkt)
    }

    /// Expand a truncated sequence number to a full sequence number,
    /// with reference to the most recently sent packet.
    pub fn reify_seq_num(&self, sn: u16) -> SeqNum {
        reify_seq_num(self.last_sent, sn)
    }

    /// Lookup the sequence number of a packet which had been queued
    /// and has now been sent.
    ///
    /// If the packet has already been acknowledged, `None` is returned.
    pub fn lookup_seq_num(&self, id: QueuedPacketId) -> Option<SeqNum> {
        let offset = id.wrapping_sub(self.last_enqueued) as i64 + self.blocked.len() as i64;
        assert!(offset <= 0, "lookup of packet which has not yet been sent");

        if -offset >= self.sent.len() as i64 {
            // already acked
            return None;
        }

        self.sent[(self.sent.len() as i64 + offset - 1) as usize]
    }

    /// Process a received acknowledgement of the given sequence number.
    ///
    /// If this is the first acknowledgement received for that sequence
    /// number, the corresponding packet is marked acknowledged and returned
    /// for the caller to dispose of.  (In this case, it is possible also
    /// the sender has become unblocked if it were blocked.) Else `None` is
    /// returned.
    ///
    /// Upon return, callers should query `retry_needed()` to
    /// determine whether to cancel any oustanding retry timer,
    /// and `unblock_needed()` to determine whether to send
    /// blocked packets.
    pub fn process_ack(&mut self, sn: SeqNum) -> Option<Pkt> {
        let offset = sn.wrapping_sub(self.last_sent) as i64;

        if offset > 0 || -offset >= self.unacked.len() as i64 {
            return None;
        }

        let idx = (self.unacked.len() as i64 + offset - 1) as usize;
        let (pkt, waker) = self.unacked[idx].take()?;

        if idx == 0 {
            self.clean_unacked_queue();
            self.clean_sent_queue();
        }

        // TODO: move wake up to caller? to minimize time under lock
        waker.wake();
        Some(pkt)
    }

    /// Returns true if there are queued unsent packets.
    ///
    /// While this is true, the caller should process those packets via
    /// `enqueue_next_blocked_packet()`.
    pub fn unblock_needed(&self) -> bool {
        !self.is_blocked() && self.has_blocked_packets()
    }

    /// Enqueues the next queued unsent packet into the send queue.
    ///
    /// Returns the assigned sequence number and a mutable reference to
    /// the packet.  The caller should use these to actually send the
    /// packet on the wire.
    ///
    /// Panics if the sender is blocked or there are no blocked packets
    /// (i.e., if `!unblock_needed()`).
    pub fn enqueue_next_blocked_packet(&mut self) -> (SeqNum, &mut Pkt) {
        assert!(!self.is_blocked(), "sender is blocked");

        let (pkt, waker) = self
            .blocked
            .pop_front()
            .expect("no blocked packets")
            .unwrap();

        self.unacked.push_back(Some((pkt, Waker::noop().clone())));
        let sn = self.last_sent.wrapping_add(1);
        self.last_sent = sn;

        self.sent.push_back(Some(sn));
        self.clean_blocked_queue();

        waker.wake(); // TODO: move this up to the caller outside of the lock?
        (
            sn,
            &mut self.unacked.back_mut().unwrap().as_mut().unwrap().0,
        )
    }

    /// Returns whether a retry timer should currently be scheduled.
    ///
    /// Such a retry timer should invoke `retry_packets()` at a regular
    /// interval in order to resend unacked packets.
    ///
    /// On a false->true transition, a timer should be started.
    /// On a true->false transition, the timer should be cancelled.
    /// Transitions only occur in response to `enqueue_packet()` and
    /// `process_ack()`.
    pub fn retry_needed(&self) -> bool {
        !self.unacked.is_empty()
    }

    /// Retrieve the list of packets which need to be retried,
    /// and mark them as having been retried.  The caller
    /// should send each packet returned (recreating it using the
    /// provided sequence number if required).
    pub fn retry_packets(&mut self) -> impl Iterator<Item = (SeqNum, &mut Pkt)> {
        let sn_base = self
            .last_sent
            .wrapping_sub(self.unacked.len() as u64)
            .wrapping_add(1);
        self.unacked
            .iter_mut()
            .enumerate()
            .filter_map(move |(offset, pkt)| {
                pkt.as_mut()
                    .map(|(pkt, _waker)| (sn_base.wrapping_add(offset as u64), pkt))
            })
    }

    /// Destructs this object, returning all currently queued packets for
    /// disposal by the caller.
    pub fn destruct(self) -> impl Iterator<Item = Pkt> {
        self.unacked
            .into_iter()
            .filter_map(|pkt| {
                pkt.map(|(pkt, waker)| {
                    waker.wake();
                    pkt
                })
            })
            .chain(self.blocked.into_iter().filter_map(|pkt| {
                pkt.map(|(pkt, waker)| {
                    waker.wake();
                    pkt
                })
            }))
    }

    /// Maintain the invariant that there are no `None` (cancelled) entries
    /// at the front of the `blocked` queue by moving them all to the end of
    /// the `sent` queue.
    fn clean_blocked_queue(&mut self) {
        while let Some(None) = self.blocked.front() {
            self.blocked.pop_front().unwrap();
            self.sent.push_back(None);
        }
    }

    /// Maintain the invariant that there are no `None` (acknowledged)
    /// entries at the front of the `unacked` queue by removing them.
    fn clean_unacked_queue(&mut self) {
        while let Some(None) = self.unacked.front() {
            self.unacked.pop_front();
        }
    }

    /// Maintain the invariant that there are no "stale"
    /// (cancelled/acknowledged) entries at the front of the `sent` queue by
    /// removing them.
    fn clean_sent_queue(&mut self) {
        while let Some(sn) = self.sent.front() {
            match sn {
                Some(sn) if !self.is_acked(*sn) => break,
                _ => {
                    let _ = self.sent.pop_front();
                }
            }
        }
    }
}

/// Whether and how to process a received packet.
#[derive(Debug)]
pub enum Disposition {
    /// Acknowledge and process the packet.
    AckAndProcess,
    /// Acknowledge, but do not process the packet.
    AckDoNotProcess,
    /// Do not acknowledge or process the packet.
    Ignore,
}

impl Disposition {
    /// Does the disposition indicate that the packet should be acknowledged.
    pub fn should_ack(&self) -> bool {
        matches!(
            self,
            Disposition::AckAndProcess | Disposition::AckDoNotProcess
        )
    }

    /// Does the disposition indicate that the packet should be processed.
    pub fn should_process(&self) -> bool {
        matches!(self, Disposition::AckAndProcess)
    }
}

/// Receiver statistic.
///
/// Note that statistics exist only for those things which are opaque
/// to the caller.  Statistics such as "number of packets received" or
/// "number of ACKs sent" are therefore not tracked.
#[derive(Clone, Copy, Debug, Enum, strum::EnumIter)]
pub enum ReceiverStat {
    /// how many packets were rejected (without being acknowledged)
    /// due to being "too old" (either a duplicate or peer error)
    TooOld,
    /// how many packets were rejected (but acknowledged) due to being duplicates
    Duplicate,
    /// how many packets were rejected (without being acknowledged)
    /// due to being "too new" (a peer error)
    TooNew,
    /// how many packets were received and processed with a sequence number
    /// earlier than the latest seen at the time
    OutOfOrder,
}

// Just use a u64 for a bitset for now.
// Why?  It's simple, large enough, and none of the common
// "bitset" crates support efficient arbitrary shift operations.
type WindowBitset = u64;

/// State of the receiving side of a reliable ZDP session.
pub struct Receiver {
    /// The window size we are willing to accept.
    window_size: usize,

    /// The highest sequence number we've seen and accepted (chosen to acknowledge).
    highest_seen: SeqNum,

    /// A bitset representing the window of packets we are awaiting.
    ///
    /// Bits n-1..0 (MSB..LSB) represent seqnums `highest_seen-n-1`..`highest_seen`.
    ///
    /// Note that bit 0 will always be 1 (since we only adjust `highest_seen`
    /// upon receiving a packet).  We represent it anyway to simplify the implementation.
    recvd: WindowBitset,

    /// Receiver statistics.
    stats: EnumMap<ReceiverStat, u64>,
}

impl Receiver {
    /// The maximum window size the receiver can be configured with.
    pub const MAX_WINDOW_SIZE: usize = WindowBitset::BITS as usize;

    // herein, all references to "offset" are relative to `highest_seen`

    /// Create a new ZDP-R receiver.
    ///
    /// The specified window size must be at least 1 and must be
    /// at most `MAX_WINDOW_SIZE`.
    pub fn new(window_size: usize) -> Self {
        assert!(window_size >= 1);
        assert!(window_size <= Self::MAX_WINDOW_SIZE);

        Self {
            window_size,
            highest_seen: SeqNum::MAX,
            recvd: WindowBitset::MAX,
            stats: Default::default(),
        }
    }

    /// Reify the truncated sequence number into a full sequence number.
    pub fn reify_seq_num(&self, sn: u16) -> SeqNum {
        reify_seq_num(self.highest_seen, sn)
    }

    fn oldest_unrecvd_offset(&self) -> i64 {
        -(WindowBitset::BITS as i64) + (self.recvd.leading_ones() as i64) + 1
    }

    /// Process the full sequence number of a received packet.
    ///
    /// The return value indicates whether and how to process
    /// the associated packet.
    pub fn process_packet(&mut self, sn: SeqNum) -> Disposition {
        let offset = sn.wrapping_sub(self.highest_seen) as i64;

        if offset <= -(self.window_size as i64) {
            // Too old!  Ignore.  (Should only happen due to race with an already-received ACK.)
            self.stats[ReceiverStat::TooOld] += 1;
            return Disposition::Ignore;
        }

        if offset >= self.oldest_unrecvd_offset() + (self.window_size as i64) {
            // Too new!  Ignore.  (Shouldn't happen if peer is functioning properly.)
            self.stats[ReceiverStat::TooNew] += 1;
            return Disposition::Ignore;
        }

        if offset > 0 {
            // Newer than any we've seen prior; accept, shift the window, and mark.
            self.highest_seen = self.highest_seen.wrapping_add(offset as SeqNum);
            self.recvd <<= offset;
            self.recvd |= 1;
            return Disposition::AckAndProcess;
        }

        if (self.recvd >> -offset) & 1 != 0 {
            // Old, but within our window.  Accept and mark.
            self.stats[ReceiverStat::OutOfOrder] += 1;
            self.recvd |= 1 << -offset;
            return Disposition::AckAndProcess;
        }

        // Already seen.  Do not process, but still acknowledge.
        self.stats[ReceiverStat::Duplicate] += 1;
        return Disposition::AckDoNotProcess;
    }

    /// Fetch & reset the specified statistic.
    pub fn fetch_reset_stat(&mut self, stat: ReceiverStat) -> u64 {
        std::mem::take(&mut self.stats[stat])
    }
}

#[cfg(test)]
mod global_tests {
    use super::reify_seq_num;

    #[test]
    fn test_reify() {
        assert_eq!(reify_seq_num(0x12342000, 0x2000), 0x12342000);
        assert_eq!(reify_seq_num(0x12342000, 0x2001), 0x12342001);
        assert_eq!(reify_seq_num(0x12342000, 0x1FFF), 0x12341FFF);
        assert_eq!(reify_seq_num(0x12342000, 0x3000), 0x12343000);
        assert_eq!(reify_seq_num(0x12342000, 0x1000), 0x12341000);
        assert_eq!(reify_seq_num(0x12342000, 0x9000), 0x12349000);
        assert_eq!(reify_seq_num(0x12342000, 0xF000), 0x1233F000);
        assert_eq!(reify_seq_num(0x12342000, 0xB000), 0x1233B000);
        assert_eq!(reify_seq_num(0x12342000, 0xA000), 0x1233A000);

        assert_eq!(reify_seq_num(0x1234E000, 0xE000), 0x1234E000);
        assert_eq!(reify_seq_num(0x1234E000, 0xDFFF), 0x1234DFFF);
        assert_eq!(reify_seq_num(0x1234E000, 0xE001), 0x1234E001);
        assert_eq!(reify_seq_num(0x1234E000, 0xD000), 0x1234D000);
        assert_eq!(reify_seq_num(0x1234E000, 0xF000), 0x1234F000);
        assert_eq!(reify_seq_num(0x1234E000, 0x7000), 0x12347000);
        assert_eq!(reify_seq_num(0x1234E000, 0x1000), 0x12351000);
        assert_eq!(reify_seq_num(0x1234E000, 0x5000), 0x12355000);
        assert_eq!(reify_seq_num(0x1234E000, 0x6000), 0x12346000);
    }
}
