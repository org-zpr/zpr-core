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
use std::task::{Context, Poll, Waker, ready};
use zpr::SeqNum;

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

    /// Returns whether the given non-cancelled queued packet has been sent.
    ///
    /// Result is undefined if packet has been cancelled.
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
                waker.clone_from(cx.waker());
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
                waker.clone_from(cx.waker());
                Poll::Pending
            }
        }
    }

    /// Implementation of `Future::poll` to wait for acknowledgement
    /// of a given packet which may not yet be sent.
    pub fn poll_send_and_ack(&mut self, cx: &mut Context<'_>, id: QueuedPacketId) -> Poll<()> {
        match ready!(self.poll_send(cx, id)) {
            Some(sn) => self.poll_ack(cx, sn),
            None => Poll::Ready(()),
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
        if self.is_blocked() || self.has_blocked_packets() {
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

    /// Lookup the sequence number of a packet which had been queued
    /// and has now been sent.
    ///
    /// If the packet has already been acknowledged `None` is returned.
    ///
    /// Panics if the packet has not yet been sent (check `is_sent()` before calling).
    /// Result is undefined if packet has been cancelled.
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

    /// Retrieve the list of packets which need to be retried.
    ///
    /// The caller should send each packet returned (recreating it using the
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
    /// disposal by the caller.  Also wakes all wakers.
    ///
    /// (Note that wakers are automatically woken on drop also.)
    pub fn destruct(mut self) -> impl Iterator<Item = Pkt> {
        self.destruct_internal()
    }

    fn destruct_internal(&mut self) -> impl Iterator<Item = Pkt> + use<Pkt> {
        let unacked = std::mem::take(&mut self.unacked);
        let blocked = std::mem::take(&mut self.blocked);

        unacked
            .into_iter()
            .filter_map(|pkt| {
                pkt.map(|(pkt, waker)| {
                    waker.wake();
                    pkt
                })
            })
            .chain(blocked.into_iter().filter_map(|pkt| {
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

impl<Pkt> Drop for Sender<Pkt> {
    fn drop(&mut self) {
        self.destruct_internal().for_each(drop);
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

        if (self.recvd >> -offset) & 1 == 0 {
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

    pub fn window_size(&self) -> usize {
        self.window_size
    }
}

#[cfg(test)]
mod sender_tests {
    use super::{EnqueueResult::*, QueuedPacketId, Sender};
    use std::sync::{Arc, atomic};
    use std::task::{Context, Wake};

    struct TestWaker {
        woken: atomic::AtomicBool,
    }

    impl TestWaker {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                woken: atomic::AtomicBool::new(false),
            })
        }

        /// fetch and clear the woken flag
        pub fn woken(&self) -> bool {
            self.woken.swap(false, atomic::Ordering::Relaxed)
        }
    }

    impl Wake for TestWaker {
        fn wake(self: Arc<Self>) {
            self.woken.store(true, atomic::Ordering::Relaxed);
        }
    }

    fn assert_quiesced<Pkt>(send: &Sender<Pkt>) {
        assert!(!send.is_blocked());
        assert!(!send.has_blocked_packets());
        assert!(!send.unblock_needed());
        assert!(!send.retry_needed());
    }

    fn retry_packets_cloned_sorted<Pkt: Clone>(send: &mut Sender<Pkt>) -> Vec<(zpr::SeqNum, Pkt)> {
        let mut retry_packets: Vec<_> = send
            .retry_packets()
            .map(|(sn, pkt)| (sn, pkt.clone()))
            .collect();
        retry_packets.sort_by_key(|(sn, _pkt)| *sn);
        retry_packets
    }

    fn enqueue_packet_expect_sent<Pkt>(
        send: &mut Sender<Pkt>,
        body: Pkt,
    ) -> (zpr::SeqNum, &mut Pkt) {
        let Sent(sn, pkt) = send.enqueue_packet(body) else {
            panic!("packet blocked");
        };
        (sn, pkt)
    }

    fn enqueue_packet_expect_sent_with_sn<Pkt>(
        send: &mut Sender<Pkt>,
        body: Pkt,
        expected_sn: zpr::SeqNum,
    ) -> &mut Pkt {
        let (sn, pkt) = enqueue_packet_expect_sent(send, body);
        assert_eq!(sn, expected_sn);
        pkt
    }

    fn enqueue_packet_expect_queued<Pkt>(send: &mut Sender<Pkt>, body: Pkt) -> QueuedPacketId {
        let Queued(id) = send.enqueue_packet(body) else {
            panic!("packet sent");
        };
        id
    }

    #[test]
    fn test_initially_quiesced() {
        let mut send: Sender<()> = Sender::new();
        assert_quiesced(&send);
        assert_eq!(send.retry_packets().count(), 0);
        assert_eq!(send.destruct().count(), 0);
    }

    #[test]
    fn test_basic_send_ack() {
        let mut send: Sender<_> = Sender::new();

        for i in 0..=2 {
            let sn = i;
            let body = 100 + i;
            assert_eq!(
                *enqueue_packet_expect_sent_with_sn(&mut send, body, sn),
                body
            );
            assert!(!send.is_acked(sn));

            let pkt = send.process_ack(sn).unwrap();
            assert_eq!(pkt, body);
            assert!(send.is_acked(sn));
        }

        assert_quiesced(&send);
    }

    #[test]
    fn test_window_and_queueing() {
        let mut send: Sender<_> = Sender::new();
        send.adjust_window_size(3);

        // fill the window
        for i in 0..=2 {
            let body = 100 + i;
            assert!(!send.is_blocked());
            assert_eq!(
                *enqueue_packet_expect_sent_with_sn(&mut send, body, i),
                body
            );
            assert!(!send.has_blocked_packets());
        }

        assert!(send.is_blocked());

        // this send should block
        assert!(matches!(send.enqueue_packet(103), Queued(_)));
        assert!(send.has_blocked_packets());
        assert!(!send.unblock_needed());

        // ACK 3rd packet, should still be blocked
        assert_eq!(send.process_ack(2).unwrap(), 102);
        assert!(send.is_blocked());
        assert!(send.has_blocked_packets());
        assert!(!send.unblock_needed());
        assert!(!send.is_acked(0));
        assert!(!send.is_acked(1));
        assert!(send.is_acked(2));

        // this send should still block
        assert!(matches!(send.enqueue_packet(104), Queued(_)));

        // ACK 1st packet, should unblock one packet despite 3rd being acked
        assert_eq!(send.process_ack(0).unwrap(), 100);
        assert!(!send.is_blocked());
        assert!(send.has_blocked_packets());
        assert!(send.unblock_needed());
        assert!(send.is_acked(0));
        assert!(!send.is_acked(1));
        assert!(send.is_acked(2));

        // this send should still block (we haven't performed unblock yet)
        assert!(matches!(send.enqueue_packet(105), Queued(_)));

        // unblock 4th packet; should leave us blocked again (2nd is still unacked)
        let (sn, pkt) = send.enqueue_next_blocked_packet();
        assert_eq!(sn, 3);
        assert_eq!(*pkt, 103);
        assert!(send.is_blocked());
        assert!(send.has_blocked_packets());
        assert!(!send.unblock_needed());
        assert!(send.is_acked(0));
        assert!(!send.is_acked(1));
        assert!(send.is_acked(2));
        assert!(!send.is_acked(3));

        // ACK 2nd packet, should unblock 5 and 6 (3rd is acked, 4th unblocked)
        assert_eq!(send.process_ack(1).unwrap(), 101);
        assert!(!send.is_blocked());
        assert!(send.has_blocked_packets());
        assert!(send.unblock_needed());
        assert!(send.is_acked(0));
        assert!(send.is_acked(1));
        assert!(send.is_acked(2));
        assert!(!send.is_acked(3));

        // unblock 5th packet, should leave us ready to send 6th
        let (sn, pkt) = send.enqueue_next_blocked_packet();
        assert_eq!(sn, 4);
        assert_eq!(*pkt, 104);
        assert!(!send.is_blocked());
        assert!(send.has_blocked_packets());
        assert!(send.unblock_needed());
        assert!(send.is_acked(1));
        assert!(send.is_acked(2));
        assert!(!send.is_acked(3));
        assert!(!send.is_acked(4));

        // unblock 6th packet, should leave us blocked
        let (sn, pkt) = send.enqueue_next_blocked_packet();
        assert_eq!(sn, 5);
        assert_eq!(*pkt, 105);
        assert!(send.is_blocked());
        assert!(!send.has_blocked_packets());
        assert!(!send.unblock_needed());
        assert!(send.is_acked(2));
        assert!(!send.is_acked(3));
        assert!(!send.is_acked(4));
        assert!(!send.is_acked(5));

        // ACK 4th packet
        assert_eq!(send.process_ack(3).unwrap(), 103);
        assert!(!send.is_blocked());
        assert!(send.is_acked(2));
        assert!(send.is_acked(3));
        assert!(!send.is_acked(4));
        assert!(!send.is_acked(5));

        // this send should not block
        assert!(matches!(send.enqueue_packet(106), Sent(_, _)));
        assert!(!send.is_acked(6));

        // ACK the remainder
        for i in 4..=6 {
            assert_eq!(send.process_ack(i), Some(100 + i));
            assert!(send.is_acked(i));
        }

        assert!(send.is_acked(0));

        assert_quiesced(&send);
    }

    #[test]
    fn test_duplicate_ack() {
        let mut send: Sender<_> = Sender::new();
        send.adjust_window_size(3);

        for i in 0..=2 {
            enqueue_packet_expect_sent_with_sn(&mut send, (), i);
        }

        assert!(send.process_ack(1).is_some());
        assert!(send.process_ack(1).is_none());

        assert!(send.process_ack(2).is_some());
        assert!(send.process_ack(0).is_some());

        assert!(send.process_ack(2).is_none());

        enqueue_packet_expect_sent_with_sn(&mut send, (), 3);

        assert!(send.process_ack(0).is_none());

        assert!(send.process_ack(3).is_some());

        assert_quiesced(&send);
    }

    #[test]
    fn test_retries() {
        let mut send: Sender<_> = Sender::new();
        send.adjust_window_size(4);

        assert!(!send.retry_needed());

        for i in 0..=2 {
            enqueue_packet_expect_sent_with_sn(&mut send, 100 + i, i);
        }

        // test no packets acked
        assert!(send.retry_needed());
        assert_eq!(
            &retry_packets_cloned_sorted(&mut send),
            &[(0, 100), (1, 101), (2, 102)]
        );

        // test one packet acked
        send.process_ack(1);
        assert!(send.retry_needed());
        assert_eq!(
            &retry_packets_cloned_sorted(&mut send),
            &[(0, 100), (2, 102)]
        );

        // test new packet
        enqueue_packet_expect_sent_with_sn(&mut send, 103, 3);
        assert!(send.retry_needed());
        assert_eq!(
            &retry_packets_cloned_sorted(&mut send),
            &[(0, 100), (2, 102), (3, 103)]
        );

        // test blocked packet
        assert!(matches!(send.enqueue_packet(104), Queued(_)));
        assert_eq!(
            &retry_packets_cloned_sorted(&mut send),
            &[(0, 100), (2, 102), (3, 103)]
        );

        // test acked new packet
        send.process_ack(0);
        send.process_ack(3);
        assert!(send.retry_needed());
        assert_eq!(&retry_packets_cloned_sorted(&mut send), &[(2, 102)]);

        // test unblocked packet
        send.enqueue_next_blocked_packet();
        assert!(send.retry_needed());
        assert_eq!(
            &retry_packets_cloned_sorted(&mut send),
            &[(2, 102), (4, 104)]
        );

        // test all acked
        send.process_ack(2);
        send.process_ack(4);
        assert!(!send.retry_needed());
        assert!(retry_packets_cloned_sorted(&mut send).is_empty());

        assert_quiesced(&send);
    }

    #[test]
    fn test_cancel_and_lookup() {
        let mut send: Sender<_> = Sender::new();
        send.adjust_window_size(3);

        for i in 0..=2 {
            enqueue_packet_expect_sent_with_sn(&mut send, 100 + i, i);
        }

        let id3 = enqueue_packet_expect_queued(&mut send, 103);
        let id4 = enqueue_packet_expect_queued(&mut send, 104);
        let id5 = enqueue_packet_expect_queued(&mut send, 105);
        let id6 = enqueue_packet_expect_queued(&mut send, 106);

        assert!(!send.is_sent(id3));
        assert!(!send.is_sent(id4));
        assert!(!send.is_sent(id5));
        assert!(!send.is_sent(id6));

        // cancel a packet
        assert_eq!(send.cancel_packet(id4), Some(104));

        // unblock a non-cancelled packet
        assert_eq!(send.process_ack(0), Some(100));
        assert!(send.unblock_needed());
        let (sn3, pkt3) = send.enqueue_next_blocked_packet();
        assert_eq!(sn3, 3);
        assert_eq!(*pkt3, 103);
        assert!(send.is_sent(id3));
        assert_eq!(send.lookup_seq_num(id3), Some(3));

        // try to cancel a now-sent packet
        assert_eq!(send.cancel_packet(id3), None);
        assert!(send.is_sent(id3));
        assert_eq!(send.lookup_seq_num(id3), Some(3));

        // unblock the next packet, which is after a cancelled packet
        assert_eq!(send.process_ack(1), Some(101));
        assert!(send.unblock_needed());
        let (sn5, pkt5) = send.enqueue_next_blocked_packet();
        assert_eq!(sn5, 4);
        assert_eq!(*pkt5, 105);
        assert!(send.is_sent(id5));
        assert_eq!(send.lookup_seq_num(id5), Some(4));

        assert_eq!(send.process_ack(2), Some(102));

        // cancel the last packet, which is currently blocked
        assert!(send.has_blocked_packets());
        assert!(send.unblock_needed());
        assert_eq!(send.cancel_packet(id6), Some(106));
        assert!(!send.has_blocked_packets());
        assert!(!send.unblock_needed());

        assert_eq!(send.process_ack(3), Some(103));
        assert_eq!(send.process_ack(4), Some(105));
        assert!(send.is_sent(id3));
        assert!(send.is_sent(id5));
        assert_eq!(send.lookup_seq_num(id3), None);
        assert_eq!(send.lookup_seq_num(id5), None);

        assert_quiesced(&send);
    }

    #[test]
    fn test_polls() {
        let mut send: Sender<_> = Sender::new();
        send.adjust_window_size(3);

        // wait for ack on packet 0
        let tw0 = TestWaker::new();
        let wk0 = tw0.clone().into();
        let mut cx0 = Context::from_waker(&wk0);
        let (sn0, _) = enqueue_packet_expect_sent(&mut send, ());
        assert!(send.poll_ack(&mut cx0, sn0).is_pending());

        // packet 1 immediately acked
        let tw1 = TestWaker::new();
        let wk1 = tw1.clone().into();
        let mut cx1 = Context::from_waker(&wk1);
        let (sn1, _) = enqueue_packet_expect_sent(&mut send, ());
        send.process_ack(sn1);
        assert!(send.poll_ack(&mut cx1, sn1).is_ready());

        // wait for ack on packet 2
        let tw2 = TestWaker::new();
        let wk2 = tw2.clone().into();
        let mut cx2 = Context::from_waker(&wk2);
        let (sn2, _) = enqueue_packet_expect_sent(&mut send, ());
        assert!(send.poll_ack(&mut cx2, sn2).is_pending());

        // wait for send on packet 3
        let tw3 = TestWaker::new();
        let wk3 = tw3.clone().into();
        let mut cx3 = Context::from_waker(&wk3);
        let id3 = enqueue_packet_expect_queued(&mut send, ());
        assert!(send.poll_send(&mut cx3, id3).is_pending());

        // wait for send and ack on packet 4
        let tw4 = TestWaker::new();
        let wk4 = tw4.clone().into();
        let mut cx4 = Context::from_waker(&wk4);
        let id4 = enqueue_packet_expect_queued(&mut send, ());
        assert!(send.poll_send_and_ack(&mut cx4, id4).is_pending());

        // ack packet 0
        tw0.woken();
        send.process_ack(sn0);
        assert!(tw0.woken());
        assert!(send.poll_ack(&mut cx0, sn0).is_ready());

        // send packet 3
        tw3.woken();
        let (sn3, _) = send.enqueue_next_blocked_packet();
        assert!(tw3.woken());
        assert!(send.poll_send(&mut cx3, id3).is_ready());

        // send packet 4
        let (sn4, _) = send.enqueue_next_blocked_packet();
        assert!(send.poll_send_and_ack(&mut cx4, id4).is_pending());

        // ack packet 4
        tw4.woken();
        send.process_ack(sn4);
        assert!(tw4.woken());
        assert!(send.poll_send_and_ack(&mut cx4, id4).is_ready());

        // queue but don't poll packets 5 and 6
        let tw5 = TestWaker::new();
        let wk5 = tw5.clone().into();
        let mut cx5 = Context::from_waker(&wk5);
        let id5 = enqueue_packet_expect_queued(&mut send, ());

        let tw6 = TestWaker::new();
        let wk6 = tw6.clone().into();
        let mut cx6 = Context::from_waker(&wk6);
        let id6 = enqueue_packet_expect_queued(&mut send, ());

        // ack packet 2
        tw2.woken();
        send.process_ack(sn2);
        assert!(tw2.woken());
        assert!(send.poll_ack(&mut cx2, sn2).is_ready());

        // send packet 5 then poll
        send.process_ack(sn3);
        let (sn5, _) = send.enqueue_next_blocked_packet();
        assert!(send.poll_send(&mut cx5, id5).is_ready());

        // send and ack packet 6, then poll
        let (sn6, _) = send.enqueue_next_blocked_packet();
        send.process_ack(sn6);
        assert!(send.poll_send_and_ack(&mut cx6, id6).is_ready());

        send.process_ack(sn5);

        assert_quiesced(&send);
    }
}

#[cfg(test)]
mod receiver_tests {
    use super::{Disposition::*, Receiver};

    #[test]
    fn test_in_order() {
        let mut recv = Receiver::new(1);
        assert!(matches!(recv.process_packet(0), AckAndProcess));
        assert!(matches!(recv.process_packet(1), AckAndProcess));
        assert!(matches!(recv.process_packet(2), AckAndProcess));
        assert!(matches!(recv.process_packet(3), AckAndProcess));
        assert!(matches!(recv.process_packet(4), AckAndProcess));
    }

    #[test]
    fn test_out_of_order_within_window() {
        let mut recv = Receiver::new(3);
        assert!(matches!(recv.process_packet(2), AckAndProcess));
        assert!(matches!(recv.process_packet(0), AckAndProcess));
        assert!(matches!(recv.process_packet(3), AckAndProcess));
        assert!(matches!(recv.process_packet(1), AckAndProcess));
        assert!(matches!(recv.process_packet(6), AckAndProcess));
    }

    #[test]
    fn test_out_of_order_ahead_of_window() {
        let mut recv = Receiver::new(3);
        assert!(matches!(recv.process_packet(3), Ignore));
        assert!(matches!(recv.process_packet(3), Ignore));
        assert!(matches!(recv.process_packet(0), AckAndProcess));
        assert!(matches!(recv.process_packet(3), AckAndProcess));
        assert!(matches!(recv.process_packet(4), Ignore));
    }

    #[test]
    fn duplicate_within_window() {
        let mut recv = Receiver::new(3);
        assert!(matches!(recv.process_packet(0), AckAndProcess));
        assert!(matches!(recv.process_packet(2), AckAndProcess));
        assert!(matches!(recv.process_packet(0), AckDoNotProcess));
        assert!(matches!(recv.process_packet(2), AckDoNotProcess));
        assert!(matches!(recv.process_packet(1), AckAndProcess));
        assert!(matches!(recv.process_packet(1), AckDoNotProcess));
    }

    #[test]
    fn duplicate_behind_window() {
        let mut recv = Receiver::new(1);
        assert!(matches!(recv.process_packet(0), AckAndProcess));
        assert!(matches!(recv.process_packet(1), AckAndProcess));
        assert!(matches!(recv.process_packet(2), AckAndProcess));
        assert!(matches!(recv.process_packet(3), AckAndProcess));
        assert!(matches!(recv.process_packet(0), Ignore));
        assert!(matches!(recv.process_packet(4), AckAndProcess));
        assert!(matches!(recv.process_packet(1), Ignore));
    }
}
