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
use replace_with::*;
use std::collections::VecDeque;
use std::task::{Context, Poll, Waker, ready};
use zpr::packet_info::SeqNum;

/// ID of a packet which was queued for sending (but maybe not yet sent).
pub type QueuedPacketId = u64;

/// State of a packet which was just enqueued.
pub enum EnqueueResult<'a, Pkt> {
    /// The packet is ready to be sent with the given sequence number.
    Sent(SeqNum, &'a mut Pkt),
    /// The packet has been enqueued with the given packet ID.
    Queued(QueuedPacketId),
}

/// Sender statistic.
///
/// Note that statistics exist only for those things which are opaque
/// to the caller.  Statistics such as "number of packets sent" or
/// "number of ACKs received" are therefore not tracked.
#[derive(Clone, Copy, Debug, Enum, strum::EnumIter)]
pub enum SenderStat {
    /// how many acknowledgement or cancel-acknowledgements were ignored
    /// due to either being unrequested, or sent in conflict with a previous
    /// acknowledgment (a peer error)
    InvalidAck,
    /// how many acknowledgements or cancel-acknowledgements were received
    /// after the sequence number exited the window (benign, but indicative of
    /// weird network behavior): such acks are _either_ invalid or duplicate,
    /// but we don't know which
    TooOldAck,
    /// how many acknowledgements or cancel-acknowledgements were received
    /// in duplicate (benign, but indicative of weird network behavior)
    DuplicateAck,
    /// how many acknowledgements or cancel-acknowledgements were received
    /// before they were requested (a peer error)
    TooNewAck,
}

impl SenderStat {
    /// Is a non-zero value for this statistic indicative of a protocol error
    /// perpetrated by the peer?
    ///
    /// The caller may wish to take corrective action such as resetting the link.
    pub fn is_protocol_error(&self) -> bool {
        matches!(self, Self::InvalidAck | Self::TooNewAck)
    }
}

enum UnackedState<Pkt> {
    // Note that `retries_remaining` can be 0 after a packet is sent,
    // but before retries are aged.  (This is needed so the sender can
    // still reference the packet body.)
    Unacked {
        packet: Pkt,
        waker: Waker,
        retry_limit: Option<u8>,
        retry_count: u8,
        forgotten: bool,
    },
    CancelRequested {
        waker: Waker,
        forgotten: bool,
    },
    Acked,
    CancelAcked,
}

impl<Pkt> UnackedState<Pkt> {
    /// Does this represent an acknowledgement or cancel-acknowledgement.
    pub fn is_acked(&self) -> bool {
        matches!(self, UnackedState::Acked | UnackedState::CancelAcked)
    }

    /// Attempt to transition from `Unacked` to `CancelRequested`.
    /// Returns the canceled packet if successful.
    pub fn cancel(&mut self) -> Option<Pkt> {
        replace_with_or_abort_and_return(self, |s| match s {
            Self::Unacked {
                packet,
                waker,
                forgotten,
                ..
            } => (Some(packet), Self::CancelRequested { waker, forgotten }),
            s => (None, s),
        })
    }

    /// Set, or reduce, a retry limit.
    ///
    /// Does not enforce the limit: [age_retries()] must be called
    /// to do that.
    pub fn limit_retries(&mut self, limit: u8) {
        let Self::Unacked { retry_limit, .. } = self else {
            return;
        };
        *retry_limit = Some(std::cmp::min(limit, retry_limit.unwrap_or(u8::MAX)));
    }

    /// Forget (or, preemptively forget) the cancellation status
    /// of this packet.  Can also be used on packets which have retry limits,
    /// but not on packets which are neither cancelled nor have retry limits.
    pub fn forget(&mut self) {
        match self {
            Self::Unacked {
                retry_limit: Some(_),
                forgotten,
                ..
            }
            | Self::CancelRequested { forgotten, .. } => *forgotten = true,
            Self::CancelAcked => *self = Self::Acked,
            _ => (),
        }
    }

    /// Increment the retry count for an `Unacked` packet.
    /// If this goes below zero, transition the packet to `CancelRequested` and
    /// returns the canceled packet.
    pub fn age_retries(&mut self) -> Option<Pkt> {
        let UnackedState::Unacked {
            retry_limit,
            retry_count,
            ..
        } = self
        else {
            return None;
        };

        if let Some(limit) = retry_limit
            && retry_count >= limit
        {
            self.cancel()
        } else {
            *retry_count = retry_count.saturating_add(1);
            None
        }
    }

    /// Wake any associated waker, and return any associated packet.
    pub fn destruct(self) -> Option<Pkt> {
        match self {
            Self::Unacked { packet, waker, .. } => {
                waker.wake();
                Some(packet)
            }
            Self::CancelRequested { waker, .. } => {
                waker.wake();
                None
            }
            Self::Acked | Self::CancelAcked => None,
        }
    }
}

enum BlockedState<Pkt> {
    Blocked {
        packet: Pkt,
        waker: Waker,
        retry_limit: Option<u8>,
    },
    Canceled,
}

impl<Pkt> BlockedState<Pkt> {
    /// Attempt to transition from Blocked to Canceled.
    /// Returns the canceled packet and associated waker if successful.
    pub fn cancel(&mut self) -> Option<(Pkt, Waker)> {
        replace_with_or_abort_and_return(self, |s| match s {
            Self::Blocked { packet, waker, .. } => (Some((packet, waker)), Self::Canceled),
            s => (None, s),
        })
    }

    /// Set, or reduce, a retry limit.
    pub fn limit_retries(&mut self, limit: u8) {
        let Self::Blocked { retry_limit, .. } = self else {
            return;
        };
        *retry_limit = Some(std::cmp::min(limit, retry_limit.unwrap_or(u8::MAX)));
    }

    /// Wake any associated waker, and return any associated packet.
    pub fn destruct(self) -> Option<Pkt> {
        match self {
            Self::Blocked { packet, waker, .. } => {
                waker.wake();
                Some(packet)
            }
            Self::Canceled => None,
        }
    }
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
    /// packet sent (with sequence number `last_sent`).  The contiguous
    /// prefix of oldest packets which have been acknowledged are removed
    /// entirely.  Thus the maximum length of this deque is exactly the
    /// window size.
    unacked: VecDeque<UnackedState<Pkt>>,

    /// The ID of the most recent packet queued waiting to be sent.
    last_enqueued: QueuedPacketId,

    /// A queue containing packets blocked waiting to be sent, indexed by
    /// packet ID.  The rightmost entry (if any) is the most recent packet
    /// enqueued (with packet ID `last_enqueued`).  Packets which have been
    /// canceled are marked `None`.  Packets are moved to the `sent` queue
    /// upon being sent, as are any preceding packets which have been canceled.
    blocked: VecDeque<BlockedState<Pkt>>,

    /// A queue containing packets which had been queued but have now been
    /// sent, indexed by packet ID.  The rightmost entry (if any) is the
    /// most recent packet to have been unblocked (with packet ID
    /// `last_enqueued - blocked.len()`).  The sole purpose of this queue is
    /// to allow asynchronous awaiters to resolve packet IDs into sequence
    /// numbers.  It therefore contains as `None` placeholders packets which
    /// were canceled and never sent.  (However, any such prefix of canceled
    /// packets are always immediately removed.)
    sent: VecDeque<Option<SeqNum>>,

    /// Sender statistics.
    stats: EnumMap<SenderStat, u64>,
}

impl<Pkt> std::fmt::Display for Sender<Pkt> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "window size: {}", self.window_size)?;

        let oldest_sent = self
            .last_sent
            .wrapping_add(1)
            .wrapping_sub(self.unacked.len() as u64);
        write!(f, "Unacked: {oldest_sent} ")?;
        for st in &self.unacked {
            match st {
                UnackedState::Unacked {
                    retry_limit: None, ..
                } => write!(f, "u")?,
                UnackedState::Unacked {
                    retry_limit: Some(limit),
                    retry_count,
                    ..
                } => write!(f, "{}", limit - retry_count)?,
                UnackedState::CancelRequested {
                    forgotten: true, ..
                } => write!(f, "f")?,
                UnackedState::CancelRequested {
                    forgotten: false, ..
                } => write!(f, "c")?,
                UnackedState::Acked => write!(f, "A")?,
                UnackedState::CancelAcked => write!(f, "C")?,
            }
        }
        writeln!(f, " {}", self.last_sent)?;

        let oldest_enqueued = self
            .last_enqueued
            .wrapping_add(1)
            .wrapping_sub(self.blocked.len() as u64);
        write!(f, "Blocked: {oldest_enqueued} ")?;
        for st in &self.blocked {
            match st {
                BlockedState::Blocked {
                    retry_limit: None, ..
                } => write!(f, "b")?,
                BlockedState::Blocked {
                    retry_limit: Some(limit),
                    ..
                } => write!(f, "{limit}")?,
                BlockedState::Canceled => write!(f, "C")?,
            }
        }
        writeln!(f, " {}", self.last_enqueued)
    }
}

// Individual sent packets conceptually follow the following state machine.
//
// States:
//
//   BLOCKED: This packet is waiting to be sent on the wire.
//
//   CANCELED: This packet was canceled by the caller while in BLOCKED
//     (and thus has not yet been assigned a sequence number).
//
//   UNACKED: This packet has been sent and we are waiting for the
//     remote to acknowledge receipt.  The caller should periodically
//     resend packets which are in this state.
//
//   CANCEL_REQUESTED: This packet was canceled by the caller while in
//     UNACKED and we are waiting for the remote to acknowledge receipt.
//     The caller should periodically resend packets which are in this state.
//
//   ACKED: This packet has been acknowledged by the remote.
//
//   CANCEL_ACKED: This packet has been cancelled by the remote.
//
//   FORGOTTEN: We no longer have any record of this packet.
//
// Events:
//
//   ENQUEUE: The caller requests to enqueue a packet.
//
//   CANCEL: The caller requests to cancel a packet, or the packet's retry count is exceeded.
//
//   ACK: An acknowledgement is received for the packet.
//
//   CANCEL_ACK: A cancellation acknowledgement is received for the packet.
//
//   UNBLOCK: There is now room in the window for this packet.
//
//   FORGET: The caller requests to forget the cancellation status of a packet.
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
//   UNACKED -[CANCEL]> CANCEL_REQUESTED
//
//   UNACKED -[ACK]> ACKED
//
//   CANCEL_REQUESTED -[ACK]> ACKED
//
//   CANCEL_REQUESTED -[CANCEL_ACK]> CANCEL_ACKED
//
//   ACKED -[AGED]> FORGOTTEN
//
//   CANCEL_ACKED -[FORGET]> FORGOTTEN
//
//   CANCELED -[AGED]> FORGOTTEN
//
//
// It can be seen from the above that the number of packets in UNACKED,
// CANCEL_REQUESTED, ACKED, or CANCEL_ACKED is bounded by the window size.
// However, the number of packets in BLOCKED and CANCELED (and trivially, in
// FORGOTTEN) are not bounded.
//
// `Waker` objects may be registered for notification when a packet leaves
// the BLOCKED, UNACKED, or CANCEL_REQUESTED states.  By waiting on exit of
// the BLOCKED state, the caller may implement basic flow control.  By
// waiting on exit of the UNACKED or CANCEL_REQUESTED states, the caller may
// track forward progress of the channel.
//
// Packets which are initially BLOCKED are assigned a `QueuedPacketId` which
// may be used to refer to this packet for the rest of its lifetime.
// Packets which are initially UNACKED are likewise assigned a `SeqNum`.
// (Packets which were BLOCKED and became UNACKED are also assigned a
// `SeqNum` which the caller may look up based on the packet's
// `QueuedPacketId` while the packet is UNACKED or CANCEL_REQUESTED in order
// to register for notification when the packet leaves either of these
// states.  If the caller performs this lookup in ACKED or CANCEL_ACKED it
// is simply informed that the packet has already been acknowledged.)
//
// CANCEL_ACKED packets are not automatically aged and must be explicitly
// FORGOTten by the caller: this prevents the caller racing with the network
// to try to retrieve cancellation status.

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
            stats: Default::default(),
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
    /// Result is undefined if packet has been cancelled while queued.
    pub fn is_sent(&self, id: QueuedPacketId) -> bool {
        let offset = id.wrapping_sub(self.last_enqueued) as i64;
        -offset >= self.blocked.len() as i64
    }

    /// Returns whether the given sent packet has been acknowledged,
    /// or acknowledged as canceled.
    pub fn is_acked(&self, sn: SeqNum) -> bool {
        let offset = sn.wrapping_sub(self.last_sent) as i64;

        if offset > 0 {
            return false;
        }

        if -offset >= self.unacked.len() as i64 {
            return true;
        }

        let idx = (self.unacked.len() as i64 + offset - 1) as usize;
        self.unacked[idx].is_acked()
    }

    /// Returns whether the given packet has been acknowledged as canceled.
    ///
    /// Panics if called on a sequence number which has not been acknowledged
    /// (i.e., for which [is_acked()] returns `false`).
    ///
    /// Returns `false` for any packet whose cancellation has been forgotten,
    /// regardless of whether it was actually canceled.
    pub fn is_cancel_acked(&self, sn: SeqNum) -> bool {
        let offset = sn.wrapping_sub(self.last_sent) as i64;

        if offset > 0 {
            panic!("packet must have been acknowledged");
        }

        if -offset >= self.unacked.len() as i64 {
            return false;
        }

        let idx = (self.unacked.len() as i64 + offset - 1) as usize;
        match self.unacked[idx] {
            UnackedState::Unacked { .. } | UnackedState::CancelRequested { .. } => {
                panic!("packet must have been acknowledged")
            }

            UnackedState::CancelAcked => true,
            UnackedState::Acked => false,
        }
    }

    /// Implementation of `Future::poll` to wait for send of a given packet.
    ///
    /// Panics if the indicated packet was canceled while blocked.
    ///
    /// Returns `None` if the packet has already been acknowledged; else returns
    /// the sequence number assigned to the packet which is suitable for
    /// passing to `poll_ack()`.
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
            BlockedState::Canceled => panic!("poll of cancelled packet"),

            BlockedState::Blocked { ref mut waker, .. } => {
                waker.clone_from(cx.waker());
                Poll::Pending
            }
        }
    }

    /// Implementation of `Future::poll` to wait for acknowledgement of a given packet
    /// (or of the cancellation thereof).
    pub fn poll_ack(&mut self, cx: &mut Context<'_>, sn: SeqNum) -> Poll<()> {
        let offset = sn.wrapping_sub(self.last_sent) as i64;
        assert!(offset <= 0, "poll of packet which has not yet been sent");

        if -offset >= self.unacked.len() as i64 {
            return Poll::Ready(());
        }

        let idx = (self.unacked.len() as i64 + offset - 1) as usize;
        match self.unacked[idx] {
            UnackedState::Acked | UnackedState::CancelAcked => Poll::Ready(()),
            UnackedState::Unacked { ref mut waker, .. }
            | UnackedState::CancelRequested { ref mut waker, .. } => {
                waker.clone_from(cx.waker());
                Poll::Pending
            }
        }
    }

    /// Implementation of `Future::poll` to wait for acknowledgement
    /// of a given packet which may not yet be sent.
    ///
    /// Panics if the indicated packet was canceled while blocked.
    ///
    /// Returns `None` if the packet has already been forgotten; else returns
    /// the sequence number assigned to the packet.
    pub fn poll_send_and_ack(&mut self, cx: &mut Context<'_>, id: QueuedPacketId) -> Poll<()> {
        match ready!(self.poll_send(cx, id)) {
            Some(sn) => {
                ready!(self.poll_ack(cx, sn));
                Poll::Ready(())
            }
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
            self.blocked.push_back(BlockedState::Blocked {
                packet,
                waker: Waker::noop().clone(),
                retry_limit: None,
            });
            return EnqueueResult::Queued(self.last_enqueued);
        }

        let UnackedState::Unacked { packet, .. } =
            self.unacked.push_back_mut(UnackedState::Unacked {
                packet,
                waker: Waker::noop().clone(),
                retry_limit: None,
                retry_count: 0,
                forgotten: false,
            })
        else {
            unreachable!()
        };

        let sn = self.last_sent.wrapping_add(1);
        self.last_sent = sn;

        EnqueueResult::Sent(sn, packet)
    }

    /// Attempt to cancel the specified queued packet.
    ///
    /// If the packet has not yet been sent, it is returned as `Some(pkt)`.
    /// The packet is now canceled.
    ///
    /// Else, `None` is returned, indicating that the packet has already
    /// been sent.  The caller may then lookup the sequence numer with
    /// `lookup_seq_num()` and use `cancel_sent_packet()` to request
    /// that the receiver cancel the packet.
    pub fn cancel_queued_packet(&mut self, id: QueuedPacketId) -> Option<Pkt> {
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

        let (pkt, waker) = self.blocked[idx].cancel()?;

        if idx == 0 {
            self.clean_blocked_queue();
        }

        // TODO: move wake up to caller? to minimize time under lock
        waker.wake();
        Some(pkt)
    }

    /// Attempt to cancel the specified sent packet.
    ///
    /// This simply marks the packet to be sent as a cancellation request
    /// on future retries.
    ///
    /// Returns `None` if the packet has already been acknowledged, or a
    /// cancel requested.  Otherwise, returns `Some(pkt)`, and remote
    /// cancellation will be attempted: future retries will send
    /// cancellation requests.  Successful cancellation will then be
    /// indicated to the caller via `poll_ack()`.
    ///
    /// If `Some(pkt)` is returned, the caller may optionally also
    /// immediately send a cancellation request, rather than waiting for
    /// the next retry.
    ///
    /// If a remote cancellation is attempted, the caller *must* at
    /// some point call `forget_canceled_packet()` to indicate that
    /// it is no longer interested in the status this packet.
    pub fn cancel_sent_packet(&mut self, sn: SeqNum) -> Option<Pkt> {
        let offset = sn.wrapping_sub(self.last_sent) as i64;

        if offset > 0 || -offset >= self.unacked.len() as i64 {
            // already acknowledged
            return None;
        }

        let idx = (self.unacked.len() as i64 + offset - 1) as usize;
        self.unacked[idx].cancel()
    }

    /// Limit the number of times this packet will be retried.
    ///
    /// May be called multiple times; the lowest limit specified
    /// remains in effect.
    ///
    /// Each time a packet is retried _after_ the initial attempt counts
    /// toward this limit.  This count is relative to the initial attempt,
    /// even if retries have already been attempted.
    ///
    /// When the specified number of retries have been reached, no further
    /// retries are attempted, and instead cancellation attempts will be made.
    ///
    /// If the packet is already canceled, this has no effect.
    pub fn limit_retries_by_id(&mut self, id: QueuedPacketId, retry_limit: u8) {
        let offset = id.wrapping_sub(self.last_enqueued) as i64;
        assert!(
            offset <= 0,
            "retry-limiting of packet which has not yet been enqueued"
        );

        if -offset >= self.blocked.len() as i64 {
            if let Some(sn) = self.lookup_seq_num(id) {
                self.limit_retries_by_seq_num(sn, retry_limit);
            }
            return;
        }

        let idx = (self.blocked.len() as i64 + offset - 1) as usize;
        self.blocked[idx].limit_retries(retry_limit);
    }

    /// Limit the number of times this packet will be retried.
    ///
    /// Same as [limit_retries_by_id()], but by sequence number.
    pub fn limit_retries_by_seq_num(&mut self, sn: SeqNum, retry_limit: u8) {
        let offset = sn.wrapping_sub(self.last_sent) as i64;

        if offset > 0 || -offset >= self.unacked.len() as i64 {
            // already acknowledged
            return;
        }

        let idx = (self.unacked.len() as i64 + offset - 1) as usize;
        self.unacked[idx].limit_retries(retry_limit);
    }

    /// After a sent packet is canceled, we track the status of
    /// whether the cancellation was successful or not.
    /// This method allows the caller to cease tracking this status
    /// for the given packet.
    ///
    /// It is *required* to call this method at some point after a remote
    /// cancellation is issued.  (It may be called before or after
    /// the cancellation is acknowledged.)
    ///
    /// This method is a no-op if cancellation was not in fact requested.
    pub fn forget_canceled_packet(&mut self, sn: SeqNum) {
        let offset = sn.wrapping_sub(self.last_sent) as i64;

        if offset > 0 || -offset >= self.unacked.len() as i64 {
            return;
        }

        let idx = (self.unacked.len() as i64 + offset - 1) as usize;

        self.unacked[idx].forget();

        if idx == 0 {
            self.clean_unacked_queue();
        }
        self.clean_sent_queue();
    }

    /// Lookup the sequence number of a packet which had been queued
    /// and has now been sent.
    ///
    /// If the packet has already been acknowledged `None` is returned.
    /// (However, packets which have been cancel-acknowledged and not
    /// yet forgotten do still resolve to a sequence number.)
    ///
    /// Panics if the packet has not yet been sent (check `is_sent()` before calling).
    /// Result is undefined if packet has been cancelled prior to sending.
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
    /// number, the corresponding packet is marked acknowledged and, if a
    /// cancel had not been requested, the packet is returned for the caller
    /// to dispose of.  It is possible also the sender has
    /// become unblocked if it were blocked.
    ///
    /// Else, `None` is returned.  (Note that this does _not_ necessarily
    /// indicate the acknowledgment was not heeded!  This may also occur
    /// if a cancel was requested but rejected, since the packet will have
    /// been already returned to the caller earlier.)
    ///
    /// Upon return, callers should query `retry_needed()` to
    /// determine whether to cancel any oustanding retry timer,
    /// and `unblock_needed()` to determine whether to send
    /// blocked packets.
    pub fn process_ack(&mut self, sn: SeqNum) -> Option<Pkt> {
        let idx = self.lookup_ack_index(sn)?;

        let (pkt, waker) = replace_with_or_abort_and_return(&mut self.unacked[idx], |s| match s {
            UnackedState::Unacked { packet, waker, .. } => {
                (Some((Some(packet), waker)), UnackedState::Acked)
            }

            UnackedState::CancelRequested { waker, .. } => {
                (Some((None, waker)), UnackedState::Acked)
            }

            UnackedState::Acked => {
                self.stats[SenderStat::DuplicateAck] += 1;
                (None, s)
            }

            UnackedState::CancelAcked => {
                self.stats[SenderStat::InvalidAck] += 1;
                (None, s)
            }
        })?;

        if idx == 0 {
            self.clean_unacked_queue();
        }
        self.clean_sent_queue();

        // TODO: move wake up to caller? to minimize time under lock
        waker.wake();

        pkt
    }

    /// Process a received cancellation acknowledgement of the given sequence number.
    ///
    /// Upon return, callers should query `retry_needed()` to
    /// determine whether to cancel any oustanding retry timer,
    /// and `unblock_needed()` to determine whether to send
    /// blocked packets.
    pub fn process_canceled(&mut self, sn: SeqNum) {
        let Some(idx) = self.lookup_ack_index(sn) else {
            return;
        };

        let Some(waker) = replace_with_or_abort_and_return(&mut self.unacked[idx], |s| match s {
            UnackedState::CancelRequested { waker, forgotten } => {
                if forgotten {
                    (Some(waker), UnackedState::Acked)
                } else {
                    (Some(waker), UnackedState::CancelAcked)
                }
            }

            UnackedState::Unacked { .. } | UnackedState::Acked => {
                self.stats[SenderStat::InvalidAck] += 1;
                (None, s)
            }

            UnackedState::CancelAcked => {
                self.stats[SenderStat::DuplicateAck] += 1;
                (None, s)
            }
        }) else {
            return;
        };

        if idx == 0 {
            // Note, this will only have an effect if the canceled packet was marked "forgotten".
            self.clean_unacked_queue();
        }
        self.clean_sent_queue();

        // TODO: move wake up to caller? to minimize time under lock
        waker.wake();
    }

    /// Returns `Some(idx)` if the ack or cancel is valid, `None` otherwise,
    /// where `idx` is the unacked index. Counts stats appropriately.
    fn lookup_ack_index(&mut self, sn: SeqNum) -> Option<usize> {
        let offset = sn.wrapping_sub(self.last_sent) as i64;

        if offset > 0 {
            self.stats[SenderStat::TooNewAck] += 1;
            return None;
        }

        if -offset >= self.unacked.len() as i64 {
            self.stats[SenderStat::TooOldAck] += 1;
            return None;
        }

        Some((self.unacked.len() as i64 + offset - 1) as usize)
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

        let BlockedState::Blocked {
            packet,
            waker,
            retry_limit,
        } = self.blocked.pop_front().expect("no blocked packets")
        else {
            panic!("sender is blocked");
        };

        self.unacked.push_back(UnackedState::Unacked {
            packet,
            waker: Waker::noop().clone(),
            retry_limit,
            retry_count: 0,
            forgotten: false,
        });
        let sn = self.last_sent.wrapping_add(1);
        self.last_sent = sn;

        self.sent.push_back(Some(sn));
        self.clean_blocked_queue();

        let Some(UnackedState::Unacked { packet, .. }) = self.unacked.back_mut() else {
            unreachable!()
        };

        waker.wake(); // TODO: move this up to the caller outside of the lock?
        (sn, packet)
    }

    /// Returns whether a retry timer should currently be scheduled.
    ///
    /// Such a retry timer should invoke `retry_packets()` at a regular
    /// interval in order to resend unacked packets.
    ///
    /// On a false->true transition, a timer should be started.
    /// On a true->false transition, the timer should be cancelled.
    /// Transitions only occur in response to `enqueue_packet()`,
    /// `process_ack()`, or `process_canceled()`.
    pub fn retry_needed(&self) -> bool {
        self.unacked.iter().any(|pkt| !pkt.is_acked())
    }

    /// Ages packet retry counts, and transitions expired packets to `CancelRequested`.
    ///
    /// Should be called first before querying [retry_packets()] and [retry_cancels()].
    ///
    /// Returns a list of canceled packets to be dropped.
    pub fn age_retries(&mut self) -> impl Iterator<Item = Pkt> {
        self.unacked.iter_mut().filter_map(|pkt| pkt.age_retries())
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
            .filter_map(move |(offset, pkt)| match pkt {
                UnackedState::Unacked { packet, .. } => {
                    Some((sn_base.wrapping_add(offset as u64), packet))
                }
                _ => None,
            })
    }

    /// Retrieve the list of cancels which need to be retried.
    ///
    /// The caller should send a cancellation request for each
    /// sequence number returned.
    pub fn retry_cancels(&self) -> impl Iterator<Item = SeqNum> {
        let sn_base = self
            .last_sent
            .wrapping_sub(self.unacked.len() as u64)
            .wrapping_add(1);
        self.unacked
            .iter()
            .enumerate()
            .filter_map(move |(offset, pkt)| match pkt {
                UnackedState::CancelRequested { .. } => Some(sn_base.wrapping_add(offset as u64)),
                _ => None,
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
            .filter_map(|pkt| pkt.destruct())
            .chain(blocked.into_iter().filter_map(|pkt| pkt.destruct()))
    }

    /// Maintain the invariant that there are no canceled entries
    /// at the front of the `blocked` queue by moving them all to the end of
    /// the `sent` queue.
    fn clean_blocked_queue(&mut self) {
        while let Some(BlockedState::Canceled) = self.blocked.front() {
            self.blocked.pop_front().unwrap();
            self.sent.push_back(None);
        }
    }

    /// Maintain the invariant that there are no `Acked` entries at the
    /// front of the `unacked` queue by removing them.
    ///
    /// Note that `CancelAcked` entries stay put until they are explicitly
    /// "purified" into `Acked` entries, since that is an operation
    /// which loses information.
    fn clean_unacked_queue(&mut self) {
        while let Some(UnackedState::Acked) = self.unacked.front() {
            self.unacked.pop_front();
        }
    }

    /// Maintain the invariant that there are no "stale"
    /// (acknowledged/canceled) entries at the front of the `sent` queue by
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

    /// Fetch & reset the specified statistic.
    pub fn fetch_reset_stat(&mut self, stat: SenderStat) -> u64 {
        std::mem::take(&mut self.stats[stat])
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
    /// Acknowledge cancellation, and do not process the packet.
    AckCancelDoNotProcess,
    /// Do not acknowledge or process the packet.
    Ignore,
}

impl Disposition {
    /// Does the disposition indicate that the packet should be acknowledged,
    /// either as received, or as canceled.  (`self.ack_is_canceled()`
    /// should be used to determine the acknowledgement type.)
    pub fn should_ack(&self) -> bool {
        matches!(
            self,
            Disposition::AckAndProcess
                | Disposition::AckDoNotProcess
                | Disposition::AckCancelDoNotProcess
        )
    }

    /// Does the disposition indicate that the acknowledgement is of a packet cancellation.
    pub fn ack_is_canceled(&self) -> bool {
        matches!(self, Disposition::AckCancelDoNotProcess)
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

impl ReceiverStat {
    /// Is a non-zero value for this statistic indicative of a protocol error
    /// perpetrated by the peer?
    ///
    /// The caller may wish to take corrective action such as resetting the link.
    pub fn is_protocol_error(&self) -> bool {
        matches!(self, Self::TooNew)
    }
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

    /// A bitset representing which acknowledged packets were canceled.
    ///
    /// Indexing matches that of `recvd`.
    ///
    /// We track canceled packets so we can provide idempotent responses.
    canceled: WindowBitset,

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
            canceled: WindowBitset::MAX,
            stats: Default::default(),
        }
    }

    fn oldest_unrecvd_offset(&self) -> i64 {
        -(WindowBitset::BITS as i64) + (self.recvd.leading_ones() as i64) + 1
    }

    /// Process a received packet.
    ///
    /// The return value indicates whether and how to process
    /// the associated packet.
    pub fn process_packet(&mut self, sn: SeqNum) -> Disposition {
        self.process_packet_or_cancel(sn, false)
    }

    /// Process a received cancellation request.
    ///
    /// The return value indicates whether and how to process
    /// the associated packet.  Note that `AckAndProcess` will
    /// never be returned from this method.
    pub fn process_cancel(&mut self, sn: SeqNum) -> Disposition {
        self.process_packet_or_cancel(sn, true)
    }

    fn process_packet_or_cancel(&mut self, sn: SeqNum, is_cancel: bool) -> Disposition {
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
            self.canceled <<= offset;
            if is_cancel {
                self.canceled |= 1;
                return Disposition::AckCancelDoNotProcess;
            } else {
                return Disposition::AckAndProcess;
            }
        }

        if (self.recvd >> -offset) & 1 == 0 {
            // Old, but within our window.  Accept and mark.
            self.stats[ReceiverStat::OutOfOrder] += 1;
            self.recvd |= 1 << -offset;
            if is_cancel {
                self.canceled |= 1 << -offset;
                return Disposition::AckCancelDoNotProcess;
            } else {
                return Disposition::AckAndProcess;
            }
        }

        // Already seen and within our window.  Do not process, but still acknowledge.
        self.stats[ReceiverStat::Duplicate] += 1;
        if (self.canceled >> -offset) & 1 == 0 {
            return Disposition::AckDoNotProcess;
        } else {
            return Disposition::AckCancelDoNotProcess;
        }
    }

    /// Query whether the received packet should be processed,
    /// without yet marking it as processed.
    ///
    /// This returns the same indication that a call to `process_packet()`
    /// will, but does not modify state, in case e.g. the packet is unable
    /// to be processed and therefore must be dropped.
    pub fn should_process_packet(&mut self, sn: SeqNum) -> bool {
        let offset = sn.wrapping_sub(self.highest_seen) as i64;

        if offset <= -(self.window_size as i64) {
            // Too old!  Ignore.  (Should only happen due to race with an already-received ACK.)
            return false;
        }

        if offset >= self.oldest_unrecvd_offset() + (self.window_size as i64) {
            // Too new!  Ignore.  (Shouldn't happen if peer is functioning properly.)
            return false;
        }

        if offset > 0 {
            // Newer than any we've seen prior; accept.
            return true;
        }

        if (self.recvd >> -offset) & 1 == 0 {
            // Old, but within our window.  Accept.
            return true;
        }

        // Already seen and within our window.  Do not process.
        return false;
    }

    /// Fetch & reset the specified statistic.
    pub fn fetch_reset_stat(&mut self, stat: ReceiverStat) -> u64 {
        std::mem::take(&mut self.stats[stat])
    }

    /// Returns the configured window size.
    pub fn window_size(&self) -> usize {
        self.window_size
    }
}

#[cfg(test)]
mod sender_tests {
    use super::{EnqueueResult::*, QueuedPacketId, Sender, SenderStat, SeqNum};
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

    fn retry_packets_cloned_sorted<Pkt: Clone>(send: &mut Sender<Pkt>) -> Vec<(SeqNum, Pkt)> {
        let mut retry_packets: Vec<_> = send
            .retry_packets()
            .map(|(sn, pkt)| (sn, pkt.clone()))
            .collect();
        retry_packets.sort_by_key(|(sn, _pkt)| *sn);
        retry_packets
    }

    fn retry_cancels_cloned_sorted<Pkt: Clone>(send: &Sender<Pkt>) -> Vec<SeqNum> {
        let mut retry_cancels: Vec<_> = send.retry_cancels().collect();
        retry_cancels.sort();
        retry_cancels
    }

    fn enqueue_packet_expect_sent<Pkt>(send: &mut Sender<Pkt>, body: Pkt) -> (SeqNum, &mut Pkt) {
        let Sent(sn, pkt) = send.enqueue_packet(body) else {
            panic!("packet blocked");
        };
        (sn, pkt)
    }

    fn enqueue_packet_expect_sent_with_sn<Pkt>(
        send: &mut Sender<Pkt>,
        body: Pkt,
        expected_sn: SeqNum,
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
        assert_eq!(send.retry_cancels().count(), 0);
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
    fn test_queued_cancel_and_lookup() {
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
        assert_eq!(send.cancel_queued_packet(id4), Some(104));

        // unblock a non-canceled packet
        assert_eq!(send.process_ack(0), Some(100));
        assert!(send.unblock_needed());
        let (sn3, pkt3) = send.enqueue_next_blocked_packet();
        assert_eq!(sn3, 3);
        assert_eq!(*pkt3, 103);
        assert!(send.is_sent(id3));
        assert_eq!(send.lookup_seq_num(id3), Some(3));

        // try to cancel a now-sent packet
        assert_eq!(send.cancel_queued_packet(id3), None);
        assert!(send.is_sent(id3));
        assert_eq!(send.lookup_seq_num(id3), Some(3));

        // unblock the next packet, which is after a canceled packet
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
        assert_eq!(send.cancel_queued_packet(id6), Some(106));
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
    fn test_sent_cancel() {
        let mut send: Sender<_> = Sender::new();
        send.adjust_window_size(3);

        for i in 0..=2 {
            enqueue_packet_expect_sent_with_sn(&mut send, 100 + i, i);
        }

        // ack a later packet
        assert_eq!(send.process_ack(2), Some(102));

        // cancel the first two packets
        assert_eq!(send.cancel_sent_packet(0), Some(100));
        assert_eq!(send.cancel_sent_packet(1), Some(101));

        assert!(!send.is_acked(0));
        assert!(!send.is_acked(1));
        assert!(send.is_acked(2));
        assert!(!send.is_cancel_acked(2));

        // ack one canceled packet, and cancel-ack the other
        assert_eq!(send.process_ack(0), None);
        assert!(!send.is_blocked()); // should no longer be blocked
        send.process_canceled(1);

        assert!(send.is_acked(0));
        assert!(send.is_acked(1));
        assert!(!send.retry_needed()); // acked cancel means no more retry

        assert!(!send.is_cancel_acked(0));
        assert!(send.is_cancel_acked(1));

        // send another packet, should be blocked again
        enqueue_packet_expect_sent_with_sn(&mut send, 103, 3);
        assert!(send.is_blocked());

        // forget our canceled packets
        send.forget_canceled_packet(0);
        send.forget_canceled_packet(1);

        assert!(!send.is_blocked()); // now, should no longer be blocked

        // queue should be empty now
        // (save the one packet we sent earlier)
        for i in 4..=5 {
            enqueue_packet_expect_sent_with_sn(&mut send, 100 + i, i);
        }

        for i in 3..=5 {
            assert_eq!(send.process_ack(i), Some(100 + i));
            assert!(send.is_acked(i));
            assert!(!send.is_cancel_acked(i));
        }

        assert_quiesced(&send);
    }

    #[test]
    fn test_sent_cancel_retries() {
        let mut send: Sender<_> = Sender::new();
        send.adjust_window_size(4);

        for i in 0..=2 {
            enqueue_packet_expect_sent_with_sn(&mut send, 100 + i, i);
        }

        // cancel the first two packets
        assert_eq!(send.cancel_sent_packet(0), Some(100));
        assert_eq!(send.cancel_sent_packet(1), Some(101));
        // test no packets acked

        assert!(send.retry_needed());
        assert_eq!(&retry_packets_cloned_sorted(&mut send), &[(2, 102)]);

        assert_eq!(&retry_cancels_cloned_sorted(&send), &[0, 1]);

        // test one packet cancel-acked
        send.process_canceled(1);
        assert!(send.retry_needed());
        assert_eq!(&retry_cancels_cloned_sorted(&send), &[0]);

        // test all acked
        send.process_ack(0);
        send.process_ack(2);
        assert!(!send.retry_needed());
        assert!(retry_packets_cloned_sorted(&mut send).is_empty());
        assert!(retry_cancels_cloned_sorted(&mut send).is_empty());

        assert_quiesced(&send);
    }

    #[test]
    fn test_limit_retries() {
        let mut send: Sender<_> = Sender::new();
        send.adjust_window_size(4);

        // immediately send four packets
        for i in 0..=3 {
            enqueue_packet_expect_sent_with_sn(&mut send, 100 + i, i);
        }

        // immediately limit retries of packets 0, 2, and 3
        send.limit_retries_by_seq_num(0, 3);
        send.limit_retries_by_seq_num(2, 3);
        send.limit_retries_by_seq_num(3, 3);

        // queue a fifth packet & limit its retries
        let id4 = enqueue_packet_expect_queued(&mut send, 104);
        send.limit_retries_by_id(id4, 3);

        // first retry (initial send for packet 4); packets 1-4 should still be active
        send.age_retries().for_each(drop);

        assert_eq!(
            &retry_packets_cloned_sorted(&mut send),
            &[(0, 100), (1, 101), (2, 102), (3, 103)]
        );

        assert!(retry_cancels_cloned_sorted(&send).is_empty());

        // acknowledge packet 0 to let packet 4 through
        send.process_ack(0);
        assert!(send.unblock_needed());
        let (sn4, _) = send.enqueue_next_blocked_packet();
        assert_eq!(sn4, 4);

        // retroactively limit retries of packet 1
        send.limit_retries_by_seq_num(1, 3);

        // further limit retries of packet 2 to only 2
        send.limit_retries_by_seq_num(2, 2);

        // immediately cancel packet 3
        send.cancel_sent_packet(3);

        // second retry (first for packet 4); packet 3 should now be in cancel
        send.age_retries().for_each(drop);

        assert_eq!(
            &retry_packets_cloned_sorted(&mut send),
            &[(1, 101), (2, 102), (4, 104)]
        );

        assert_eq!(&retry_cancels_cloned_sorted(&send), &[3]);

        // try to raise retry limit of packet 1 (should have no effect)
        send.limit_retries_by_seq_num(1, 10);

        // third retry (second for packet 4); packets 2 and 3 should now be in cancel
        send.age_retries().for_each(drop);

        assert_eq!(
            &retry_packets_cloned_sorted(&mut send),
            &[(1, 101), (4, 104)]
        );

        assert_eq!(&retry_cancels_cloned_sorted(&send), &[2, 3]);

        // fourth retry (third for packet 4); only packet 4 should still be active
        send.age_retries().for_each(drop);

        assert_eq!(&retry_packets_cloned_sorted(&mut send), &[(4, 104)]);

        assert_eq!(&retry_cancels_cloned_sorted(&send), &[1, 2, 3]);

        // fourth retry for packet 4; all should now be in cancel
        send.age_retries().for_each(drop);

        assert!(retry_packets_cloned_sorted(&mut send).is_empty());

        assert_eq!(&retry_cancels_cloned_sorted(&send), &[1, 2, 3, 4]);

        // cancel all
        for sn in 1..=4 {
            send.process_canceled(sn);
            send.forget_canceled_packet(sn);
        }

        assert_quiesced(&send);
    }

    #[test]
    fn test_sent_stats() {
        let mut send: Sender<_> = Sender::new();
        send.adjust_window_size(4);

        // immediately send four packets
        for i in 0..=3 {
            enqueue_packet_expect_sent_with_sn(&mut send, 100 + i, i);
        }

        // ack the first packet
        send.process_ack(0);

        // cancel packets 1 and 2
        send.cancel_sent_packet(1);
        send.cancel_sent_packet(2);

        // 1 gets canceled, 2 gets acked
        send.process_ack(2);
        send.process_canceled(1);

        // this ack is too new
        send.process_ack(4);
        assert_eq!(send.fetch_reset_stat(SenderStat::TooNewAck), 1);

        // this ack is too old
        send.process_ack(0);
        assert_eq!(send.fetch_reset_stat(SenderStat::TooOldAck), 1);

        // this ack and cancel are duplicate
        send.process_ack(2);
        send.process_canceled(1);
        assert_eq!(send.fetch_reset_stat(SenderStat::DuplicateAck), 2);

        // this ack and both cancels are erroneous (for two different reasons)
        send.process_ack(1);
        send.process_canceled(2);
        send.process_canceled(3);
        assert_eq!(send.fetch_reset_stat(SenderStat::InvalidAck), 3);

        // clean up
        send.process_ack(3);
        send.forget_canceled_packet(1);
        send.forget_canceled_packet(2);
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
    use super::{Disposition::*, Receiver, ReceiverStat};

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
        assert_eq!(recv.fetch_reset_stat(ReceiverStat::OutOfOrder), 2);
    }

    #[test]
    fn test_out_of_order_ahead_of_window() {
        let mut recv = Receiver::new(3);
        assert!(matches!(recv.process_packet(3), Ignore));
        assert!(matches!(recv.process_packet(3), Ignore));
        assert!(matches!(recv.process_packet(0), AckAndProcess));
        assert!(matches!(recv.process_packet(3), AckAndProcess));
        assert!(matches!(recv.process_packet(4), Ignore));
        assert!(matches!(recv.process_cancel(4), Ignore));
        assert_eq!(recv.fetch_reset_stat(ReceiverStat::TooNew), 4);
    }

    #[test]
    fn test_duplicate_within_window() {
        let mut recv = Receiver::new(3);
        assert!(matches!(recv.process_packet(0), AckAndProcess));
        assert!(matches!(recv.process_packet(2), AckAndProcess));
        assert!(matches!(recv.process_packet(0), AckDoNotProcess));
        assert!(matches!(recv.process_packet(2), AckDoNotProcess));
        assert!(matches!(recv.process_packet(1), AckAndProcess));
        assert!(matches!(recv.process_packet(1), AckDoNotProcess));
        assert_eq!(recv.fetch_reset_stat(ReceiverStat::Duplicate), 3);
    }

    #[test]
    fn test_duplicate_behind_window() {
        let mut recv = Receiver::new(1);
        assert!(matches!(recv.process_packet(0), AckAndProcess));
        assert!(matches!(recv.process_packet(1), AckAndProcess));
        assert!(matches!(recv.process_packet(2), AckAndProcess));
        assert!(matches!(recv.process_packet(3), AckAndProcess));
        assert!(matches!(recv.process_packet(0), Ignore));
        assert!(matches!(recv.process_packet(4), AckAndProcess));
        assert!(matches!(recv.process_packet(1), Ignore));
        assert!(matches!(recv.process_cancel(1), Ignore));
        assert_eq!(recv.fetch_reset_stat(ReceiverStat::TooOld), 3);
    }

    #[test]
    fn test_cancel() {
        let mut recv = Receiver::new(3);
        assert!(matches!(recv.process_packet(0), AckAndProcess));
        assert!(matches!(recv.process_cancel(0), AckDoNotProcess));
        assert!(matches!(recv.process_cancel(1), AckCancelDoNotProcess));
        assert!(matches!(recv.process_packet(1), AckCancelDoNotProcess));
        assert!(matches!(recv.process_packet(2), AckAndProcess));
        assert!(matches!(recv.process_cancel(0), AckDoNotProcess));
        assert!(matches!(recv.process_packet(1), AckCancelDoNotProcess));
    }
}
