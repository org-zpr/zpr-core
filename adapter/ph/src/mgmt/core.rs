#![allow(dead_code)]

//! Core management packet functions.
//!
//! These are low-level primitives; most code should use the higher-level
//! functions in `requests` instead.

use crate::assembly::Assembly;
use crate::config;
use crate::counters::ManagementCounterType;
use crate::packet::Packet;
use crate::zdp;
use crate::zdpr;
use std::task::{Context, Poll, ready};
use tracing::*;
use zerocopy::FromBytes;
use zpr::packet_info::{LINK_ID_UNKNOWN, LinkId, SeqNum, StreamId};

/// Helper to allocate a new Packet with default parameters from the heap.
/// The packet is sized to fit most outbound management traffic, but
/// is not necessarily large enough to fit any arbitrary jumbo packet.
pub fn new_heap_packet() -> Packet {
    Packet::new(
        Box::new([0u8; config::SMALL_PACKET_BUFFER_SIZE]),
        config::DEFAULT_MESSAGE_HEADROOM,
    )
}

/// Helper to allocate a new Packet suitable only for bodyless messages.
/// Since the only such messages right now are ACKs, and those are only
/// generated from within this module, this is private for now.
fn new_tiny_heap_packet() -> Packet {
    Packet::new(
        Box::new([0u8; config::TINY_PACKET_BUFFER_SIZE]),
        config::TINY_MESSAGE_HEADROOM,
    )
}

pub fn count_event(asm: &Assembly, event: ManagementCounterType) {
    debug!(target: crate::logging::targets::MGMT_EVENTS, "packet event {event}");
    asm.counters.management[event].increment();
}

pub fn count_events(asm: &Assembly, event: ManagementCounterType, count: u64) {
    if count == 0 {
        return;
    }
    debug!(target: crate::logging::targets::MGMT_EVENTS, "packet event {event} ({count})");
    asm.counters.management[event].increase_by(count);
}

/// Send a unidirectional non-flow management message on the given link.
/// The packet should contain only the message body.
pub fn send_non_flow_mgmt(
    asm: &Assembly,
    link_id: LinkId,
    packet_type: zdp::ZdpPacketType,
    packet: Packet,
) -> Sent<'_> {
    send_mgmt_helper(asm, link_id, packet_type, None, None, packet)
}

/// Send a unidirectional per-flow management message on the given link.
/// The packet should contain only the message body.
pub fn send_per_flow_mgmt(
    asm: &Assembly,
    link_id: LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: StreamId,
    packet: Packet,
) -> Sent<'_> {
    send_mgmt_helper(asm, link_id, packet_type, Some(stream_id), None, packet)
}

pub fn send_per_flow_txn_mgmt(
    asm: &Assembly,
    link_id: LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: StreamId,
    txn_id: u16,
    packet: Packet,
) -> Sent<'_> {
    send_mgmt_helper(
        asm,
        link_id,
        packet_type,
        Some(stream_id),
        Some(txn_id),
        packet,
    )
}

pub fn send_acknowledgement(asm: &Assembly, link_id: LinkId, sequence_number: SeqNum) {
    send_zdpr_common(
        asm,
        link_id,
        sequence_number,
        zdp::ZdpPacketType::Acknowledgement,
    )
}

pub fn send_cancel(asm: &Assembly, link_id: LinkId, sequence_number: SeqNum) {
    send_zdpr_common(asm, link_id, sequence_number, zdp::ZdpPacketType::Cancel)
}

pub fn send_canceled(asm: &Assembly, link_id: LinkId, sequence_number: SeqNum) {
    send_zdpr_common(asm, link_id, sequence_number, zdp::ZdpPacketType::Canceled)
}

fn send_zdpr_common(
    asm: &Assembly,
    link_id: LinkId,
    sequence_number: SeqNum,
    packet_type: zdp::ZdpPacketType,
) {
    // TODO: just allocate this on the stack, pending #985.
    let mut packet = new_tiny_heap_packet();

    let mgmt_hdr = packet.alloc_zeroed_header::<zdp::ZdpMgmtHeader>();
    mgmt_hdr.sequence_number = sequence_number.into();

    let base_hdr = packet.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
    base_hdr.packet_type = packet_type;

    // It's possible (but unlikely) the MgmtSubstrateEgress queue fills up.
    // In that case, just ignore the error; act as if the packet was dropped
    // by the substrate due to congestion.
    let _ = asm
        .mgmt_substrate_egress
        .try_enqueue_packet(link_id, &mut packet);
}

pub enum MgmtSendError {
    LinkClosed,
}

#[derive(Clone, Copy)]
enum PacketId {
    Queued(zdpr::QueuedPacketId),
    Sent(SeqNum),
    Acked,
    Canceled,
}

/// Future which represents a packet waiting to be sent on the link.
///
/// Dropping this future cancels delivery of the packet if it has not
/// already been sent.  (This ensures that the number of queued unsent
/// packets is bounded by the number of active waiters.  `self.enqueue()`
/// can be used to explicitly bypass this limit.)
///
/// Note that completion of this future does not indicate whether the peer
/// has actually received the packet!  It merely indicates that we have
/// committed to delivering the packet.
///
/// Resolves to another future which may be waited upon for acknowledgement
/// by the remote peer.  Resolves to an error if the link was terminated (and
/// therefore the packet was never sent).
#[must_use = "dropping a sent packet may cancel it"]
pub struct Sent<'a> {
    asm: &'a Assembly,
    link_id: LinkId,
    packet_id: PacketId,
    // NOTE: if we add anything without a trivial destructor,
    // modify `enqueue()` appropriately!
}

impl<'a> Sent<'a> {
    /// If sending would block, queue this packet instead.
    pub fn enqueue(self) {
        // Note that in fact, if we are blocked, we already are in the
        // queue.  So we just need to prevent running our Drop impl which
        // would take us _out_ of the queue.  `forget()` is the simplest way
        // to do that.  (This does not leak anything because we have no
        // members with nontrivial destructors.)
        std::mem::forget(self)
    }

    /// Has the packet been dequeued and sent?
    ///
    /// Once true, [try_cancel()] can no longer succeed, dropping will no
    /// longer cancel the packet, and this future will be ready immediately.
    pub fn is_sent(&self) -> bool {
        let PacketId::Queued(packet_id) = self.packet_id else {
            return true;
        };

        let Some(peer_state) = self.asm.peer_table.get(self.link_id) else {
            // We don't know whether the packet got sent before the link was dropped,
            // but `true` is compatible with the packet having been sent then dropped.
            return true;
        };
        let zdpr_send = peer_state.zdpr_send.lock().unwrap();
        zdpr_send.is_sent(packet_id)
    }

    /// Explicitly try to cancel sending the packet, returning the packet if
    /// successful, or an error if unsuccessful (meaning the packet was
    /// already sent).
    pub fn try_cancel(mut self) -> Result<Packet, Acked<'a>> {
        match self.try_cancel_internal() {
            Ok(packet) => Ok(packet),
            Err(()) => Err(Acked(self)),
        }
    }

    fn try_cancel_internal(&mut self) -> Result<Packet, ()> {
        let PacketId::Queued(packet_id) = self.packet_id else {
            return Err(());
        };

        let Some(peer_state) = self.asm.peer_table.get(self.link_id) else {
            return Err(());
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();

        if let Some(pkt) = zdpr_send.cancel_queued_packet(packet_id) {
            Ok(pkt)
        } else {
            self.update_sent_packet_id(zdpr_send.lookup_seq_num(packet_id));
            Err(())
        }
    }

    /// Returns a future which waits for this packet to be acked (after it is sent).
    pub fn acked(self) -> Acked<'a> {
        Acked(self)
    }

    // Design note: Why does request_cancel() transition to AckedOrCanceled
    // and not a hypothetical SentCancellable?  This is because it's not in
    // fact possible/meaningful to wait for a canceled packet to be sent: if
    // the packet is not yet sent, it will be canceled immediately!

    /// Request that the peer cancel this packet.
    ///
    /// This is only useful if the caller has reason to suspect that the
    /// packet is manifestly undeliverable after having been sent (e.g. due
    /// to MTU issues or deep-packet inspection).  Requesting cancellation
    /// ensures forward progress of the peer.
    ///
    /// Returns a future which resolves to an indication of whether the
    /// packet was indeed canceled.
    pub fn request_cancel(mut self) -> AckedOrCanceled<'a> {
        self.request_cancel_internal();
        AckedOrCanceled(self)
    }

    fn request_cancel_internal(&mut self) {
        if matches!(self.packet_id, PacketId::Acked | PacketId::Canceled) {
            // already acked or canceled
            return;
        }

        let Some(peer_state) = self.asm.peer_table.get(self.link_id) else {
            // no more link
            return;
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();

        if matches!(self.packet_id, PacketId::Queued(_)) {
            if self.try_cancel_internal().is_ok() {
                // immediately canceled
                self.packet_id = PacketId::Canceled;
                return;
            }
            // else, packet_id is now mutated to Sent
        }

        let PacketId::Sent(seq_num) = self.packet_id else {
            // handled above
            unreachable!();
        };

        let Some(_pkt) = zdpr_send.cancel_sent_packet(seq_num) else {
            // already acked or cancel-requested
            return;
        };

        // note, we drop the user's packet here; we could return it to them

        // send an immediate cancellation request
        // (future cancellation requests will be sent via the retry mechanism)
        send_cancel(self.asm, self.link_id, seq_num);
    }

    // Design note: Why does limit_retries() transition to AckedOrCanceled?
    // This is a deliberate philosophical choice, under the belief that
    // waiting for a packet to be sent, but then not caring whether it gets
    // delivered, is inadvisable at the application layer.  It would require
    // adding an extra state "SentCancelable" to represent this scenario,
    // which is simply not worth it.  If the user really wants to do this,
    // they can explicitly wait for the packet to be sent, and then add a
    // retry limit.

    pub fn limit_retries(mut self, retry_limit: u8) -> AckedOrCanceled<'a> {
        self.limit_retries_internal(retry_limit);
        AckedOrCanceled(self)
    }

    fn limit_retries_internal(&mut self, retry_limit: u8) {
        if matches!(self.packet_id, PacketId::Acked | PacketId::Canceled) {
            // already acked or canceled
            return;
        }

        let Some(peer_state) = self.asm.peer_table.get(self.link_id) else {
            // no more link
            return;
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();

        match self.packet_id {
            PacketId::Queued(packet_id) => zdpr_send.limit_retries_by_id(packet_id, retry_limit),
            PacketId::Sent(seq_num) => zdpr_send.limit_retries_by_seq_num(seq_num, retry_limit),
            PacketId::Acked | PacketId::Canceled => unreachable!(), // handled above
        }
    }

    fn update_sent_packet_id(&mut self, seq_num: Option<SeqNum>) {
        match seq_num {
            Some(seq_num) => self.packet_id = PacketId::Sent(seq_num),
            None => self.packet_id = PacketId::Acked,
        }
    }
}

impl<'a> Drop for Sent<'a> {
    fn drop(&mut self) {
        drop(self.try_cancel_internal())
    }
}

impl<'a> std::future::Future for Sent<'a> {
    type Output = Result<Acked<'a>, MgmtSendError>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.packet_id {
            PacketId::Queued(packet_id) => {
                let Some(peer_state) = self.asm.peer_table.get(self.link_id) else {
                    return Poll::Ready(Err(MgmtSendError::LinkClosed));
                };

                let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();
                let seq_num = ready!(zdpr_send.poll_send(cx, packet_id));
                self.update_sent_packet_id(seq_num);
                Poll::Ready(Ok(Acked(Sent {
                    asm: self.asm,
                    link_id: self.link_id,
                    packet_id: self.packet_id,
                })))
            }

            packet_id => Poll::Ready(Ok(Acked(Sent {
                asm: self.asm,
                link_id: self.link_id,
                packet_id,
            }))),
        }
    }
}

/// Future which represents the acknowledgement of a packet
/// by the link peer.  (Does _not_ indicate that the peer has
/// necessarily done anything useful with the packet!  Just that
/// we've made forward progress in communicating the packet.)
///
/// Resolves to an error if the link was terminated (and therefore
/// it is unknown whether the peer ever received the packet).
#[must_use = "dropping a sent packet may cancel it"]
pub struct Acked<'a>(Sent<'a>);

impl<'a> Acked<'a> {
    pub fn enqueue(self) {
        self.0.enqueue()
    }

    pub fn is_sent(&self) -> bool {
        self.0.is_sent()
    }

    pub fn request_cancel(self) -> AckedOrCanceled<'a> {
        self.0.request_cancel()
    }

    pub fn limit_retries(self, retry_limit: u8) -> AckedOrCanceled<'a> {
        self.0.limit_retries(retry_limit)
    }
}

impl<'a> std::future::Future for Acked<'a> {
    type Output = Result<(), MgmtSendError>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if matches!(self.0.packet_id, PacketId::Acked) {
            return Poll::Ready(Ok(()));
        }

        let Some(peer_state) = self.0.asm.peer_table.get(self.0.link_id) else {
            return Poll::Ready(Err(MgmtSendError::LinkClosed));
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();

        match self.0.packet_id {
            PacketId::Queued(packet_id) => {
                zdpr_send.poll_send_and_ack(cx, packet_id).map(|()| Ok(()))
            }
            PacketId::Sent(seq_num) => zdpr_send.poll_ack(cx, seq_num).map(|()| Ok(())),
            PacketId::Acked => unreachable!(),    // handled above
            PacketId::Canceled => unreachable!(), // not possible in this state
        }
    }
}

pub enum PacketStatus {
    /// The packet was acknowledged by the peer.  It will (should) act
    /// on the packet.
    Acked,
    /// The packet was acknowledged as canceled by the peer.  It will not
    /// act on the packet.
    Canceled,
}

/// Future which represents the acknowledgement or cancellation of a packet
/// by the link peer.  (Does _not_ indicate that the peer has necessarily
/// done anything useful with the packet!  Just that we've made forward
/// progress in communicating the packet or cancellation thereof.)
///
/// Resolves to an error if the link was terminated (and therefore
/// it is unknown whether the peer ever received the packet).
#[must_use = "dropping a sent packet may cancel it"]
pub struct AckedOrCanceled<'a>(Sent<'a>);

impl<'a> AckedOrCanceled<'a> {
    pub fn enqueue(mut self) {
        // skip Sent destructor, but not our destructor
        self.forget_internal();
        std::mem::forget(self);
    }

    pub fn is_sent(&self) -> bool {
        self.0.is_sent()
    }

    /// Although this packet is already scheduled for cancellation,
    /// the cancellation may be in the form of a retry limit;
    /// if so, this may still be used to immediately request cancellation.
    pub fn request_cancel(mut self) -> Self {
        self.0.request_cancel_internal();
        self
    }

    pub fn limit_retries(mut self, retry_limit: u8) -> Self {
        self.0.limit_retries_internal(retry_limit);
        self
    }

    fn forget_internal(&mut self) {
        let PacketId::Sent(seq_num) = self.0.packet_id else {
            return;
        };

        let Some(peer_state) = self.0.asm.peer_table.get(self.0.link_id) else {
            return;
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();
        zdpr_send.forget_canceled_packet(seq_num);
    }
}

impl<'a> std::future::Future for AckedOrCanceled<'a> {
    type Output = Result<PacketStatus, MgmtSendError>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.0.packet_id {
            PacketId::Acked => {
                return Poll::Ready(Ok(PacketStatus::Acked));
            }
            PacketId::Canceled => {
                return Poll::Ready(Ok(PacketStatus::Canceled));
            }
            _ => (),
        }

        let Some(peer_state) = self.0.asm.peer_table.get(self.0.link_id) else {
            return Poll::Ready(Err(MgmtSendError::LinkClosed));
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();

        match self.0.packet_id {
            PacketId::Queued(packet_id) => {
                ready!(zdpr_send.poll_send_and_ack(cx, packet_id));
                Poll::Ready(Ok(PacketStatus::Acked))
            }

            PacketId::Sent(seq_num) => {
                ready!(zdpr_send.poll_ack(cx, seq_num));
                if zdpr_send.is_cancel_acked(seq_num) {
                    Poll::Ready(Ok(PacketStatus::Canceled))
                } else {
                    Poll::Ready(Ok(PacketStatus::Acked))
                }
            }

            PacketId::Acked | PacketId::Canceled => unreachable!(), // handled above
        }
    }
}

impl<'a> From<Acked<'a>> for AckedOrCanceled<'a> {
    fn from(value: Acked<'a>) -> Self {
        Self(value.0)
    }
}

impl<'a> Drop for AckedOrCanceled<'a> {
    fn drop(&mut self) {
        self.forget_internal()
    }
}

fn send_mgmt_helper(
    asm: &Assembly,
    link_id: LinkId,
    packet_type: zdp::ZdpPacketType,
    stream_id: Option<StreamId>,
    txn_id: Option<u16>,
    mut packet: Packet,
) -> Sent<'_> {
    assert_ne!(packet_type, zdp::ZdpPacketType::KeyManagement);
    assert_eq!(stream_id.is_some(), packet_type.is_per_flow());

    debug_assert_eq!(stream_id.is_some(), packet_type.is_per_flow());

    if let Some(txn_id) = txn_id {
        let txn_hdr = packet.alloc_zeroed_header::<zdp::ZdpTransactionHeader>();
        txn_hdr.transaction_id = txn_id.into();
    }

    if let Some(stream_id) = stream_id {
        let per_flow_hdr = packet.alloc_zeroed_header::<zdp::ZdpPerFlowHeader>();
        per_flow_hdr.stream_id = stream_id.into();
    }

    let _mgmt_hdr = packet.alloc_zeroed_header::<zdp::ZdpMgmtHeader>();
    // sequence_number is chosen and filled in upon egress, if the packet is not cancelled

    let base_hdr = packet.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
    base_hdr.packet_type = packet_type;

    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Sent {
            asm,
            link_id: LINK_ID_UNKNOWN,
            packet_id: PacketId::Queued(0), // will not be used due to unknown link ID
        };
    };
    let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();

    let old_retry_needed = zdpr_send.retry_needed();

    match zdpr_send.enqueue_packet(packet) {
        zdpr::EnqueueResult::Sent(seq_num, pkt) => {
            build_and_egress_packets(asm, link_id, std::iter::once((seq_num, pkt)));

            debug_assert!(
                zdpr_send.retry_needed(),
                "sent packet but not signalled for retry"
            );
            if !old_retry_needed {
                // This packet should activate / restart our retry timer.
                peer_state.zdpr_retry_timer_reset.notify_one();
            }

            Sent {
                asm,
                link_id,
                packet_id: PacketId::Sent(seq_num),
            }
        }

        zdpr::EnqueueResult::Queued(packet_id) => Sent {
            asm,
            link_id,
            packet_id: PacketId::Queued(packet_id),
        },
    }
}

/// Used to send packets as instructed by ZDPR mechanism.
///
/// Simply fills in the assigned sequence number (which is
/// a no-op for retries), and forwards to the fastpath.
pub fn build_and_egress_packets<'a>(
    asm: &Assembly,
    link_id: LinkId,
    packets: impl Iterator<Item = (SeqNum, &'a mut Packet)>,
) {
    let mut dropped_backpressure = 0;

    packets.for_each(|(seq_num, packet)| {
        let (mgmt_hdr, _) = zdp::ZdpMgmtHeader::mut_from_prefix(
            &mut packet.body_mut()[std::mem::size_of::<zdp::ZdpBaseHeader>()..],
        )
        .unwrap();
        mgmt_hdr.sequence_number = seq_num.into();

        // It's possible (but unlikely) the MgmtSubstrateEgress queue fills up.
        // In that case, just ignore the error; act as if the packet was dropped
        // by the substrate due to congestion.
        if !asm
            .mgmt_substrate_egress
            .try_enqueue_packet(link_id, packet)
        {
            dropped_backpressure += 1;
        }
    });

    count_events(
        asm,
        ManagementCounterType::QueueBackpressure,
        dropped_backpressure,
    );
}
