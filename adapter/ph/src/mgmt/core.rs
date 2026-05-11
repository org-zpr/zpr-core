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
use std::task::{Context, Poll};
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
#[allow(dead_code)]
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

#[allow(dead_code)]
enum PacketId {
    Sent(SeqNum),
    Queued(zdpr::QueuedPacketId),
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

    /// Explicitly try to cancel the packet, returning the packet if successful,
    /// or an `Acked` future if unsuccessful (meaning the packet was already sent).
    #[allow(dead_code)]
    pub fn try_cancel(mut self) -> Result<Packet, Acked<'a>> {
        self.try_cancel_internal()
    }

    fn try_cancel_internal(&mut self) -> Result<Packet, Acked<'a>> {
        match self.packet_id {
            PacketId::Sent(seq_num) => Err(Acked {
                asm: self.asm,
                link_id: self.link_id,
                seq_num: Some(seq_num),
            }),

            PacketId::Queued(packet_id) => {
                let Some(peer_state) = self.asm.peer_table.get(self.link_id) else {
                    return Err(Acked {
                        asm: self.asm,
                        link_id: LINK_ID_UNKNOWN,
                        seq_num: None,
                    });
                };
                let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();
                if let Some(pkt) = zdpr_send.cancel_sent_packet(packet_id) {
                    Ok(pkt)
                } else {
                    Err(Acked {
                        asm: self.asm,
                        link_id: self.link_id,
                        seq_num: zdpr_send.lookup_seq_num(packet_id),
                    })
                }
            }
        }
    }

    /// Returns a future which waits for this packet to be acked (after it is sent).
    pub fn acked(self) -> SentAndAcked<'a> {
        SentAndAcked(self)
    }
}

impl<'a> Drop for Sent<'a> {
    fn drop(&mut self) {
        drop(self.try_cancel_internal())
    }
}

impl<'a> std::future::Future for Sent<'a> {
    type Output = Result<Acked<'a>, MgmtSendError>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.packet_id {
            PacketId::Sent(seq_num) => Poll::Ready(Ok(Acked {
                asm: self.asm,
                link_id: self.link_id,
                seq_num: Some(seq_num),
            })),

            PacketId::Queued(packet_id) => {
                let Some(peer_state) = self.asm.peer_table.get(self.link_id) else {
                    return Poll::Ready(Err(MgmtSendError::LinkClosed));
                };

                let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();
                zdpr_send.poll_send(cx, packet_id).map(|seq_num| {
                    Ok(Acked {
                        asm: self.asm,
                        link_id: self.link_id,
                        seq_num,
                    })
                })
            }
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
///
/// Unlike `Sent`, dropping `Acked` has no impact on delivery of the packet.
pub struct Acked<'a> {
    asm: &'a Assembly,
    link_id: LinkId,
    seq_num: Option<SeqNum>, // None indicates acked before we knew the sequenece number
}

impl<'a> Acked<'a> {
    /// Request that the peer cancel this packet.
    ///
    /// This is only useful if the caller has reason to suspect that the
    /// packet is manifestly undeliverable after having been sent (e.g. due
    /// to MTU issues or deep-packet inspection).  Requesting cancellation
    /// ensures forward progress of the peer.
    ///
    /// Returns a future which resolves to an indication of whether the
    /// packet was indeed canceled.
    #[allow(dead_code)]
    pub fn request_cancel(self) -> AckedOrCanceled<'a> {
        let Some(seq_num) = self.seq_num else {
            // was acked before we even knew the sequence number
            return AckedOrCanceled(self);
        };

        let Some(peer_state) = self.asm.peer_table.get(self.link_id) else {
            // no more link
            return AckedOrCanceled(self);
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();
        let Some(_pkt) = zdpr_send.cancel_sent_packet(seq_num) else {
            // already acked
            return AckedOrCanceled(self);
        };

        // note, we drop the user's packet here; we could return it to them

        // send an immediate cancellation request
        // (future cancellation requests will be sent via the retry mechanism)
        send_cancel(self.asm, self.link_id, seq_num);

        AckedOrCanceled(self)
    }

    // TODO: request_cancel_after aka limit_retries
}

impl<'a> std::future::Future for Acked<'a> {
    type Output = Result<(), MgmtSendError>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(seq_num) = self.seq_num else {
            return Poll::Ready(Ok(()));
        };

        let Some(peer_state) = self.asm.peer_table.get(self.link_id) else {
            return Poll::Ready(Err(MgmtSendError::LinkClosed));
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();
        zdpr_send.poll_ack(cx, seq_num).map(|()| Ok(()))
    }
}

/// Future which represents the acknowledgement or cancellation of a packet
/// by the link peer.  (Does _not_ indicate that the peer has necessarily
/// done anything useful with the packet!  Just that we've made forward
/// progress in communicating the packet or cancellation thereof.)
///
/// Resolves to an error if the link was terminated (and therefore
/// it is unknown whether the peer ever received the packet).
///
/// Unlike `Sent`, dropping `AckedOrCanceled` has no impact on delivery
/// or cancellation of the packet.
pub struct AckedOrCanceled<'a>(Acked<'a>);

pub enum PacketStatus {
    /// The packet was acknowledged by the peer.  It will (should) act
    /// on the packet.
    Acked,
    /// The packet was acknowledged as canceled by the peer.  It will not
    /// act on the packet.
    Canceled,
}

impl<'a> std::future::Future for AckedOrCanceled<'a> {
    type Output = Result<PacketStatus, MgmtSendError>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(seq_num) = self.0.seq_num else {
            return Poll::Ready(Ok(PacketStatus::Acked));
        };

        let Some(peer_state) = self.0.asm.peer_table.get(self.0.link_id) else {
            return Poll::Ready(Err(MgmtSendError::LinkClosed));
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();
        zdpr_send.poll_ack(cx, seq_num).map(|()| {
            if zdpr_send.is_cancel_acked(seq_num) {
                Ok(PacketStatus::Canceled)
            } else {
                Ok(PacketStatus::Acked)
            }
        })
    }
}

impl<'a> Drop for AckedOrCanceled<'a> {
    fn drop(&mut self) {
        let Some(seq_num) = self.0.seq_num else {
            return;
        };

        let Some(peer_state) = self.0.asm.peer_table.get(self.0.link_id) else {
            return;
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();
        zdpr_send.forget_canceled_packet(seq_num);
    }
}

/// Future which waits for a packet to be both sent and acknowledged.
///
/// Dropping this future cancels delivery of the packet if
/// it has not already been sent.
///
/// Resolves to an error if the link was terminated (and therefore
/// it is unknown whether the peer ever received the packet).
#[must_use = "dropping a sent packet may cancel it"]
pub struct SentAndAcked<'a>(Sent<'a>);

#[allow(dead_code)]
impl<'a> SentAndAcked<'a> {
    /// Returns a future which waits for this packet to be sent only.
    pub fn sent(self) -> Sent<'a> {
        self.0
    }

    /// If sending would block, queue this packet instead.
    pub fn enqueue(self) {
        self.0.enqueue()
    }

    /// Explicitly try to cancel the packet, returning the packet if successful,
    /// or an `Acked` future if unsuccessful (meaning the packet was already sent).
    pub fn try_cancel(self) -> Result<Packet, Acked<'a>> {
        self.0.try_cancel()
    }

    // TODO: request_cancel_after
}

impl<'a> std::future::Future for SentAndAcked<'a> {
    type Output = Result<(), MgmtSendError>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(peer_state) = self.0.asm.peer_table.get(self.0.link_id) else {
            return Poll::Ready(Err(MgmtSendError::LinkClosed));
        };

        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();

        match self.0.packet_id {
            PacketId::Sent(seq_num) => zdpr_send.poll_ack(cx, seq_num).map(|()| Ok(())),
            PacketId::Queued(packet_id) => {
                zdpr_send.poll_send_and_ack(cx, packet_id).map(|()| Ok(()))
            }
        }
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
