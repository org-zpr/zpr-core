//! Core management packet functions.
//!
//! These are low-level primitives; most code should use the higher-level
//! functions in `requests` instead.

use crate::assembly::Assembly;
use crate::config;
use crate::counters::ManagementCounterType;
use crate::packet::{self, Packet};
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
    // TODO: just allocate this on the stack, pending #985.
    let mut packet = new_tiny_heap_packet();

    // let the OS know we're ACKing data from the peer
    packet.metadata_mut().flags |= packet::flags::CONFIRM;

    let mgmt_hdr = packet.alloc_zeroed_header::<zdp::ZdpMgmtHeader>();
    mgmt_hdr.sequence_number = sequence_number.into();

    let base_hdr = packet.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
    base_hdr.packet_type = zdp::ZdpPacketType::Acknowledgement;

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
/// Dropping this future cancels delivery of the packet if
/// it has not already been sent.
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
        // to do that.  (This do not leak anything because we have no
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
                if let Some(pkt) = zdpr_send.cancel_packet(packet_id) {
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
pub struct Acked<'a> {
    asm: &'a Assembly,
    link_id: LinkId,
    seq_num: Option<SeqNum>, // None indicates acked before we knew the sequenece number
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
    /// if sending would block, queue this packet instead
    pub fn enqueue(self) {
        self.0.enqueue()
    }

    /// explicitly try to cancel the packet, returning the packet if successful,
    /// or an `Acked` future if unsuccessful
    pub fn try_cancel(self) -> Result<Packet, Acked<'a>> {
        self.0.try_cancel()
    }
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
