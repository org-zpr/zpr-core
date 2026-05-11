//! Code which handles dispatching management packets from fastpath.

use super::core;
use crate::assembly::Assembly;
use crate::counters::{ManagementCounterType, ManagementCounters};
use crate::km_multiplexor;
use crate::link_state::LinkType;
use crate::logging::targets::{KEY_MGMT, ZDP};
use crate::packet::Packet;
use crate::queues;
use crate::zdp;
use crate::zdpr;
use bytes::Buf;
use std::sync::Arc;
use strum::IntoEnumIterator;
use tracing::*;
use zerocopy::FromBytes;
use zpr::packet_info::{KM_ID_NOISE, KM_ID_NULL, LINK_ID_UNKNOWN, SubstrateAddr};
use zpr_ext::std::num::NonZeroExt;
use zpr_ext::zerocopy::FromBytesExt;
use zpr_utils::net_defs;

/// Dispatch a management packet for a link that hasn't been established yet
///
/// This function does not block, and does not perform significant processing.
/// It merely dispatches the management packet to the correct queue.
pub fn dispatch_mgmt_packet_with_addr(
    asm: &Arc<Assembly>,
    peer_sa: SubstrateAddr,
    interface_addr: net_defs::ScopedIpAddr,
    pkt: &mut Packet,
) {
    match zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()) {
        Ok(base_hdr) if base_hdr.0.packet_type == zdp::ZdpPacketType::KeyManagement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());

            // TODO: once we have multi-node, how do we know whether this is a link or a
            // tether?

            // It is possible we are processing a queue of messages and we have already set up a
            // tether for this source.  So before trying to start a tether check if we already have one.

            let mut ingress_link_id = asm
                .peer_table
                .lookup_peer(&peer_sa, &interface_addr)
                .unwrap_or_zero();

            if ingress_link_id == LINK_ID_UNKNOWN {
                let Some(i_link_id) = asm
                    .start_tether(&peer_sa, &interface_addr, LinkType::NodeToAdapter)
                    .ok()
                else {
                    core::count_event(asm, ManagementCounterType::UnknownPeer);
                    return;
                };
                ingress_link_id = i_link_id.get();
            }

            pkt.metadata_mut().ingress_link_id = ingress_link_id;
            handle_key_management(asm, pkt);
        }
        _ => {
            core::count_event(asm, ManagementCounterType::UnknownPeer);
            return;
        }
    }
}

/// Dispatch the given management packet.
///
/// This function does not block, and does not perform significant processing.
/// It merely dispatches the management packet to the correct queue.
pub fn dispatch_mgmt_packet_with_link(asm: &Arc<Assembly>, pkt: &mut Packet) {
    match zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()) {
        Ok((base_hdr, _)) if base_hdr.packet_type == zdp::ZdpPacketType::KeyManagement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
            handle_key_management(asm, pkt);
        }

        Ok((base_hdr, _)) if base_hdr.packet_type == zdp::ZdpPacketType::Acknowledgement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
            handle_acknowledgement(asm, pkt)
        }

        Ok((base_hdr, _)) if base_hdr.packet_type == zdp::ZdpPacketType::Cancel => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
            handle_cancel(asm, pkt)
        }

        Ok((base_hdr, _)) if base_hdr.packet_type == zdp::ZdpPacketType::Canceled => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
            handle_canceled(asm, pkt)
        }

        Ok((_base_hdr, rest)) => {
            let (mgmt_hdr, _) = zdp::ZdpMgmtHeader::ref_from_prefix(rest).unwrap();

            let Some(peer_state) = asm.peer_table.get(pkt.metadata().ingress_link_id) else {
                core::count_event(asm, ManagementCounterType::PeerRemoved);
                return;
            };

            // expand sequence number and store in packet metadata
            let mut receiver = peer_state.zdpr_recv.lock().unwrap();
            let seq_num = mgmt_hdr.sequence_number.get();
            pkt.metadata_mut().seq_num = seq_num;

            // determine packet disposition per ZDPR mechanism
            let disp = receiver.process_packet(seq_num);
            count_zdpr_receiver_stats(&asm.counters.management, &mut receiver);
            drop(receiver);

            if disp.should_ack() {
                if disp.ack_is_canceled() {
                    core::send_canceled(&asm, pkt.metadata().ingress_link_id, seq_num);
                } else {
                    core::send_acknowledgement(&asm, pkt.metadata().ingress_link_id, seq_num);
                }
            }

            if disp.should_process() {
                let mgmt_pkt = Packet::new_with_existing_metadata(pkt.buffer().clone());
                match peer_state.mgmt_processor.try_enqueue_packet(mgmt_pkt) {
                    Ok(()) => (),
                    Err(queues::TryEnqueueError::Full(_mgmt_pkt)) => {
                        core::count_event(asm, ManagementCounterType::QueueBackpressure);
                        return;
                    }
                }
            }
        }

        Err(_) => core::count_event(asm, ManagementCounterType::BadStructure),
    }
}

fn handle_cancel(asm: &Assembly, pkt: &mut Packet) {
    let Ok(mgmt_hdr) = zdp::ZdpMgmtHeader::read_from_buf(pkt) else {
        core::count_event(asm, ManagementCounterType::BadStructure);
        return;
    };

    let seq_num = mgmt_hdr.sequence_number.get();
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Some(peer_state) = asm.peer_table.get(ingress_link_id) else {
        core::count_event(asm, ManagementCounterType::PeerRemoved);
        return;
    };

    let mut receiver = peer_state.zdpr_recv.lock().unwrap();
    let disp = receiver.process_cancel(seq_num);
    count_zdpr_receiver_stats(&asm.counters.management, &mut receiver);

    if disp.should_ack() {
        if disp.ack_is_canceled() {
            core::send_canceled(&asm, pkt.metadata().ingress_link_id, seq_num);
        } else {
            core::send_acknowledgement(&asm, pkt.metadata().ingress_link_id, seq_num);
        }
    }
}

fn handle_acknowledgement(asm: &Assembly, pkt: &mut Packet) {
    handle_acknowledgement_canceled_common(asm, pkt, false)
}

fn handle_canceled(asm: &Assembly, pkt: &mut Packet) {
    handle_acknowledgement_canceled_common(asm, pkt, true)
}

fn handle_acknowledgement_canceled_common(asm: &Assembly, pkt: &mut Packet, is_canceled: bool) {
    // From dispatch's point of view, acknowledgement and cancellation of a packet are
    // identical; either way, we don't care about the referenced packet any more.
    // The only difference is ultimately to the sender/canceller, who must learn whether
    // the remote canceled or processed the packet.

    let Ok(mgmt_hdr) = zdp::ZdpMgmtHeader::read_from_buf(pkt) else {
        core::count_event(asm, ManagementCounterType::BadStructure);
        return;
    };

    let seq_num = mgmt_hdr.sequence_number.get();
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Some(peer_state) = asm.peer_table.get(ingress_link_id) else {
        core::count_event(asm, ManagementCounterType::PeerRemoved);
        return;
    };
    let mut sender = peer_state.zdpr_send.lock().unwrap();

    if is_canceled {
        sender.process_canceled(seq_num);
    } else {
        sender.process_ack(seq_num);
    }
    count_zdpr_sender_stats(&asm.counters.management, &mut sender);

    // If at this point (after processing the ACK) we should not have our
    // retry timer running (because all outstanding packets have been
    // ACKed), we may be liable to restart the timer after possibly sending
    // unblocked packets.
    let old_retry_needed = sender.retry_needed();

    // We may now be unblocked and may have been blocked before;
    // try to send queued packets.
    while sender.unblock_needed() {
        let sn_pkt = sender.enqueue_next_blocked_packet();
        core::build_and_egress_packets(asm, ingress_link_id, std::iter::once(sn_pkt));
    }

    if sender.retry_needed() && !old_retry_needed {
        // We should activate / restart our retry timer.
        peer_state.zdpr_retry_timer_reset.notify_one();
    }
}

// ZPI and Base header is already gone by the time we get here.  So we expect
// to parse starting from the KeyManagement header.
fn handle_key_management(asm: &Arc<Assembly>, pkt: &mut Packet) {
    let Ok(km_hdr) = zdp::ZdpKeyManagementHeader::read_from_buf(pkt) else {
        error!(target: ZDP, "KeyManagement packet arrived with unparseable header");
        core::count_event(asm, ManagementCounterType::BadStructure);
        return;
    };

    if (km_hdr.is_noise() && asm.config.get().km_impl != KM_ID_NOISE)
        || (km_hdr.is_null() && asm.config.get().km_impl != KM_ID_NULL)
    {
        error!(
            target: KEY_MGMT,
            "KeyManagement packet type does not match KM implementation - type is {}",
            km_hdr.message_type
        );
        core::count_event(asm, ManagementCounterType::OtherError);
        return;
    }

    let km_msg_len = usize::from(km_hdr.message_length);
    if pkt.remaining() < km_msg_len {
        error!(target: KEY_MGMT, "KeyManagement packet arrived with truncated payload");
        core::count_event(asm, ManagementCounterType::BadStructure);
        return;
    }

    match km_multiplexor::handle_inbound_km_msg(
        asm,
        pkt.metadata().ingress_link_id,
        &pkt.body()[..km_msg_len],
    ) {
        Ok(()) => (),
        Err(e) => {
            error!(
                target: KEY_MGMT,
                "key management handling failed on link {}: {e:?}",
                pkt.metadata().ingress_link_id,
            );
            core::count_event(asm, ManagementCounterType::OtherError);
            return;
        }
    };
    return;
}

/// Maps a `zdpr::SenderStat` to a `CounterType`.
fn zdpr_sender_stat_to_counter(sn_stat: zdpr::SenderStat) -> ManagementCounterType {
    match sn_stat {
        zdpr::SenderStat::InvalidAck => ManagementCounterType::BadMgmtResponse,
        zdpr::SenderStat::TooOldAck => ManagementCounterType::DroppedTooOld,
        zdpr::SenderStat::DuplicateAck => ManagementCounterType::DroppedDuplicate,
        zdpr::SenderStat::TooNewAck => ManagementCounterType::DroppedTooNew,
    }
}

/// Maps a `zdpr::ReceiverStat` to a `CounterType`.
fn zdpr_receiver_stat_to_counter(sn_stat: zdpr::ReceiverStat) -> ManagementCounterType {
    match sn_stat {
        zdpr::ReceiverStat::TooOld => ManagementCounterType::DroppedTooOld,
        zdpr::ReceiverStat::Duplicate => ManagementCounterType::DroppedDuplicate,
        zdpr::ReceiverStat::TooNew => ManagementCounterType::DroppedTooNew,
        zdpr::ReceiverStat::OutOfOrder => ManagementCounterType::OutOfOrderPacket,
    }
}

/// Pulls stats delta from `zdpr::Sender` and feeds them into the global counters.
fn count_zdpr_sender_stats<Pkt>(
    mgmt_counters: &ManagementCounters,
    sender: &mut zdpr::Sender<Pkt>,
) {
    for stat in zdpr::SenderStat::iter() {
        mgmt_counters[zdpr_sender_stat_to_counter(stat)].increase_by(sender.fetch_reset_stat(stat));
    }
}

/// Pulls stats delta from `zdpr::Receiver` and feeds them into the global counters.
fn count_zdpr_receiver_stats(mgmt_counters: &ManagementCounters, receiver: &mut zdpr::Receiver) {
    for stat in zdpr::ReceiverStat::iter() {
        mgmt_counters[zdpr_receiver_stat_to_counter(stat)]
            .increase_by(receiver.fetch_reset_stat(stat));
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::config::PACKET_BUFFER_SIZE;
    use crate::km_cert_exchange::KmCertExchange;
    use crate::km_noise::NoiseKeypair;
    use crate::km_testdata::test::*;
    use std::net::Ipv4Addr;
    use tokio::task::LocalSet;

    // Ensure that this old issue is fixed:
    // https://github.com/org-zpr/zpr-core/issues/929
    #[tokio::test]
    async fn test_duplicate_no_tether_packet_no_crash() {
        let mut asm = create_assembly(TestAssemblyBuilder::new());
        asm.self_noise_keypair = Some(NoiseKeypair::generate());
        asm.certx = Some(KmCertExchange::new_from_pem(ADAPTER_CERT_DATA, CA_CERT_DATA).unwrap());
        let aasm = Arc::new(asm);

        let buf1 = Box::new([0u8; PACKET_BUFFER_SIZE]);
        let mut pkt1 = Packet::new(buf1, 64);

        // write ZDP base header
        let hdr = pkt1.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
        hdr.packet_type = zdp::ZdpPacketType::KeyManagement;

        let buf2 = Box::new([0u8; PACKET_BUFFER_SIZE]);
        let mut pkt2 = Packet::new(buf2, 64);

        let hdr = pkt2.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
        hdr.packet_type = zdp::ZdpPacketType::KeyManagement;

        let peer_sa = SubstrateAddr::from(([127, 0, 0, 1], 1234));
        let int_addr = net_defs::ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 1).into());

        let local = LocalSet::new();
        local
            .run_until(async move {
                dispatch_mgmt_packet_with_addr(&aasm, peer_sa, int_addr, &mut pkt1);
                dispatch_mgmt_packet_with_addr(&aasm, peer_sa, int_addr, &mut pkt2);
            })
            .await;

        // If we get here we didn't crash!
        assert!(true);
    }
}
