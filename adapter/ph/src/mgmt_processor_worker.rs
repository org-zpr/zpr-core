use crate::assembly::Assembly;
use crate::counters::{CounterType, Counters};
use crate::link_state::LinkEvent;
use crate::logging::targets::{LINK_STATE, ZDP};
use crate::mgmt;
use crate::mgmt::handlers::{self, HandleMgmtError, HandleMgmtResult};
use crate::packet::Packet;
use crate::queues::MgmtProcessorMessage;
use crate::seq_nums::*;
use crate::zdp::*;
use std::sync::Arc;
use strum::IntoEnumIterator;
use tokio::sync::mpsc;
use tracing::*;
use zpr;
use zpr_ext::zerocopy::*;

#[derive(Clone, Copy)]
pub struct Config {
    pub link_id: std::num::NonZero<zpr::LinkId>,
}

pub async fn launch(
    config: Config,
    asm: Arc<Assembly>,
    mut queue: mpsc::Receiver<MgmtProcessorMessage>,
) {
    while let Some(msg) = queue.recv().await {
        match msg {
            MgmtProcessorMessage::Packet(mut pkt) => {
                // Drop packets which are intended for a link other than the one we are assigned to,
                // since processing them here will violate concurrency assumptions.
                if pkt.metadata().ingress_link_id != config.link_id.get() {
                    mgmt::core::count_event(&asm, &mut pkt, CounterType::InternalRoutingError);
                    continue;
                }

                match handle_packet(&asm, pkt).await {
                    Ok(()) => (),
                    Err((err, mut pkt)) => {
                        let link_id = config.link_id.get();
                        error!(target: ZDP, "Error handling packet received on link {link_id}: {err}");
                        if let Err(e) = asm.process_link_state_event(link_id, LinkEvent::Error) {
                            error!(target: LINK_STATE, "Error handling link error on link {link_id}: {e}");
                        }
                        mgmt::core::count_event(&asm, &mut pkt, err.into());
                    }
                }
            }

            MgmtProcessorMessage::TestPacket(pkt) => pkt.acknowledge(queue.len(), 1),
        }
    }
}

async fn handle_packet(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let Ok(base_hdr) = ZdpBaseHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    let seq_num;

    if base_hdr.packet_type.is_per_flow() {
        // VERY HACK:
        // Right now BindActorAddressRequest still uses the "old-style" sync-response mechanism.
        // Therefore we must exempt it from standardized sequence number processing.
        // Conveniently, it's also the only per-flow message we actually process here.
        // So we use that as a proxy to detect this type of message (in order not to have to parse
        // the flow header here) and use traditional sequence number processing.

        seq_num = base_hdr.sequence_number.get() as u64;
    } else {
        let truncated_seq_num = base_hdr.sequence_number.get();

        let maybe_seq_num;
        {
            let Some(peer_state) = asm.peer_table.get(pkt.metadata().ingress_link_id) else {
                mgmt::core::count_event(asm, &mut pkt, CounterType::PeerRemoved);
                return Ok(());
            };

            let mut sn_track = peer_state.sn_track.lock().unwrap();
            maybe_seq_num = sn_track.process_seq_num(truncated_seq_num);
            count_seq_num_tracker_stats(&asm.counters, &mut sn_track);
        }

        let Some(sn) = maybe_seq_num else {
            // Possible duplicate packet, drop!
            // (Counted above by `count_seq_num_tracker_stats()`).
            debug!(
                target: ZDP,
                "Link {}: dropping mgmt message type {:?} truncated_seq_num {truncated_seq_num}",
                pkt.metadata().ingress_link_id,
                base_hdr.packet_type,
            );

            return Ok(());
        };

        seq_num = sn;
    }

    match base_hdr.packet_type {
        ZdpPacketType::EchoRequest | ZdpPacketType::EchoResponse => {
            trace!(
                target: ZDP,
                "Link {}: handling mgmt message type {:?} seq_num {seq_num}",
                pkt.metadata().ingress_link_id,
                base_hdr.packet_type,

            );
        }
        _ => {
            debug!(
                target: ZDP,
                "Link {}: handling mgmt message type {:?} seq_num {seq_num}",
                pkt.metadata().ingress_link_id,
                base_hdr.packet_type,
            );
        }
    }

    if base_hdr.packet_type.is_per_flow() {
        let Ok(per_flow_hdr) = ZdpPerFlowHeader::read_from_buf(&mut pkt) else {
            return Err((HandleMgmtError::BadStructure, pkt));
        };

        pkt.metadata_mut().ingress_stream_id = per_flow_hdr.stream_id.into();

        match base_hdr.packet_type {
            ZdpPacketType::TransitPacket => panic!("unexpected Transit Packet in management path"),

            ZdpPacketType::BindActorAddressRequest => {
                handlers::handle_bind_actor_address_request(asm, seq_num, pkt).await
            }

            packet_type => Err((HandleMgmtError::UnknownType(packet_type.0), pkt)),
        }
    } else {
        match base_hdr.packet_type {
            ZdpPacketType::Report => handlers::handle_report(asm, pkt).await,

            ZdpPacketType::Discard => handlers::handle_discard(asm, pkt).await,

            ZdpPacketType::EchoRequest => handlers::handle_echo_request(asm, seq_num, pkt).await,

            ZdpPacketType::EchoResponse => handlers::handle_echo_response(asm, pkt).await,

            ZdpPacketType::KeyManagement => {
                panic!("unexpected Key Management message in mgmt processor")
            }

            ZdpPacketType::TerminateLinkRequest => {
                handlers::handle_terminate_request(asm, seq_num, pkt).await
            }

            ZdpPacketType::TerminateLinkResponse => {
                handlers::handle_terminate_response(asm, pkt).await
            }

            ZdpPacketType::TerminateLinkIndication => {
                handlers::handle_terminate_indication(asm, seq_num, pkt).await
            }

            ZdpPacketType::HelloRequest => handlers::handle_hello_request(asm, seq_num, pkt).await,

            ZdpPacketType::HelloResponse => handlers::handle_hello_response(asm, pkt).await,

            ZdpPacketType::InitAuthenticationRequest => {
                handlers::handle_init_authentication_request(asm, seq_num, pkt).await
            }

            ZdpPacketType::InitAuthenticationResponse => {
                handlers::handle_init_authentication_response(asm, pkt).await
            }

            ZdpPacketType::AcquireZprAddressRequest => {
                handlers::handle_acquire_zpr_address_request(asm, seq_num, pkt).await
            }

            ZdpPacketType::AcquireZprAddressResponse => {
                handlers::handle_acquire_zpr_address_response(asm, pkt).await
            }

            ZdpPacketType::GrantZprAddressRequest => {
                handlers::handle_grant_zpr_address_request(asm, seq_num, pkt).await
            }

            ZdpPacketType::GrantZprAddressResponse => {
                handlers::handle_grant_zpr_address_response(asm, pkt).await
            }

            packet_type => {
                warn!("unhandled mgmt packet type {:?}", packet_type);
                Err((HandleMgmtError::UnknownType(packet_type.0), pkt))
            }
        }
    }
}

/// Maps a `SeqnumTrackerStat` to a `CounterType`.
fn seq_num_tracker_stat_to_counter(sn_stat: SeqNumTrackerStat) -> CounterType {
    match sn_stat {
        SeqNumTrackerStat::TooOld => CounterType::DroppedTooOld,
        SeqNumTrackerStat::Duplicate => CounterType::DroppedDuplicate,
        SeqNumTrackerStat::Lost => CounterType::LostPacket,
        SeqNumTrackerStat::OutOfOrder => CounterType::OutOfOrderPacket,
    }
}

/// Pulls stats delta from `SeqNumTracker` and feeds them into the global counters.
fn count_seq_num_tracker_stats(counters: &Counters, sn_track: &mut SeqNumTracker) {
    for stat in SeqNumTrackerStat::iter() {
        counters[seq_num_tracker_stat_to_counter(stat)]
            .increase_by(sn_track.fetch_reset_stat(stat));
    }
}
