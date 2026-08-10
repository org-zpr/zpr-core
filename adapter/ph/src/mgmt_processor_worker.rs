//! The management process worker pulls management messages
//! (that is, excluding ZDPR control messages) for a specific link,
//! pulled from that link's management processor queue, and
//! handles them via the management handlers.

use crate::counters::ManagementCounterType;
use crate::link_state::LinkEvent;
use crate::mgmt;
use crate::mgmt::handlers::{self, HandleMgmtError, HandleMgmtResult};
use crate::prelude::*;
use crate::queues::MgmtProcessorMessage;
use crate::zdp::*;
use tokio::sync::mpsc;
use zpr_ext::zerocopy::*;

#[derive(Clone, Copy)]
pub struct Config {
    pub link_id: std::num::NonZero<LinkId>,
}

pub async fn launch(
    config: Config,
    asm: Arc<Assembly>,
    mut queue: mpsc::Receiver<MgmtProcessorMessage>,
) {
    while let Some(msg) = queue.recv().await {
        match msg {
            MgmtProcessorMessage::Packet(pkt) => {
                // Drop packets which are intended for a link other than the one we are assigned to,
                // since processing them here will violate concurrency assumptions.
                if pkt.metadata().ingress_link_id != config.link_id.get() {
                    mgmt::core::count_event(&asm, ManagementCounterType::InternalRoutingError);
                    continue;
                }

                match handle_packet(&asm, pkt).await {
                    Ok(()) => (),
                    Err(err) => {
                        let link_id = config.link_id.get();
                        error!(target: ZDP, "Error handling packet received on {}: {err}", asm.formatted_link_id(link_id));
                        if let Err(e) = asm.process_link_state_event(link_id, LinkEvent::Error) {
                            error!(target: LINK_STATE, "Error handling link error on {}: {e}", asm.formatted_link_id(link_id));
                        }
                        mgmt::core::count_event(&asm, (&err).into());
                    }
                }
            }

            MgmtProcessorMessage::TestPacket(pkt) => pkt.acknowledge(queue.len(), 1),
        }
    }
}

async fn handle_packet(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let Ok(base_hdr) = ZdpBaseHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let Ok(_mgmt_hdr) = ZdpMgmtHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let seq_num = pkt.metadata().seq_num;

    match base_hdr.packet_type {
        ZdpPacketType::Echo => {
            trace!(
                target: ZDP,
                "{}: handling mgmt message type {:?} seq_num {seq_num}",
                asm.formatted_link_id(pkt.metadata().ingress_link_id),
                base_hdr.packet_type,

            );
        }
        _ => {
            debug!(
                target: ZDP,
                "{}: handling mgmt message type {:?} seq_num {seq_num}",
                asm.formatted_link_id(pkt.metadata().ingress_link_id),
                base_hdr.packet_type,
            );
        }
    }

    if base_hdr.packet_type.is_per_flow() {
        let Ok(per_flow_hdr) = ZdpPerFlowHeader::read_from_buf(&mut pkt) else {
            return Err(HandleMgmtError::BadStructure);
        };

        pkt.metadata_mut().ingress_stream_id = per_flow_hdr.stream_id.into();

        match base_hdr.packet_type {
            ZdpPacketType::TransitPacket => panic!("unexpected Transit Packet in management path"),

            ZdpPacketType::BindActorAddressRequest => {
                let Ok(txn_hdr) = ZdpTransactionHeader::read_from_buf(&mut pkt) else {
                    return Err(HandleMgmtError::BadStructure);
                };
                handlers::handle_bind_actor_address_request(asm, txn_hdr.transaction_id.into(), pkt)
                    .await
            }

            ZdpPacketType::BindActorAddressResponse => {
                let Ok(txn_hdr) = ZdpTransactionHeader::read_from_buf(&mut pkt) else {
                    return Err(HandleMgmtError::BadStructure);
                };
                handlers::handle_bind_actor_address_response(
                    asm,
                    txn_hdr.transaction_id.into(),
                    pkt,
                )
                .await
            }

            ZdpPacketType::BindEgressStreamRequest => {
                let Ok(txn_hdr) = ZdpTransactionHeader::read_from_buf(&mut pkt) else {
                    return Err(HandleMgmtError::BadStructure);
                };
                handlers::handle_bind_egress_stream_request(asm, txn_hdr.transaction_id.into(), pkt)
                    .await
            }

            ZdpPacketType::BindEgressStreamResponse => {
                let Ok(txn_hdr) = ZdpTransactionHeader::read_from_buf(&mut pkt) else {
                    return Err(HandleMgmtError::BadStructure);
                };
                handlers::handle_bind_egress_stream_response(
                    asm,
                    txn_hdr.transaction_id.into(),
                    pkt,
                )
                .await
            }
            ZdpPacketType::UnbindEgressStreamIndication => {
                handlers::handle_unbind_indication(asm, pkt).await
            }
            packet_type => Err(HandleMgmtError::UnknownType(packet_type.0)),
        }
    } else {
        match base_hdr.packet_type {
            ZdpPacketType::Report => handlers::handle_report(asm, pkt).await,

            ZdpPacketType::Discard => handlers::handle_discard(asm, pkt).await,

            ZdpPacketType::Echo => handlers::handle_echo_request(asm, pkt).await,

            ZdpPacketType::KeyManagement => {
                panic!("unexpected Key Management message in mgmt processor")
            }

            ZdpPacketType::TerminateLinkOrDockingSession => {
                handlers::handle_terminate_link_or_docking_session(asm, pkt).await
            }

            ZdpPacketType::HelloRequest => handlers::handle_hello_request(asm, pkt).await,

            ZdpPacketType::HelloResponse => handlers::handle_hello_response(asm, pkt).await,

            ZdpPacketType::InitAuthenticationRequest => {
                handlers::handle_init_authentication_request(asm, pkt).await
            }

            ZdpPacketType::AcquireZprAddress => {
                handlers::handle_acquire_zpr_address_request(asm, pkt).await
            }

            ZdpPacketType::GrantZprAddress => {
                handlers::handle_grant_zpr_address_request(asm, pkt).await
            }

            packet_type => {
                warn!("unhandled mgmt packet type {:?}", packet_type);
                Err(HandleMgmtError::UnknownType(packet_type.0))
            }
        }
    }
}
