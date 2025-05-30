use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::logging::targets::ZDP;
use crate::mgmt;
use crate::mgmt::handlers::{self, HandleMgmtError, HandleMgmtResult};
use crate::packet::Packet;
use crate::queues::MgmtProcessorMessage;
use crate::zdp::*;
use std::sync::Arc;
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
                    Err((err, mut pkt)) => mgmt::core::count_event(&asm, &mut pkt, err.into()),
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

    debug!(
        target: ZDP,
        "Link {}: handling mgmt message type {:?} seq_num {}",
        pkt.metadata().ingress_link_id,
        base_hdr.packet_type,
        base_hdr.sequence_number
    );

    // TODO: reconstitute full seq num given expected seq num state
    let seq_num = base_hdr.sequence_number.get() as u64;

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

            ZdpPacketType::TerminateLinkIndication => {
                handlers::handle_terminate_indication(asm, seq_num, pkt).await
            }

            ZdpPacketType::HelloRequest => handlers::handle_hello_request(asm, seq_num, pkt).await,

            ZdpPacketType::HelloResponse => handlers::handle_hello_response(asm, pkt).await,

            ZdpPacketType::InitAuthenticationRequest => {
                handlers::handle_init_authentication_request(asm, seq_num, pkt).await
            }

            ZdpPacketType::AcquireZprAddressRequest => {
                handlers::handle_acquire_zpr_address_request(asm, seq_num, pkt).await
            }

            ZdpPacketType::GrantZprAddressRequest => {
                handlers::handle_grant_zpr_address_request(asm, seq_num, pkt).await
            }

            packet_type => {
                warn!("unhandled mgmt packet type {:?}", packet_type);
                Err((HandleMgmtError::UnknownType(packet_type.0), pkt))
            }
        }
    }
}
