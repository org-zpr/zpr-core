use crate::assembly::Assembly;
use crate::fastpath;
use crate::mgmt::{self, HandleMgmtError, HandleMgmtResult};
use crate::packet::Packet;
use crate::queues::MgmtProcessorMessage;
use crate::zdp::*;
use crate::zpr;
use std::future::Future;
use tokio::sync::mpsc;
use zpr_ext::zerocopy::*;

#[derive(Clone, Copy)]
pub struct Config {
    pub link_id: zpr::LinkId,
}

async fn worker<'pktbuf>(
    config: &Config,
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<MgmtProcessorMessage<'pktbuf>>,
) {
    while let Some(msg) = queue.recv().await {
        match msg {
            MgmtProcessorMessage::Packet(pkt) => {
                eprintln!(
                    "{}: dequeued mgmt message from {}",
                    asm.system_name, config.link_id
                );
                match handle_packet(asm, config.link_id, pkt).await {
                    Ok(()) => (),
                    Err((err, pkt)) => fastpath::drop_and_count(asm, pkt, err),
                }
            }

            MgmtProcessorMessage::TestPacket(pkt) => pkt.acknowledge(queue.len(), 1),
        }
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    config: &Config,
    asm: AsmRef,
    mut queue: mpsc::Receiver<MgmtProcessorMessage<'pktbuf>>,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &mut queue).await }
}

async fn handle_packet<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    mut pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    eprintln!(
        "{}: handling mgmt message from {}",
        asm.system_name, ingress_link_id
    );

    let Some(base_hdr) = ZdpBaseHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    let packet_type = base_hdr.packet_type;

    if packet_type.is_response() {
        eprintln!("{}: got response from {}", asm.system_name, ingress_link_id);

        // Gets the designated sender, attempts to send the response, if not drops
        // the packet and increments corresponding counter
        asm.peer_table
            .inspect(ingress_link_id, |peer_state| {
                let channel = peer_state.sync_req_state.get_sender();
                match channel {
                    Some(channel) => {
                        eprintln!(
                            "{}: sending response {} to channel!",
                            asm.system_name, ingress_link_id
                        );
                        match channel.send((pkt, packet_type)) {
                            Ok(()) => Ok(()),
                            Err((pkt, _)) => Err((HandleMgmtError::UnexpectedMgmtResponse, pkt)),
                        }
                    }

                    None => Err((HandleMgmtError::UnexpectedMgmtResponse, pkt)),
                }
            })
            .unwrap() // FIXME: handle link deleted
    } else if base_hdr.packet_type.is_per_flow() {
        let Some(per_flow_hdr) = ZdpPerFlowHeader::read_from_buf(&mut pkt) else {
            return Err((HandleMgmtError::BadStructure, pkt));
        };

        let stream_id: zpr::StreamId = per_flow_hdr.stream_id.into();

        match base_hdr.packet_type {
            ZdpPacketType::TransitPacket => panic!("unexpected Transit Packet in management path"),

            ZdpPacketType::BindAgentAddressRequest => {
                mgmt::handle_bind_agent_address_request(asm, ingress_link_id, stream_id, pkt).await
            }

            packet_type => Err((HandleMgmtError::UnknownType(packet_type.0), pkt)),
        }
    } else {
        match base_hdr.packet_type {
            ZdpPacketType::Report => mgmt::handle_report(asm, ingress_link_id, pkt).await,

            ZdpPacketType::Discard => mgmt::handle_discard(asm, ingress_link_id, pkt).await,

            ZdpPacketType::KeyManagement => {
                mgmt::handle_key_management(asm, ingress_link_id, pkt).await
            }

            ZdpPacketType::HelloRequest => {
                mgmt::handle_hello_request(asm, ingress_link_id, pkt).await
            }

            packet_type => Err((HandleMgmtError::UnknownType(packet_type.0), pkt)),
        }
    }
}
