use crate::assembly::Assembly;
use crate::fastpath;
use crate::mgmt::handlers::{self, HandleMgmtError, HandleMgmtResult};
use crate::packet::Packet;
use crate::queues::MgmtProcessorMessage;
use crate::zdp::*;
use crate::zpr;
use std::future::Future;
use tokio::sync::mpsc;
use tracing::debug;
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
) -> impl Future<Output = ()> + 'pktbuf
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
    let Some(base_hdr) = ZdpBaseHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    debug!(
        "{}: handling mgmt message from {} type {:?} seq_num {}",
        asm.system_name, ingress_link_id, base_hdr.packet_type, base_hdr.sequence_number
    );

    assert!(
        !base_hdr.packet_type.is_response(),
        "stray mgmt response in mgmt processor"
    );

    let seq_num = base_hdr.sequence_number.get() as u64; // TODO: reconstitute full seq num given expected seq num state

    if base_hdr.packet_type.is_per_flow() {
        let Some(per_flow_hdr) = ZdpPerFlowHeader::read_from_buf(&mut pkt) else {
            return Err((HandleMgmtError::BadStructure, pkt));
        };

        let stream_id: zpr::StreamId = per_flow_hdr.stream_id.into();

        match base_hdr.packet_type {
            ZdpPacketType::TransitPacket => panic!("unexpected Transit Packet in management path"),

            ZdpPacketType::BindAgentAddressRequest => {
                handlers::handle_bind_agent_address_request(
                    asm,
                    ingress_link_id,
                    stream_id,
                    seq_num,
                    pkt,
                )
                .await
            }

            packet_type => Err((HandleMgmtError::UnknownType(packet_type.0), pkt)),
        }
    } else {
        match base_hdr.packet_type {
            ZdpPacketType::Report => handlers::handle_report(asm, ingress_link_id, pkt).await,

            ZdpPacketType::Discard => handlers::handle_discard(asm, ingress_link_id, pkt).await,

            ZdpPacketType::KeyManagement => {
                panic!("unexpected Key Management message in mgmt processor")
            }

            ZdpPacketType::HelloRequest => {
                handlers::handle_hello_request(asm, ingress_link_id, seq_num, pkt).await
            }

            packet_type => Err((HandleMgmtError::UnknownType(packet_type.0), pkt)),
        }
    }
}
