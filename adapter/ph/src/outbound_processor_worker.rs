use crate::assembly::Assembly;
use crate::fastpath;
use crate::queues::OutboundProcessorMessage;
use crate::zdp::*;
use crate::zpr;
use core::future::Future;
use tokio::sync::mpsc;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize,
}

async fn worker<'pktbuf>(
    config: &Config,
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<OutboundProcessorMessage<'pktbuf>>,
) {
    let mut pkts = Vec::new();

    while let count @ 1.. = queue.recv_many(&mut pkts, config.batch_size).await {
        for pkt in pkts.drain(..) {
            match pkt {
                OutboundProcessorMessage::Packet(mut pkt) => {
                    // allocate and fill in the headers
                    let stream_id = pkt.metadata().flow_id;
                    let per_flow_hdr = pkt.alloc_zeroed_header::<ZdpPerFlowHeader>();
                    per_flow_hdr.stream_id = stream_id.into();

                    let base_hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
                    base_hdr.packet_type = ZdpPacketType::TransitPacket;

                    fastpath::substrate_egress(
                        asm,
                        zpr::ADAPTER_DOCKING_SESSION_ID,
                        zpr::ZPI_0,
                        pkt,
                    );
                }
                OutboundProcessorMessage::TestPacket(pkt) => pkt.acknowledge(queue.len(), count),
                OutboundProcessorMessage::NonFlowMgmt(pack_type, mut pkt) => {
                    let hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
                    hdr.packet_type = pack_type;

                    fastpath::substrate_egress(
                        asm,
                        zpr::ADAPTER_DOCKING_SESSION_ID,
                        zpr::ZPI_0,
                        pkt,
                    );
                }
                OutboundProcessorMessage::PerFlowMgmt(pack_type, stream_id, mut pkt) => {
                    let per_flow_hdr = pkt.alloc_zeroed_header::<ZdpPerFlowHeader>();
                    per_flow_hdr.stream_id = stream_id.into();

                    let base_hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
                    base_hdr.packet_type = pack_type;

                    fastpath::substrate_egress(
                        asm,
                        zpr::ADAPTER_DOCKING_SESSION_ID,
                        zpr::ZPI_0,
                        pkt,
                    );
                }
            }
        }
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    config: &Config,
    asm: AsmRef,
    mut queue: mpsc::Receiver<OutboundProcessorMessage<'pktbuf>>,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &mut queue).await }
}
