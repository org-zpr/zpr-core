use crate::assembly::Assembly;
use crate::packet::Packet;
use crate::zdp::*;
use crate::OutboundProcessorMessage;
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
                OutboundProcessorMessage::Packet(pkt) => {
                    handle_packets(pkt, asm).await;
                }
                OutboundProcessorMessage::TestPacket(pkt) => pkt.acknowledge(queue.len(), count),
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

async fn handle_packets<'pktbuf>(mut pkt: Packet<'pktbuf>, asm: &Assembly<'pktbuf>) {
    // allocate and fill in the header
    let hdr = pkt.alloc_zeroed_header::<ZdpHeader>();
    hdr.abbreviated_header.packet_type = ZdpPacketType::UncompressedAgentPacket;

    // fill in metadata
    pkt.metadata_mut().flow_id = 0; // TODO: fill from IP header

    // forward encapsulated packet on
    asm.outbound_send.enqueue_packet(pkt).await;
}
