use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::defs::Direction;
use crate::ext::std::mem::drop_guard;
use crate::fastpath;
use crate::packet::Packet;
use crate::queues::OutboundProcessorMessage;
use crate::zdp::*;
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

                    handle_packet(pkt, asm).await;
                }
                OutboundProcessorMessage::TestPacket(pkt) => pkt.acknowledge(queue.len(), count),
                OutboundProcessorMessage::NonFlowMgmt(pack_type, mut pkt) => {
                    let hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
                    hdr.packet_type = pack_type;
                    handle_packet(pkt, asm).await;
                }
                OutboundProcessorMessage::PerFlowMgmt(pack_type, stream_id, mut pkt) => {
                    let per_flow_hdr = pkt.alloc_zeroed_header::<ZdpPerFlowHeader>();
                    per_flow_hdr.stream_id = stream_id.into();

                    let base_hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
                    base_hdr.packet_type = pack_type;

                    handle_packet(pkt, asm).await;
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

async fn handle_packet<'pktbuf>(mut pkt: Packet<'pktbuf>, asm: &Assembly<'pktbuf>) {
    // fill in metadata
    pkt.metadata_mut().flow_id = 0; // TODO: fill from IP header

    fastpath::encap_zpi(asm, 0, 0, &mut pkt);

    fastpath::maybe_capture(asm, Direction::Outbound, &mut pkt);

    fastpath::encrypt(asm, 0, &mut pkt);

    // forward encapsulated packet on
    match asm
        .outbound_send
        .enqueue_packet(drop_guard(pkt, |p| {
            asm.buffer_stack.put_buffer(p.destroy())
        }))
        .await
    {
        Ok(()) => asm.counters[CounterType::OutPacksSent].increment(),
        Err(_) => asm.counters[CounterType::OutPacksErr].increment(),
    }
}
