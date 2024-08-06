use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::defs::Direction;
use crate::fastpath;
use crate::packet::Packet;
use crate::queues::{OutboundProcessorMessage, TryEnqueueError};
use crate::zdp::*;
use core::future::Future;
use tokio::sync::mpsc;
use zpr_ext::std::mem::{drop_guard, DropGuard};

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

                    handle_packet(asm, pkt);
                }
                OutboundProcessorMessage::TestPacket(pkt) => pkt.acknowledge(queue.len(), count),
                OutboundProcessorMessage::NonFlowMgmt(pack_type, mut pkt) => {
                    let hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
                    hdr.packet_type = pack_type;
                    handle_packet(asm, pkt);
                }
                OutboundProcessorMessage::PerFlowMgmt(pack_type, stream_id, mut pkt) => {
                    let per_flow_hdr = pkt.alloc_zeroed_header::<ZdpPerFlowHeader>();
                    per_flow_hdr.stream_id = stream_id.into();

                    let base_hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
                    base_hdr.packet_type = pack_type;

                    handle_packet(asm, pkt);
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

fn handle_packet<'pktbuf>(asm: &Assembly<'pktbuf>, mut pkt: Packet<'pktbuf>) {
    // fill in metadata
    pkt.metadata_mut().flow_id = 0; // TODO: fill from IP header

    fastpath::encap_zpi(asm, 0, 0, &mut pkt);

    fastpath::maybe_capture(asm, Direction::Outbound, &mut pkt);

    fastpath::encrypt(asm, 0, &mut pkt);

    // forward encapsulated packet on
    match asm
        .outbound_send
        .try_enqueue_packet(drop_guard(pkt, |p|
            fastpath::drop_and_count(asm, p, CounterType::OutPacksSent)
        ))
    {
        Ok(()) => (),
        Err(TryEnqueueError::Full(pkt)) =>
            fastpath::drop_and_count(asm, pkt.into_inner(), CounterType::OutPacksErr),
    }
}
