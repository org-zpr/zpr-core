use crate::assembly::Assembly;
use crate::packet::Packet;
use crate::queues::TryEnqueueError;
use crate::zdp::*;
use crate::OutboundProcessorMessage;
use core::future::Future;
use std::time::SystemTime;
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
        if asm.flow_control.get_outbound() {
            let mut bufs = Vec::new();
            let _ = asm.buffer_stack.try_get_buffers(count, &mut bufs);
            for (i, buf) in bufs.drain(..).enumerate() {
                match &pkts[i] {
                    OutboundProcessorMessage::Packet(pkt) => {
                        let pkt_clone: Packet = pkt.clone_into(buf);
                        match asm
                            .capture_queue
                            .try_enqueue_packet(pkt_clone, SystemTime::now())
                        {
                            Ok(()) => (),
                            Err(TryEnqueueError::Full(ret_capture_packet)) => {
                                let ret_buf = ret_capture_packet.packet.destroy();
                                asm.buffer_stack.put_buffer(ret_buf);
                            }
                        }
                    }
                    OutboundProcessorMessage::TestPacket(_pkt) => asm.buffer_stack.put_buffer(buf),
                    // TODO potentially restrustructure, this wastes a buffer if there are lots of test packets
                }
            }
        }
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
