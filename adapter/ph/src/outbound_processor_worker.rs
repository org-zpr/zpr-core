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
            clone_cap_packs(asm, &pkts, count);
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

fn clone_cap_packs<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    pkts: &Vec<OutboundProcessorMessage<'pktbuf>>,
    count: usize,
) {
    let mut bufs = Vec::new();
    let mut num_bufs = asm.buffer_stack.try_get_buffers(count, &mut bufs);
    // now that this loop is based on packets, it could be moved into the loop
    // below for performance
    for pkt in pkts {
        if num_bufs > 0 {
            match pkt {
                OutboundProcessorMessage::Packet(pkt) => {
                    let pkt_clone: Packet = pkt.clone_into(bufs.pop().unwrap());
                    match asm
                        .capture_queue
                        .try_enqueue_packet(pkt_clone, SystemTime::now())
                    {
                        Ok(()) => num_bufs -= 1,
                        Err(TryEnqueueError::Full(ret_packet)) => {
                            let ret_buf = ret_packet.destroy();
                            asm.buffer_stack.put_buffer(ret_buf);
                            break;
                        }
                    }
                }
                OutboundProcessorMessage::TestPacket(_pkt) => (),
            }
        }
    }
    asm.buffer_stack.put_buffers(bufs.into_iter());
}
