use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::flow_control;
use crate::packet::Packet;
use crate::queues::{Direction, TryEnqueueError};
use crate::zdp::*;
use crate::OutboundProcessorMessage;
use bytes::Buf;
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
        if asm.flow_control.program_exists().await {
            clone_cap_packs(asm, &mut pkts, count).await;
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

async fn clone_cap_packs<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    pkts: &mut Vec<OutboundProcessorMessage<'pktbuf>>,
    count: usize,
) {
    let mut bufs = Vec::new();
    let _ = asm.buffer_stack.try_get_buffers(count, &mut bufs);
    let mut num_enqueued: u64 = 0;
    for pkt in pkts {
        // Splits between Packets and TestPackets
        match pkt {
            OutboundProcessorMessage::Packet(pkt) => {
                if asm.flow_control.check_packet(pkt.body()).await {
                    let dir: &mut u8 = pkt.alloc_zeroed_header();
                    *dir = 1;
                    // Ensures there's at least one buffer
                    match bufs.pop() {
                        Some(buf) => {
                            let pkt_clone: Packet = pkt.clone_into(buf);
                            pkt.advance(flow_control::DIRECTION_HEADER_SIZE);
                            // Checks to see if the packet enqueue was successful
                            match asm.capture_queue.try_enqueue_packet(
                                pkt_clone,
                                SystemTime::now(),
                                Direction::Outbound,
                            ) {
                                Ok(()) => {
                                    asm.counters[CounterType::OutCapPacksWrite].increment();
                                    num_enqueued += 1;
                                }
                                Err(TryEnqueueError::Full(ret_packet)) => {
                                    let ret_buf = ret_packet.destroy();
                                    asm.buffer_stack.put_buffer(ret_buf);
                                    break;
                                }
                            };
                        }
                        None => {
                            pkt.advance(flow_control::DIRECTION_HEADER_SIZE);
                            break;
                        }
                    }
                }
            }
            OutboundProcessorMessage::TestPacket(_) => (),
        }
    }
    asm.buffer_stack.put_buffers(bufs.into_iter());
    asm.counters[CounterType::OutCapPacksDrop].increase_by(count as u64 - num_enqueued)
}
