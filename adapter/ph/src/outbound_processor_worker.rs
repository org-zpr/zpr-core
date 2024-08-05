use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::flow_control;
use crate::packet::Packet;
use crate::queues::OutboundProcessorMessage;
use crate::queues::{Direction, TryEnqueueError};
use crate::zdp::*;
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
        for pkt in pkts.drain(..) {
            match pkt {
                OutboundProcessorMessage::Packet(mut pkt) => {
                    // allocate and fill in the headers
                    let stream_id = pkt.metadata().flow_id;
                    let per_flow_hdr = pkt.alloc_zeroed_header::<ZdpPerFlowHeader>();
                    per_flow_hdr.stream_id = stream_id;

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

    let _: &u8 = pkt.alloc_zeroed_header(); // account for fact we don't yet have ZPI

    // Clones packet into capture queue after adding direction to beginning of packet
    let dir: &mut u8 = pkt.alloc_zeroed_header();
    *dir = 1;
    let caplen = asm.flow_control.check_packet(pkt.body()).await;
    //println!("caplen outbound {}", caplen);
    if caplen > 0 {
        let mut bufs = Vec::new();
        let _ = asm.buffer_stack.try_get_buffers(1, &mut bufs);
        // Ensures there's at least one buffer
        match bufs.pop() {
            Some(buf) => {
                let pkt_clone: Packet = pkt.clone_into(buf);
                // Checks to see if the packet enqueue was successful
                match asm.capture_queue.try_enqueue_packet(
                    pkt_clone,
                    SystemTime::now(),
                    Direction::Outbound,
                    caplen, // Not currently used
                ) {
                    Ok(()) => {
                        asm.counters[CounterType::OutCapPacksWrite].increment();
                    }
                    Err(TryEnqueueError::Full(ret_packet)) => {
                        let ret_buf = ret_packet.destroy();
                        asm.buffer_stack.put_buffer(ret_buf);
                        asm.counters[CounterType::OutCapPacksDrop].increment();
                    }
                };
            }
            None => {
                asm.counters[CounterType::OutCapPacksDrop].increment();
            }
        }
    }
    // remove direction indicator from beginning of packet
    pkt.advance(flow_control::DIRECTION_HEADER_SIZE);
    // forward encapsulated packet on
    asm.outbound_send.enqueue_packet(pkt).await;
}
