use crate::assembly::Assembly;
use crate::classifier::classify;
use crate::counters_enum::CounterType;
use crate::options::PhMode;
use crate::packet::Packet;
use crate::queues::TryEnqueueError;
use crate::zdp::*;
use crate::InboundProcessorMessage;
use bytes::Buf;
use std::future::Future;
use std::time::SystemTime;
use tokio::sync::mpsc;
use zerocopy::FromBytes;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize,
    pub mode: PhMode,
}

async fn worker<'pktbuf>(
    config: &Config,
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<InboundProcessorMessage<'pktbuf>>,
) {
    let mut pkts = Vec::new();

    while let count @ 1.. = queue.recv_many(&mut pkts, config.batch_size).await {
        if asm.flow_control.get_inbound() {
            clone_cap_packs(asm, &pkts, count);
        }
        for pkt in pkts.drain(..) {
            match pkt {
                InboundProcessorMessage::Packet(pkt) => {
                    handle_packets(config, pkt, asm).await;
                }
                InboundProcessorMessage::TestPacket(pkt) => {
                    pkt.acknowledge(queue.len(), count);
                }
            }
        }
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    config: &Config,
    asm: AsmRef,
    mut queue: mpsc::Receiver<InboundProcessorMessage<'pktbuf>>,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &mut queue).await }
}

async fn handle_packets<'pktbuf>(
    config: &Config,
    mut pkt: Packet<'pktbuf>,
    asm: &Assembly<'pktbuf>,
) {
    let hdr = ZdpHeader::ref_from_prefix(pkt.body()).expect("too-short inbound packet");

    match hdr.abbreviated_header.packet_type {
        ZdpPacketType::UncompressedAgentPacket => {
            // copy out relevant header info
            pkt.metadata_mut().flow_id = hdr.abbreviated_header.stream_id;

            // strip packet header
            pkt.advance(std::mem::size_of::<ZdpHeader>());

            if config.mode == PhMode::Server {
                // TODO: drop error packets
                let _ = classify(&mut pkt);
            }

            // send out decapsulated packet
            asm.inbound_send.enqueue_packet(pkt).await;
        }

        packet_type => panic!("unhandled inbound packet type {}", packet_type.0),
    }
}

fn clone_cap_packs<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    pkts: &Vec<InboundProcessorMessage<'pktbuf>>,
    count: usize,
) {
    let mut bufs = Vec::new();
    let _ = asm.buffer_stack.try_get_buffers(count, &mut bufs);
    let mut num_enqueued: u64 = 0;
    for pkt in pkts {
        match pkt {
            // Splits between Packets and TestPackets
            InboundProcessorMessage::Packet(pkt) => match bufs.pop() {
                // Ensures there's at least one buffer
                Some(buf) => {
                    let pkt_clone: Packet = pkt.clone_into(buf);
                    match asm
                        .capture_queue
                        .try_enqueue_packet(pkt_clone, SystemTime::now())
                    {
                        // Checks to see if the packet enqueue was successful
                        Ok(()) => {
                            asm.counters[CounterType::InCapPacksWrite].increment();
                            num_enqueued += 1;
                        }
                        Err(TryEnqueueError::Full(ret_packet)) => {
                            let ret_buf = ret_packet.destroy();
                            asm.buffer_stack.put_buffer(ret_buf);
                            break;
                        }
                    };
                }
                None => break,
            },
            InboundProcessorMessage::TestPacket(_) => (),
        }
    }
    asm.buffer_stack.put_buffers(bufs.into_iter());
    asm.counters[CounterType::InCapPacksDrop].increase_by(pkts.len() as u64 - num_enqueued)
}
