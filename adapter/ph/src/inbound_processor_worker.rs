use crate::assembly::Assembly;
use crate::classifier::classify;
use crate::flow_control;
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
        if asm.flow_control.program_exists().await {
            clone_cap_packs(asm, &mut pkts, count).await;
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

async fn clone_cap_packs<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    pkts: &mut Vec<InboundProcessorMessage<'pktbuf>>,
    count: usize,
) {
    let mut bufs = Vec::new();
    let _ = asm.buffer_stack.try_get_buffers(count, &mut bufs);
    for pkt in pkts {
        // Splits between Packets and TestPackets
        match pkt {
            InboundProcessorMessage::Packet(pkt) => {
                if asm.flow_control.check_packet(pkt.body()).await {
                    let dir: &mut u8 = pkt.alloc_zeroed_header();
                    *dir = 0;
                    // Ensures there's at least one buffer
                    match bufs.pop() {
                        Some(buf) => {
                            let pkt_clone: Packet = pkt.clone_into(buf);
                            pkt.advance(flow_control::DIRECTION_HEADER_SIZE);

                            // Checks to see if the packet enqueue was successful
                            match asm
                                .capture_queue
                                .try_enqueue_packet(pkt_clone, SystemTime::now())
                            {
                                Ok(()) => (),
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
            InboundProcessorMessage::TestPacket(_) => (),
        }
    }
    asm.buffer_stack.put_buffers(bufs.into_iter());
}
