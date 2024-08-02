use crate::assembly::Assembly;
use crate::classifier::classify;
use crate::counters_enum::CounterType;
use crate::ext::zerocopy::*;
use crate::flow_control;
use crate::options::PhMode;
use crate::packet::Packet;
use crate::queues::{Direction, TryEnqueueError};
use crate::zdp::*;
use crate::InboundProcessorMessage;
// use crate::buffer_stack::BufferStack;
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
                    handle_packet(config, pkt, asm).await;
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

async fn handle_packet<'pktbuf>(
    config: &Config,
    mut pkt: Packet<'pktbuf>,
    asm: &Assembly<'pktbuf>,
) {
    pkt.advance(std::mem::size_of::<u8>()); // Account for extra byte at beginning because of ZPI

    let base_hdr_ref = ZdpBaseHeader::ref_from_prefix(pkt.body()).expect("too-short inbound packet");

    if base_hdr_ref.packet_type.is_per_flow() {
        let per_flow_hdr =
            ZdpPerFlowHeader::read_from_buf(&mut pkt).expect("too-short per-flow message");

        match per_flow_hdr.base_header.packet_type {
            ZdpPacketType::TransitPacket => {
                pkt.metadata_mut().flow_id = per_flow_hdr.stream_id;

                if config.mode == PhMode::Server {
                    // TODO: drop error packets
                    let _ = classify(&mut pkt);
                }

                // send out decapsulated packet
                asm.inbound_send.enqueue_packet(pkt).await;
            }

            packet_type => panic!("unhandled inbound packet type {}", packet_type.0),
        }
    } else {
        let base_hdr = ZdpBaseHeader::read_from_buf(&mut pkt).unwrap();

        match base_hdr.packet_type {
            ZdpPacketType::Report => {
                let hdr =
                    ZdpReportHeader::ref_from_prefix(pkt.body()).expect("too-short inbound packet");
                // TODO handle protocol errors i.e. if the body is shorter
                let report_data_length: usize = hdr.report_data_length.into();
                pkt.advance(std::mem::size_of::<ZdpReportHeader>());
                if pkt.body().len() >= report_data_length {
                    // TODO printing to stderr blocks indefinitely, this is just temporary
                    eprintln!(
                        "{}",
                        std::str::from_utf8(&pkt.body()[..report_data_length]).unwrap()
                    );
                }
                let ret_buf = pkt.destroy();
                asm.buffer_stack.put_buffer(ret_buf);
            }
            ZdpPacketType::Discard => {
                // TODO print to debug log, when implemented
                eprintln!("Discard message recieved");
            }
            packet_type => panic!("unhandled inbound packet type {}", packet_type.0),
        }
    }
}

async fn clone_cap_packs<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    pkts: &mut Vec<InboundProcessorMessage<'pktbuf>>,
    count: usize,
) {
    let mut bufs = Vec::new();
    let _ = asm.buffer_stack.try_get_buffers(count, &mut bufs);
    let mut num_enqueued: u64 = 0;
    for pkt in pkts {
        // Splits between Packets and TestPackets
        match pkt {
            InboundProcessorMessage::Packet(pkt) => {
                let dir: &mut u8 = pkt.alloc_zeroed_header();
                *dir = 0;
                let caplen = asm.flow_control.check_packet(pkt.body()).await;
                //println!("caplen inbound {}", caplen);
                if caplen > 0 {
                    // Ensures there's at least one buffer
                    match bufs.pop() {
                        Some(buf) => {
                            let pkt_clone: Packet = pkt.clone_into(buf);
                            // Checks to see if the packet enqueue was successful
                            match asm.capture_queue.try_enqueue_packet(
                                pkt_clone,
                                SystemTime::now(),
                                Direction::Inbound,
                                caplen, // Not currently used
                            ) {
                                Ok(()) => {
                                    asm.counters[CounterType::InCapPacksWrite].increment();
                                    num_enqueued += 1;
                                }
                                Err(TryEnqueueError::Full(ret_packet)) => {
                                    let ret_buf = ret_packet.destroy();
                                    asm.buffer_stack.put_buffer(ret_buf);
                                    pkt.advance(flow_control::DIRECTION_HEADER_SIZE);
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
                pkt.advance(flow_control::DIRECTION_HEADER_SIZE);
            }
            InboundProcessorMessage::TestPacket(_) => (),
        }
    }
    asm.buffer_stack.put_buffers(bufs.into_iter());
    asm.counters[CounterType::InCapPacksDrop].increase_by(count as u64 - num_enqueued)
}
