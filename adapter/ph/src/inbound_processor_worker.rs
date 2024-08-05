use crate::assembly::Assembly;
use crate::classifier::classify;
use crate::counters_enum::CounterType;
use crate::defs::Direction;
use crate::ext::zerocopy::*;
use crate::fastpath::*;
use crate::options::PhMode;
use crate::packet::Packet;
use crate::queues::InboundProcessorMessage;
use crate::zdp::*;
use bytes::Buf;
use std::future::Future;
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
    let mut msgs = Vec::new();

    while let count @ 1.. = queue.recv_many(&mut msgs, config.batch_size).await {
        for msg in msgs.drain(..) {
            match msg {
                InboundProcessorMessage::Packet(mut pkt) => {
                    maybe_capture(asm, Direction::Inbound, [&mut pkt]);  // FIXME: batch
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

    let base_hdr = ZdpBaseHeader::read_from_buf(&mut pkt).expect("too-short ZDP message");

    if base_hdr.packet_type.is_response() {
        let channel = asm.get_sender();
        match channel {
            Some(channel) => match channel.send(pkt) {
                Ok(()) => (),
                Err(pkt) => {
                    let ret_buf = pkt.destroy();
                    asm.buffer_stack.put_buffer(ret_buf);
                    asm.counters[CounterType::UnexpectedMgmtResponse].increment();
                }
            },
            None => {
                let ret_buf = pkt.destroy();
                asm.buffer_stack.put_buffer(ret_buf);
                asm.counters[CounterType::UnexpectedMgmtResponse].increment();
            }
        }
    } else if base_hdr.packet_type.is_per_flow() {
        let per_flow_hdr =
            ZdpPerFlowHeader::read_from_buf(&mut pkt).expect("too-short per-flow message");

        match base_hdr.packet_type {
            ZdpPacketType::TransitPacket => {
                pkt.metadata_mut().flow_id = per_flow_hdr.stream_id.into();

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
