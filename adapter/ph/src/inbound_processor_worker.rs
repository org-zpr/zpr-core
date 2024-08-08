use crate::assembly::Assembly;
use crate::config;
use crate::counters_enum::CounterType;
use crate::fastpath;
use crate::packet::Packet;
use crate::queues::InboundProcessorMessage;
use crate::zdp::*;
use bytes::Buf;
use std::future::Future;
use tokio::sync::mpsc;
use zerocopy::FromBytes;
use zpr_ext::zerocopy::*;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize,
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
                InboundProcessorMessage::Packet(pkt) => {
                    handle_packet(asm, pkt).await;
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
    asm: &Assembly<'pktbuf>,
    mut pkt: Packet<'pktbuf>,
) {
    let base_hdr = ZdpBaseHeader::read_from_buf(&mut pkt).expect("too-short ZDP message");

    let packet_type = base_hdr.packet_type;

    if packet_type.is_response() {
        let channel = asm.sync_req_state.get_sender();
        match channel {
            Some(channel) => match channel.send((pkt, packet_type)) {
                Ok(()) => (),
                Err(ret_sender) => {
                    fastpath::drop_and_count(
                        asm,
                        ret_sender.0,
                        CounterType::UnexpectedMgmtResponse,
                    );
                }
            },
            None => {
                fastpath::drop_and_count(asm, pkt, CounterType::UnexpectedMgmtResponse);
            }
        }
    } else if base_hdr.packet_type.is_per_flow() {
        let _per_flow_hdr =
            ZdpPerFlowHeader::read_from_buf(&mut pkt).expect("too-short per-flow message");

        match base_hdr.packet_type {
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
                asm.buffer_stack.put_buffer(pkt.destroy());
            }
            ZdpPacketType::Discard => {
                // TODO print to debug log, when implemented
                eprintln!("Discard message received");
            }
            ZdpPacketType::HelloRequest => {
                let mut send_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
                let hdr = send_pkt.alloc_zeroed_header::<ZdpHelloResponseHeader>();
                hdr.status = 0;
                asm.outbound_processor
                    .enqueue_non_flow_mgmt(ZdpPacketType::HelloResponse, send_pkt)
                    .await;
                eprintln!("Received HelloRequest");
            }
            packet_type => panic!("unhandled inbound packet type {}", packet_type.0),
        }
    }
}
