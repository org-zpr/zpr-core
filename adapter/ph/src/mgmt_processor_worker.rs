use crate::assembly::Assembly;
use crate::config;
use crate::counters_enum::CounterType;
use crate::fastpath;
use crate::mgmt;
use crate::packet::Packet;
use crate::queues::MgmtProcessorMessage;
use crate::zdp::*;
use bytes::Buf;
use std::future::Future;
use tokio::sync::mpsc;
use zerocopy::FromBytes;
use zpr_ext::zerocopy::*;

async fn worker<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<MgmtProcessorMessage<'pktbuf>>,
) {
    while let Some(msg) = queue.recv().await {
        match msg {
            MgmtProcessorMessage::Packet(pkt) => handle_packet(asm, pkt).await,

            MgmtProcessorMessage::TestPacket(pkt) => pkt.acknowledge(queue.len(), 1),
        }
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    asm: AsmRef,
    mut queue: mpsc::Receiver<MgmtProcessorMessage<'pktbuf>>,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
{
    async move { worker(&*asm, &mut queue).await }
}

async fn handle_packet<'pktbuf>(asm: &Assembly<'pktbuf>, mut pkt: Packet<'pktbuf>) {
    let base_hdr = ZdpBaseHeader::read_from_buf(&mut pkt).expect("too-short ZDP message");

    let packet_type = base_hdr.packet_type;

    if packet_type.is_response() {
        // Gets the designated sender, attempts to send the response, if not drops
        // the packet and increments corresponding counter
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
            ZdpPacketType::TransitPacket => panic!("unexpected TransitPacket in management path"),
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
                mgmt::send_non_flow_mgmt(
                    asm,
                    asm.adapter_docking_session_id, /* FIXME: parameterize */
                    ZdpPacketType::HelloResponse,
                    send_pkt,
                )
                .await;
                eprintln!("Received HelloRequest");
            }
            packet_type => panic!("unhandled inbound packet type {}", packet_type.0),
        }
    }
}
