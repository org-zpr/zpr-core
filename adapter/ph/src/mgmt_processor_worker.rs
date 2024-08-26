use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::fastpath;
use crate::mgmt;
use crate::packet::Packet;
use crate::queues::MgmtProcessorMessage;
use crate::zdp::*;
use crate::zpr;
use std::future::Future;
use tokio::sync::mpsc;
use zpr_ext::zerocopy::*;

async fn worker<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<MgmtProcessorMessage<'pktbuf>>,
) {
    while let Some(msg) = queue.recv().await {
        match msg {
            MgmtProcessorMessage::Packet(ingress_link_id, pkt) => {
                handle_packet(asm, ingress_link_id, pkt).await
            }

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

async fn handle_packet<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    mut pkt: Packet<'pktbuf>,
) {
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
        let per_flow_hdr =
            ZdpPerFlowHeader::read_from_buf(&mut pkt).expect("too-short per-flow message");

        let stream_id: zpr::StreamId = per_flow_hdr.stream_id.into();

        match base_hdr.packet_type {
            ZdpPacketType::TransitPacket => panic!("unexpected TransitPacket in management path"),

            ZdpPacketType::BindAgentAddressRequest => {
                mgmt::handle_bind_agent_address_request(asm, ingress_link_id, stream_id, pkt).await
            }

            packet_type => panic!("unhandled inbound packet type {}", packet_type.0),
        }
    } else {
        match base_hdr.packet_type {
            ZdpPacketType::Report => mgmt::handle_report(asm, ingress_link_id, pkt).await,

            ZdpPacketType::Discard => mgmt::handle_discard(asm, ingress_link_id, pkt).await,

            ZdpPacketType::HelloRequest => {
                mgmt::handle_hello_request(asm, ingress_link_id, pkt).await
            }

            packet_type => panic!("unhandled inbound packet type {}", packet_type.0),
        }
    }
}
