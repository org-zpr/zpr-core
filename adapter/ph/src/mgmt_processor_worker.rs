use crate::assembly::Assembly;
use crate::fastpath;
use crate::mgmt::{self, HandleMgmtError, HandleMgmtResult};
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
                match handle_packet(asm, ingress_link_id, pkt).await {
                    Ok(()) => (),
                    Err((err, pkt)) => fastpath::drop_and_count(asm, pkt, err),
                }
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
) -> HandleMgmtResult<'pktbuf> {
    let Some(base_hdr) = ZdpBaseHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    let packet_type = base_hdr.packet_type;

    if packet_type.is_response() {
        // Gets the designated sender, attempts to send the response, if not drops
        // the packet and increments corresponding counter
        let channel = asm.sync_req_state.get_sender();
        match channel {
            Some(channel) => match channel.send((pkt, packet_type)) {
                Ok(()) => Ok(()),
                Err((pkt, _)) => Err((HandleMgmtError::UnexpectedMgmtResponse, pkt)),
            },

            None => Err((HandleMgmtError::UnexpectedMgmtResponse, pkt)),
        }
    } else if base_hdr.packet_type.is_per_flow() {
        let Some(per_flow_hdr) = ZdpPerFlowHeader::read_from_buf(&mut pkt) else {
            return Err((HandleMgmtError::BadStructure, pkt));
        };

        let stream_id: zpr::StreamId = per_flow_hdr.stream_id.into();

        match base_hdr.packet_type {
            ZdpPacketType::TransitPacket => panic!("unexpected Transit Packet in management path"),

            ZdpPacketType::BindAgentAddressRequest => {
                mgmt::handle_bind_agent_address_request(asm, ingress_link_id, stream_id, pkt).await
            }

            packet_type => Err((HandleMgmtError::UnknownType(packet_type.0), pkt)),
        }
    } else {
        match base_hdr.packet_type {
            ZdpPacketType::Report => mgmt::handle_report(asm, ingress_link_id, pkt).await,

            ZdpPacketType::Discard => mgmt::handle_discard(asm, ingress_link_id, pkt).await,

            ZdpPacketType::KeyManagement => {
                // This needs to be sent to the KM running on the link.
                // Um, we need the arriving link ID !
                //

                todo!("KeyManagement packet arrived but no way to hanle it!");

                // Once we have the link---
                // - parse down to the payload and hand it off:

                // km_multiplexor::handle_inbound_km_msg(asm, from_link, km_payload);
            }

            ZdpPacketType::HelloRequest => {
                mgmt::handle_hello_request(asm, ingress_link_id, pkt).await
            }

            packet_type => Err((HandleMgmtError::UnknownType(packet_type.0), pkt)),
        }
    }
}
