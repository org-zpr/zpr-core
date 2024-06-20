use std::future::Future;
use bytes::Buf;
use tokio::sync::mpsc;
use zerocopy::FromBytes;
use crate::assembly::Assembly;
use crate::classifier::classify;
use crate::packet::Packet;
use crate::zdp::*;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize
}

async fn worker<'pktbuf>(
    config: &Config, asm: &Assembly<'pktbuf>, queue: &mut mpsc::Receiver<Packet<'pktbuf>>
) {
    let mut pkts = Vec::new();

    while let _count @ 1.. = queue.recv_many(&mut pkts, config.batch_size).await {
        for mut pkt in pkts.drain(..) {
            let hdr = ZdpHeader::ref_from_prefix(pkt.body()).expect("too-short inbound packet");

            match hdr.abbreviated_header.packet_type {
                ZdpPacketType::UncompressedAgentPacket => {
                    // copy out relevant header info
                    pkt.metadata_mut().flow_id = hdr.abbreviated_header.stream_id;

                    // strip packet header
                    pkt.advance(std::mem::size_of::<ZdpHeader>());

                    classify(&mut pkt);

                    // send out decapsulated packet
                    asm.inbound_send.enqueue(pkt).await;
                },

                packet_type =>
                    panic!("unhandled inbound packet type {}", packet_type.0)
            }
        }
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    config: &Config, asm: AsmRef,
    mut queue: mpsc::Receiver<Packet<'pktbuf>>)
-> impl Future<Output = ()> + Send + 'pktbuf
    where AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &mut queue).await }
}
