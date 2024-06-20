use core::future::Future;
use tokio::sync::mpsc;
use crate::assembly::Assembly;
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
            // allocate and fill in the header
            let hdr = pkt.alloc_zeroed_header::<ZdpHeader>();
            hdr.abbreviated_header.packet_type = ZdpPacketType::UncompressedAgentPacket;

            // fill in metadata
            pkt.metadata_mut().flow_id = 0;  // TODO: fill from IP header

            // forward encapsulated packet on
            asm.outbound_send.enqueue_packet(pkt).await;
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
