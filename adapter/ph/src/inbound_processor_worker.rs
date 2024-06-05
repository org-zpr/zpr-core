use core::future::Future;
use tokio::sync::mpsc;
use crate::assembly::Assembly;
use crate::packet::Packet;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize
}

async fn worker<'pktbuf>(
    config: &Config, asm: &Assembly<'pktbuf>, queue: &mut mpsc::Receiver<Packet<'pktbuf>>
) {
    let mut pkts = Vec::new();

    while let count @ 1.. = queue.recv_many(&mut pkts, config.batch_size).await {
        eprintln!("Inbound processing {count} packets!");
        for pkt in pkts.drain(..) {
            //eprintln!("Inbound packet: {}", std::str::from_utf8(&pkt.buf[..pkt.len]).unwrap());
            // TODO: consider enqueueing in parallel to avoid blocking all if one Q is full
            asm.inbound_send.enqueue(pkt).await;
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
