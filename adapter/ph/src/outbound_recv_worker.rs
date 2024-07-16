use crate::assembly::Assembly;
use crate::counters_enum::*;
use crate::ext::tokio_tun::*;
use crate::net_defs;
use crate::packet::Packet;
use std::future::Future;
use tokio_tun::Tun;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize,
}

// How much space to leave for the ZDP headers.
const OUTBOUND_PACKET_HEADROOM: usize = 256;

fn is_ip(pi: tun_pi::TunPi) -> bool {
    pi.proto == net_defs::ethertype::IP || pi.proto == net_defs::ethertype::IPV6
}

async fn worker(config: &Config, asm: &Assembly<'_>, tun: &Tun) {
    let mut bufs = Vec::new();

    loop {
        // grab some buffers from the pool
        asm.buffer_stack
            .get_buffers(config.batch_size, &mut bufs)
            .await;

        // read & forward packets one at a time, no sense to batch really
        // since neither `read_buf()` nor `enqueue()` support it
        for buf in bufs.drain(..) {
            let mut pkt = Packet::new(buf, OUTBOUND_PACKET_HEADROOM);

            tun_recv_buf(tun, &mut pkt).await.unwrap();

            let pi = tun_pi::read_pi(&mut pkt);
            if pi.strip || !is_ip(pi) {
                // packet was too large or non-IP; drop
                asm.counters[CounterType::OutPacksDrop].increment();
                asm.buffer_stack.put_buffer(pkt.destroy());
                continue;
            }

            asm.counters[CounterType::OutPacksRec].increment();
            asm.outbound_processor.enqueue_packet(pkt).await;
        }
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf, TunRef: 'pktbuf>(
    config: &Config,
    asm: AsmRef,
    tun: TunRef,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
    TunRef: std::ops::Deref<Target = Tun> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &*tun).await }
}
