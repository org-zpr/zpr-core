use crate::assembly::Assembly;
use crate::config;
use crate::counters::*;
use crate::fastpath;
use crate::net_defs;
use crate::packet::Packet;
use crate::sys::ZprTun;
use crate::zprtun::tun_pi;
use std::sync::Arc;

#[derive(Copy, Clone)]
pub struct Config {
    #[allow(dead_code)]
    pub worker_index: usize,
    pub batch_size: usize,
}

fn is_ip(pi: tun_pi::TunPi) -> bool {
    pi.proto == net_defs::ethertype::IP || pi.proto == net_defs::ethertype::IPV6
}

pub async fn launch(config: Config, asm: Arc<Assembly>, tun: Arc<ZprTun>) {
    let mut bufs = Vec::new();

    loop {
        // grab some buffers from the pool
        asm.buffer_stack
            .get_buffers(config.batch_size, &mut bufs)
            .await;

        // read & forward packets one at a time, no sense to batch really
        // since neither `read_buf()` nor `enqueue()` support it
        for mut buf in bufs.drain(..) {
            let pkt = loop {
                let mut pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);

                tun.recv_buf(&mut pkt).await.unwrap();
                let pi = tun_pi::read_pi(&mut pkt);
                if pi.strip || !is_ip(pi) {
                    // packet was too large or non-IP; drop
                    asm.counters[CounterType::OutPacksDrop].increment();
                    // reuse `buf`
                    buf = pkt.destroy();
                    continue;
                }

                break pkt;
            };

            asm.counters[CounterType::OutPacksRec].increment();

            fastpath::agent_output(&asm, pkt);
        }
    }
}
