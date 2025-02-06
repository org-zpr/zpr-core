use crate::assembly::Assembly;
use crate::config;
use crate::counters::*;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::net_defs;
use crate::packet::Packet;
use crate::sys::TunPi;
use crate::sys::ZprTun;
use crate::zprtun;
use std::sync::Arc;
use tokio::net::UnixDatagram;
use tokio::select;

fn is_ip(pi: TunPi) -> bool {
    pi.proto == net_defs::ethertype::IP || pi.proto == net_defs::ethertype::IPV6
}

pub async fn launch(
    config: FastpathWorkerConfig,
    worker_index: usize,
    asm: Arc<Assembly>,
    tun: Arc<ZprTun>,
    requeue_outq: UnixDatagram,
) {
    let mut worker = FastpathWorker::new(config, worker_index, asm.clone());

    loop {
        // process the return buffer queue
        if worker.buffers.is_empty() {
            // if we are out of buffers, block
            worker
                .adapter_manager
                .async_recv_return_buffers(&mut worker.buffers, worker.config.buffer_count)
                .await;
        } else {
            worker
                .adapter_manager
                .try_recv_return_buffers(&mut worker.buffers, worker.config.buffer_count);
        }

        // read & forward packets one at a time
        let mut pkt = Packet::new(
            worker.buffers.pop().unwrap(),
            config::DEFAULT_MESSAGE_HEADROOM,
        );

        // TODO: batch receive
        select! {
            // read from TUN device
            res = tun.recv_buf(&mut pkt) => {
                res.unwrap();

                if zprtun::TUN_HAS_PI {
                    let pi = TunPi::read_pi(&mut pkt);
                    if pi.strip || !is_ip(pi) {
                        // packet was too large or non-IP; drop
                        worker.drop_and_count(pkt, CounterType::OutPacksDrop);
                        continue;
                    }
                } else {
                    // No packet info, permit IP and IPv6 only (for now?)
                    if pkt.body()[0] >> 4 != 4 && pkt.body()[0] >> 4 != 6 {
                        worker.drop_and_count(pkt, CounterType::OutPacksDrop);
                        continue;
                    }
                }

                worker.asm.counters[CounterType::OutPacksRec].increment();
                worker.agent_output(pkt);
            }

            // read from requeue
            _ = requeue_outq.readable() => {
                let mut buf = pkt.destroy();
                if let Err(err) = requeue_outq.try_recv(buf.as_mut()) {
                    match err.kind() {
                        std::io::ErrorKind::WouldBlock => {
                            worker.buffers.push(buf);
                            continue;
                        }

                        _ => {
                            // FIXME: detect packet-too-large
                            panic!("unrecoverable I/O error {err}");
                        }
                    }
                }

                worker.asm.counters[CounterType::RequeuedPacketsReceived].increment();
                let pkt = Packet::new_with_existing_metadata(buf);
                worker.agent_output_post_classify(pkt, /* allow_bind_request */ false);
            }
        }
    }
}
