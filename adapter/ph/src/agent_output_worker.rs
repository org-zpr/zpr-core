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
    let mut bufs = Vec::new();

    loop {
        // process the return buffer queue
        worker
            .adapter_manager
            .try_recv_return_buffers(&mut bufs, worker.config.buffer_count);
        worker.buffer_stack.put_buffers(bufs.drain(..));

        // grab some buffers from the pool;
        // if none are available immediately, also wait on the return buffer queue
        select! {
            biased;

            _ = worker.buffer_stack
                .get_buffers(worker.config.batch_size - bufs.len(), &mut bufs) => (),

            buf = worker.adapter_manager.async_recv_return_buffer() => {
                // weird two-step approach necessitated by bufs ownership issue with select
                bufs.push(buf);
                worker.adapter_manager.try_recv_return_buffers(&mut bufs, worker.config.batch_size - 1);
            }
        }

        // read & forward packets one at a time, no sense to batch really
        // since neither `read_buf()` nor `enqueue()` support it
        for mut buf in bufs.drain(..) {
            let (pkt, is_requeue) = loop {
                let mut pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
                let is_requeue;

                select! {
                    res = tun.recv_buf(&mut pkt) => {
                        res.unwrap();

                        if zprtun::TUN_HAS_PI {
                            let pi = TunPi::read_pi(&mut pkt);
                            if pi.strip || !is_ip(pi) {
                                // packet was too large or non-IP; drop
                                asm.counters[CounterType::OutPacksDrop].increment();
                                // reuse `buf`
                                buf = pkt.destroy().try_into().unwrap();
                                continue;
                            }
                        } else {
                            // No packet info, permit IP and IPv6 only (for now?)
                            if pkt.body()[0] >> 4 != 4 && pkt.body()[0] >> 4 != 6 {
                                asm.counters[CounterType::OutPacksDrop].increment();
                                buf = pkt.destroy().try_into().unwrap();
                                continue;
                            }
                        }

                        is_requeue = false;
                    }

                    _ = requeue_outq.readable() => {
                        buf = pkt.destroy().try_into().unwrap();
                        if let Err(err) = requeue_outq.try_recv(buf.as_mut()) {
                            match err.kind() {
                                std::io::ErrorKind::WouldBlock => {
                                    continue;
                                }

                                _ => {
                                    // FIXME: detect packet-too-large
                                    panic!("unrecoverable I/O error {err}");
                                }
                            }
                        }

                        pkt = Packet::new_with_existing_metadata(buf);

                        is_requeue = true;
                    }
                }

                break (pkt, is_requeue);
            };

            if is_requeue {
                worker.agent_output_post_classify(pkt, /* allow_bind_request */ false);
            } else {
                asm.counters[CounterType::OutPacksRec].increment();
                worker.agent_output(pkt);
            }
        }
    }
}
