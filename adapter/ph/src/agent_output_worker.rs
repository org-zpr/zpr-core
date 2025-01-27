use crate::assembly::Assembly;
use crate::classifier::{self, ClassifierResult};
use crate::config;
use crate::counters::*;
use crate::fastpath;
use crate::net_defs;
use crate::packet::Packet;
use crate::sys::TunPi;
use crate::sys::ZprTun;
use crate::zprtun;
use std::sync::Arc;
use tokio::net::UnixDatagram;
use tokio::select;

#[derive(Copy, Clone)]
pub struct Config {
    pub worker_index: usize,
    pub batch_size: usize,
}

fn is_ip(pi: TunPi) -> bool {
    pi.proto == net_defs::ethertype::IP || pi.proto == net_defs::ethertype::IPV6
}

pub async fn launch(
    config: Config,
    asm: Arc<Assembly>,
    tun: Arc<ZprTun>,
    requeue_outq: UnixDatagram,
) {
    let worker = Worker {
        config,
        asm: asm.clone(),
    };

    let mut bufs = Vec::new();

    loop {
        // grab some buffers from the pool
        asm.buffer_stack
            .get_buffers(config.batch_size, &mut bufs)
            .await;

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
                fastpath::agent_output_post_classify(
                    &asm, pkt, /* allow_bind_request */ false,
                );
            } else {
                asm.counters[CounterType::OutPacksRec].increment();
                worker.process(pkt);
            }
        }
    }
}

struct Worker {
    #[allow(dead_code)]
    config: Config,
    asm: Arc<Assembly>,
}

impl Worker {
    /// Process uncompressed packet from the agent.
    /// The packet will be compressed, or trigger a Bind request.
    pub fn process(&self, mut pkt: Packet) {
        pkt.metadata_mut().ingress_link_id = zpr::LOCAL_AGENT_LINK_ID;
        pkt.metadata_mut().ingress_lane_id = self.config.worker_index as u8;

        // determine five tuple
        let classification = match classifier::classify(&mut pkt) {
            Ok(cls) => cls,
            Err(_why) => {
                fastpath::drop_and_count(&self.asm, pkt, CounterType::InPacksDrop);
                return;
            }
        };

        match classification {
            ClassifierResult::OK | ClassifierResult::UnclassifiedL4 => (),

            ClassifierResult::FirstFragment | ClassifierResult::SubsequentFragment => {
                // TODO: handle fragments!
                fastpath::drop_and_count(&self.asm, pkt, CounterType::InPacksDrop);
                return;
            }

            ClassifierResult::NonIP => {
                // should never happen; TUN doesn't deal in non-IP
                fastpath::drop_and_count(&self.asm, pkt, CounterType::InPacksDrop);
                return;
            }
        }

        fastpath::agent_output_post_classify(&self.asm, pkt, /* allow_bind_request */ true);
    }
}
