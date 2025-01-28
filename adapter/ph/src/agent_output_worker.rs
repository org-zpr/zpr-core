use crate::adapter_tables::AltEntry;
use crate::assembly::Assembly;
use crate::classifier::{self, ClassifierResult};
use crate::compress;
use crate::config;
use crate::counters::*;
use crate::fastpath;
use crate::net_defs;
use crate::packet::Packet;
use crate::queues::{AdapterManager, TryEnqueueError};
use crate::sys::TunPi;
use crate::sys::ZprTun;
use crate::zdp;
use crate::zprtun;
use bytes::BufMut;
use std::sync::Arc;
use tokio::net::UnixDatagram;
use tokio::select;

#[derive(Copy, Clone)]
pub struct Config {
    pub worker_index: usize,
    pub buffer_count: usize,
    #[allow(dead_code)]
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
    let mut worker = Worker {
        config,
        asm: asm.clone(),
        adapter_manager: asm.adapter_manager.clone(),
    };

    let mut bufs = Vec::new();

    loop {
        // process the return buffer queue
        worker
            .adapter_manager
            .try_recv_return_buffers(&mut bufs, config.buffer_count);
        asm.buffer_stack.put_buffers(bufs.drain(..));

        // grab some buffers from the pool;
        // if none are available immediately, also wait on the return buffer queue
        select! {
            biased;

            _ = asm.buffer_stack
                .get_buffers(config.batch_size - bufs.len(), &mut bufs) => (),

            buf = worker.adapter_manager.async_recv_return_buffer() => {
                // weird two-step approach necessitated by bufs ownership issue with select
                bufs.push(buf);
                worker.adapter_manager.try_recv_return_buffers(&mut bufs, config.batch_size - 1);
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
                worker.process_packet_post_classify(pkt, /* allow_bind_request */ false);
            } else {
                asm.counters[CounterType::OutPacksRec].increment();
                worker.process_packet(pkt);
            }
        }
    }
}

struct Worker {
    #[allow(dead_code)]
    config: Config,
    asm: Arc<Assembly>,
    adapter_manager: AdapterManager,
}

impl Worker {
    /// Process uncompressed packet from the agent.
    /// The packet will be compressed, or trigger a Bind request.
    pub fn process_packet(&mut self, mut pkt: Packet) {
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

        self.process_packet_post_classify(pkt, /* allow_bind_request */ true);
    }

    /// Post-classification portion of `agent_output` function.  Used for
    /// re-injecting already-classified packets e.g.  which were held
    /// awaiting bind.  `allow_bind_request` should be `true` for "real"
    /// packets; `false` for packets re-injected from mgmt plane after
    /// fulfilling a bind request (so as to prevent the theoretical
    /// possibility of a packet loop).
    pub fn process_packet_post_classify(&mut self, mut pkt: Packet, allow_bind_request: bool) {
        let five_tuple = *pkt.metadata().five_tuple(); // TODO: convince borrow checker we don't need to copy this out

        // lookup five tuple in ALT
        match self.asm.alt.get(&five_tuple) {
            Some(entry) => match &*entry {
                AltEntry::Active(pep) => {
                    // compute A2A MAC
                    // TODO: use actual A2A SAID & keyed hash
                    let a2a_said: zpr::A2aSaid = 0;
                    let a2a_mac_size = zdp::ZDP_A2A_MAC_SIZE; // TODO: may be smaller depending on A2A SAID
                    let mut a2a_mac = [0u8; zdp::ZDP_A2A_MAC_SIZE];
                    // SECURITY: truncating BLAKE3 is safe
                    a2a_mac[..a2a_mac_size]
                        .copy_from_slice(&blake3::hash(pkt.body()).as_bytes()[..a2a_mac_size]);

                    // compress packet
                    compress::compress(
                        pep.compression_mode,
                        five_tuple.l3_type,
                        five_tuple.l4_protocol,
                        &mut pkt,
                    );

                    // append A2A MAC
                    pkt.put(&a2a_mac[..a2a_mac_size]);
                    pkt.alloc_zeroed_header::<zdp::ZdpA2aHeader>().a2a_said = a2a_said;

                    pkt.metadata_mut().ingress_stream_id = pep.tether_id;

                    // forward packet on
                    fastpath::forward(&self.asm, pkt);
                }

                AltEntry::Pending(_) => {
                    // Bind request pending; drop this packet
                    fastpath::drop_and_count(&self.asm, pkt, CounterType::DroppedAwaitingBind);
                }
            },

            None => {
                if !allow_bind_request {
                    // avoid the (all-but purely theoretical) chance of a packet loop,
                    // when this is initiated due to a requeue from bind setup code
                    fastpath::drop_and_count(&self.asm, pkt, CounterType::OtherError);
                    return;
                }

                // issue bind request
                match self.adapter_manager.try_request_tether_id(pkt) {
                    Ok(()) => self.asm.counters[CounterType::AgentSlowpath].increment(),
                    Err(TryEnqueueError::Full(pkt)) => {
                        fastpath::drop_and_count(&self.asm, pkt, CounterType::QueueBackpressure)
                    }
                }
            }
        }
    }
}
