use crate::assembly::Assembly;
use crate::config;
use crate::counters::CounterType;
use crate::defs::Direction;
use crate::fastpath;
use crate::km_noise::NOISE_PADLEN;
use crate::logging::targets::DATAPATH;
use crate::packet::Packet;
use crate::queues::{MgmtDispatch, TryEnqueueError};
use crate::zdp;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::select;
use tracing::*;
use zerocopy::FromBytes;
use zpr_ext::std::num::NonZeroExt;
use zpr_ext::zerocopy::*;

#[derive(Copy, Clone)]
pub struct Config {
    pub worker_index: usize,
    pub buffer_count: usize,
    #[allow(dead_code)]
    pub batch_size: usize,
}

pub async fn launch(config: Config, asm: Arc<Assembly>, socket: Arc<UdpSocket>) {
    let mut worker = Worker {
        config,
        asm: asm.clone(),
        mgmt_dispatch: asm.mgmt_dispatch.clone(),
    };

    let mut bufs = Vec::new();

    loop {
        // process the return buffer queue
        worker
            .mgmt_dispatch
            .try_recv_return_buffers(&mut bufs, config.buffer_count);
        asm.buffer_stack.put_buffers(bufs.drain(..));

        // grab some buffers from the pool;
        // if none are available immediately, also wait on the return buffer queue
        select! {
            biased;

            _ = asm.buffer_stack
                .get_buffers(config.batch_size - bufs.len(), &mut bufs) => (),

            buf = worker.mgmt_dispatch.async_recv_return_buffer() => {
                // weird two-step approach necessitated by bufs ownership issue with select
                bufs.push(buf);
                let _ = worker.mgmt_dispatch.try_recv_return_buffers(&mut bufs, config.batch_size - 1);
            }
        }

        // TODO: batch receive
        for buf in bufs.drain(..) {
            let mut pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
            let mut sender = loop {
                match socket.recv_buf_from(&mut pkt).await {
                    Ok((_size, sender)) => break sender,

                    Err(err) => {
                        match err.kind() {
                            ErrorKind::ConnectionRefused => (), // FIXME: do something with this later...
                            _ => panic!("got socket error {}", err),
                        }
                    }
                }
            };

            // SocketAddrV6 distinguishes addresses also by `flowinfo` which
            // we do not want -- only the 5-tuple.  So clear it.
            match &mut sender {
                SocketAddr::V4(_) => (),
                SocketAddr::V6(sender) => sender.set_flowinfo(0),
            }

            worker.process_packet(&sender, pkt);
        }
    }
}

#[cfg(debug_assertions)]
/// This table is used to track whether a flow ever switches from one worker
/// to another (indicating potential for out-of-order packets) -- meaning
/// our packet steerer isn't steering correctly.  This is used only in debug mode.
const AGENT_PACKET_FLOW_TRACKER: std::sync::LazyLock<
    dashmap::DashMap<(zpr::LinkId, zpr::StreamId), usize>,
> = std::sync::LazyLock::new(|| dashmap::DashMap::new());

struct Worker {
    config: Config,
    asm: Arc<Assembly>,
    mgmt_dispatch: MgmtDispatch,
}

impl Worker {
    /// Process packets ingressing from the specified address.
    pub fn process_packet(&mut self, peer_sa: &zpr::SubstrateAddr, mut pkt: Packet) {
        self.asm.counters[CounterType::InPacksRec].increment();

        pkt.metadata_mut().ingress_link_id =
            self.asm.peer_table.lookup_peer(peer_sa).unwrap_or_zero();

        // Read, but do not remove the ZPI header
        let Ok((zpi_hdr, _)) = zdp::ZdpZpiHeader::read_from_prefix(&pkt.body()) else {
            fastpath::drop_and_count(&self.asm, pkt, CounterType::BadStructure);
            return;
        };

        let peer_state = self.asm.peer_table.get(pkt.metadata().ingress_link_id);

        // If a ZPI is setup on this link, then we expect the message to use one of the valid
        // ZPI values.
        let secure;
        match peer_state {
            Some(state) => match state.get_established_transport_association() {
                Some(ref transport_sa) => {
                    if zpi_hdr.zpi == transport_sa.recv_zpis.hmac {
                        match fastpath::decrypt_hmac(transport_sa.recv_hmac_key, &mut pkt) {
                            Ok(()) => secure = true,
                            Err(err) => {
                                fastpath::drop_and_count(&self.asm, pkt, err);
                                return;
                            }
                        }
                    } else if zpi_hdr.zpi == transport_sa.recv_zpis.encr {
                        // TODO: Put padlen in state somewhere too
                        match fastpath::decrypt_full(
                            &self.asm,
                            &*transport_sa.codec,
                            NOISE_PADLEN,
                            &mut pkt,
                        ) {
                            Ok(()) => secure = true,
                            Err(err) => {
                                fastpath::drop_and_count(&self.asm, pkt, err);
                                return;
                            }
                        }
                    } else {
                        // We have an SA and ZPI does not match.
                        warn!(
                            target: DATAPATH,
                            "ingress: link {}: unexpected ZPI value {} (expected {:?})",
                            pkt.metadata().ingress_link_id,
                            zpi_hdr.zpi,
                            transport_sa.recv_zpis
                        );
                        fastpath::drop_and_count(&self.asm, pkt, CounterType::UnknownZpi);
                        return;
                    }
                }
                None => {
                    // Either no security association on link, or it is not yet established.
                    warn!(target: DATAPATH, "INSECURE, no SA on link {}", pkt.metadata().ingress_link_id);
                    secure = false;
                }
            },
            None => {
                // No link in peer table
                warn!(
                    target: DATAPATH,
                    "INSECURE, no link in peer table for {}",
                    pkt.metadata().ingress_link_id
                );
                secure = false;
            }
        };

        if !secure {
            // Not under a security assocation, which means only ZPI 0 is allowed.
            if zpi_hdr.zpi != zpr::ZPI_0 && pkt.metadata().ingress_link_id != zpr::LINK_ID_UNKNOWN {
                warn!(
                    target: DATAPATH,
                    "ingress: {}: ZPI {} not allowed on unestablished SA",
                    pkt.metadata().ingress_link_id,
                    zpi_hdr.zpi
                );
                fastpath::drop_and_count(&self.asm, pkt, CounterType::UnknownZpi);
                return;
            }
            warn!(
                target: DATAPATH,
                "INSECURE, decrypting null packet from {}",
                pkt.metadata().ingress_link_id
            );
            match fastpath::decrypt_null(&mut pkt) {
                Ok(()) => (),
                Err(err) => {
                    fastpath::drop_and_count(&self.asm, pkt, err);
                    return;
                }
            }
        }

        // Watch out -- may not be secure
        fastpath::maybe_capture(&self.asm, Direction::Inbound, &mut pkt);

        // now pop the ZPI off the packet. We've already checked it.
        if zdp::ZdpZpiHeader::read_from_buf(&mut pkt).is_err() {
            fastpath::drop_and_count(&self.asm, pkt, CounterType::BadStructure);
            return;
        }

        // If we weren't able to match this packet to an existing link,
        // send it off to be processed as a potential new link.
        if pkt.metadata().ingress_link_id == zpr::LINK_ID_UNKNOWN {
            match self
                .mgmt_dispatch
                .try_dispatch_mgmt_packet_with_addr(peer_sa, pkt)
            {
                Ok(()) => self.asm.counters[CounterType::DispatchedToMgmt].increment(),
                Err(TryEnqueueError::Full(pkt)) => {
                    fastpath::drop_and_count(&self.asm, pkt, CounterType::QueueBackpressure)
                }
            }
            return;
        }

        let Ok(base_hdr) = zdp::ZdpBaseHeader::read_from_buf(&mut pkt) else {
            return fastpath::drop_and_count(&self.asm, pkt, CounterType::BadStructure);
        };

        // In ZPI zero only KM messages are allowed (well, and APR ARP which we don't support yet)
        // Can be overridden (FOR TESTING ONLY) in the flags.
        if !secure && base_hdr.packet_type != zdp::ZdpPacketType::KeyManagement {
            warn!(
                target: DATAPATH,
                "ingress: link {}: ZPI 0 only allows key management messages, not {:?}",
                pkt.metadata().ingress_link_id,
                base_hdr.packet_type
            );
            fastpath::drop_and_count(&self.asm, pkt, CounterType::OtherError);
            return;
        }

        // enqueue non-transit packets with the management processor
        if base_hdr.packet_type != zdp::ZdpPacketType::TransitPacket {
            // TODO: should we peel off the ZDP header here??
            // (instead of this silly code to restore it?)
            *pkt.alloc_zeroed_header() = base_hdr;
            match self.mgmt_dispatch.try_dispatch_mgmt_packet_with_link(pkt) {
                Ok(()) => self.asm.counters[CounterType::DispatchedToMgmt].increment(),
                Err(TryEnqueueError::Full(pkt)) => {
                    fastpath::drop_and_count(&self.asm, pkt, CounterType::QueueBackpressure)
                }
            }
            return;
        }

        let Ok(per_flow_hdr) = zdp::ZdpPerFlowHeader::read_from_buf(&mut pkt) else {
            return fastpath::drop_and_count(&self.asm, pkt, CounterType::BadStructure);
        };

        let ingress_stream_id: zpr::StreamId = per_flow_hdr.stream_id.into();
        pkt.metadata_mut().ingress_stream_id = ingress_stream_id;

        // in debug builds, track which worker this agent traffic came in on
        // ensure a given flow isn't hopping between workers (potentially
        // resulting in out-of-order packets)
        #[cfg(debug_assertions)]
        if let Some(old_index) = AGENT_PACKET_FLOW_TRACKER.insert(
            (
                pkt.metadata().ingress_link_id,
                pkt.metadata().ingress_stream_id,
            ),
            self.config.worker_index,
        ) {
            if old_index != self.config.worker_index {
                self.asm.counters[CounterType::AgentPacketsOutOfOrder].increment();
            }
        }

        fastpath::forward(&self.asm, pkt);
    }
}
