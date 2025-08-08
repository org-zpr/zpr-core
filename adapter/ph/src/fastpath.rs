//! Fastpath operations.
//!
//! General rule: no fastpath operation may block.
//! This implies that all functions here must be non-async.

use crate::adapter_tables::AltEntry;
use crate::assembly::{Assembly, PhMode};
use crate::batch_io::BatchIoEngine;
use crate::classifier::{self, ClassifierResult};
use crate::config;
use crate::counters::{Aggregate, BatchCounters, CounterType, Counters, Increment};
use crate::defs::Direction;
use crate::km::{Codec, KmTransportSA};
use crate::km_noise::NOISE_PADLEN;
use crate::logging::targets::DATAPATH;
use crate::net_defs;
use crate::packet::{Packet, PacketBuffer};
use crate::queues::{AdapterManager, MgmtDispatch, TryEnqueueError};
use crate::two_way_queue;
use crate::zdp;
use crate::zdp_ll;
use crate::{compress, km};
use blake3;
use bytes::{Buf, BufMut};
use classifier::{IPv4Header, IPv6Header};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::*;
use zerocopy::FromBytes;
use zpr;
use zpr::L3Type;
use zpr_ext::std::num::NonZeroExt;
use zpr_ext::zerocopy::*;

/// Simple function used on an adapter to forward actor packets to the the tether and vice-versa.
const fn adapter_next_hop_link(ingress_link_id: zpr::LinkId) -> zpr::LinkId {
    // this optimization is checked by the static asserts below
    // this allows us to avoid an unpredictable branch on every packet
    (ingress_link_id % 2) + 1
}

const _: () = assert!(adapter_next_hop_link(zpr::LOCAL_ACTOR_LINK_ID) == zpr::DOCK_LINK_ID);
const _: () = assert!(adapter_next_hop_link(zpr::DOCK_LINK_ID) == zpr::LOCAL_ACTOR_LINK_ID);

#[cfg(debug_assertions)]
/// This table is used to track whether a flow ever switches from one worker
/// to another (indicating potential for out-of-order packets) -- meaning
/// our packet steerer isn't steering correctly.  This is used only in debug mode.
const ACTOR_PACKET_FLOW_TRACKER: std::sync::LazyLock<
    dashmap::DashMap<(zpr::LinkId, zpr::StreamId), usize>,
> = std::sync::LazyLock::new(|| dashmap::DashMap::new());

#[derive(Clone, Copy)]
pub struct FastpathWorkerConfig {
    pub batch_io_engine: &'static BatchIoEngine,
    pub buffer_count: usize,
    pub batch_size: usize,
}

pub struct QueuedEgressPacket {
    pub pkt: Packet,
    pub dst: std::net::SocketAddr,
    pub src: net_defs::ScopedIpAddr,
}

pub struct FastpathWorker {
    pub config: FastpathWorkerConfig,
    pub worker_index: usize,
    pub asm: Arc<Assembly>,
    pub buffers: Vec<PacketBuffer>,
    pub batch_counters: BatchCounters,

    pub return_q: two_way_queue::ReturnQueue<PacketBuffer>,
    pub adapter_manager: AdapterManager,
    pub mgmt_dispatch: MgmtDispatch,

    pub actor_input_q: Vec<Packet>,
    pub substrate_egress_q: Vec<QueuedEgressPacket>,
}

impl FastpathWorker {
    pub fn new(config: FastpathWorkerConfig, worker_index: usize, asm: Arc<Assembly>) -> Self {
        let buffers =
            vec![Box::new([0u8; config::PACKET_BUFFER_SIZE]) as Box<[_]>; config.buffer_count];

        let return_q = two_way_queue::ReturnQueue::new();
        let adapter_manager = asm.adapter_manager_factory.make(&return_q);
        let mgmt_dispatch = asm.mgmt_dispatch_factory.make(&return_q);
        let batch_counters = Default::default();

        Self {
            config,
            worker_index,
            asm,
            buffers,
            batch_counters,

            return_q,
            adapter_manager,
            mgmt_dispatch,

            actor_input_q: Vec::with_capacity(config.buffer_count),
            substrate_egress_q: Vec::with_capacity(config.buffer_count),
        }
    }

    /// Drop a packet and count the drop with the given reason.
    pub fn drop_and_count(&mut self, pkt: Packet, reason: impl Into<CounterType>) {
        let reason = reason.into();
        debug!(target: DATAPATH, "dropping packet because {reason}");
        self.buffers.push(pkt.destroy());
        self.batch_counters.increment(reason);
    }

    pub fn get_fresh_packets(&mut self, n: usize, dest: &mut Vec<Packet>) -> usize {
        let nbufs = std::cmp::min(self.buffers.len(), n);

        dest.extend(
            self.buffers
                .drain(self.buffers.len() - nbufs..)
                .rev()
                .map(|buf| Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM)),
        );

        nbufs
    }

    /// Process packet ingressing from the specified address.
    pub fn substrate_ingress(
        &mut self,
        peer_sa: &zpr::SubstrateAddr,
        interface_addr: &net_defs::ScopedIpAddr,
        mut pkt: Packet,
    ) {
        // Lookup peer by its substrate address.
        pkt.metadata_mut().ingress_link_id = self
            .asm
            .peer_table
            .lookup_peer(peer_sa, interface_addr)
            .unwrap_or_zero();

        // Read, but do not remove the ZPI header
        let Ok((zpi_hdr, _)) = zdp::ZdpZpiHeader::read_from_prefix(&pkt.body()) else {
            self.drop_and_count(pkt, CounterType::BadStructure);
            return;
        };

        // Decrypt the packet, per its ZPI header and security association (if any)
        if let Err(err) = decrypt(&self.asm, zpi_hdr, &mut pkt) {
            self.drop_and_count(pkt, err);
            return;
        }

        // Watch out -- may not be secure
        maybe_capture(&self.asm, Direction::Inbound, &mut pkt);

        // now pop the ZPI off the packet. We've already checked it.
        if zdp::ZdpZpiHeader::read_from_buf(&mut pkt).is_err() {
            self.drop_and_count(pkt, CounterType::BadStructure);
            return;
        }

        // If we weren't able to match this packet to an existing link,
        // send it off to be processed as a potential new link.
        if pkt.metadata().ingress_link_id == zpr::LINK_ID_UNKNOWN {
            match self.mgmt_dispatch.try_dispatch_mgmt_packet_with_addr(
                peer_sa,
                interface_addr,
                pkt,
            ) {
                Ok(()) => self.batch_counters.increment(CounterType::DispatchedToMgmt),
                Err(TryEnqueueError::Full(pkt)) => {
                    self.drop_and_count(pkt, CounterType::QueueBackpressure)
                }
            }
            return;
        }

        let Ok(base_hdr) = zdp::ZdpBaseHeader::read_from_buf(&mut pkt) else {
            return self.drop_and_count(pkt, CounterType::BadStructure);
        };

        // In ZPI zero only KM messages are allowed (well, and ZPR ARP which we don't support yet)
        // Can be overridden (FOR TESTING ONLY) in the flags.
        if zpi_hdr.zpi == zpr::ZPI_0 && base_hdr.packet_type != zdp::ZdpPacketType::KeyManagement {
            warn!(
                target: DATAPATH,
                "ingress: link {}: ZPI 0 only allows key management messages, not {:?}",
                pkt.metadata().ingress_link_id,
                base_hdr.packet_type
            );
            self.drop_and_count(pkt, CounterType::OtherError);
            return;
        }

        // enqueue non-transit packets with the management processor
        if base_hdr.packet_type != zdp::ZdpPacketType::TransitPacket {
            // TODO: should we peel off the ZDP header here??
            // (instead of this silly code to restore it?)
            *pkt.alloc_zeroed_header() = base_hdr;
            match self.mgmt_dispatch.try_dispatch_mgmt_packet_with_link(pkt) {
                Ok(()) => self.batch_counters.increment(CounterType::DispatchedToMgmt),
                Err(TryEnqueueError::Full(pkt)) => {
                    self.drop_and_count(pkt, CounterType::QueueBackpressure)
                }
            }
            return;
        }

        let Ok(per_flow_hdr) = zdp::ZdpPerFlowHeader::read_from_buf(&mut pkt) else {
            return self.drop_and_count(pkt, CounterType::BadStructure);
        };

        let ingress_stream_id: zpr::StreamId = per_flow_hdr.stream_id.into();
        pkt.metadata_mut().ingress_stream_id = ingress_stream_id;

        // in debug builds, track which worker this actor traffic came in on
        // ensure a given flow isn't hopping between workers (potentially
        // resulting in out-of-order packets)
        #[cfg(debug_assertions)]
        if let Some(old_index) = ACTOR_PACKET_FLOW_TRACKER.insert(
            (
                pkt.metadata().ingress_link_id,
                pkt.metadata().ingress_stream_id,
            ),
            self.worker_index,
        ) {
            if old_index != self.worker_index {
                self.batch_counters
                    .increment(CounterType::ActorPacketsOutOfOrder);
            }
        }

        self.forward(pkt);
    }

    /// Process uncompressed packet from the actor.
    /// The packet will be compressed, or trigger a Bind request.
    pub fn actor_output(&mut self, mut pkt: Packet) {
        pkt.metadata_mut().ingress_link_id = zpr::LOCAL_ACTOR_LINK_ID;
        pkt.metadata_mut().ingress_lane_id = self.worker_index as u8;

        // determine five tuple
        let classification = match classifier::classify(&mut pkt) {
            Ok(cls) => cls,
            Err(_why) => {
                self.drop_and_count(pkt, CounterType::InPacksDrop);
                return;
            }
        };

        match classification {
            ClassifierResult::OK | ClassifierResult::UnclassifiedL4 => (),

            ClassifierResult::FirstFragment | ClassifierResult::SubsequentFragment => {
                // TODO: handle fragments!
                self.drop_and_count(pkt, CounterType::InPacksDrop);
                return;
            }

            ClassifierResult::NonIP => {
                // should never happen; TUN doesn't deal in non-IP
                self.drop_and_count(pkt, CounterType::InPacksDrop);
                return;
            }
        }

        let ttl_expired = decrement_ttl(&mut pkt);
        if ttl_expired == true {
            error!(target: DATAPATH,"Packet dropped becuase TTL reached 0");
            self.drop_and_count(pkt, CounterType::TtlExpired);
            return;
        }

        self.actor_output_post_classify(pkt, /* allow_bind_request */ true);
    }

    /// Post-classification portion of `actor_output` function.  Used for
    /// re-injecting already-classified packets e.g.  which were held
    /// awaiting bind.  `allow_bind_request` should be `true` for "real"
    /// packets; `false` for packets re-injected from mgmt plane after
    /// fulfilling a bind request (so as to prevent the theoretical
    /// possibility of a packet loop).
    pub fn actor_output_post_classify(&mut self, mut pkt: Packet, allow_bind_request: bool) {
        // note: this weird two-phase structure is needed to appease the borrow checker
        let forward = {
            // lookup five tuple in ALT
            let five_tuple = *pkt.metadata().five_tuple(); // TODO: convince borrow checker we don't need to copy this out
            let Some(entry) = self.asm.alt.get(&five_tuple) else {
                if !allow_bind_request {
                    // avoid the (all-but purely theoretical) chance of a packet loop,
                    // when this is initiated due to a requeue from bind setup code
                    self.drop_and_count(pkt, CounterType::OtherError);
                    return;
                }

                // issue bind request
                match self.adapter_manager.try_request_tether_id(pkt) {
                    Ok(()) => self.batch_counters.increment(CounterType::ActorSlowpath),
                    Err(TryEnqueueError::Full(pkt)) => {
                        self.drop_and_count(pkt, CounterType::QueueBackpressure)
                    }
                }

                return;
            };

            match &*entry {
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
                    true
                }

                AltEntry::Pending(_) => {
                    // do not forward
                    false
                }
            }
        };

        if forward {
            self.forward(pkt);
        } else {
            // Bind request pending; drop this packet
            self.drop_and_count(pkt, CounterType::DroppedAwaitingBind);
        }
    }

    /// Forward compressed packet.
    pub fn forward(&mut self, mut pkt: Packet) {
        let egress_link_id;
        let egress_stream_id;

        match self.asm.ph_mode {
            PhMode::Adapter => {
                egress_link_id = adapter_next_hop_link(pkt.metadata().ingress_link_id);
                egress_stream_id = pkt.metadata().ingress_stream_id;
            }

            PhMode::Node => {
                let Some(ingress_peer_state) =
                    self.asm.peer_table.get(pkt.metadata().ingress_link_id)
                else {
                    self.drop_and_count(pkt, CounterType::UnknownPeer);
                    return;
                };

                let Some(pep) = ingress_peer_state.pft.get(pkt.metadata().ingress_stream_id) else {
                    drop(ingress_peer_state);
                    self.drop_and_count(pkt, CounterType::UnknownStreamId);
                    return;
                };

                // TODO: policy enforcement

                egress_link_id = pep.next_hop.0;
                egress_stream_id = pep.next_hop.1;
            }
        }

        if egress_link_id == zpr::LOCAL_ACTOR_LINK_ID {
            self.actor_input(egress_stream_id, pkt);
        } else {
            let per_flow_hdr = pkt.alloc_zeroed_header::<zdp::ZdpPerFlowHeader>();
            per_flow_hdr.stream_id = egress_stream_id.into();

            let base_hdr = pkt.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
            base_hdr.packet_type = zdp::ZdpPacketType::TransitPacket;

            pkt.metadata_mut().egress_link_id = egress_link_id;

            self.substrate_egress(pkt);
        }
    }

    /// Send a compressed actor packet to the actor.
    /// The packet will be decompressed according to the given stream ID.
    pub fn actor_input(
        &mut self,
        tether_id: zpr::StreamId, // TODO: should we keep this in metadata? or per-flow header?
        mut pkt: Packet,
    ) {
        // extract A2A MAC
        let Ok(a2a_hdr) = zdp::ZdpA2aHeader::read_from_buf(&mut pkt) else {
            self.drop_and_count(pkt, CounterType::BadStructure);
            return;
        };

        if a2a_hdr.a2a_said != 0 {
            todo!("A2A SAID");
        }

        let a2a_mac_size = zdp::ZDP_A2A_MAC_SIZE; // TODO: checksum may be shorter depending on A2A SA

        if pkt.body().len() < a2a_mac_size {
            self.drop_and_count(pkt, CounterType::BadStructure);
            return;
        }
        let mut a2a_mac = [0u8; zdp::ZDP_A2A_MAC_SIZE];
        a2a_mac[..a2a_mac_size].copy_from_slice(&pkt.body()[pkt.body().len() - a2a_mac_size..]);
        pkt.shrink_by(a2a_mac_size);

        // lookup PEP in DLT and expand compressed packet
        let Some(pep) = self.asm.dlt.get(tether_id) else {
            self.drop_and_count(pkt, CounterType::UnknownStreamId);
            return;
        };

        compress::expand(pep.compression_mode, &pep.five_tuple, &mut pkt);

        // check A2A MAC
        // TODO: use actual A2A SAID & keyed hash
        if blake3::hash(pkt.body()).as_bytes()[..a2a_mac_size] != a2a_mac[..a2a_mac_size] {
            drop(pep);
            return self.drop_and_count(pkt, CounterType::MicvFailure);
        }

        // queue decapsulated packet for send to actor
        self.actor_input_q.push(pkt);
    }

    /// Egress a ZDP packet on the given link ID, according to the given ZPI.
    /// The ZPI header will be added to the packet.
    pub fn substrate_egress(&mut self, mut pkt: Packet) {
        let link_id = pkt.metadata().egress_link_id;

        let (dest_sa, src_intf) = match substrate_egress_common(&self.asm, link_id, &mut pkt) {
            Ok(Some((dest_sa, src_intf))) => (dest_sa, src_intf),
            Ok(None) => {
                self.drop_and_count(pkt, CounterType::PeerRemoved);
                return;
            }
            Err(err) => {
                error!(target: DATAPATH, "egress: link {link_id}: encryption error: {err}");
                self.drop_and_count(pkt, CounterType::EncryptionFailure);
                return;
            }
        };

        // queue packet for send via substrate
        self.substrate_egress_q.push(QueuedEgressPacket {
            pkt,
            dst: dest_sa,
            src: src_intf,
        });
    }

    pub fn substrate_egress_packets_queued(&self) -> bool {
        !self.substrate_egress_q.is_empty()
    }

    pub fn aggregate(&mut self) {
        self.asm.counters.aggregate(&self.batch_counters);
        self.batch_counters.clear()
    }
}

/// Add the ZPI header to a packet.
pub fn encap_zpi(_asm: &Assembly, _link_id: zpr::LinkId, zpi: zpr::Zpi, pkt: &mut Packet) {
    pkt.alloc_zeroed_header::<zdp::ZdpZpiHeader>().zpi = zpi;
}

/// Offer a packet to be captured by the packet capture facility.
/// The packet must be a complete ZDP message.
/// Despite the &mut borrow, the packet will return materially unchanged.
/// (It will have a link-layer header temporarily added to it.)
pub fn maybe_capture(asm: &Assembly, dir: Direction, pkt: &mut Packet) {
    maybe_capture_batch(asm, dir, [pkt])
}

/// Batch packet capture.
pub fn maybe_capture_batch<'a>(
    asm: &'a Assembly,
    dir: Direction,
    pkts: impl IntoIterator<Item = &'a mut Packet>,
) {
    if !asm.flow_control.program_exists() {
        return;
    }

    let capture_time = SystemTime::now();

    let mut num_captured: usize = 0;
    let mut num_filtered: usize = 0;

    let mut pkts_iter = pkts.into_iter();

    for pkt in &mut pkts_iter {
        // Copies packet body into capture queue after adding direction to beginning of packet
        let ll_hdr = pkt.alloc_zeroed_header::<zdp_ll::ZdpLinkP2P>();
        ll_hdr.direction = zdp_ll::encode_direction(dir);

        // FIXME: ideally, take an RCU reference to the program once on function entry
        let caplen = asm.flow_control.check_packet(pkt.body()) as usize;
        if caplen > 0 {
            let res = asm
                .capture_queue
                .try_enqueue_packet(pkt, capture_time, caplen);

            // remove direction indicator from beginning of packet
            pkt.advance(std::mem::size_of::<zdp_ll::ZdpLinkP2P>());

            // Checks to see if the packet enqueue was successful
            match res {
                Ok(()) => num_captured += 1,

                // No sense to try enqueuing more packets; exit the loop early.
                Err(TryEnqueueError::Full(())) => break,
            }
        } else {
            num_filtered += 1;
            // remove direction indicator from beginning of packet
            pkt.advance(std::mem::size_of::<zdp_ll::ZdpLinkP2P>());
        }
    }

    // If we exited early, there are remaining packets we won't be capturing.
    let num_dropped = pkts_iter.count();

    match dir {
        Direction::Inbound => {
            asm.counters[CounterType::InCapPacksWrite].increase_by(num_captured as u64);
            asm.counters[CounterType::InCapPacksDrop].increase_by(num_dropped as u64);
            asm.counters[CounterType::InCapPacksFilt].increase_by(num_filtered as u64);
        }

        Direction::Outbound => {
            asm.counters[CounterType::OutCapPacksWrite].increase_by(num_captured as u64);
            asm.counters[CounterType::OutCapPacksDrop].increase_by(num_dropped as u64);
            asm.counters[CounterType::OutCapPacksFilt].increase_by(num_filtered as u64);
        }
    }
}

/// Encrypt a ZDP packet according to its ZPI header (which is not encrypted).
pub fn encrypt_null(pkt: &mut Packet) {
    // RFC 6.5 § 5.25.2
    pkt.put(
        net_defs::inet_checksum(&pkt.body()[std::mem::size_of::<zdp::ZdpZpiHeader>()..]).as_slice(),
    );
}

/// Slap an HMAC onto the end of the packet.
pub fn encrypt_hmac(send_hmac_key: [u8; 32], pkt: &mut Packet) {
    let mut link_mac = [0u8; zdp::ZDP_PACKET_MAC_SIZE];
    link_mac[..zdp::ZDP_PACKET_MAC_SIZE].copy_from_slice(
        &blake3::keyed_hash(&send_hmac_key, pkt.body()).as_bytes()[..zdp::ZDP_PACKET_MAC_SIZE],
    );
    pkt.put(&link_mac[..zdp::ZDP_PACKET_MAC_SIZE]);
}

pub fn encrypt_full(
    _asm: &Assembly,
    codec: &dyn Codec,
    pkt: &mut Packet,
) -> Result<(), km::EncryptionError> {
    // TODO: Could do some length checks here on the packet body.  Is it too short? Too long? Etc.

    let zpi_hdr_len = std::mem::size_of::<zdp::ZdpZpiHeader>(); // = 1

    let mut enc_buf = [0u8; config::PACKET_BUFFER_SIZE];
    let encr_len = pkt.body().len() - zpi_hdr_len; // Everything except the ZPI byte

    match codec.encrypt_transport_stateless(
        &pkt.body()[zpi_hdr_len..encr_len + zpi_hdr_len],
        &mut enc_buf,
    ) {
        Ok(len) => {
            pkt.shrink_by(encr_len); // remove cleartext body, leavign ZPI
            pkt.put(&enc_buf[0..len]); // copy ciphertext body over
            Ok(())
        }
        Err(e) => Err(e),
    }
}

enum DecryptError {
    BadStructure,
    UnknownZpi,
    DecryptionFailure,
    MicvFailure,
    BadChecksum,
}

impl From<DecryptError> for CounterType {
    fn from(value: DecryptError) -> Self {
        match value {
            DecryptError::BadStructure => Self::BadStructure,
            DecryptError::UnknownZpi => Self::UnknownZpi,
            DecryptError::DecryptionFailure => Self::DecryptionFailure,
            DecryptError::MicvFailure => Self::MicvFailure,
            DecryptError::BadChecksum => Self::BadChecksum,
        }
    }
}

/// "Decrypt" a packet using NULL encryption.
fn decrypt_null(pkt: &mut Packet) -> Result<(), DecryptError> {
    // RFC 6.5 § 5.25.2
    if !net_defs::validate_inet_checksum(&pkt.body()[std::mem::size_of::<zdp::ZdpZpiHeader>()..]) {
        return Err(DecryptError::BadChecksum);
    }

    pkt.shrink_by(2); // remove checksum

    Ok(())
}

/// Check and remove the link-2-link HMAC on the (presumed) transit packet.
fn decrypt_hmac(recv_hmac_key: [u8; 32], pkt: &mut Packet) -> Result<(), DecryptError> {
    if pkt.body().len() < zdp::ZDP_PACKET_MAC_SIZE {
        return Err(DecryptError::BadStructure);
    }

    let mut link_mac = [0u8; zdp::ZDP_PACKET_MAC_SIZE];

    link_mac.copy_from_slice(&pkt.body()[pkt.body().len() - zdp::ZDP_PACKET_MAC_SIZE..]);
    pkt.shrink_by(zdp::ZDP_PACKET_MAC_SIZE);

    if &blake3::keyed_hash(&recv_hmac_key, &pkt.body()).as_bytes()[..zdp::ZDP_PACKET_MAC_SIZE]
        != &link_mac[..zdp::ZDP_PACKET_MAC_SIZE]
    {
        return Err(DecryptError::MicvFailure);
    }

    Ok(())
}

/// Decrypt a packet using the given encryption codec.
fn decrypt_full(
    _asm: &Assembly,
    codec: &dyn Codec,
    padlen: usize,
    pkt: &mut Packet,
) -> Result<(), DecryptError> {
    if pkt.body().len() < 1 {
        return Err(DecryptError::BadStructure);
    }
    let encr_len = pkt.body().len() - 1;
    if encr_len < padlen {
        return Err(DecryptError::BadStructure);
    }

    let mut decr_buf = [0u8; config::PACKET_BUFFER_SIZE];

    match codec.decrypt_transport_stateless(&pkt.body()[1..encr_len + 1], &mut decr_buf) {
        Ok(len) => {
            // Copy the decrypted data back into the message -- do not overwrite ZPI.
            pkt.shrink_by(encr_len); // remove ciphertext body, leave ZPI
            pkt.put(&decr_buf[0..len]); // copy over cleartext body
        }
        Err(e) => {
            error!(target: DATAPATH, "decryption failed: {}", e);
            return Err(DecryptError::DecryptionFailure);
        }
    }
    Ok(())
}

/// Decrypt a ZDP packet according to its ZPI header (which is not removed) and known security association.
fn decrypt_with_sa(
    asm: &Assembly,
    zpi_hdr: zdp::ZdpZpiHeader,
    transport_sa: &KmTransportSA,
    pkt: &mut Packet,
) -> Result<(), DecryptError> {
    if zpi_hdr.zpi == transport_sa.recv_zpis.hmac {
        return decrypt_hmac(transport_sa.recv_hmac_key, pkt);
    } else if zpi_hdr.zpi == transport_sa.recv_zpis.encr {
        // TODO: Put padlen in state somewhere too
        return decrypt_full(asm, &*transport_sa.codec, NOISE_PADLEN, pkt);
    } else {
        // We have an SA and ZPI does not match.
        warn!(
            target: DATAPATH,
            "ingress: link {}: unexpected ZPI value {} (expected {:?})",
            pkt.metadata().ingress_link_id,
            zpi_hdr.zpi,
            transport_sa.recv_zpis
        );
        return Err(DecryptError::UnknownZpi);
    }
}

/// Decrypt a ZDP packet according to its ZPI header (which is not removed).
fn decrypt(
    asm: &Assembly,
    zpi_hdr: zdp::ZdpZpiHeader,
    pkt: &mut Packet,
) -> Result<(), DecryptError> {
    let peer_state = asm.peer_table.get(pkt.metadata().ingress_link_id);

    // If a ZPI is setup on this link, then we expect the message to use one of the valid
    // ZPI values.
    match peer_state {
        Some(state) => {
            match state.get_established_transport_association() {
                Some(ref transport_sa) => {
                    // We've found a matching security association; use it to decrypt.
                    return decrypt_with_sa(asm, zpi_hdr, &transport_sa, pkt);
                }
                None => {
                    // Either no security association on link, or it is not yet established.
                    debug!(target: DATAPATH, "INSECURE, no SA on link {}", pkt.metadata().ingress_link_id);
                }
            }
        }
        None => {
            // No link in peer table
            debug!(
                target: DATAPATH,
                "INSECURE, no link in peer table for {}",
                pkt.metadata().ingress_link_id
            );
        }
    }

    // If we got here, it's because we couldn't find a security association.
    // This means only ZPI 0 is allowed.
    if zpi_hdr.zpi != zpr::ZPI_0 && pkt.metadata().ingress_link_id != zpr::LINK_ID_UNKNOWN {
        warn!(
            target: DATAPATH,
            "ingress: {}: ZPI {} not allowed on unestablished SA",
            pkt.metadata().ingress_link_id,
            zpi_hdr.zpi
        );
        return Err(DecryptError::UnknownZpi);
    }

    debug!(
        target: DATAPATH,
        "INSECURE, decrypting null packet from {}",
        pkt.metadata().ingress_link_id
    );

    return decrypt_null(pkt);
}

fn substrate_egress_common(
    asm: &Assembly,
    link_id: zpr::LinkId,
    pkt: &mut Packet,
) -> Result<Option<(zpr::SubstrateAddr, net_defs::ScopedIpAddr)>, km::EncryptionError> {
    // TODO: should we add ZDP header here also??

    let zdp_hdr = match zdp::ZdpBaseHeader::ref_from_prefix(&pkt.body()) {
        Ok((zdp_hdr, _)) => zdp_hdr,
        Err(_) => {
            error!(target: DATAPATH, "egress: link {}: failed to parse the ZDP header", link_id);
            return Err(km::EncryptionError::ParseError);
        }
    };

    let transit = zdp_hdr.packet_type == zdp::ZdpPacketType::TransitPacket;

    // Get the security association for this link and extrant the correct ZPI.
    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Ok(None);
    };

    // If this is key management we do not use transport security.
    // TODO: Not quite correct.  We ought to be able to use an existing
    //       security association for re-keying.  But for the intitial
    //       SA exchange, the node goes into transport mode as it consumes
    //       the message from the adapter.  But we need to send that initial
    //       message back under ZIP-0.
    //
    //       See https://github.com/org-zpr/zpr-core/issues/444
    let transport_sa;
    if zdp_hdr.packet_type == zdp::ZdpPacketType::KeyManagement {
        debug!(target: DATAPATH, "link {link_id}: KM message detected, using ZPI=0 ignoring security association");
        transport_sa = None;
    } else {
        transport_sa = peer_state.get_established_transport_association();
    }

    let real_zpi;
    match transport_sa {
        Some(ref transport_sa) => {
            if transit {
                real_zpi = transport_sa.send_zpis.hmac;
            } else {
                real_zpi = transport_sa.send_zpis.encr;
            }
            assert!(real_zpi != zpr::ZPI_0);
        }
        None => {
            real_zpi = zpr::ZPI_0;
        }
    }

    encap_zpi(asm, link_id, real_zpi, pkt);
    maybe_capture(asm, Direction::Outbound, pkt);

    match transport_sa {
        Some(ref transport_sa) => {
            if transit {
                encrypt_hmac(transport_sa.send_hmac_key, pkt);
            } else {
                match encrypt_full(asm, &*transport_sa.codec, pkt) {
                    Ok(()) => (),
                    Err(err) => return Err(err),
                }
            }
        }
        None => {
            encrypt_null(pkt);
        }
    }

    let mut dest_sa = peer_state.substrate_addr;

    // Set substrate flowinfo from our flowhash.
    set_flowinfo(&mut dest_sa, pkt.flowhash());

    Ok(Some((dest_sa, peer_state.interface_addr)))
}

/// If substrate supports flow info, set it to the specified value.
fn set_flowinfo(substrate_addr: &mut zpr::SubstrateAddr, flowinfo: u32) {
    match substrate_addr {
        SocketAddr::V4(_) => (),
        SocketAddr::V6(sa) => sa.set_flowinfo(flowinfo),
    }
}

/// Decrement the ttl of a ZDP packet, if the ZDP packet is an IP packet
/// Returns true if ttl reaches zero and false otherwise, to indicate whether
/// the packet should be discarded
fn decrement_ttl(pkt: &mut Packet) -> bool {
    // decrement TTL
    match pkt.metadata().get_l3_type() {
        L3Type::Ipv4 => {
            let body = pkt.body_mut();

            let header_bytes = &mut body[..size_of::<IPv4Header>()];
            let ipv4_header = IPv4Header::mut_from_bytes(header_bytes).unwrap();
            // TODO remove when conditional decrement
            if ipv4_header.ttl > 0 {
                ipv4_header.ttl -= 1;
            }
            match ipv4_header.ttl {
                0 => true,
                _ => false,
            }
        }
        L3Type::Ipv6 => {
            let body = pkt.body_mut();

            let header_bytes = &mut body[..size_of::<IPv6Header>()];
            let ipv6_header = IPv6Header::mut_from_bytes(header_bytes).unwrap();
            // TODO remove when conditional decrement
            if ipv6_header.hop_limit > 0 {
                ipv6_header.hop_limit -= 1;
            }
            match ipv6_header.hop_limit {
                0 => true,
                _ => false,
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::config::PACKET_BUFFER_SIZE;

    #[test]
    fn test_encrypt_decrypt_null() {
        let buf = Box::new([0u8; PACKET_BUFFER_SIZE]);
        let mut pkt = Packet::new(buf, 64);

        pkt.put(&b"this is a test of encrypt zero"[..]);

        let orig_len = pkt.body().len();

        encrypt_null(&mut pkt);

        assert!(pkt.body().len() == orig_len + 2); // did add checksum

        let res = decrypt_null(&mut pkt);
        assert!(res.is_ok());

        assert!(pkt.body().len() == orig_len); // did remove checksum
    }

    #[test]
    fn test_add_and_check_hmac() {
        let buf = Box::new([0u8; PACKET_BUFFER_SIZE]);
        let mut pkt = Packet::new(buf, 64);

        pkt.put(&b"this is a test of hmac"[..]);
        let key: [u8; 32] = [6u8; 32];

        let orig_len = pkt.body().len();

        encrypt_hmac(key, &mut pkt);

        assert!(pkt.body().len() == orig_len + zdp::ZDP_PACKET_MAC_SIZE); // did add hmac

        let res = decrypt_hmac(key, &mut pkt);
        assert!(res.is_ok());

        assert!(pkt.body().len() == orig_len); // did remove hmac
    }

    #[test]
    fn test_add_and_check_hmac_fail() {
        let buf = Box::new([0u8; PACKET_BUFFER_SIZE]);
        let mut pkt = Packet::new(buf, 64);

        pkt.put(&b"this is a test of hmac"[..]);
        let key: [u8; 32] = [6u8; 32];

        let orig_len = pkt.body().len();

        encrypt_hmac(key, &mut pkt);

        assert!(pkt.body().len() == orig_len + zdp::ZDP_PACKET_MAC_SIZE); // did add hmac

        let wrong_key: [u8; 32] = [7u8; 32];

        let res = decrypt_hmac(wrong_key, &mut pkt);
        assert!(res.is_err());
    }

    #[test]
    fn test_ipv4_ttl_reduction() {
        let mut buf = Box::new([0u8; config::PACKET_BUFFER_SIZE]);
        let offset = Packet::MIN_BODY_OFFSET + 123;
        let data = [5; 50].as_slice();
        buf[offset..offset + 50].copy_from_slice(data);
        let mut pkt = Packet::new_with_existing_data(buf, Packet::MIN_BODY_OFFSET + 123, 50);

        pkt.metadata_mut().set_l3_type(L3Type::Ipv4);
        let body = pkt.body_mut();

        let header_bytes = &mut body[..size_of::<IPv4Header>()];
        let ipv4_header = IPv4Header::mut_from_bytes(header_bytes).unwrap();
        ipv4_header.ttl = 3;

        assert!(ipv4_header.ttl == 3);

        let result = decrement_ttl(&mut pkt);

        let new_body = pkt.body_mut();
        let new_header_bytes = &mut new_body[..size_of::<IPv4Header>()];
        let new_ipv4_header = IPv4Header::mut_from_bytes(new_header_bytes).unwrap();

        assert!(result == false);
        assert!(new_ipv4_header.ttl == 2);
    }

    #[test]
    fn test_ipv4_ttl_reduction_with_destroy() {
        let mut buf = Box::new([0u8; config::PACKET_BUFFER_SIZE]);
        let offset = Packet::MIN_BODY_OFFSET + 123;
        let data = [5; 50].as_slice();
        buf[offset..offset + 50].copy_from_slice(data);
        let mut pkt = Packet::new_with_existing_data(buf, Packet::MIN_BODY_OFFSET + 123, 50);

        pkt.metadata_mut().set_l3_type(L3Type::Ipv4);
        let body = pkt.body_mut();

        let header_bytes = &mut body[..size_of::<IPv4Header>()];
        let ipv4_header = IPv4Header::mut_from_bytes(header_bytes).unwrap();
        ipv4_header.ttl = 1;

        assert!(ipv4_header.ttl == 1);

        let result = decrement_ttl(&mut pkt);

        let new_body = pkt.body_mut();
        let new_header_bytes = &mut new_body[..size_of::<IPv4Header>()];
        let new_ipv4_header = IPv4Header::mut_from_bytes(new_header_bytes).unwrap();

        assert!(result == true);
        assert!(new_ipv4_header.ttl == 0);
    }

    #[test]
    fn test_ipv6_ttl_reduction() {
        let mut buf = Box::new([0u8; config::PACKET_BUFFER_SIZE]);
        let offset = Packet::MIN_BODY_OFFSET + 123;
        let data = [5; 50].as_slice();
        buf[offset..offset + 50].copy_from_slice(data);
        let mut pkt = Packet::new_with_existing_data(buf, Packet::MIN_BODY_OFFSET + 123, 50);

        pkt.metadata_mut().set_l3_type(L3Type::Ipv6);
        let body = pkt.body_mut();

        let header_bytes = &mut body[..size_of::<IPv6Header>()];
        let ipv6_header = IPv6Header::mut_from_bytes(header_bytes).unwrap();
        ipv6_header.hop_limit = 3;

        assert!(ipv6_header.hop_limit == 3);

        let result = decrement_ttl(&mut pkt);

        let new_body = pkt.body_mut();
        let new_header_bytes = &mut new_body[..size_of::<IPv6Header>()];
        let new_ipv6_header = IPv6Header::mut_from_bytes(new_header_bytes).unwrap();

        assert!(result == false);
        assert!(new_ipv6_header.hop_limit == 2);
    }

    #[test]
    fn test_ipv6_ttl_reduction_with_destroy() {
        let mut buf = Box::new([0u8; config::PACKET_BUFFER_SIZE]);
        let offset = Packet::MIN_BODY_OFFSET + 123;
        let data = [5; 50].as_slice();
        buf[offset..offset + 50].copy_from_slice(data);
        let mut pkt = Packet::new_with_existing_data(buf, Packet::MIN_BODY_OFFSET + 123, 50);

        pkt.metadata_mut().set_l3_type(L3Type::Ipv6);
        let body = pkt.body_mut();

        let header_bytes = &mut body[..size_of::<IPv6Header>()];
        let ipv6_header = IPv6Header::mut_from_bytes(header_bytes).unwrap();
        ipv6_header.hop_limit = 1;

        assert!(ipv6_header.hop_limit == 1);

        let result = decrement_ttl(&mut pkt);

        let new_body = pkt.body_mut();
        let new_header_bytes = &mut new_body[..size_of::<IPv6Header>()];
        let new_ipv6_header = IPv6Header::mut_from_bytes(new_header_bytes).unwrap();

        assert!(result == true);
        assert!(new_ipv6_header.hop_limit == 0);
    }
}
