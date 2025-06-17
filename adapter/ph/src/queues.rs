//! Queues (i.e., frontend interface) for each stage of the system.

use crate::config;
use crate::net_defs;
use crate::packet::{self, Packet, PacketBuffer};
use crate::packet_queue;
use crate::test_packet::*;
use crate::two_way_queue;
use bytes::Buf;
use libc;
use std::io::ErrorKind;
use std::os::unix::net::UnixDatagram;
use std::result::Result;
use std::time::SystemTime;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot::error::RecvError;
use zpr;

pub enum TryEnqueueError<T = ()> {
    Full(T),
}

pub enum MgmtProcessorMessage {
    Packet(Packet),
    TestPacket(TestPacket),
}

/// MgmtProcessor processes all inbound management requests.
/// Unlike other queues, this doesn't live directly in the assembly,
/// but rather in the peer table, as there is one of these per peer.
pub struct MgmtProcessor {
    sender: mpsc::Sender<MgmtProcessorMessage>,
}

impl MgmtProcessor {
    pub fn new(sender: mpsc::Sender<MgmtProcessorMessage>) -> Self {
        Self { sender }
    }

    pub fn try_enqueue_packet(&self, packet: Packet) -> Result<(), TryEnqueueError<Packet>> {
        match self.sender.try_send(MgmtProcessorMessage::Packet(packet)) {
            Ok(()) => Ok(()),

            Err(TrySendError::Closed(_)) => panic!("mgmt processor channel closed"),

            Err(TrySendError::Full(msg)) => {
                let MgmtProcessorMessage::Packet(pkt) = msg else {
                    unreachable!()
                };
                Err(TryEnqueueError::Full(pkt))
            }
        }
    }

    /// Sends TestPacket through system using MgmtProcessor sender, awaits response from
    /// the corresponding receiver via TestPacket::acknowledge, returns metrics or an error
    // TODO perhaps enqueue_test_packet is not the best name, because it does more than
    // just enqueue, it also waits for the response, unlike the other enqueue methods of other
    // queues
    #[allow(dead_code)]
    pub async fn enqueue_test_packet(&self) -> Result<TestPacketMetrics, RecvError> {
        let test_tuple = TestPacket::create();

        self.sender
            .send(MgmtProcessorMessage::TestPacket(test_tuple.0))
            .await
            .unwrap();

        Ok(test_tuple.1.await?)
    }
}

/// MgmtSubstrateEgress allows mgmt to inject ZDP packets into the substrate egress fastpath.
pub struct MgmtSubstrateEgress {
    queue: packet_queue::Sender<{ config::PACKET_BUFFER_SIZE }>,
}

impl MgmtSubstrateEgress {
    /// Sockets must be marked non-blocking by caller.
    pub fn new(queue: packet_queue::Sender<{ config::PACKET_BUFFER_SIZE }>) -> Self {
        Self { queue }
    }

    /// Enqueue the given packet to be egressed on the substrate.
    /// Blocks until the packet is in the hands of the fastpath.
    /// The packet is marked PRIORITY, which instructs the fastpath to
    /// ensure it eventually gets queued with the OS.
    #[allow(dead_code)]
    pub async fn enqueue_packet(&self, link_id: zpr::LinkId, mut packet: Packet) {
        packet.metadata_mut().egress_link_id = link_id;
        packet.metadata_mut().flags |= packet::flags::PRIORITY;
        self.queue
            .send(&packet)
            .await
            .expect("unrecoverable I/O error");
    }

    /// Try to enqueue the given packet to be egressed on the substrate.
    /// Returns said packet if there is no room in the queue.
    /// Unlike `enqueue_packet()`, the packet is not marked for any special processing.
    pub fn try_enqueue_packet(&self, link_id: zpr::LinkId, mut packet: Packet) -> bool {
        packet.metadata_mut().egress_link_id = link_id;
        match self.queue.try_send(&packet) {
            Ok(()) => true,
            Err(packet_queue::TrySendError::Full) => false,
            Err(err) => panic!("unrecoverable I/O error: {err:?}"),
        }
    }
}

/// Used for requeueing actor output packets from mgmt.
pub struct ActorOutputRequeue {
    queues: Box<[packet_queue::Sender<{ config::PACKET_BUFFER_SIZE }>]>,
}

impl ActorOutputRequeue {
    pub fn new(
        queues: impl IntoIterator<Item = packet_queue::Sender<{ config::PACKET_BUFFER_SIZE }>>,
    ) -> Self {
        Self {
            queues: queues.into_iter().collect(),
        }
    }

    pub fn try_enqueue_packet(&self, packet: Packet) -> Result<(), TryEnqueueError<Packet>> {
        let queue = self.select_queue(&packet);

        match queue.try_send(&packet) {
            Ok(()) => {
                drop(packet);
                Ok(())
            }

            Err(packet_queue::TrySendError::Full) => Err(TryEnqueueError::Full(packet)),
            Err(err) => panic!("unrecoverable I/O error: {err:?}"),
        }
    }

    fn select_queue(
        &self,
        packet: &Packet,
    ) -> &packet_queue::Sender<{ config::PACKET_BUFFER_SIZE }> {
        &self.queues[packet.metadata().ingress_lane_id as usize]
    }
}

/// Capture will intercept packets in the PH and dump them into a file for debugging purposes
pub struct Capture {
    sender: UnixDatagram,
}

impl Capture {
    /// `sender` must be set nonblocking
    pub fn new(sender: UnixDatagram) -> Self {
        Self { sender }
    }

    /// Try to send a packet to the capture system.
    /// Only `incl_len` bytes will be captured.  (If this is larger than the
    /// actual packet length, it is reduced accordingly.)
    /// Does not block.
    ///
    /// NOTE: requires mut reference to the packet, but the packet is
    /// materially unchanged.  Simply, a 16-byte header is briefly added to
    /// and then removed from it.
    pub fn try_enqueue_packet(
        &self,
        packet: &mut Packet,
        timestamp: SystemTime,
        incl_len: usize,
    ) -> Result<(), TryEnqueueError> {
        let incl_len = std::cmp::min(incl_len, packet.remaining());

        let hdr = crate::pcap_writer::PcaprecHdr::new(timestamp, incl_len, packet.remaining());

        // temporarily add header
        // TODO: instead of requiring a &mut Packet,
        // we can instead accept any &[u8] and use vectored send
        // once we it becomes stable
        packet.push_header(&hdr);

        // does not block, as we know the socket is nonblocking
        let res = self.sender.send(
            &packet.body()[..std::mem::size_of::<crate::pcap_writer::PcaprecHdr>() + incl_len],
        );

        // remove temporary header
        packet.advance(std::mem::size_of::<crate::pcap_writer::PcaprecHdr>());

        match res {
            Ok(_) => Ok(()),

            Err(err) => match err.kind() {
                ErrorKind::WouldBlock => Err(TryEnqueueError::Full(())),
                ErrorKind::ConnectionRefused | ErrorKind::BrokenPipe => {
                    panic!("capture channel closed")
                }
                _ => match err.raw_os_error() {
                    Some(libc::ENOBUFS) => Err(TryEnqueueError::Full(())),
                    _ => panic!("unrecoverable I/O error: {}", err),
                },
            },
        }
    }
}

pub enum MgmtDispatchMessage {
    WithLink(Packet), // Link ID stored in packet metadata
    WithAddr {
        peer_sa: zpr::SubstrateAddr,
        interface_addr: net_defs::ScopedIpAddr,
        packet: Packet,
    },
}

impl two_way_queue::TwoWayReturnable<MgmtDispatchMessage> for PacketBuffer {
    fn convert(value: MgmtDispatchMessage) -> Self {
        match value {
            MgmtDispatchMessage::WithLink(pkt) => pkt.destroy(),
            MgmtDispatchMessage::WithAddr { packet, .. } => packet.destroy(),
        }
    }
}

pub struct MgmtDispatch {
    sender: two_way_queue::Sender<MgmtDispatchMessage, PacketBuffer>,
}

impl MgmtDispatch {
    pub fn try_dispatch_mgmt_packet_with_link(
        &mut self,
        packet: Packet,
    ) -> Result<(), TryEnqueueError<Packet>> {
        debug_assert_ne!(packet.metadata().ingress_link_id, 0);
        match self.sender.try_send(MgmtDispatchMessage::WithLink(packet)) {
            Ok(()) => Ok(()),

            Err(two_way_queue::TrySendError::Closed(_)) => panic!("mgmt dispatch channel closed"),

            Err(two_way_queue::TrySendError::Full(msg)) => {
                let MgmtDispatchMessage::WithLink(pkt) = msg else {
                    unreachable!()
                };
                Err(TryEnqueueError::Full(pkt))
            }
        }
    }

    pub fn try_dispatch_mgmt_packet_with_addr(
        &mut self,
        peer_sa: &zpr::SubstrateAddr,
        interface_addr: &net_defs::ScopedIpAddr,
        packet: Packet,
    ) -> Result<(), TryEnqueueError<Packet>> {
        debug_assert_eq!(packet.metadata().ingress_link_id, 0);
        match self.sender.try_send(MgmtDispatchMessage::WithAddr {
            peer_sa: *peer_sa,
            interface_addr: *interface_addr,
            packet,
        }) {
            Ok(()) => Ok(()),

            Err(two_way_queue::TrySendError::Closed(_)) => panic!("mgmt dispatch channel closed"),

            Err(two_way_queue::TrySendError::Full(msg)) => {
                let MgmtDispatchMessage::WithAddr { packet, .. } = msg else {
                    unreachable!()
                };
                Err(TryEnqueueError::Full(packet))
            }
        }
    }
}

/// Factory to build `MgmtDispatch` ingresses for specified two-way-queue return queues.
pub struct MgmtDispatchFactory(two_way_queue::SenderFactory<MgmtDispatchMessage, PacketBuffer>);

impl MgmtDispatchFactory {
    pub fn new(fact: two_way_queue::SenderFactory<MgmtDispatchMessage, PacketBuffer>) -> Self {
        Self(fact)
    }

    pub fn make(&self, ret_q: &two_way_queue::ReturnQueue<PacketBuffer>) -> MgmtDispatch {
        MgmtDispatch {
            sender: self.0.make(ret_q),
        }
    }
}

pub enum AdapterManagerMessage {
    RequestTetherId(Packet),
}

impl two_way_queue::TwoWayReturnable<AdapterManagerMessage> for PacketBuffer {
    fn convert(value: AdapterManagerMessage) -> Self {
        match value {
            AdapterManagerMessage::RequestTetherId(pkt) => pkt.destroy(),
        }
    }
}

pub struct AdapterManager {
    sender: two_way_queue::Sender<AdapterManagerMessage, PacketBuffer>,
}

impl AdapterManager {
    /// Request a tether ID to use for sending packets starting with the
    /// specified packet.
    ///
    /// While awaiting a tether ID, the five-tuple will be marked pending in
    /// the ALT.  (Note that this occurs asynchronously!  Ensure that this
    /// race is benign for your use case before relying on the pending mark.)
    ///
    /// After a tether ID is received, a PEP will be added to
    /// the ALT, and an attempt will be made to send the specified packet.
    ///
    /// The specified packet must have already been classified.
    pub fn try_request_tether_id(&mut self, packet: Packet) -> Result<(), TryEnqueueError<Packet>> {
        match self
            .sender
            .try_send(AdapterManagerMessage::RequestTetherId(packet))
        {
            Ok(()) => Ok(()),

            Err(two_way_queue::TrySendError::Closed(_)) => panic!("adapter manager channel closed"),

            Err(two_way_queue::TrySendError::Full(msg)) => match msg {
                AdapterManagerMessage::RequestTetherId(packet) => {
                    Err(TryEnqueueError::Full(packet))
                }
            },
        }
    }
}

/// Factory to build `AdapterManager` ingresses for specified two-way-queue return queues.
pub struct AdapterManagerFactory(two_way_queue::SenderFactory<AdapterManagerMessage, PacketBuffer>);

impl AdapterManagerFactory {
    pub fn new(fact: two_way_queue::SenderFactory<AdapterManagerMessage, PacketBuffer>) -> Self {
        Self(fact)
    }

    pub fn make(&self, ret_q: &two_way_queue::ReturnQueue<PacketBuffer>) -> AdapterManager {
        AdapterManager {
            sender: self.0.make(ret_q),
        }
    }
}
