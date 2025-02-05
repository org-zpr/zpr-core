//! Queues (i.e., frontend interface) for each stage of the system.

use crate::net_defs;
use crate::packet::{Packet, PacketBuffer};
use crate::sys::TunPi;
use crate::sys::ZprTun;
use crate::test_packet::*;
use crate::two_way_queue;
use bytes::Buf;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::result::Result;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::{UdpSocket, UnixDatagram};
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

/// AgentInput is responsible for emitting decapsulated agent packets on the
/// host's TUN interface.
pub struct AgentInput {
    tuns: Box<[Arc<ZprTun>]>,
}

impl AgentInput {
    // We necessarily have multiple queues, corresponding to the multiple
    // FDs of a multiqueue-enabled TUN interface.
    pub fn new(tuns: impl IntoIterator<Item = Arc<ZprTun>>) -> Self {
        Self {
            tuns: tuns.into_iter().collect(),
        }
    }

    pub fn try_enqueue_packet(&self, packet: &mut Packet) -> Result<(), TryEnqueueError> {
        let tun = &self.tuns[packet.flowhash() as usize % self.tuns.len()];
        match TunPi::PI_SIZE {
            0 => (),
            sz => {
                let proto = net_defs::ip_ethertype(net_defs::ip_version(packet.body()));
                let mut hdr = packet.alloc_zeroed_headroom(sz);
                TunPi::write_pi(
                    &mut hdr,
                    TunPi {
                        strip: false,
                        proto,
                    },
                );
            }
        };

        let ret = tun.try_send(packet.body());

        packet.advance(std::mem::size_of::<TunPi>());

        match ret {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == ErrorKind::WouldBlock => Err(TryEnqueueError::Full(())),
            Err(err) => panic!("unrecoverable TUN error: {}", err),
        }
    }

    #[allow(dead_code)]
    pub fn fanout(&self) -> usize {
        self.tuns.len()
    }
}

/// SubstrateEgress is responsible for sending encapsulated agent packets to the dock.
pub struct SubstrateEgress {
    sockets: Box<[Arc<UdpSocket>]>,
}

impl SubstrateEgress {
    pub fn new(sockets: impl IntoIterator<Item = Arc<UdpSocket>>) -> Self {
        Self {
            sockets: sockets.into_iter().collect(),
        }
    }

    pub async fn enqueue_packet(
        &self,
        packet: &Packet,
        dest_sa: zpr::SubstrateAddr,
    ) -> Result<(), ()> {
        let (socket, dest_sockaddr) = self.select_socket_and_set_flowinfo(packet, dest_sa);

        match socket.send_to(packet.body(), dest_sockaddr).await {
            Ok(_) => Ok(()),

            Err(err) => {
                match err.kind() {
                    ErrorKind::InvalidInput | ErrorKind::Unsupported => {
                        panic!("unrecoverable I/O error: {}", err)
                    }

                    // most other network errors are temporary; return packet to caller
                    // TODO: it would be nice to report to the user _why_ packets aren't moving;
                    // this depends on <https://github.com/rust-lang/rust/issues/86442> though
                    _ => Err(()),
                }
            }
        }
    }

    // TODO: batch enqueue
    pub fn try_enqueue_packet(
        &self,
        packet: &Packet,
        dest_sa: zpr::SubstrateAddr,
    ) -> Result<(), TryEnqueueError> {
        let (socket, dest_sockaddr) = self.select_socket_and_set_flowinfo(packet, dest_sa);

        match socket.try_send_to(packet.body(), dest_sockaddr) {
            Ok(_) => Ok(()),

            Err(err) => {
                match err.kind() {
                    ErrorKind::InvalidInput | ErrorKind::Unsupported => {
                        panic!("unrecoverable I/O error: {}", err)
                    }

                    ErrorKind::WouldBlock => Err(TryEnqueueError::Full(())),

                    // most other network errors are temporary; return packet to caller
                    // TODO: it would be nice to report to the user _why_ packets aren't moving;
                    // this depends on <https://github.com/rust-lang/rust/issues/86442> though
                    _ => Err(TryEnqueueError::Full(())),
                }
            }
        }
    }

    fn select_socket_and_set_flowinfo(
        &self,
        packet: &Packet,
        mut dest_sa: zpr::SubstrateAddr,
    ) -> (&UdpSocket, std::net::SocketAddr) {
        match &mut dest_sa {
            SocketAddr::V4(_) => (),
            SocketAddr::V6(dest_sa) => dest_sa.set_flowinfo(packet.flowhash()),
        }

        (
            &self.sockets[packet.flowhash() as usize % self.sockets.len()],
            dest_sa,
        )
    }

    #[allow(dead_code)]
    pub fn fanout(&self) -> usize {
        self.sockets.len()
    }
}

/// Used for requeueing agent output packets from mgmt.
pub struct AgentOutputRequeue {
    sockets: Box<[UnixDatagram]>,
}

impl AgentOutputRequeue {
    pub fn new(sockets: impl IntoIterator<Item = UnixDatagram>) -> Self {
        Self {
            sockets: sockets.into_iter().collect(),
        }
    }

    pub fn try_enqueue_packet(&self, packet: Packet) -> Result<(), TryEnqueueError<Packet>> {
        let socket = self.select_socket(&packet);

        match socket.try_send(packet.buffer()) {
            Ok(_) => Ok(()),

            Err(err) => match err.kind() {
                ErrorKind::WouldBlock => Err(TryEnqueueError::Full(packet)),
                _ => panic!("unrecoverable I/O error: {}", err),
            },
        }
    }

    fn select_socket(&self, packet: &Packet) -> &UnixDatagram {
        &self.sockets[packet.metadata().ingress_lane_id as usize]
    }
}

/// Capture will intercept packets in the PH and dump them into a file for debugging purposes
pub struct Capture {
    sender: std::os::unix::net::UnixDatagram,
}

impl Capture {
    pub fn new(sender: std::os::unix::net::UnixDatagram) -> Self {
        sender.set_nonblocking(true).unwrap();
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

        // does not block, as we've set O_NONBLOCK in `new()`
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
                _ => panic!("unrecoverable I/O error: {}", err),
            },
        }
    }
}

pub enum MgmtDispatchMessage {
    WithLink(Packet), // Link ID stored in packet metadata
    WithAddr(zpr::SubstrateAddr, Packet),
}

impl two_way_queue::TwoWayReturnable<MgmtDispatchMessage> for PacketBuffer {
    fn convert(value: MgmtDispatchMessage) -> Self {
        match value {
            MgmtDispatchMessage::WithLink(pkt) => pkt.destroy(),
            MgmtDispatchMessage::WithAddr(_, pkt) => pkt.destroy(),
        }
    }
}

#[derive(Clone)]
pub struct MgmtDispatch {
    sender: two_way_queue::Sender<MgmtDispatchMessage, PacketBuffer>,
}

impl MgmtDispatch {
    pub fn new(sender: two_way_queue::Sender<MgmtDispatchMessage, PacketBuffer>) -> Self {
        Self { sender }
    }

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
        packet: Packet,
    ) -> Result<(), TryEnqueueError<Packet>> {
        debug_assert_eq!(packet.metadata().ingress_link_id, 0);
        match self
            .sender
            .try_send(MgmtDispatchMessage::WithAddr(*peer_sa, packet))
        {
            Ok(()) => Ok(()),

            Err(two_way_queue::TrySendError::Closed(_)) => panic!("mgmt dispatch channel closed"),

            Err(two_way_queue::TrySendError::Full(msg)) => {
                let MgmtDispatchMessage::WithAddr(_, pkt) = msg else {
                    unreachable!()
                };
                Err(TryEnqueueError::Full(pkt))
            }
        }
    }

    #[allow(dead_code)]
    pub fn recv_return_buffers(&mut self, returns: &mut Vec<PacketBuffer>, limit: usize) -> usize {
        self.sender.blocking_recv_many_returns(returns, limit)
    }

    #[allow(dead_code)]
    pub fn try_recv_return_buffers(
        &mut self,
        returns: &mut Vec<PacketBuffer>,
        limit: usize,
    ) -> usize {
        self.sender.try_recv_many_returns(returns, limit)
    }

    #[allow(dead_code)]
    pub async fn async_recv_return_buffers(
        &mut self,
        returns: &mut Vec<PacketBuffer>,
        limit: usize,
    ) -> usize {
        self.sender.recv_many_returns(returns, limit).await
    }

    pub async fn async_recv_return_buffer(&mut self) -> PacketBuffer {
        self.sender.recv_return().await
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

#[derive(Clone)]
pub struct AdapterManager {
    sender: two_way_queue::Sender<AdapterManagerMessage, PacketBuffer>,
}

impl AdapterManager {
    pub fn new(sender: two_way_queue::Sender<AdapterManagerMessage, PacketBuffer>) -> Self {
        Self { sender }
    }

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

    #[allow(dead_code)]
    pub fn recv_return_buffers(&mut self, returns: &mut Vec<PacketBuffer>, limit: usize) -> usize {
        self.sender.blocking_recv_many_returns(returns, limit)
    }

    #[allow(dead_code)]
    pub fn try_recv_return_buffers(
        &mut self,
        returns: &mut Vec<PacketBuffer>,
        limit: usize,
    ) -> usize {
        self.sender.try_recv_many_returns(returns, limit)
    }

    #[allow(dead_code)]
    pub async fn async_recv_return_buffers(
        &mut self,
        returns: &mut Vec<PacketBuffer>,
        limit: usize,
    ) -> usize {
        self.sender.recv_many_returns(returns, limit).await
    }

    pub async fn async_recv_return_buffer(&mut self) -> PacketBuffer {
        self.sender.recv_return().await
    }
}
