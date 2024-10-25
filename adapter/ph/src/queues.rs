//! Queues (i.e., frontend interface) for each stage of the system.

use crate::net_defs;
use crate::packet::Packet;
use crate::test_packet::*;
use zpr;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::result::Result;
use std::time::SystemTime;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot::error::RecvError;
use zpr_ext::std::mem::DropGuard;
use zpr_ext::tokio_tun::tun_pi;

pub enum TryEnqueueError<T> {
    Full(T),
}

pub enum MgmtProcessorMessage<'pktbuf> {
    Packet(Packet<'pktbuf>),
    TestPacket(TestPacket),
}

/// MgmtProcessor processes all inbound management requests.
/// Unlike other queues, this doesn't live directly in the assembly,
/// but rather in the peer table, as there is one of these per peer.
pub struct MgmtProcessor<'pktbuf> {
    sender: mpsc::Sender<MgmtProcessorMessage<'pktbuf>>,
}

impl<'pktbuf> MgmtProcessor<'pktbuf> {
    pub fn new(sender: mpsc::Sender<MgmtProcessorMessage<'pktbuf>>) -> Self {
        Self { sender }
    }

    pub fn try_enqueue_packet(
        &self,
        packet: Packet<'pktbuf>,
    ) -> Result<(), TryEnqueueError<Packet<'pktbuf>>> {
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
pub struct AgentInput<'a> {
    tuns: Box<[&'a tokio_tun::Tun]>,
}

impl<'a> AgentInput<'a> {
    // We necessarily have multiple queues, corresponding to the multiple
    // FDs of a multiqueue-enabled TUN interface.
    pub fn new(tuns: impl IntoIterator<Item = &'a tokio_tun::Tun>) -> Self {
        Self {
            tuns: tuns.into_iter().collect(),
        }
    }

    pub fn try_enqueue_packet<'pktbuf, P: DropGuard<Packet<'pktbuf>>>(
        &self,
        mut packet: P,
    ) -> Result<(), TryEnqueueError<P>> {
        let tun = self.tuns[packet.flowhash() as usize % self.tuns.len()];

        let proto = net_defs::ip_ethertype(net_defs::ip_version(packet.body()));
        let mut hdr = packet.alloc_zeroed_headroom(tun_pi::PI_SIZE);
        tun_pi::write_pi(
            &mut hdr,
            tun_pi::TunPi {
                strip: false,
                proto,
            },
        );

        match tun.try_send(packet.body()) {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == ErrorKind::WouldBlock => Err(TryEnqueueError::Full(packet)),
            Err(err) => panic!("unrecoverable TUN error: {}", err),
        }
    }

    #[allow(dead_code)]
    pub fn fanout(&self) -> usize {
        self.tuns.len()
    }
}

/// SubstrateEgress is responsible for sending encapsulated agent packets to the dock.
pub struct SubstrateEgress<'a> {
    sockets: Box<[&'a UdpSocket]>,
}

impl<'a> SubstrateEgress<'a> {
    pub fn new(sockets: impl IntoIterator<Item = &'a UdpSocket>) -> Self {
        Self {
            sockets: sockets.into_iter().collect(),
        }
    }

    pub async fn enqueue_packet<'pktbuf, P: DropGuard<Packet<'pktbuf>>>(
        &self,
        packet: P,
        dest_sa: zpr::SubstrateAddr,
    ) -> Result<(), P> {
        let (socket, dest_sockaddr) = self.select_socket_and_set_flowinfo(&*packet, dest_sa);

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
                    _ => Err(packet),
                }
            }
        }
    }

    // TODO: batch enqueue
    pub fn try_enqueue_packet<'pktbuf, P: DropGuard<Packet<'pktbuf>>>(
        &self,
        packet: P,
        dest_sa: zpr::SubstrateAddr,
    ) -> Result<(), TryEnqueueError<P>> {
        let (socket, dest_sockaddr) = self.select_socket_and_set_flowinfo(&*packet, dest_sa);

        match socket.try_send_to(packet.body(), dest_sockaddr) {
            Ok(_) => Ok(()),

            Err(err) => {
                match err.kind() {
                    ErrorKind::InvalidInput | ErrorKind::Unsupported => {
                        panic!("unrecoverable I/O error: {}", err)
                    }

                    ErrorKind::WouldBlock => Err(TryEnqueueError::Full(packet)),

                    // most other network errors are temporary; return packet to caller
                    // TODO: it would be nice to report to the user _why_ packets aren't moving;
                    // this depends on <https://github.com/rust-lang/rust/issues/86442> though
                    _ => Err(TryEnqueueError::Full(packet)),
                }
            }
        }
    }

    fn select_socket_and_set_flowinfo(
        &self,
        packet: &Packet<'_>,
        mut dest_sa: zpr::SubstrateAddr,
    ) -> (&'a UdpSocket, std::net::SocketAddr) {
        match &mut dest_sa {
            SocketAddr::V4(_) => (),
            SocketAddr::V6(dest_sa) => dest_sa.set_flowinfo(packet.flowhash()),
        }

        (
            self.sockets[packet.flowhash() as usize % self.sockets.len()],
            dest_sa,
        )
    }

    #[allow(dead_code)]
    pub fn fanout(&self) -> usize {
        self.sockets.len()
    }
}

/// Capture will intercept packets in the PH and dump them into a file for debugging purposes
pub struct CapPacket<'pktbuf> {
    pub packet: Packet<'pktbuf>,
    pub timestamp: SystemTime,
    pub orig_len: usize,
}

pub struct Capture<'pktbuf> {
    sender: mpsc::Sender<CapPacket<'pktbuf>>,
}

impl<'pktbuf> Capture<'pktbuf> {
    pub fn new(sender: mpsc::Sender<CapPacket<'pktbuf>>) -> Self {
        Self { sender }
    }

    /// Blocks until packet is enqueued
    #[allow(dead_code)]
    pub async fn enqueue_packet(
        &self,
        packet: Packet<'pktbuf>,
        timestamp: SystemTime,
        orig_len: usize,
    ) {
        let cap_pack: CapPacket = CapPacket {
            packet,
            timestamp,
            orig_len,
        };
        self.sender.send(cap_pack).await.unwrap();
    }

    /// Does not block
    pub fn try_enqueue_packet(
        &self,
        packet: Packet<'pktbuf>,
        timestamp: SystemTime,
        orig_len: usize,
    ) -> Result<(), TryEnqueueError<Packet<'pktbuf>>> {
        let cap_pack: CapPacket = CapPacket {
            packet,
            timestamp,
            orig_len,
        };
        match self.sender.try_send(cap_pack) {
            Ok(()) => Ok(()),
            Err(TrySendError::Closed(_)) => panic!("capture channel closed"),
            Err(TrySendError::Full(cap_pack)) => Err(TryEnqueueError::Full(cap_pack.packet)),
        }
    }
}

pub enum MgmtDispatchMessage<'pktbuf> {
    WithLink(Packet<'pktbuf>), // Link ID stored in packet metadata
    WithAddr(zpr::SubstrateAddr, Packet<'pktbuf>),
}

pub struct MgmtDispatch<'pktbuf> {
    sender: mpsc::Sender<MgmtDispatchMessage<'pktbuf>>,
}

impl<'pktbuf> MgmtDispatch<'pktbuf> {
    pub fn new(sender: mpsc::Sender<MgmtDispatchMessage<'pktbuf>>) -> Self {
        Self { sender }
    }

    pub fn try_dispatch_mgmt_packet_with_link(
        &self,
        packet: Packet<'pktbuf>,
    ) -> Result<(), TryEnqueueError<Packet<'pktbuf>>> {
        debug_assert_ne!(packet.metadata().ingress_link_id, 0);
        match self.sender.try_send(MgmtDispatchMessage::WithLink(packet)) {
            Ok(()) => Ok(()),

            Err(TrySendError::Closed(_)) => panic!("mgmt dispatch channel closed"),

            Err(TrySendError::Full(msg)) => {
                let MgmtDispatchMessage::WithLink(pkt) = msg else {
                    unreachable!()
                };
                Err(TryEnqueueError::Full(pkt))
            }
        }
    }

    pub fn try_dispatch_mgmt_packet_with_addr(
        &self,
        peer_sa: &zpr::SubstrateAddr,
        packet: Packet<'pktbuf>,
    ) -> Result<(), TryEnqueueError<Packet<'pktbuf>>> {
        debug_assert_eq!(packet.metadata().ingress_link_id, 0);
        match self
            .sender
            .try_send(MgmtDispatchMessage::WithAddr(*peer_sa, packet))
        {
            Ok(()) => Ok(()),

            Err(TrySendError::Closed(_)) => panic!("mgmt dispatch channel closed"),

            Err(TrySendError::Full(msg)) => {
                let MgmtDispatchMessage::WithAddr(_, pkt) = msg else {
                    unreachable!()
                };
                Err(TryEnqueueError::Full(pkt))
            }
        }
    }
}

pub enum AdapterManagerMessage<'pktbuf> {
    RequestTetherId(Packet<'pktbuf>),
}

pub struct AdapterManager<'pktbuf> {
    sender: mpsc::Sender<AdapterManagerMessage<'pktbuf>>,
}

impl<'pktbuf> AdapterManager<'pktbuf> {
    pub fn new(sender: mpsc::Sender<AdapterManagerMessage<'pktbuf>>) -> Self {
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
    pub fn try_request_tether_id(
        &self,
        packet: Packet<'pktbuf>,
    ) -> Result<(), TryEnqueueError<Packet<'pktbuf>>> {
        match self
            .sender
            .try_send(AdapterManagerMessage::RequestTetherId(packet))
        {
            Ok(()) => Ok(()),

            Err(TrySendError::Closed(_)) => panic!("adapter manager channel closed"),

            Err(TrySendError::Full(msg)) => match msg {
                AdapterManagerMessage::RequestTetherId(packet) => {
                    Err(TryEnqueueError::Full(packet))
                }
            },
        }
    }
}
