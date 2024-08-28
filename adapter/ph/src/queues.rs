//! Queues (i.e., frontend interface) for each stage of the system.

use crate::net_defs;
use crate::packet::Packet;
use crate::test_packet::*;
use crate::zpr;
use std::io::ErrorKind;
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
    Packet(zpr::LinkId, Packet<'pktbuf>),
    TestPacket(TestPacket),
}

/// MgmtProcessor processes all inbound management packets
pub struct MgmtProcessor<'pktbuf> {
    sender: mpsc::Sender<MgmtProcessorMessage<'pktbuf>>,
}

impl<'pktbuf> MgmtProcessor<'pktbuf> {
    pub fn new(sender: mpsc::Sender<MgmtProcessorMessage<'pktbuf>>) -> Self {
        Self { sender }
    }

    pub fn try_enqueue_packet(
        &self,
        ingress_link_id: zpr::LinkId,
        packet: Packet<'pktbuf>,
    ) -> Result<(), TryEnqueueError<Packet<'pktbuf>>> {
        match self
            .sender
            .try_send(MgmtProcessorMessage::Packet(ingress_link_id, packet))
        {
            Ok(()) => Ok(()),

            Err(TrySendError::Full(msg) | TrySendError::Closed(msg)) => {
                let MgmtProcessorMessage::Packet(_, pkt) = msg else {
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
        dest_sa: std::net::SocketAddr,
    ) -> Result<(), P> {
        let socket = self.sockets[packet.flowhash() as usize % self.sockets.len()];

        match socket.send_to(packet.body(), dest_sa).await {
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
        dest_sa: std::net::SocketAddr,
    ) -> Result<(), TryEnqueueError<P>> {
        let socket = self.sockets[packet.flowhash() as usize % self.sockets.len()];

        match socket.try_send_to(packet.body(), dest_sa) {
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
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(cap_pack)) | Err(TrySendError::Closed(cap_pack)) => {
                return Err(TryEnqueueError::Full(cap_pack.packet));
            }
        };
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

            Err(TrySendError::Full(msg) | TrySendError::Closed(msg)) => match msg {
                AdapterManagerMessage::RequestTetherId(packet) => {
                    Err(TryEnqueueError::Full(packet))
                }
            },
        }
    }
}
