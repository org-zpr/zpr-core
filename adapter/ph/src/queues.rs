//! Queues (i.e., frontend interface) for each stage of the system.

//! "Inbound" refers to the dock->adapter direction (i.e., inbound to this host).
//! "Outbound" refers to the adapter->dock direction (i.e., outbound from this host).

//! InboundProcessor is responsible for all "processing" of packets in the inbound direction.
//! All agent packets from the dock are sent here for decapsulation, and any
//! CPU-intensive postprocessing (e.g. signature verification).
//! This may morph into more or fewer (i.e. zero) stages depending on future requirements.

use crate::net_defs;
use crate::packet::Packet;
use crate::test_packet::*;
use crate::zdp;
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

pub enum InboundProcessorMessage<'pktbuf> {
    Packet(Packet<'pktbuf>),
    TestPacket(TestPacket),
}

pub struct InboundProcessor<'pktbuf> {
    sender: mpsc::Sender<InboundProcessorMessage<'pktbuf>>,
}

impl<'pktbuf> InboundProcessor<'pktbuf> {
    // TODO: this will almost certainly morph into multiple queues

    #[allow(dead_code)]
    pub(crate) fn new(sender: mpsc::Sender<InboundProcessorMessage<'pktbuf>>) -> Self {
        Self { sender }
    }

    pub async fn enqueue_packet(&self, packet: Packet<'pktbuf>) {
        self.sender
            .send(InboundProcessorMessage::Packet(packet))
            .await
            .unwrap();
    }

    pub async fn enqueue_test_packet(&self) -> Result<TestPacketMetrics, RecvError> {
        let test_tuple = TestPacket::create();

        self.sender
            .send(InboundProcessorMessage::TestPacket(test_tuple.0))
            .await
            .unwrap();

        Ok(test_tuple.1.await?)
    }
}

/// InboundSend is responsible for emitting decapsulated agent packets on the
/// host's TUN interface.
pub struct InboundSend<'a> {
    tuns: Box<[&'a tokio_tun::Tun]>,
}

impl<'a> InboundSend<'a> {
    // We necessarily have multiple queues, corresponding to the multiple
    // FDs of a multiqueue-enabled TUN interface.
    pub fn new(tuns: impl IntoIterator<Item = &'a tokio_tun::Tun>) -> Self {
        Self {
            tuns: tuns.into_iter().collect(),
        }
    }

    pub fn try_enqueue_packet<'pktbuf, P: DropGuard<Packet<'pktbuf>>>
        (&self, mut packet: P) ->
        Result<(), TryEnqueueError<P>>
    {
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

    pub fn fanout(&self) -> usize {
        self.tuns.len()
    }
}

/// OutboundProcessor is responsible for all "processing" of packets in the outbound direction.
/// All packets from the host are sent here for encapsulation, and any
/// CPU-intensive preprocessing (e.g. signature generation).
/// This may morph into more or fewer (i.e. zero) stages depending on future requirements.
#[allow(dead_code)]
pub enum OutboundProcessorMessage<'pktbuf> {
    Packet(Packet<'pktbuf>),
    TestPacket(TestPacket),
    NonFlowMgmt(zdp::ZdpPacketType, Packet<'pktbuf>),
    PerFlowMgmt(zdp::ZdpPacketType, u32, Packet<'pktbuf>),
}

pub struct OutboundProcessor<'pktbuf> {
    sender: mpsc::Sender<OutboundProcessorMessage<'pktbuf>>,
}

impl<'pktbuf> OutboundProcessor<'pktbuf> {
    // TODO: this will almost certainly morph into multiple queues

    #[allow(dead_code)]
    pub(crate) fn new(sender: mpsc::Sender<OutboundProcessorMessage<'pktbuf>>) -> Self {
        Self { sender }
    }

    pub async fn enqueue_packet(&self, packet: Packet<'pktbuf>) {
        self.sender
            .send(OutboundProcessorMessage::Packet(packet))
            .await
            .unwrap();
    }

    pub async fn enqueue_test_packet(&self) -> Result<TestPacketMetrics, RecvError> {
        let test_tuple = TestPacket::create();

        self.sender
            .send(OutboundProcessorMessage::TestPacket(test_tuple.0))
            .await
            .unwrap();

        Ok(test_tuple.1.await?)
    }

    pub async fn enqueue_non_flow_mgmt(
        &self,
        zdp_packet_type: zdp::ZdpPacketType,
        packet: Packet<'pktbuf>,
    ) {
        self.sender
            .send(OutboundProcessorMessage::NonFlowMgmt(
                zdp_packet_type,
                packet,
            ))
            .await
            .unwrap();
    }

    #[allow(dead_code)]
    pub async fn enqueue_per_flow_mgmt(
        &self,
        zdp_packet_type: zdp::ZdpPacketType,
        stream_id: u32,
        packet: Packet<'pktbuf>,
    ) {
        self.sender
            .send(OutboundProcessorMessage::PerFlowMgmt(
                zdp_packet_type,
                stream_id,
                packet,
            ))
            .await
            .unwrap();
    }
}

/// OutboundSend is responsible for sending encapsulated agent packets to the dock.
pub struct OutboundSend<'a> {
    sockets: Box<[&'a UdpSocket]>,
}

impl<'a> OutboundSend<'a> {
    pub fn new(sockets: impl IntoIterator<Item = &'a UdpSocket>) -> Self {
        Self {
            sockets: sockets.into_iter().collect(),
        }
    }

    // TODO: batch enqueue
    pub fn try_enqueue_packet<'pktbuf, P: DropGuard<Packet<'pktbuf>>>(
        &self,
        packet: P,
    ) -> Result<(), TryEnqueueError<P>> {
        let socket = self.sockets[packet.flowhash() as usize % self.sockets.len()];

        match socket.try_send(packet.body()) {
            Ok(_) => Ok(()),

            Err(err) => {
                match err.kind() {
                    ErrorKind::InvalidInput | ErrorKind::Unsupported => {
                        panic!("Unrecoverable I/O error: {}", err)
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

    pub fn fanout(&self) -> usize {
        self.sockets.len()
    }
}

/// Capture will intercept packets in the PH and dump them into a file for debugging purposes
#[allow(dead_code)]
pub struct CapPacket<'pktbuf> {
    pub packet: Packet<'pktbuf>,
    pub timestamp: SystemTime,
    pub caplen: u32,
}

pub struct Capture<'pktbuf> {
    sender: mpsc::Sender<CapPacket<'pktbuf>>,
}

#[allow(dead_code)]
impl<'pktbuf> Capture<'pktbuf> {
    pub(crate) fn new(sender: mpsc::Sender<CapPacket<'pktbuf>>) -> Self {
        Self { sender }
    }

    /// Blocks until packet is enqueued
    pub async fn enqueue_packet(
        &self,
        packet: Packet<'pktbuf>,
        timestamp: SystemTime,
        caplen: u32,
    ) {
        let cap_pack: CapPacket = CapPacket {
            packet,
            timestamp,
            caplen,
        };
        self.sender.send(cap_pack).await.unwrap();
    }

    /// Does not block
    pub fn try_enqueue_packet(
        &self,
        packet: Packet<'pktbuf>,
        timestamp: SystemTime,
        caplen: u32,
    ) -> Result<(), TryEnqueueError<Packet<'pktbuf>>> {
        let cap_pack: CapPacket = CapPacket {
            packet,
            timestamp,
            caplen,
        };
        match self.sender.try_send(cap_pack) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(cap_pack)) | Err(TrySendError::Closed(cap_pack)) => {
                return Err(TryEnqueueError::Full(cap_pack.packet));
            }
        };
    }
}
