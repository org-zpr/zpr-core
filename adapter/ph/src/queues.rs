use crate::packet::Packet;
use crate::test_packet::*;
use std::time::SystemTime;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot::error::RecvError;

// Queues (i.e., frontend interface) for each stage of the system.

// "Inbound" refers to the dock->adapter direction (i.e., inbound to this host).
// "Outbound" refers to the adapter->dock direction (i.e., outbound from this host).

// InboundProcessor is responsible for all "processing" of packets in the inbound direction.
// All agent packets from the dock are sent here for decapsulation, and any
// CPU-intensive postprocessing (e.g. signature verification).
// This may morph into more or fewer (i.e. zero) stages depending on future requirements.
pub enum InboundProcessorMessage<'pktbuf> {
    Packet(Packet<'pktbuf>),
    TestPacket(TestPacket),
}

pub struct InboundProcessor<'pktbuf> {
    sender: mpsc::Sender<InboundProcessorMessage<'pktbuf>>,
}

impl<'pktbuf> InboundProcessor<'pktbuf> {
    // TODO: this will almost certainly morph into multiple queues

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

// InboundSend is responsible for emitting decapsulated agent packets on the
// host's TUN interface.
pub enum InboundSendMessage<'pktbuf> {
    Packet(Packet<'pktbuf>),
    TestPacket(TestPacket),
}

pub struct InboundSend<'pktbuf> {
    senders: Box<[mpsc::Sender<InboundSendMessage<'pktbuf>>]>,
}

impl<'pktbuf> InboundSend<'pktbuf> {
    // We necessarily have multiple queues, corresponding to the multiple
    // FDs of a multiqueue-enabled TUN interface.
    pub(crate) fn new(senders: Box<[mpsc::Sender<InboundSendMessage<'pktbuf>>]>) -> Self {
        Self { senders }
    }

    pub async fn enqueue_packet(&self, packet: Packet<'pktbuf>) {
        self.senders[packet.flowhash() as usize % self.senders.len()]
            .send(InboundSendMessage::Packet(packet))
            .await
            .unwrap();
    }

    pub async fn enqueue_test_packet(&self, queue: usize) -> Result<TestPacketMetrics, RecvError> {
        let test_tuple = TestPacket::create();

        self.senders[queue]
            .send(InboundSendMessage::TestPacket(test_tuple.0))
            .await
            .unwrap();

        Ok(test_tuple.1.await?)
    }

    // gets size of the queue array in order for the user to give a reasonable queue value in
    // enqueue_test_packet
    pub fn fanout(&self) -> usize {
        self.senders.len()
    }
}

// OutboundProcessor is responsible for all "processing" of packets in the outbound direction.
// All packets from the host are sent here for encapsulation, and any
// CPU-intensive preprocessing (e.g. signature generation).
// This may morph into more or fewer (i.e. zero) stages depending on future requirements.
pub enum OutboundProcessorMessage<'pktbuf> {
    Packet(Packet<'pktbuf>),
    TestPacket(TestPacket),
}

pub struct OutboundProcessor<'pktbuf> {
    sender: mpsc::Sender<OutboundProcessorMessage<'pktbuf>>,
}

impl<'pktbuf> OutboundProcessor<'pktbuf> {
    // TODO: this will almost certainly morph into multiple queues

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
}

// OutboundSend is responsible for sending encapsulated agent packets to the dock.
pub enum OutboundSendMessage<'pktbuf> {
    Packet(Packet<'pktbuf>),
    TestPacket(TestPacket),
}

pub struct OutboundSend<'pktbuf> {
    sender: mpsc::Sender<OutboundSendMessage<'pktbuf>>,
}

impl<'pktbuf> OutboundSend<'pktbuf> {
    // Only one outbound socket, only one queue for now.  (To be determined
    // whether `sendmmsg` via multiple threads provides any needed performance gain.)
    pub(crate) fn new(sender: mpsc::Sender<OutboundSendMessage<'pktbuf>>) -> Self {
        Self { sender }
    }

    pub async fn enqueue_packet(&self, packet: Packet<'pktbuf>) {
        self.sender
            .send(OutboundSendMessage::Packet(packet))
            .await
            .unwrap();
    }

    pub async fn enqueue_test_packet(&self) -> Result<TestPacketMetrics, RecvError> {
        let test_tuple = TestPacket::create();

        self.sender
            .send(OutboundSendMessage::TestPacket(test_tuple.0))
            .await
            .unwrap();

        Ok(test_tuple.1.await?)
    }
}

// Capture will intercept packets in the PH and dump them into a file for debugging purposes
pub struct CapPacket<'pktbuf> {
    pub packet: Packet<'pktbuf>,
    pub timestamp: SystemTime,
    pub direction: Direction,
}

pub enum Direction {
    Inbound,
    Outbound,
}

pub struct Capture<'pktbuf> {
    sender: mpsc::Sender<CapPacket<'pktbuf>>,
}

pub enum TryEnqueueError<T> {
    Full(T),
}

impl<'pktbuf> Capture<'pktbuf> {
    pub(crate) fn new(sender: mpsc::Sender<CapPacket<'pktbuf>>) -> Self {
        Self { sender }
    }

    // Blocks until packet is enqueued
    #[allow(dead_code)]
    pub async fn enqueue_packet(
        &self,
        packet: Packet<'pktbuf>,
        timestamp: SystemTime,
        direction: Direction,
    ) {
        let cap_pack: CapPacket = CapPacket {
            packet,
            timestamp,
            direction,
        };
        self.sender.send(cap_pack).await.unwrap();
    }

    // Does not block
    pub fn try_enqueue_packet(
        &self,
        packet: Packet<'pktbuf>,
        timestamp: SystemTime,
        direction: Direction,
    ) -> Result<(), TryEnqueueError<Packet<'pktbuf>>> {
        let cap_pack: CapPacket = CapPacket {
            packet,
            timestamp,
            direction,
        };
        match self.sender.try_send(cap_pack) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(cap_pack)) | Err(TrySendError::Closed(cap_pack)) => {
                return Err(TryEnqueueError::Full(cap_pack.packet));
            }
        };
    }
}
