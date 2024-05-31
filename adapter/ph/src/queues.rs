use tokio::sync::mpsc;
use crate::packet::Packet;

// Queues (i.e., frontend interface) for each stage of the system.

// "Inbound" refers to the dock->adapter direction (i.e., inbound to this host).
// "Outbound" refers to the adapter->dock direction (i.e., outbound from this host).



// InboundProcessor is responsible for all "processing" of packets in the inbound direction.
// All agent packets from the dock are sent here for decapsulation, and any
// CPU-intensive postprocessing (e.g. signature verification).
// This may morph into more or fewer (i.e. zero) stages depending on future requirements.

pub struct InboundProcessor<'pktbuf> {
    sender: mpsc::Sender<Packet<'pktbuf>>
}

impl<'pktbuf> InboundProcessor<'pktbuf> {
    // TODO: this will almost certainly morph into multiple queues

    pub(crate) fn new(sender: mpsc::Sender<Packet<'pktbuf>>) -> Self {
        Self{ sender }
    }

    pub async fn enqueue(&self, packet: Packet<'pktbuf>) {
        self.sender.send(packet).await.unwrap();
    }
}


// InboundSend is responsible for emitting decapsulated agent packets on the
// host's TUN interface.

pub struct InboundSend<'pktbuf> {
    senders: Box<[mpsc::Sender<Packet<'pktbuf>>]>
}

impl<'pktbuf> InboundSend<'pktbuf> {
    // We necessarily have multiple queues, corresponding to the multiple
    // FDs of a multiqueue-enabled TUN interface.
    pub(crate) fn new(senders: Box<[mpsc::Sender<Packet<'pktbuf>>]>) -> Self {
        Self{ senders }
    }

    pub async fn enqueue(&self, packet: Packet<'pktbuf>) {
        self.senders[packet.flowhash() as usize % self.senders.len()].send(packet).await.unwrap();
    }
}


// OutboundProcessor is responsible for all "processing" of packets in the outbound direction.
// All packets from the host are sent here for encapsulation, and any
// CPU-intensive preprocessing (e.g. signature generation).
// This may morph into more or fewer (i.e. zero) stages depending on future requirements.

pub struct OutboundProcessor<'pktbuf> {
    sender: mpsc::Sender<Packet<'pktbuf>>
}

impl<'pktbuf> OutboundProcessor<'pktbuf> {
    // TODO: this will almost certainly morph into multiple queues

    pub(crate) fn new(sender: mpsc::Sender<Packet<'pktbuf>>) -> Self {
        Self{ sender }
    }

    pub async fn enqueue(&self, packet: Packet<'pktbuf>) {
        self.sender.send(packet).await.unwrap();
    }
}


// OutboundSend is responsible for sending encapsulated agent packets to the dock.

pub struct OutboundSend<'pktbuf> {
    sender: mpsc::Sender<Packet<'pktbuf>>
}

impl<'pktbuf> OutboundSend<'pktbuf> {
    // Only one outbound socket, only one queue for now.  (To be determined
    // whether `sendmmsg` via multiple threads provides any needed performance gain.)
    pub(crate) fn new(sender: mpsc::Sender<Packet<'pktbuf>>) -> Self {
        Self{ sender }
    }

    pub async fn enqueue(&self, packet: Packet<'pktbuf>) {
        self.sender.send(packet).await.unwrap();
    }
}
