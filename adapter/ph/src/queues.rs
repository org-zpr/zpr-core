use tokio::sync::mpsc;
use crate::packet::Packet;

// Queues (i.e., frontend interface) for each stage of the system.


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


pub struct InboundSend<'pktbuf> {
    senders: Box<[mpsc::Sender<Packet<'pktbuf>>]>
}

impl<'pktbuf> InboundSend<'pktbuf> {
    pub(crate) fn new(senders: Box<[mpsc::Sender<Packet<'pktbuf>>]>) -> Self {
        Self{ senders }
    }

    pub async fn enqueue(&self, packet: Packet<'pktbuf>) {
        self.senders[packet.flowhash() as usize % self.senders.len()].send(packet).await.unwrap();
    }
}


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


pub struct OutboundSend<'pktbuf> {
    sender: mpsc::Sender<Packet<'pktbuf>>
}

impl<'pktbuf> OutboundSend<'pktbuf> {
    pub(crate) fn new(sender: mpsc::Sender<Packet<'pktbuf>>) -> Self {
        Self{ sender }
    }

    pub async fn enqueue(&self, packet: Packet<'pktbuf>) {
        self.sender.send(packet).await.unwrap();
    }
}
