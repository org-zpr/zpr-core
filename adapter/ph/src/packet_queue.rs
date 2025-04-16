//! Queue used to transfer packet from mgmt to datapath.
//!
//! Some properties:
//! * no allocations/deallocations on datapath (receive) side
//! * datapath (receive) notifications provided via file descriptor
//! * async mgmt (send) side
//! * bounded queue

use crate::packet::Packet;
use crate::sys::notify;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct Sender<const BUFSIZE: usize> {
    send: mpsc::Sender<[u8; BUFSIZE]>,
    notify: Arc<notify::Notify>,
}

impl<const BUFSIZE: usize> Sender<BUFSIZE> {
    pub async fn send(&self, packet: &Packet) -> Result<(), ()> {
        let mut buf = [0u8; BUFSIZE];
        packet.serialize(&mut buf[..]).unwrap();
        self.send.send(buf).await.map_err(|_| ())?;
        self.notify.post();
        Ok(())
    }
}

pub enum TryRecvError {
    Empty,
    Disconnected,
}

pub struct Receiver<const BUFSIZE: usize> {
    recv: mpsc::Receiver<[u8; BUFSIZE]>,
    notify: Arc<notify::Notify>,
}

impl<const BUFSIZE: usize> Receiver<BUFSIZE> {
    pub fn poll_fd(&self) -> BorrowedFd<'_> {
        self.notify.poll_fd()
    }

    pub fn try_recv(&mut self, packet: &mut Packet) -> Result<(), TryRecvError> {
        match self.recv.try_recv() {
            Ok(buf) => Ok(packet.deserialize_from(&buf[..]).unwrap()),
            Err(mpsc::error::TryRecvError::Empty) => Err(TryRecvError::Empty),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(TryRecvError::Disconnected),
        }
    }
}

pub fn packet_queue<const BUFSIZE: usize>(depth: usize) -> (Sender<BUFSIZE>, Receiver<BUFSIZE>) {
    let (send, recv) = mpsc::channel(depth);
    let notify_send = Arc::new(notify::Notify::new().unwrap());
    let notify_recv = notify_send.clone();
    (Sender { send, notify: notify_send }, Receiver { recv, notify: notify_recv })
}
