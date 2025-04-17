//! Queue used to transfer packet from mgmt to datapath.
//!
//! Some properties:
//! * no allocations/deallocations on datapath (receive) side
//! * datapath (receive) notifications provided via file descriptor
//! * async mgmt (send) side
//! * bounded queue

use crate::packet::{Packet, PacketBuffer};
use crate::sys::notify;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum SendError {
    Closed,
    Oversize,
}

#[derive(Debug)]
pub enum TrySendError {
    Full,
    Closed,
    Oversize,
}

#[derive(Clone)]
pub struct Sender<const BUFSIZE: usize> {
    send: mpsc::Sender<[u8; BUFSIZE]>,
    notify: Arc<notify::Notify>,
}

impl<const BUFSIZE: usize> Sender<BUFSIZE> {
    pub async fn send(&self, packet: &Packet) -> Result<(), SendError> {
        let mut buf = [0u8; BUFSIZE];
        packet
            .serialize(&mut buf[..])
            .map_err(|_| SendError::Oversize)?;
        self.send.send(buf).await.map_err(|_| SendError::Closed)?;
        self.notify.post();
        Ok(())
    }

    pub fn try_send(&self, packet: &Packet) -> Result<(), TrySendError> {
        let mut buf = [0u8; BUFSIZE];
        packet
            .serialize(&mut buf[..])
            .map_err(|_| TrySendError::Oversize)?;
        match self.send.try_send(buf) {
            Ok(()) => (),
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(TrySendError::Full);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(TrySendError::Closed);
            }
        }
        self.notify.post();
        Ok(())
    }
}

#[derive(Debug)]
pub enum TryRecvError {
    Empty(PacketBuffer),
    Disconnected(PacketBuffer),
    Oversize(PacketBuffer),
}

impl TryRecvError {
    #[allow(dead_code)]
    pub fn into_inner(self) -> PacketBuffer {
        match self {
            Self::Empty(buf) => buf,
            Self::Disconnected(buf) => buf,
            Self::Oversize(buf) => buf,
        }
    }
}

pub struct Receiver<const BUFSIZE: usize> {
    recv: mpsc::Receiver<[u8; BUFSIZE]>,
    notify: Arc<notify::Notify>,
}

impl<const BUFSIZE: usize> Receiver<BUFSIZE> {
    pub fn poll_fd(&self) -> BorrowedFd<'_> {
        self.notify.poll_fd()
    }

    pub fn len(&self) -> usize {
        self.recv.len()
    }

    pub fn try_recv(&mut self, pkt_buf: PacketBuffer) -> Result<Packet, TryRecvError> {
        match self.recv.try_recv() {
            Ok(buf) => Packet::deserialize_into(buf.as_slice(), pkt_buf)
                .map_err(|pkt_buf| TryRecvError::Oversize(pkt_buf)),
            Err(mpsc::error::TryRecvError::Empty) => Err(TryRecvError::Empty(pkt_buf)),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(TryRecvError::Disconnected(pkt_buf))
            }
        }
    }
}

pub fn packet_queue<const BUFSIZE: usize>(depth: usize) -> (Sender<BUFSIZE>, Receiver<BUFSIZE>) {
    let (send, recv) = mpsc::channel(depth);
    let notify_send = Arc::new(notify::Notify::new().unwrap());
    let notify_recv = notify_send.clone();
    (
        Sender {
            send,
            notify: notify_send,
        },
        Receiver {
            recv,
            notify: notify_recv,
        },
    )
}
