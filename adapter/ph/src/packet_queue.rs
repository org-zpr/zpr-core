//! Queue used to transfer packet from mgmt to datapath.
//!
//! Some properties:
//! * no allocations/deallocations on datapath (receive) side
//! * datapath (receive) notifications provided via file descriptor
//! * async mgmt (send) side
//! * bounded queue

use crate::packet::{self, Packet, PacketBuffer};
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

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.recv.len()
    }

    pub fn try_recv(&mut self, pkt_buf: PacketBuffer) -> Result<Packet, TryRecvError> {
        if !self.notify.consume() {
            return Err(TryRecvError::Empty(pkt_buf));
        }

        let avail = self.recv.len();
        if avail == 0 {
            return Err(TryRecvError::Empty(pkt_buf));
        }

        match self.recv.try_recv() {
            Ok(buf) => {
                if avail > 1 {
                    // It is likely that we ate the notification of these remaining items.
                    // Re-post it.  (If we didn't eat it, this is harmless.)
                    self.notify.post();
                }

                match Packet::deserialize_into(buf.as_slice(), pkt_buf) {
                    Ok(pkt) => Ok(pkt),
                    Err(packet::DeserializeError::BufferTooSmall(pkt_buf)) => {
                        Err(TryRecvError::Oversize(pkt_buf))
                    }
                    Err(packet::DeserializeError::InvalidSerialization(_)) => {
                        panic!("corrupt data in packet_queue")
                    }
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use nix;

    #[test]
    fn test_empty_recv() {
        let (_send, mut recv) = packet_queue::<256>(16);

        assert_eq!(recv.len(), 0);
        assert!(!poll(recv.poll_fd()));

        match recv.try_recv(new_buf(256)).unwrap_err() {
            TryRecvError::Empty(_) => (),
            err => panic!("wrong error: {err:?}"),
        }
    }

    #[test]
    fn test_full_send() {
        let (send, _recv) = packet_queue::<256>(1);
        send.try_send(&new_pkt(256)).unwrap();
        match send.try_send(&new_pkt(256)).unwrap_err() {
            TrySendError::Full => (),
            err => panic!("wrong error: {err:?}"),
        }
    }

    #[test]
    fn test_oversize_send() {
        let (send, _recv) = packet_queue::<16>(1);

        let mut send_pkt = new_pkt(256);
        send_pkt.put("This is a packet larger than sixteen bytes".as_bytes());

        match send.try_send(&send_pkt).unwrap_err() {
            TrySendError::Oversize => (),
            err => panic!("wrong error: {err:?}"),
        }
    }

    #[test]
    fn test_send_recv_one() {
        let (send, mut recv) = packet_queue::<256>(16);

        let mut send_pkt = new_pkt(256);
        send_pkt.put("Hello!".as_bytes());
        send.try_send(&send_pkt).unwrap();

        assert_eq!(recv.len(), 1);
        assert!(poll(recv.poll_fd()));

        let recv_pkt = recv.try_recv(new_buf(256)).unwrap();
        assert_eq!(recv_pkt, send_pkt);

        assert_eq!(recv.len(), 0);
        assert!(!poll(recv.poll_fd()));

        match recv.try_recv(new_buf(256)).unwrap_err() {
            TryRecvError::Empty(_) => (),
            err => panic!("wrong error: {err:?}"),
        }
    }

    #[test]
    fn test_oversize_recv() {
        let (send, mut recv) = packet_queue::<256>(16);

        let mut send_pkt = new_pkt(256);
        send_pkt.put("This is a packet larger than sixteen bytes".as_bytes());
        send.try_send(&send_pkt).unwrap();

        match recv.try_recv(new_buf(16)).unwrap_err() {
            TryRecvError::Oversize(_) => (),
            err => panic!("wrong error: {err:?}"),
        }
    }

    #[test]
    fn test_send_recv_many() {
        let (send, mut recv) = packet_queue::<256>(16);

        let mut send_pkts = Vec::new();

        for _i in 0..16 {
            let mut send_pkt = new_pkt(256);
            send_pkt.put("Hello!".as_bytes());
            send.try_send(&send_pkt).unwrap();
            send_pkts.push(send_pkt);
        }

        for i in 0..16 {
            assert_eq!(recv.len(), 16 - i);
            assert!(poll(recv.poll_fd()));

            let recv_pkt = recv.try_recv(new_buf(256)).unwrap();
            assert_eq!(recv_pkt, send_pkts.pop().unwrap());
        }

        assert_eq!(recv.len(), 0);
        assert!(!poll(recv.poll_fd()));

        match recv.try_recv(new_buf(256)).unwrap_err() {
            TryRecvError::Empty(_) => (),
            err => panic!("wrong error: {err:?}"),
        }
    }

    fn new_buf(size: usize) -> PacketBuffer {
        let mut vec = Vec::with_capacity(size);
        vec.resize(size, 0);
        vec.into_boxed_slice()
    }

    fn new_pkt(size: usize) -> Packet {
        Packet::new(new_buf(size), 0)
    }

    fn poll(fd: BorrowedFd<'_>) -> bool {
        let mut pfd = nix::poll::PollFd::new(fd, nix::poll::PollFlags::POLLIN);
        nix::poll::poll(std::slice::from_mut(&mut pfd), nix::poll::PollTimeout::ZERO).unwrap() > 0
    }
}
