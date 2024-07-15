use std::io::{Error, Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;

pub struct UdpStream<'a> {
    socket: &'a UdpSocket,
}

impl<'a> UdpStream<'a> {
    pub fn new(socket: &'a UdpSocket) -> Self {
        Self { socket }
    }
}

impl<'a> AsyncRead for UdpStream<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut().socket.poll_recv(cx, buf)
    }
}

impl<'a> AsyncWrite for UdpStream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().socket.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    // NOTE: no point to implement the _vectored methods;
    // SSL BIO provides no means to make use of them
}

// A `GatedUdpStream` provides a means to communicate with a single remote address over
// an unbound/unconnected `UdpSocket`.  Writes are sent to the configured remote address;
// and reads can be gated to only succeed when it's known that an appropriate packet
// is at the head of the queue.  (If there isn't one, it is dropped instead of being returned.)
// When the gate is closed, a `WouldBlock` error is returned.

pub struct GatedUdpStream<'a> {
    socket: &'a std::net::UdpSocket,
    remote_addr: SocketAddr,
    read_gate: usize,
}

#[allow(dead_code)]
impl<'a> GatedUdpStream<'a> {
    pub fn new(socket: &'a std::net::UdpSocket, remote_addr: &SocketAddr) -> Self {
        Self {
            socket,
            remote_addr: *remote_addr,
            read_gate: 0,
        }
    }

    // Allow the next call to `read` to succeed.
    pub fn open_read_gate(&mut self) {
        self.read_gate = 1;
    }

    // Change the remote address this `GatedUdpStream` is associated with.
    pub fn set_remote_addr(&mut self, new_remote_addr: &SocketAddr) {
        self.remote_addr = *new_remote_addr;
    }

    // Update just the flowinfo of the remote address, if the address is IPv6.
    // (No-op for IPv4.)
    pub fn set_flowinfo(&mut self, new_flowinfo: u32) {
        match &mut self.remote_addr {
            SocketAddr::V4(_) => (),
            SocketAddr::V6(sa) => sa.set_flowinfo(new_flowinfo),
        }
    }
}

fn sockaddr_eq_modulo_flowinfo(a: &SocketAddr, b: &SocketAddr) -> bool {
    match (a, b) {
        (SocketAddr::V4(a), SocketAddr::V4(b)) => a == b,
        (SocketAddr::V6(a), SocketAddr::V6(b)) => {
            a.ip() == b.ip() && a.port() == b.port() && a.scope_id() == b.scope_id()
        }

        _ => false,
    }
}

impl Read for GatedUdpStream<'_> {
    fn read(self: &mut Self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read_gate > 0 {
            self.read_gate -= 1;

            let (recvd, sender) = self.socket.recv_from(buf)?;

            if sockaddr_eq_modulo_flowinfo(&sender, &self.remote_addr) {
                Ok(recvd)
            } else {
                // shouldn't have been gated!  drop
                Err(Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "unexpected source address",
                ))
            }
        } else {
            Err(Error::new(std::io::ErrorKind::WouldBlock, "gate closed"))
        }
    }
}

impl Write for GatedUdpStream<'_> {
    fn write(self: &mut Self, buf: &[u8]) -> std::io::Result<usize> {
        self.socket.send_to(buf, self.remote_addr)
    }

    fn flush(self: &mut Self) -> std::io::Result<()> {
        Ok(())
    }

    // NOTE: no point to implement the _vectored methods;
    // SSL BIO provides no means to make use of them
}
