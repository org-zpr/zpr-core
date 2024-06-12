use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;

pub struct UdpStream<'a> {
    socket: &'a UdpSocket
}

impl<'a> UdpStream<'a> {
    pub fn new(socket: &'a UdpSocket) -> Self {
        Self { socket }
    }
}

impl<'a> AsyncRead for UdpStream<'a> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>)
        -> Poll<std::io::Result<()>>
    {
        self.get_mut().socket.poll_recv(cx, buf)
    }
}

impl<'a> AsyncWrite for UdpStream<'a> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8])
        -> Poll<std::io::Result<usize>>
    {
        self.get_mut().socket.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>)
        -> Poll<std::io::Result<()>>
    {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>)
        -> Poll<std::io::Result<()>>
    {
        Poll::Ready(Ok(()))
    }

    // NOTE: no point to implement the _vectored methods;
    // SSL BIO provides no means to make use of them
}
