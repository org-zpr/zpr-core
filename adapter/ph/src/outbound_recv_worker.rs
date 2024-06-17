use core::future::Future;
use nix::errno::Errno;
use std::os::fd::{AsFd, AsRawFd};
use tokio::io::unix::AsyncFd;
use crate::ext::std::vec::VecExt;
use crate::ext::tokio::io::unix::*;
use crate::assembly::Assembly;
use crate::packet::Packet;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize
}

// How much space to leave for the ZDP headers.
const OUTBOUND_PACKET_HEADROOM: usize = 256;

async fn worker<Fd: AsFd + AsRawFd + Send + Sync>(
    config: &Config, asm: &Assembly<'_>, tun_fd: &AsyncFd<Fd>
) {
    let mut bufs = Vec::new();
    let mut recvd_outer = Vec::new();

    loop {
        // grab some buffers from the pool
        asm.buffer_stack.get_buffers(config.batch_size, &mut bufs).await;
        let mut bufs_iter = bufs.drain(..);

        let mut recvd = recvd_outer;

        let buf = bufs_iter.next().unwrap();
        let mut pkt = Packet::new(buf, OUTBOUND_PACKET_HEADROOM);
        // FIXME: how to detect truncated packet??
        async_fd_read_buf(tun_fd, &mut pkt).await.unwrap();
        recvd.push(pkt);

        while let Some(buf) = bufs_iter.next() {
            let mut pkt = Packet::new(buf, OUTBOUND_PACKET_HEADROOM);
            match tun_fd.try_read_buf(&mut pkt) {
                Err(e) if e.raw_os_error().map(Errno::from_raw) == Some(Errno::EAGAIN) => break,
                r => { r.unwrap(); recvd.push(pkt); }
            }
        }

        // return unused buffers
        asm.buffer_stack.put_buffers(bufs_iter);

        for pkt in recvd.drain(..) {
            asm.outbound_processor.enqueue(pkt).await;
        }

        recvd_outer = recvd.recycle();
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf, AfdRef: 'pktbuf, Fd: AsFd + AsRawFd + Send + Sync>(
    config: &Config, asm: AsmRef, tun_fd: AfdRef
) -> impl Future<Output = ()> + Send + 'pktbuf
    where AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
        AfdRef: std::ops::Deref<Target = AsyncFd<Fd>> + Send + Sync
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &*tun_fd).await }
}
