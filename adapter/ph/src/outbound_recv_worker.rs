use core::future::Future;
use std::os::fd::{AsFd, AsRawFd};
use tokio::io::unix::AsyncFd;
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

    loop {
        // grab some buffers from the pool
        asm.buffer_stack.get_buffers(config.batch_size, &mut bufs).await;

        // read & forward packets one at a time, no sense to batch really
        // since neither `read_buf()` nor `enqueue()` support it
        for buf in bufs.drain(..) {
            let mut pkt = Packet::new(buf, OUTBOUND_PACKET_HEADROOM);
            async_fd_read_buf(tun_fd, &mut pkt).await.unwrap();
            asm.outbound_processor.enqueue(pkt).await;
        }
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
