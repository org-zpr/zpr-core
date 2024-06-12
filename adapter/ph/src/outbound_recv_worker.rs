use core::future::Future;
use nix::errno::Errno;
use std::os::fd::{AsFd, AsRawFd};
use tokio::io::unix::AsyncFd;
use crate::ext::std::vec::VecExt;
use crate::ext::tokio::io::unix::*;
use crate::assembly::Assembly;
use crate::packet::{packet_body_buffer, Packet};

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize
}

async fn worker<Fd: AsFd + AsRawFd + Send + Sync>(
    config: &Config, asm: &Assembly<'_>, tun_fd: &AsyncFd<Fd>
) {
    let mut bufs = Vec::new();
    let mut recvd_outer = Vec::new();

    loop {
        // grab some buffers from the pool
        asm.buffer_stack.get_buffers(config.batch_size, &mut bufs).await;

        let mut recvd = recvd_outer;

        // FIXME: how to detect truncated packet??
        recvd.push(async_fd_read(tun_fd, packet_body_buffer(bufs[0])).await.unwrap());

        for buf in &mut bufs[1..] {
            match tun_fd.try_read(packet_body_buffer(buf)) {
                Err(e) if e.raw_os_error().map(Errno::from_raw) == Some(Errno::EAGAIN) => break,
                r => recvd.push(r.unwrap())
            }
        }

        // return unused buffers
        asm.buffer_stack.put_buffers(bufs.drain(recvd.len()..));

        for (buf, &recvd) in bufs.drain(..).zip(&recvd) {
            let mut pkt = Packet{ buf };
            pkt.metadata_mut().len = recvd;
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
