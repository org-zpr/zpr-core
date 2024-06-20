use core::future::Future;
use std::io::IoSlice;
use std::os::fd::{AsFd, AsRawFd};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use crate::ext::tokio::io::unix::*;
use crate::assembly::Assembly;
// use crate::packet::Packet;
use crate::InboundSendMessage;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize
}

async fn worker<'pktbuf, Fd: AsFd + AsRawFd + Send + Sync>(
    config: &Config, asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<InboundSendMessage<'pktbuf>>,
    tun_fd: &AsyncFd<Fd>
) {
    let mut messages = Vec::new();

    while let _count @ 1.. = queue.recv_many(&mut messages, config.batch_size).await {
        for msg in &messages {
            match msg {
                InboundSendMessage::Packet(msg) => async_fd_write_vectored(tun_fd, &[IoSlice::new(msg.body())]).await.unwrap(),  // TODO: error handling
            };
        }
        asm.buffer_stack.put_buffers(messages.drain(..).filter_map(|msg| 
            match msg {
                InboundSendMessage::Packet(msg) => Some(msg.destroy()),
                // testpacket => None()
            }
        ));
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf, AfdRef: 'pktbuf, Fd: AsFd + AsRawFd + Send + Sync>(
    config: &Config, asm: AsmRef,
    mut queue: mpsc::Receiver<InboundSendMessage<'pktbuf>>,
    tun_fd: AfdRef
) -> impl Future<Output = ()> + Send + 'pktbuf
    where AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
        AfdRef: std::ops::Deref<Target = AsyncFd<Fd>> + Send + Sync
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &mut queue, &*tun_fd).await }
}
