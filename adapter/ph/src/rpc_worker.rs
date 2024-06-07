use core::future::Future;
use std::io::IoSliceMut;
use tokio::net::UdpSocket;
use crate::ext::std::vec::VecExt;
use crate::ext::tokio::net::*;
use crate::assembly::Assembly;
use crate::packet::Packet;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::io::AsyncWriteExt;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize
}

async fn worker(
    config: &Config, asm: &Assembly<'_>, socket: &UnixListener
) {

    loop {
        match socket.accept().await {
            Ok((mut stream, _addr)) => {
                eprintln!("Connection recieved");
                stream.shutdown();
            }
            Err(e) => {
                eprintln!("Connection failed");
            }
        }   
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf, UnixListenerRef: 'pktbuf>(
    config: &Config, asm: AsmRef, socket: UnixListenerRef)
-> impl Future<Output = ()> + Send + 'pktbuf
    where AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
        UnixListenerRef: std::ops::Deref<Target = UnixListener> + Send + Sync
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &*socket).await }
}