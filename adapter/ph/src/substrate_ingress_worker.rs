use crate::assembly::Assembly;
use crate::config;
use crate::fastpath;
use crate::packet::Packet;
use std::future::Future;
use std::io::ErrorKind;
use tokio::net::UdpSocket;

#[derive(Copy, Clone)]
pub struct Config {
    #[allow(dead_code)]
    pub worker_index: usize,
    pub batch_size: usize,
}

async fn worker<'a>(config: &Config, asm: &Assembly<'a>, socket: &UdpSocket) {
    let mut bufs = Vec::new();

    loop {
        // grab some buffers from the pool
        asm.buffer_stack
            .get_buffers(config.batch_size, &mut bufs)
            .await;

        // TODO: batch receive
        for buf in bufs.drain(..) {
            let mut pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
            let sender = loop {
                match socket.recv_buf_from(&mut pkt).await {
                    Ok((_size, sender)) => break sender,

                    Err(err) => {
                        match err.kind() {
                            ErrorKind::ConnectionRefused => (), // FIXME: do something with this later...
                            _ => panic!("got socket error {}", err),
                        }
                    }
                }
            };

            fastpath::substrate_ingress(asm, &sender, pkt);
        }
    }
}

pub fn launch<'a, AsmRef: 'a, SocketRef: 'a>(
    config: &Config,
    asm: AsmRef,
    socket: SocketRef,
) -> impl Future<Output = ()> + Send + 'a
where
    AsmRef: std::ops::Deref<Target = Assembly<'a>> + Send + Sync,
    SocketRef: std::ops::Deref<Target = UdpSocket> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &*socket).await }
}
