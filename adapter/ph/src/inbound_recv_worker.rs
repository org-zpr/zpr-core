use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::packet::Packet;
use std::future::Future;
use std::io::ErrorKind;
use tokio::net::UdpSocket;

#[derive(Copy, Clone)]
pub struct Config {
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
            let mut pkt = Packet::new(buf, 0);
            loop {
                match socket.recv_buf(&mut pkt).await {
                    Ok(_) => (),

                    Err(err) => {
                        match err.kind() {
                            ErrorKind::ConnectionRefused => (), // FIXME: do something with this later...
                            _ => panic!("got socket error {}", err),
                        }
                        continue;
                    }
                }

                asm.counters[CounterType::InPacksRec].increment();
                // FIXME: Detect a too-large packet.
                asm.inbound_processor.enqueue_packet(pkt).await;
                break;
            }
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
