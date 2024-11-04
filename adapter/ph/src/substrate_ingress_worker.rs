use crate::assembly::Assembly;
use crate::config;
use crate::fastpath;
use crate::packet::Packet;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

#[derive(Copy, Clone)]
pub struct Config {
    pub worker_index: usize,
    pub batch_size: usize,
}

pub async fn launch(config: Config, asm: Arc<Assembly>, socket: Arc<UdpSocket>) {
    let mut bufs = Vec::new();

    loop {
        // grab some buffers from the pool
        asm.buffer_stack
            .get_buffers(config.batch_size, &mut bufs)
            .await;

        // TODO: batch receive
        for buf in bufs.drain(..) {
            let mut pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
            let mut sender = loop {
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

            // SocketAddrV6 distinguishes addresses also by `flowinfo` which
            // we do not want -- only the 5-tuple.  So clear it.
            match &mut sender {
                SocketAddr::V4(_) => (),
                SocketAddr::V6(sender) => sender.set_flowinfo(0),
            }

            fastpath::substrate_ingress(&asm, config.worker_index, &sender, pkt);
        }
    }
}
