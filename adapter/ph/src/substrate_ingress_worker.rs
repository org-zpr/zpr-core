use crate::assembly::Assembly;
use crate::config;
use crate::counters::*;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::packet::Packet;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub async fn launch(
    config: FastpathWorkerConfig,
    worker_index: usize,
    asm: Arc<Assembly>,
    socket: Arc<UdpSocket>,
) {
    let mut worker = FastpathWorker::new(config, worker_index, asm.clone());

    loop {
        // process the return buffer queue
        if worker.buffers.is_empty() {
            // if we are out of buffers, block
            worker
                .mgmt_dispatch
                .async_recv_return_buffers(&mut worker.buffers, worker.config.buffer_count)
                .await;
        } else {
            worker
                .mgmt_dispatch
                .try_recv_return_buffers(&mut worker.buffers, worker.config.buffer_count);
        }

        // TODO: batch receive
        let mut pkt = Packet::new(
            worker.buffers.pop().unwrap(),
            config::DEFAULT_MESSAGE_HEADROOM,
        );
        let mut sender = match socket.recv_buf_from(&mut pkt).await {
            Ok((_size, sender)) => sender,

            Err(err) => {
                match err.kind() {
                    ErrorKind::ConnectionRefused => {
                        // FIXME: do something with this later...
                        worker.drop_and_count(pkt, CounterType::InPacksDrop);
                        continue;
                    }
                    _ => panic!("got socket error {}", err),
                }
            }
        };

        // SocketAddrV6 distinguishes addresses also by `flowinfo` which
        // we do not want -- only the 5-tuple.  So clear it.
        match &mut sender {
            SocketAddr::V4(_) => (),
            SocketAddr::V6(sender) => sender.set_flowinfo(0),
        }

        worker.asm.counters[CounterType::InPacksRec].increment();
        worker.substrate_ingress(&sender, pkt);
    }
}
