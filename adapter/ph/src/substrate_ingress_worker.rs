use crate::assembly::Assembly;
use crate::config;
use crate::fastpath::FastpathWorker;
use crate::packet::Packet;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::select;

#[derive(Copy, Clone)]
pub struct Config {
    pub worker_index: usize,
    pub buffer_count: usize,
    #[allow(dead_code)]
    pub batch_size: usize,
}

pub async fn launch(config: Config, asm: Arc<Assembly>, socket: Arc<UdpSocket>) {
    let mut worker = FastpathWorker::new(config.worker_index, asm.clone());
    let mut bufs = Vec::new();

    loop {
        // process the return buffer queue
        worker
            .mgmt_dispatch
            .try_recv_return_buffers(&mut bufs, config.buffer_count);
        asm.buffer_stack.put_buffers(bufs.drain(..));

        // grab some buffers from the pool;
        // if none are available immediately, also wait on the return buffer queue
        select! {
            biased;

            _ = asm.buffer_stack
                .get_buffers(config.batch_size - bufs.len(), &mut bufs) => (),

            buf = worker.mgmt_dispatch.async_recv_return_buffer() => {
                // weird two-step approach necessitated by bufs ownership issue with select
                bufs.push(buf);
                let _ = worker.mgmt_dispatch.try_recv_return_buffers(&mut bufs, config.batch_size - 1);
            }
        }

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

            worker.substrate_ingress(&sender, pkt);
        }
    }
}
