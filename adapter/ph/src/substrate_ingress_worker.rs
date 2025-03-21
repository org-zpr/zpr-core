use crate::assembly::Assembly;
use crate::config;
use crate::counters::*;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::packet::Packet;
use bytes::Buf;
use nix::poll;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::fd::AsFd;
use std::sync::Arc;

pub fn launch(
    config: FastpathWorkerConfig,
    worker_index: usize,
    asm: Arc<Assembly>,
    socket: Arc<UdpSocket>,
) -> impl FnOnce() {
    move || {
        let worker = FastpathWorker::new(config, worker_index, asm.clone());
        substrate_ingress_main(worker, &socket);
    }
}

fn substrate_ingress_main(mut worker: FastpathWorker, socket: &UdpSocket) {
    let mut poll_fd = poll::PollFd::new(socket.as_fd(), poll::PollFlags::POLLIN);

    loop {
        // output anything we've queued up
        worker.process_out_queues();

        // process the return buffer queue
        if worker.buffers.is_empty() {
            // if we are out of buffers, block
            worker
                .mgmt_dispatch
                .recv_return_buffers(&mut worker.buffers, worker.config.buffer_count);
        } else {
            worker
                .mgmt_dispatch
                .try_recv_return_buffers(&mut worker.buffers, worker.config.buffer_count);
        }

        let _n = match poll::poll(std::slice::from_mut(&mut poll_fd), poll::PollTimeout::NONE)
            .map_err(|err| std::io::Error::from_raw_os_error(err as i32))
        {
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            ret @ Err(_) => ret.unwrap(),
        };

        let nbufs = std::cmp::min(worker.buffers.len(), worker.config.batch_size);

        // read from socket
        let mut pkts: Vec<_> = worker
            .buffers
            .drain(worker.buffers.len() - nbufs..)
            .rev()
            .map(|buf| Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM))
            .collect(); // TODO: recycle
        let mut results = Vec::new(); // TODO: recycle
        let n = worker
            .batch_io
            .try_recv_buf_from_batch(&socket, pkts.iter_mut(), &mut results)
            .unwrap();

        // return empty buffers to pool
        worker
            .buffers
            .extend(pkts.drain(n..).rev().map(|pkt| pkt.destroy()));

        // process packets
        for (pkt, result) in pkts.into_iter().zip(results) {
            let mut sender = match result {
                Ok((size, _sender)) if size > pkt.remaining() => {
                    worker.drop_and_count(pkt, CounterType::DroppedOversize);
                    continue;
                }

                Ok((_size, sender)) => {
                    sender.expect("received from non-IP address, should not happen!")
                }

                Err(err) => {
                    match err.kind() {
                        ErrorKind::WouldBlock | ErrorKind::ResourceBusy => {
                            worker.buffers.push(pkt.destroy());
                            continue;
                        }

                        // FIXME: do something with this later...
                        ErrorKind::ConnectionRefused => {
                            worker.buffers.push(pkt.destroy());
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
}
