use crate::assembly::Assembly;
use crate::counters::*;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::net_defs;
use crate::packet::Packet;
use crate::sys::TunPi;
use crate::sys::ZprTun;
use crate::zprtun;
use bytes::Buf;
use enum_map::{enum_map, Enum};
use nix::poll;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;

fn is_ip(pi: TunPi) -> bool {
    pi.proto == net_defs::ethertype::IP || pi.proto == net_defs::ethertype::IPV6
}

#[derive(Enum)]
enum PollSlot {
    Substrate,
    Tun,
    Requeue,
    Returns,
}

pub fn launch(
    config: FastpathWorkerConfig,
    worker_index: usize,
    asm: Arc<Assembly>,
    socket: Arc<UdpSocket>,
    agent_input_tun: Arc<ZprTun>,
    requeue_outq: UnixDatagram,
) -> impl FnOnce() {
    move || {
        let worker = FastpathWorker::new(config, worker_index, asm.clone(), agent_input_tun);
        fastpath_main(worker, &socket, &requeue_outq);
    }
}

fn fastpath_main(mut worker: FastpathWorker, socket: &UdpSocket, requeue_outq: &UnixDatagram) {
    loop {
        // output anything we've queued up
        worker.process_out_queues();

        // WORKING: move return logic into fastpath common

        let recv_poll_flags;
        if worker.buffers.is_empty() {
            // If we have no buffers, let's not get woken up to receive packets.
            recv_poll_flags = poll::PollFlags::empty();
        } else {
            recv_poll_flags = poll::PollFlags::POLLIN;
        }

        let mut poll_fds = enum_map! {
            PollSlot::Substrate => poll::PollFd::new(socket.as_fd(), recv_poll_flags),
            PollSlot::Tun => poll::PollFd::new(worker.agent_input_tun.as_fd(), recv_poll_flags),
            PollSlot::Requeue => poll::PollFd::new(requeue_outq.as_fd(), recv_poll_flags),
            PollSlot::Returns => poll::PollFd::new(worker.return_q.poll_fd(), poll::PollFlags::POLLIN),
        };

        let _n = match poll::poll(poll_fds.as_mut_slice(), poll::PollTimeout::NONE)
            .map_err(|err| std::io::Error::from_raw_os_error(err as i32))
        {
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            ret @ Err(_) => ret.unwrap(),
        };

        // Extracting the revents here allows us to drop the `PollFd`s, which hold
        // references to things in `worker`, which we need `&mut` access to later.
        let revents = poll_fds.map(|_, pfd| pfd.revents().unwrap());

        // FIXME: fairness... address this in tandem with batch receive
        // for now, prioritize requeue so it doesn't starve

        if revents[PollSlot::Requeue].contains(poll::PollFlags::POLLIN) {
            // read from requeue
            // TODO: batch receive
            let mut buf = worker.buffers.pop().unwrap();

            if let Err(err) = requeue_outq.recv(buf.as_mut()) {
                match err.kind() {
                    ErrorKind::WouldBlock | ErrorKind::ResourceBusy => {
                        worker.buffers.push(buf);
                        continue;
                    }

                    _ => {
                        // FIXME: detect packet-too-large
                        panic!("unrecoverable I/O error {err}");
                    }
                }
            }

            worker.asm.counters[CounterType::RequeuedPacketsReceived].increment();
            let pkt = Packet::new_with_existing_metadata(buf);
            worker.agent_output_post_classify(pkt, /* allow_bind_request */ false);
        }

        if revents[PollSlot::Substrate].contains(poll::PollFlags::POLLIN) {
            // read from socket
            let mut pkts = Vec::new(); // TODO: recycle
            let _nbufs = worker.get_fresh_packets(worker.config.batch_size, &mut pkts);
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
                clear_flowinfo(&mut sender);

                worker.asm.counters[CounterType::InPacksRec].increment();
                worker.substrate_ingress(&sender, pkt);
            }
        }

        if revents[PollSlot::Tun].contains(poll::PollFlags::POLLIN) {
            // read from TUN device
            let mut pkts = Vec::new(); // TODO: recycle
            let _nbufs = worker.get_fresh_packets(worker.config.batch_size, &mut pkts);
            let mut results = Vec::new(); // TODO: recycle
            let n = worker
                .batch_io
                .try_read_buf_batch(&worker.agent_input_tun, pkts.iter_mut(), &mut results)
                .unwrap();

            // return empty buffers to pool
            worker
                .buffers
                .extend(pkts.drain(n..).rev().map(|pkt| pkt.destroy()));

            // process packets
            for (mut pkt, result) in pkts.into_iter().zip(results) {
                if let Err(err) = result {
                    match err.kind() {
                        ErrorKind::WouldBlock | ErrorKind::ResourceBusy => {
                            worker.buffers.push(pkt.destroy());
                            continue;
                        }

                        _ => panic!("unrecoverable I/O error {err}"),
                    }
                }

                if zprtun::TUN_HAS_PI {
                    let pi = TunPi::read_pi(&mut pkt);
                    if pi.strip || !is_ip(pi) {
                        // packet was too large or non-IP; drop
                        worker.drop_and_count(pkt, CounterType::OutPacksDrop);
                        continue;
                    }
                } else {
                    // No packet info, permit IP and IPv6 only (for now?)
                    if pkt.body()[0] >> 4 != 4 && pkt.body()[0] >> 4 != 6 {
                        worker.drop_and_count(pkt, CounterType::OutPacksDrop);
                        continue;
                    }
                }

                worker.asm.counters[CounterType::OutPacksRec].increment();
                worker.agent_output(pkt);
            }
        }

        if revents[PollSlot::Returns].contains(poll::PollFlags::POLLIN) {
            // process the return buffer queue
            worker
                .return_q
                .try_recv_many_returns(&mut worker.buffers, worker.config.buffer_count);
        }
    }
}

fn clear_flowinfo(addr: &mut SocketAddr) {
    match addr {
        SocketAddr::V4(_) => (),
        SocketAddr::V6(addr) => addr.set_flowinfo(0),
    }
}
