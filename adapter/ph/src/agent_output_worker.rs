use crate::assembly::Assembly;
use crate::config;
use crate::counters::*;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::net_defs;
use crate::packet::Packet;
use crate::sys::TunPi;
use crate::sys::ZprTun;
use crate::zprtun;
use enum_map::{enum_map, Enum};
use nix::poll;
use std::io::ErrorKind;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;

fn is_ip(pi: TunPi) -> bool {
    pi.proto == net_defs::ethertype::IP || pi.proto == net_defs::ethertype::IPV6
}

#[derive(Enum)]
enum PollSlot {
    Tun,
    Requeue,
}

pub fn launch(
    config: FastpathWorkerConfig,
    worker_index: usize,
    asm: Arc<Assembly>,
    tun: Arc<ZprTun>,
    requeue_outq: UnixDatagram,
) -> impl FnOnce() {
    move || {
        let worker = FastpathWorker::new(config, worker_index, asm.clone());
        agent_output_main(worker, &tun, &requeue_outq);
    }
}

fn agent_output_main(mut worker: FastpathWorker, tun: &ZprTun, requeue_outq: &UnixDatagram) {
    // temp hack until we move ZprTun to be non-Tokio
    let tun_fd = unsafe { BorrowedFd::borrow_raw(tun.as_raw_fd()) };

    let mut poll_fds = enum_map! {
        PollSlot::Tun => poll::PollFd::new(tun_fd, poll::PollFlags::POLLIN),
        PollSlot::Requeue => poll::PollFd::new(requeue_outq.as_fd(), poll::PollFlags::POLLIN),
    };

    loop {
        // output anything we've queued up
        worker.process_out_queues();

        // process the return buffer queue
        if worker.buffers.is_empty() {
            // if we are out of buffers, block
            worker
                .adapter_manager
                .recv_return_buffers(&mut worker.buffers, worker.config.buffer_count);
        } else {
            worker
                .adapter_manager
                .try_recv_return_buffers(&mut worker.buffers, worker.config.buffer_count);
        }

        // read & forward packets one at a time
        let _n = match poll::poll(poll_fds.as_mut_slice(), poll::PollTimeout::NONE)
            .map_err(|err| std::io::Error::from_raw_os_error(err as i32))
        {
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            ret @ Err(_) => ret.unwrap(),
        };

        // FIXME: fairness... address this in tandem with batch receive
        // for now, prioritize requeue so it doesn't starve

        if poll_fds[PollSlot::Requeue]
            .revents()
            .unwrap()
            .contains(poll::PollFlags::POLLIN)
        {
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

        if poll_fds[PollSlot::Tun]
            .revents()
            .unwrap()
            .contains(poll::PollFlags::POLLIN)
        {
            let nbufs = std::cmp::min(worker.buffers.len(), worker.config.batch_size);

            // read from TUN device
            let mut pkts: Vec<_> = worker
                .buffers
                .drain(worker.buffers.len() - nbufs..)
                .rev()
                .map(|buf| Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM))
                .collect(); // TODO: recycle
            let mut results = Vec::new(); // TODO: recycle
            let n = worker
                .batch_io
                .try_read_buf_batch(&tun_fd, pkts.iter_mut(), &mut results)
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
    }
}
