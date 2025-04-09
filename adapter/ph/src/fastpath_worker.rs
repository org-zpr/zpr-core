use crate::assembly::Assembly;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::fastpath_io::FastpathIo;
use crate::sys::ZprTun;
use enum_map::{enum_map, Enum};
use nix::poll;
use std::net::UdpSocket;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;

#[derive(Enum)]
enum PollSlot {
    Substrate,
    Tun,
    Requeue,
    MgmtSubstrate,
    Returns,
}

pub fn launch(
    config: FastpathWorkerConfig,
    worker_index: usize,
    asm: Arc<Assembly>,
    substrate_socket: UdpSocket,
    actor_input_tun: Arc<ZprTun>,
    requeue_outq: UnixDatagram,
    mgmt_substrate_outq: Option<UnixDatagram>,
) -> impl FnOnce() {
    move || {
        let worker = FastpathWorker::new(config, worker_index, asm.clone());
        let io = FastpathIo::new(
            config,
            substrate_socket,
            actor_input_tun,
            requeue_outq,
            mgmt_substrate_outq,
        );
        fastpath_main(worker, io);
    }
}

fn fastpath_main(mut worker: FastpathWorker, mut io: FastpathIo) {
    loop {
        // try to immediately output anything we've queued up;
        // if we can't, drop it, unless it's on the substrate and marked PRIORITY
        io.process_out_queues(&mut worker);

        let recv_poll_flags;
        if worker.buffers.is_empty() {
            // If we have no buffers, let's not get woken up to receive packets.
            recv_poll_flags = poll::PollFlags::empty();
        } else {
            recv_poll_flags = poll::PollFlags::POLLIN;
        }

        let send_poll_flags;
        if worker.substrate_egress_packets_queued() {
            send_poll_flags = poll::PollFlags::POLLOUT;
        } else {
            send_poll_flags = poll::PollFlags::empty();
        }

        let mut poll_fds = enum_map! {
            PollSlot::Substrate => poll::PollFd::new(io.substrate_socket_fd(), recv_poll_flags | send_poll_flags),
            PollSlot::Tun => poll::PollFd::new(io.actor_tun_fd(), recv_poll_flags),
            PollSlot::Requeue => poll::PollFd::new(io.requeue_fd(), recv_poll_flags),
            PollSlot::MgmtSubstrate => poll::PollFd::new(io.mgmt_substrate_fd(), recv_poll_flags),
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

        if revents[PollSlot::Substrate].contains(poll::PollFlags::POLLOUT) {
            // try to send queued PRIORITY packets
            io.process_substrate_socket_out(&mut worker);
        }

        if revents[PollSlot::Requeue].contains(poll::PollFlags::POLLIN) {
            // read from requeue
            io.process_requeue_in(&mut worker);
        }

        if revents[PollSlot::MgmtSubstrate].contains(poll::PollFlags::POLLIN) {
            // read from mgmt_substrate
            io.process_mgmt_substrate_in(&mut worker);
        }

        if revents[PollSlot::Substrate].contains(poll::PollFlags::POLLIN) {
            // read from socket
            let mut pkts = Vec::new(); // TODO: recycle
            let nbufs = worker.get_fresh_packets(worker.config.batch_size, &mut pkts);
            if nbufs == 0 {
                continue;
            }

            io.process_substrate_socket_in(&mut worker, &mut pkts);
        }

        if revents[PollSlot::Tun].contains(poll::PollFlags::POLLIN) {
            // read from TUN device
            let mut pkts = Vec::new(); // TODO: recycle
            let nbufs = worker.get_fresh_packets(worker.config.batch_size, &mut pkts);
            if nbufs == 0 {
                continue;
            }

            io.process_actor_tun_in(&mut worker, &mut pkts);
        }

        if revents[PollSlot::Returns].contains(poll::PollFlags::POLLIN) {
            // process the return buffer queue
            worker
                .return_q
                .try_recv_many_returns(&mut worker.buffers, worker.config.buffer_count);
        }
    }
}
