use crate::assembly::Assembly;
use crate::config;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::fastpath_io::FastpathIo;
use crate::packet_queue;
use crate::sys::ZprTun;
use enum_map::{enum_map, Enum};
use nix::poll;
use std::net::UdpSocket;
use std::sync::Arc;

#[derive(Debug, Enum)]
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
    requeue_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
    mgmt_substrate_outq: Option<packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>>,
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
    // See discussion on fairness below for the reason for this assertion
    // and the magic constant used in it.
    assert!(worker.config.buffer_count >= 5 * worker.config.batch_size);

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

        // FAIRNESS
        //
        // There are two types of resources these I/O routines contend for:
        // packet buffers, and system I/O output queues.
        //
        // Memory is cheap, so we solve the problem of packet buffer
        // contention simply by making sure there are at least as many
        // packet buffers existing as there can be outstanding.
        //
        // Packet buffers can be outstanding only while they are queued for
        // egress.  Buffers holding non-priority packets, as produced by the
        // Requeue, Substrate, Tun, and (possibly) MgmtSubstrate I/O
        // routines, are recovered at the end of every I/O cycle.
        // Therefore, it is sufficient that we have a number of packet
        // buffers available equal to the sum of the batch sizes for these
        // four paths.
        //
        // Buffers holding priority packets however are only recovered on
        // successful submission of the packet to the OS.  Though we do not
        // care if these starve non-priority paths, we do care that said
        // paths are starved of buffers fairly.  It suffices that we reserve
        // an additional number of packet buffers (beyond those already
        // reserved on behalf of MgmtSubstrate, the only source of priority
        // packets) equal to the batch size, corresponding to those priority
        // packets which were held from the last cycle.  (If priority
        // packets are held for two cycles, this implies that we are not
        // sending any non-priority packets and thus dropping them.)
        //
        // These buffer count requirements are enforced by the assert at the
        // top of this function.
        //
        // Regarding contention for system I/O output queues.  Only packets
        // from Substrate and Tun will ever be high enough rate to actually
        // matter.  So we statically give priority to packets Requeue and
        // MgmtSubstrate packets (the latter of which are almost certainly
        // actually marked as such).  For packets from Substrate and Tun, we
        // consider separately the adapter and node cases.
        //
        // On the adapter, traffic from Substrate always flows out the Tun
        // interface, and vice-versa.  So there is no contention between these
        // for the system I/O output queues.
        //
        // On the node, traffic to or from the Tun is management (typically
        // Visa-related) traffic, and thus typically lower rate than traffic
        // which only transits the Substrate, and also more important.  So
        // we can safely statically prioritize this traffic, which also
        // ensures that it doesn't get starved.

        // First, get any returned buffers, so we have them immediately to work with.
        if revents[PollSlot::Returns].contains(poll::PollFlags::POLLIN) {
            worker
                .return_q
                .try_recv_many_returns(&mut worker.buffers, worker.config.buffer_count);
        }

        // Now, try to send queued PRIORITY packets, possibly freeing their buffers also.
        if revents[PollSlot::Substrate].contains(poll::PollFlags::POLLOUT) {
            io.process_substrate_socket_out(&mut worker);
        }

        // Next, read and process any substrate traffic from mgmt.  This is
        // typically/always marked PRIORITY, but even if not, it's low rate
        // and we don't want it to get starved.
        if revents[PollSlot::MgmtSubstrate].contains(poll::PollFlags::POLLIN) {
            io.process_mgmt_substrate_in(&mut worker);
        }

        // Now, read and process any requeued agent traffic.  Typically this
        // is from mgmt.  It is not priority, but it is low rate, so we want
        // to process it first.
        if revents[PollSlot::Requeue].contains(poll::PollFlags::POLLIN) {
            io.process_requeue_in(&mut worker);
        }

        // Now we read and process agent traffic from the TUN device.
        // On the adapter, this may be high rate, so we process it after all low-rate sources.
        // On the node, this is likely low rate, so we process it before substrate traffic.
        if revents[PollSlot::Tun].contains(poll::PollFlags::POLLIN) {
            io.process_actor_tun_in(&mut worker);
        }

        // Finally, read and process agent traffic from the substrate.
        // This is likely high rate, so process it after all other sources.
        if revents[PollSlot::Substrate].contains(poll::PollFlags::POLLIN) {
            // read from socket
            io.process_substrate_socket_in(&mut worker);
        }
        worker.aggregate()
    }
}
