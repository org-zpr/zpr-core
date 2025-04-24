use crate::batch_io::BatchIo;
use crate::config;
use crate::counters::*;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::net_defs;
use crate::packet::{self, Packet};
use crate::packet_queue;
use crate::sys::{TunPi, ZprTun};
use crate::zprtun;
use bytes::Buf;
use std::io::{ErrorKind, Result};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;

pub struct FastpathIo {
    batch_io: BatchIo,
    actor_tun: Arc<ZprTun>,
    substrate_socket: UdpSocket,
    pub requeue_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
    pub mgmt_substrate_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,

    /// temporary packet storage during I/O batch operations
    packets: Vec<Packet>,
    /// temporary read result storage during I/O batch operations
    io_results: Vec<Result<usize>>,
    /// temporary recv result storage during I/O batch operations
    recv_results: Vec<Result<(usize, Option<SocketAddr>)>>,
}

impl FastpathIo {
    pub fn new(
        config: FastpathWorkerConfig,
        substrate_socket: UdpSocket,
        actor_tun: Arc<ZprTun>,
        requeue_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
        maybe_mgmt_substrate_outq: Option<packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>>,
    ) -> Self {
        // HACK: nix does not support disabling an FD, so instead, make a dummy mgmt_substrate_outq socket
        // if we weren't given one
        let mgmt_substrate_outq;
        match maybe_mgmt_substrate_outq {
            Some(outq) => mgmt_substrate_outq = outq,
            None => {
                let (_, outq) = packet_queue::packet_queue(1);
                mgmt_substrate_outq = outq;
            }
        }

        Self {
            batch_io: BatchIo::new(config.batch_size).unwrap(),
            actor_tun,
            substrate_socket,
            requeue_outq,
            mgmt_substrate_outq,
            packets: Vec::with_capacity(config.batch_size),
            io_results: Vec::with_capacity(config.batch_size),
            recv_results: Vec::with_capacity(config.batch_size),
        }
    }

    /// Substrate socket FD for polling.
    pub fn substrate_socket_fd(&self) -> BorrowedFd<'_> {
        self.substrate_socket.as_fd()
    }

    /// Actor TUN FD for polling.
    pub fn actor_tun_fd(&self) -> BorrowedFd<'_> {
        self.actor_tun.as_fd()
    }

    /// Requeue socket FD for polling.
    pub fn requeue_fd(&self) -> BorrowedFd<'_> {
        self.requeue_outq.poll_fd()
    }

    /// Mgmt substrate FD for polling.
    pub fn mgmt_substrate_fd(&self) -> BorrowedFd<'_> {
        self.mgmt_substrate_outq.poll_fd()
    }

    /// Process an input-ready notification on the substrate socket (substrate ingress).
    pub fn process_substrate_socket_in(&mut self, worker: &mut FastpathWorker) {
        let _nbufs = worker.get_fresh_packets(worker.config.batch_size, &mut self.packets);

        self.io_results.clear();
        let n = self
            .batch_io
            .try_recv_buf_from_batch(
                &self.substrate_socket,
                self.packets.iter_mut(),
                &mut self.recv_results,
            )
            .unwrap();

        // return empty buffers to pool
        worker
            .buffers
            .extend(self.packets.drain(n..).rev().map(|pkt| pkt.destroy()));

        // process packets
        for (pkt, result) in self.packets.drain(..).zip(self.recv_results.drain(..)) {
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

                        _ => panic!("got socket error {err}"),
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

    /// Process an output-ready notification on the substrate socket
    /// (substrate egress of PRIORITY packets).
    pub fn process_substrate_socket_out(&mut self, worker: &mut FastpathWorker) {
        self.process_substrate_egress_queue(worker);
    }

    /// Process an input-ready notification on the actor TUN (actor output).
    pub fn process_actor_tun_in(&mut self, worker: &mut FastpathWorker) {
        let _nbufs = worker.get_fresh_packets(worker.config.batch_size, &mut self.packets);

        self.io_results.clear();
        let n = self
            .batch_io
            .try_read_buf_batch(
                &self.actor_tun,
                self.packets.iter_mut(),
                &mut self.io_results,
            )
            .unwrap();

        // return empty buffers to pool
        worker
            .buffers
            .extend(self.packets.drain(n..).rev().map(|pkt| pkt.destroy()));

        // process packets
        for (mut pkt, result) in self.packets.drain(..).zip(self.io_results.drain(..)) {
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
            worker.actor_output(pkt);
        }
    }

    /// Process an input-ready notification on the requeue socket.
    pub fn process_requeue_in(&mut self, worker: &mut FastpathWorker) {
        batch_process_packet_queue(
            worker,
            &mut self.requeue_outq,
            worker.config.batch_size,
            |worker, pkt| {
                worker.asm.counters[CounterType::RequeuedPacketsReceived].increment();
                worker.actor_output_post_classify(pkt, /* allow_bind_request */ false);
            },
        );
    }

    /// Process an input-ready notification on the mgmt substrate socket.
    pub fn process_mgmt_substrate_in(&mut self, worker: &mut FastpathWorker) {
        batch_process_packet_queue(
            worker,
            &mut self.mgmt_substrate_outq,
            worker.config.batch_size,
            |worker, pkt| {
                worker.asm.counters[CounterType::MgmtPacketsSent].increment();
                worker.substrate_egress(pkt);
            },
        );
    }

    /// Egress any queued packets, or drop if there is no space in the system queues.
    ///
    /// After this call, the actor input queue will be empty, and the substrate egress queue
    /// will contain only PRIORITY packets.
    pub fn process_out_queues(&mut self, worker: &mut FastpathWorker) {
        self.process_actor_input_queue(worker);
        self.process_substrate_egress_queue(worker);
    }

    /// Egress queued actor input packets only.
    fn process_actor_input_queue(&mut self, worker: &mut FastpathWorker) {
        // Add TUN PI header.
        match TunPi::PI_SIZE {
            0 => (),
            sz => {
                for pkt in &mut worker.actor_input_q {
                    let proto = net_defs::ip_ethertype(net_defs::ip_version(pkt.body()));
                    let mut hdr = pkt.alloc_zeroed_headroom(sz);
                    TunPi::write_pi(
                        &mut hdr,
                        TunPi {
                            strip: false,
                            proto,
                        },
                    );
                }
            }
        }

        // (Try to) send packets.
        self.io_results.clear();
        let n = self
            .batch_io
            .try_write_batch(
                &self.actor_tun.as_fd(),
                worker.actor_input_q.iter().map(|pkt| pkt.body()),
                &mut self.io_results,
            )
            .expect("unrecoverable TUN error");

        // Tally results.
        let mut dropped = worker.actor_input_q.len() - n;
        for res in self.io_results.drain(..) {
            match res {
                Ok(_) => (),
                Err(err) if err.kind() == ErrorKind::WouldBlock => dropped += 1,
                Err(err) => panic!("unrecoverable TUN error: {}", err),
            }
        }
        worker.asm.counters[CounterType::InPacksSent]
            .increase_by((worker.actor_input_q.len() - dropped) as u64);
        worker.asm.counters[CounterType::InPacksDrop].increase_by(dropped as u64);

        // Return buffers to buffer stack.
        worker
            .buffers
            .extend(worker.actor_input_q.drain(..).map(|pkt| pkt.destroy()));
    }

    /// Egress queued substrate egress packets only.
    fn process_substrate_egress_queue(&mut self, worker: &mut FastpathWorker) {
        // (Try to) send packets.
        self.io_results.clear();
        let n = self
            .batch_io
            .try_send_to_batch(
                &self.substrate_socket,
                worker
                    .substrate_egress_q
                    .iter()
                    .map(|(pkt, dest)| (pkt.body(), *dest)),
                &mut self.io_results,
            )
            .expect("unrecoverable I/O error");

        // Tally results.
        let mut dropped = 0;
        let mut retained = 0;

        for i in 0..worker.substrate_egress_q.len() {
            // Determine whether the packet was in fact sent.
            // If it was, leave it in place and skip to the next packet.
            if i < n {
                match &self.io_results[i] {
                    Ok(_) => continue,
                    Err(err) if err.kind() == ErrorKind::WouldBlock => (),
                    // TODO: pending <https://github.com/rust-lang/rust/issues/86442>, provide more info to user
                    // (or potentially recover from certain errors)
                    Err(err) => panic!("unrecoverable I/O error: {err}"),
                }
            }

            // Packet was not sent.

            if worker.substrate_egress_q[i].0.metadata().flags & packet::flags::PRIORITY != 0 {
                // This was a priority packet.  Move it to the front of the queue.
                worker.substrate_egress_q.swap(i, retained);
                retained += 1;
            } else {
                // This was a normal packet.  Leave it to get dropped.
                dropped += 1;
            }
        }
        self.io_results.clear();

        // Now all un-sent priority packets are at the head of the queue.

        worker.asm.counters[CounterType::OutPacksSent]
            .increase_by((worker.substrate_egress_q.len() - dropped - retained) as u64);
        worker.asm.counters[CounterType::OutPacksDrop].increase_by(dropped as u64);

        // Return buffers to buffer stack, except for un-sent priority packets, which are retained for next time.
        worker.buffers.extend(
            worker
                .substrate_egress_q
                .drain(retained..)
                .map(|(pkt, _)| pkt.destroy()),
        );
    }
}

fn is_ip(pi: TunPi) -> bool {
    pi.proto == net_defs::ethertype::IP || pi.proto == net_defs::ethertype::IPV6
}

fn clear_flowinfo(addr: &mut SocketAddr) {
    match addr {
        SocketAddr::V4(_) => (),
        SocketAddr::V6(addr) => addr.set_flowinfo(0),
    }
}

fn batch_process_packet_queue(
    worker: &mut FastpathWorker,
    queue: &mut packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
    limit: usize,
    mut process_fn: impl FnMut(&mut FastpathWorker, Packet),
) {
    for _i in 0..limit {
        let Some(buf) = worker.buffers.pop() else {
            break;
        };

        match queue.try_recv(buf) {
            Ok(pkt) => {
                process_fn(worker, pkt);
            }

            Err(packet_queue::TryRecvError::Empty(buf)) => {
                worker.buffers.push(buf);
                break;
            }

            Err(err) => {
                panic!("unrecoverable I/O error {err:?}");
            }
        }
    }
}
