//! Fuzz testing harness for substrate_ingress.
//! Only available with feature="fuzzing".

use crate::assembly::{test::create_assembly, test::TestAssemblyBuilder};
use crate::batch_io;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::mgmt::dispatch::{dispatch_mgmt_packet_with_addr, dispatch_mgmt_packet_with_link};
use crate::packet::Packet;
use crate::prelude::*;
use crate::queues::{MgmtDispatchFactory, MgmtDispatchMessage, MgmtHairpinDispatch};
use crate::two_way_queue;
use std::sync::Arc;
use tokio::sync::mpsc;
use zpr_utils::net_defs::{ScopedIpAddr, ScopedIpv6Addr};

/// Wrapper for fuzzing infrastructure including the worker and the receiving
/// end of the mgmt_dispatch queue.
pub struct FuzzContext {
    pub worker: FastpathWorker,
    pub asm: Arc<Assembly>,
    /// The consumer half of the mgmt_dispatch queue.  In production this is
    /// read by the asynchronous `mgmt_dispatch_worker` task; here we drain it
    /// synchronously (see `dispatch_pending_mgmt_packets`) so that fuzzer
    /// crashes can be attributed to a specific input.
    pub mgmt_dispatch_receiver: two_way_queue::Receiver<MgmtDispatchMessage, PacketBuffer>,
}

/// Create a fuzz context with a `FastpathWorker` and the receiving end of the
/// mgmt_dispatch queue.
pub fn make_fuzz_context() -> FuzzContext {
    // Create the two-way queue used for mgmt_dispatch.  `worker` (below) will
    // hold a `Sender` for this queue (as `worker.mgmt_dispatch`), whose return
    // path is the worker's own `return_q`.  We keep the `Receiver` here so we
    // can synchronously pull packets off of it and dispatch them ourselves.
    let (md_inq_factory, mgmt_dispatch_receiver) = two_way_queue::two_way_queue(64);
    let (mhd_inq, _mhd_outq) = mpsc::channel(64);

    // Build Assembly with proper queue factories
    let mut builder = TestAssemblyBuilder::new();
    builder.mgmt_dispatch_factory = Some(MgmtDispatchFactory::new(md_inq_factory));
    builder.mgmt_hairpin_dispatch = Some(MgmtHairpinDispatch::new(mhd_inq));

    let asm = Arc::new(create_assembly(builder));

    // Create FastpathWorker.  This creates its own `mgmt_dispatch` sender
    // (from `asm.mgmt_dispatch_factory`) whose return path is the worker's
    // own `return_q`.
    let batch_io_engine = batch_io::auto_select_engine();
    let config = FastpathWorkerConfig {
        buffer_count: 8,
        batch_size: 8,
        batch_io_engine,
    };
    let worker = FastpathWorker::new(config, 0, asm.clone());

    FuzzContext {
        worker,
        asm,
        mgmt_dispatch_receiver,
    }
}

/// Synchronously process any packets pending on the mgmt_dispatch queue.
///
/// This stands in for the asynchronous `mgmt_dispatch_worker` task: it pulls
/// each pending packet off of the queue (via `try_recv()`), dispatches it
/// using the same logic `mgmt_dispatch_worker` would use, and then drops the
/// message so its buffer is returned along the queue's return path (the
/// worker's `return_q`).  Finally, any buffers that have made their way back
/// are reclaimed into the worker's buffer pool.
pub fn dispatch_pending_mgmt_packets(ctx: &mut FuzzContext) {
    while let Some(mut msg) = ctx.mgmt_dispatch_receiver.try_recv() {
        match &mut *msg {
            MgmtDispatchMessage::WithLink(pkt) => {
                dispatch_mgmt_packet_with_link(&ctx.asm, pkt);
            }
            MgmtDispatchMessage::WithAddr {
                peer_sa,
                interface_addr,
                packet,
            } => {
                dispatch_mgmt_packet_with_addr(&ctx.asm, *peer_sa, *interface_addr, packet);
            }
        }

        // Dropping the guard returns the packet's buffer along the queue's
        // return path (the worker's `return_q`), just as would happen once
        // `mgmt_dispatch_worker` finishes processing a message.
        drop(msg);
    }

    // Reclaim any buffers that have made their way back to the worker's pool.
    ctx.worker
        .return_q
        .try_recv_many_returns(&mut ctx.worker.buffers, ctx.worker.config.buffer_count);
}

/// Number of bytes used for packet parameters (2 for port + 16 for IPv6)
pub const PARAMS_SIZE: usize = 18;

/// Extract fuzz input parameters (peer_addr, interface_addr) from bytes.
/// Consumes the first PARAMS_SIZE bytes of data.
pub fn build_packet_params(data: &[u8]) -> (SubstrateAddr, ScopedIpAddr) {
    use std::net::{Ipv6Addr, SocketAddrV6};

    // Extract port from first two bytes
    let port = if data.len() > 0 {
        u16::from_le_bytes([data[0], data.get(1).copied().unwrap_or(0)])
    } else {
        0
    };

    // Extract IPv6 from next 16 bytes
    let mut octets = [0u8; 16];
    for (i, &b) in data.iter().skip(2).take(16).enumerate() {
        octets[i] = b;
    }
    let ip = Ipv6Addr::from(octets);
    let peer_addr = SubstrateAddr::from(SocketAddrV6::new(ip, port, 0, 0));

    // Create ScopedIpAddr::V6 — use unspecified address and zero scope for fuzz testing
    let iface = ScopedIpAddr::V6(ScopedIpv6Addr::new(Ipv6Addr::UNSPECIFIED, 0));

    (peer_addr, iface)
}

/// Fill a packet buffer with fuzz input data.
///
/// A freshly obtained packet has an empty body (zero length), so writing via
/// `body_mut()` has no effect -- there's nothing there to write into.
/// Instead, use the `BufMut` impl on `Packet`, which appends into the
/// tailroom and grows the body accordingly (via `put_slice()`).  Only as much
/// of `data` as fits in the available tailroom is written.
pub fn fill_packet_from_bytes(pkt: &mut Packet, data: &[u8]) {
    let n = std::cmp::min(data.len(), pkt.remaining_mut());
    pkt.put_slice(&data[..n]);
}
