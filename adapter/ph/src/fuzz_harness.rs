//! Fuzz testing harness for substrate_ingress.
//! Only available with feature="fuzzing".

use crate::assembly::{test::create_assembly, test::TestAssemblyBuilder};
use crate::batch_io;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::mgmt_dispatch_worker;
use crate::packet::Packet;
use crate::prelude::*;
use crate::queues::{MgmtDispatch, MgmtDispatchFactory, MgmtDispatchMessage, MgmtHairpinDispatch};
use crate::two_way_queue;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use zpr_utils::net_defs::{ScopedIpAddr, ScopedIpv6Addr};

/// Wrapper for fuzzing infrastructure including worker, queues, and async runtime.
pub struct FuzzContext {
    pub worker: FastpathWorker,
    pub asm: Arc<Assembly>,
    pub runtime: Runtime,
    pub mgmt_dispatch_sender: Option<MgmtDispatch>,
}

/// Create a fuzz context with Tokio runtime and mgmt_dispatch_worker.
pub fn make_fuzz_context() -> FuzzContext {
    // Create Tokio runtime
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // Create separate queues for mgmt_dispatch
    let (md_inq_factory, md_outq) = two_way_queue::two_way_queue(64);
    let (mhd_inq, mhd_outq) = mpsc::channel(64);

    // Build Assembly with proper queue factories
    let mut builder = TestAssemblyBuilder::new();
    builder.mgmt_dispatch_factory = Some(MgmtDispatchFactory::new(md_inq_factory));
    builder.mgmt_hairpin_dispatch = Some(MgmtHairpinDispatch::new(mhd_inq));

    let asm = Arc::new(create_assembly(builder));

    // Create mgmt_dispatch sender for packets
    let ret_q = two_way_queue::ReturnQueue::new();
    let md_dispatch = asm.mgmt_dispatch_factory.make(&ret_q);

    // Spawn mgmt_dispatch_worker in the runtime
    let asm_for_worker = asm.clone();
    runtime.spawn(async move {
        mgmt_dispatch_worker::launch(asm_for_worker, md_outq, mhd_outq).await;
    });

    // Create FastpathWorker
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
        runtime,
        mgmt_dispatch_sender: Some(md_dispatch),
    }
}

/// Process pending mgmt_dispatch by giving the Tokio runtime a chance to run.
pub fn drain_mgmt_dispatch(ctx: &mut FuzzContext) {
    // Yield to Tokio runtime for a brief moment to process queued packets
    // This allows mgmt_dispatch_worker to handle messages
    ctx.runtime.block_on(async {
        // Give the event loop one chance to process pending work
        tokio::task::yield_now().await;
    });
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
/// Writes up to the full body length with fuzz data.
pub fn fill_packet_from_bytes(pkt: &mut Packet, data: &[u8]) {
    let body = pkt.body_mut();
    let n = std::cmp::min(data.len(), body.len());
    body[..n].copy_from_slice(&data[..n]);
}

