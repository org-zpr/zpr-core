//! Fuzz testing harness for substrate_ingress.
//! Only available with feature="fuzzing".

use crate::assembly::{test::TestAssemblyBuilder, test::create_assembly};
use crate::batch_io;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::packet::Packet;
use crate::prelude::*;
use std::sync::Arc;
use zpr_utils::net_defs::{ScopedIpAddr, ScopedIpv6Addr};

/// Create a minimal FastpathWorker for fuzzing.
pub fn make_test_worker() -> FastpathWorker {
    // Use TestAssemblyBuilder to create a minimal Assembly with all required fields.
    let builder = TestAssemblyBuilder::new();
    let asm = Arc::new(create_assembly(builder));

    // Get a suitable batch I/O engine for this platform
    let batch_io_engine = batch_io::auto_select_engine();

    let config = FastpathWorkerConfig {
        batch_io_engine,
        buffer_count: 8,
        batch_size: 8,
    };

    FastpathWorker::new(config, 0, asm)
}

/// Build packet ingress parameters from fuzz input bytes.
pub fn build_from_bytes(data: &[u8]) -> (SubstrateAddr, ScopedIpAddr, Packet) {
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

    // Build packet from remaining bytes
    const MAX_PKT_SIZE: usize = 2048;
    let pkt_data = &data[std::cmp::min(32, data.len())..];

    let mut buf = Box::new([0u8; MAX_PKT_SIZE]);
    let n = pkt_data.len().min(MAX_PKT_SIZE);
    buf[..n].copy_from_slice(&pkt_data[..n]);

    let pkt = Packet::new(buf, crate::config::DEFAULT_MESSAGE_HEADROOM);

    (peer_addr, iface, pkt)
}
