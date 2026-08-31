//! Fuzz testing harness for substrate_ingress.
//! Only available with feature="fuzzing".

use crate::packet::Packet;
use crate::prelude::*;
use crate::assembly::Assembly;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use std::sync::Arc;
use zpr_utils::net_defs::ScopedIpAddr;

/// Create a minimal FastpathWorker for fuzzing.
/// 
/// NOTE: This is a stub that needs Assembly::new_test() to be implemented
/// in the assembly module to create a test-safe instance with all required fields.
pub fn make_test_worker() -> FastpathWorker {
    // Placeholder: In a real implementation, Assembly::new_test() would 
    // return a minimal Assembly configured for fuzzing (with test doubles
    // for peer_table, mgmt_dispatch_factory, etc.).
    //
    // For now, this is intentionally incomplete and will fail to compile
    // until Assembly::new_test() is implemented.
    
    static BATCH_IO: crate::batch_io::BatchIoEngine = crate::batch_io::BatchIoEngine::new_test();
    let config = FastpathWorkerConfig {
        batch_io_engine: &BATCH_IO,
        buffer_count: 8,
        batch_size: 8,
    };
    
    let asm = Arc::new(Assembly::new_test());
    FastpathWorker::new(config, 0, asm)
}

/// Build packet ingress parameters from fuzz input bytes.
///
/// Splits the input into:
/// - First 16 bytes (or less): peer socket address (deterministic)
/// - Next 16 bytes (or less): interface address (default)
/// - Remaining bytes: packet payload
pub fn build_from_bytes(data: &[u8]) -> (SubstrateAddr, ScopedIpAddr, Packet) {
    use std::net::{SocketAddrV6, Ipv6Addr};
    
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
    
    let iface = ScopedIpAddr::default();
    
    // Build packet from remaining bytes
    const MAX_PKT_SIZE: usize = 2048;
    let pkt_data = &data[std::cmp::min(32, data.len())..];
    
    let mut buf = Box::new([0u8; MAX_PKT_SIZE]);
    let n = pkt_data.len().min(MAX_PKT_SIZE);
    buf[..n].copy_from_slice(&pkt_data[..n]);
    
    let pkt = Packet::new(buf, crate::config::DEFAULT_MESSAGE_HEADROOM);
    
    (peer_addr, iface, pkt)
}

