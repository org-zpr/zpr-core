#![no_main]
use libfuzzer_sys::fuzz_target;
use ph::fuzz_harness;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return; // Need at least some data to work with
    }

    // Create a test worker
    let mut worker = fuzz_harness::make_test_worker();
    
    // Build packet ingress parameters from fuzz input
    let (peer_addr, iface_addr, pkt) = fuzz_harness::build_from_bytes(data);
    
    // Call substrate_ingress — this should not panic or crash
    // even with arbitrary untrusted packet data.
    worker.substrate_ingress(&peer_addr, &iface_addr, pkt);
});

