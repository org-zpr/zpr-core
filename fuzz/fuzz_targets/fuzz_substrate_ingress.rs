#![no_main]
use libfuzzer_sys::fuzz_target;
use ph::fuzz_harness;
use std::cell::RefCell;

thread_local! {
    // Per-thread cached worker and assembly to avoid reallocating each iteration.
    // The assembly contains the mgmt_dispatch path needed for link creation.
    static WORKER_DATA: RefCell<Option<(ph::fastpath::FastpathWorker, std::sync::Arc<ph::assembly::Assembly>)>> = RefCell::new(None);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < fuzz_harness::PARAMS_SIZE {
        return; // Need at least PARAMS_SIZE bytes for parameters
    }

    WORKER_DATA.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            *opt = Some(fuzz_harness::make_test_worker());
        }
        if let Some((worker, asm)) = opt.as_mut() {
            // Split input: first PARAMS_SIZE bytes for parameters, rest for packet body
            let (params_data, body_data) = data.split_at(fuzz_harness::PARAMS_SIZE);
            
            // Extract parameters from first segment
            let (peer_addr, iface_addr) = fuzz_harness::build_packet_params(params_data);

            // Get a fresh packet buffer from the worker's pool
            let mut pkts = Vec::with_capacity(1);
            let n = worker.get_fresh_packets(1, &mut pkts);

            // Only proceed if we got a packet from the pool
            if n > 0 && !pkts.is_empty() {
                let mut pkt = pkts.pop().unwrap();

                // Fill the packet with body data (second segment)
                fuzz_harness::fill_packet_from_bytes(&mut pkt, body_data);

                // Call substrate_ingress — processes the pre-auth packet
                worker.substrate_ingress(&peer_addr, &iface_addr, pkt);
                
                // Attempt to dispatch the packet for link creation.
                // For unidentified packets, this starts the link authentication process.
                // The dispatch function handles various packet types appropriately.
                // Note: This is a simplification; in production, the mgmt_dispatch_worker
                // would drain a queue. Here we directly invoke dispatch for fuzzing.
                
                // Get a fresh packet for dispatch (we consumed the previous one)
                let mut pkts2 = Vec::with_capacity(1);
                if worker.get_fresh_packets(1, &mut pkts2) > 0 {
                    if let Some(pkt2) = pkts2.pop() {
                        fuzz_harness::dispatch_packet_if_unidentified(asm, peer_addr, iface_addr, pkt2);
                    }
                }
            }
        }
    });
});
