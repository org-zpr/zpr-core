#![no_main]
use libfuzzer_sys::fuzz_target;
use ph::fuzz_harness;
use std::cell::RefCell;

thread_local! {
    // Per-thread cached fuzz context with Tokio runtime and mgmt_dispatch_worker.
    static FUZZ_CTX: RefCell<Option<fuzz_harness::FuzzContext>> = RefCell::new(None);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < fuzz_harness::PARAMS_SIZE {
        return; // Need at least PARAMS_SIZE bytes for parameters
    }

    FUZZ_CTX.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            *opt = Some(fuzz_harness::make_fuzz_context());
        }
        if let Some(ctx) = opt.as_mut() {
            // Split input: first PARAMS_SIZE bytes for parameters, rest for packet body
            let (params_data, body_data) = data.split_at(fuzz_harness::PARAMS_SIZE);
            
            // Extract parameters from first segment
            let (peer_addr, iface_addr) = fuzz_harness::build_packet_params(params_data);

            // Get a fresh packet buffer from the worker's pool
            let mut pkts = Vec::with_capacity(1);
            let n = ctx.worker.get_fresh_packets(1, &mut pkts);

            // Only proceed if we got a packet from the pool
            if n > 0 && !pkts.is_empty() {
                let mut pkt = pkts.pop().unwrap();

                // Fill the packet with body data (second segment)
                fuzz_harness::fill_packet_from_bytes(&mut pkt, body_data);

                // Call substrate_ingress to process the pre-auth packet
                ctx.worker.substrate_ingress(&peer_addr, &iface_addr, pkt);
                
                // Drain the mgmt_dispatch queue to process any link creation or auth requests.
                // This allows the mgmt_dispatch_worker to handle packets that need special processing.
                fuzz_harness::drain_mgmt_dispatch(ctx);
            }
        }
    });
});
