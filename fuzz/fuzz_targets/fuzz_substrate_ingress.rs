#![no_main]
use libfuzzer_sys::fuzz_target;
use ph::fuzz_harness;
use std::cell::RefCell;

thread_local! {
    // Per-thread cached worker to avoid reallocating full Assembly each iteration
    static WORKER: RefCell<Option<ph::fastpath::FastpathWorker>> = RefCell::new(None);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return; // Need at least some data to work with
    }

    WORKER.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            *opt = Some(fuzz_harness::make_test_worker());
        }
        if let Some(worker) = opt.as_mut() {
            // Build packet ingress parameters from fuzz input
            let (peer_addr, iface_addr, pkt) = fuzz_harness::build_from_bytes(data);
            // Reuse the worker for substrate_ingress calls
            worker.substrate_ingress(&peer_addr, &iface_addr, pkt);
        }
    });
});

