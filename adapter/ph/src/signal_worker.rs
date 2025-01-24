//! Worker which handles Unix signals.

use crate::assembly::Assembly;
use crate::counters::*;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};

fn emit_counts(counters: &Counters, uptime: std::time::Duration) {
    println!("\n*** Counters ***");
    for (key, ref value) in counters {
        println!("{}: {}", key, value.get_count());
    }
    println!("Uptime: {uptime:?}");
}

pub async fn launch(asm: Arc<Assembly>) {
    let usr1_stream = Box::leak(Box::new(signal(SignalKind::user_defined1()).unwrap()));
    let term_stream = Box::leak(Box::new(signal(SignalKind::terminate()).unwrap()));

    loop {
        tokio::select! {
            _ = usr1_stream.recv() => emit_counts(&asm.counters, asm.get_uptime()),
            _ = term_stream.recv() => {
                asm.shutdown().await;
                emit_counts(&asm.counters, asm.get_uptime());
                std::process::exit(128 + SignalKind::terminate().as_raw_value())
            }
        }
    }
}
