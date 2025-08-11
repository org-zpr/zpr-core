//! Worker which handles Unix signals.

use crate::assembly::Assembly;
use crate::counters::*;
use crate::logging::targets::STARTUP;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::spawn_local;
use tracing::*;

pub async fn launch(asm: Arc<Assembly>) {
    let mut usr1_stream = signal(SignalKind::user_defined1()).unwrap();
    let mut term_stream = signal(SignalKind::terminate()).unwrap();
    let mut int_stream = signal(SignalKind::interrupt()).unwrap();

    let mut int_received = false;

    loop {
        tokio::select! {
            _ = usr1_stream.recv() => emit_counts(&asm.counters, asm.get_uptime()),

            _ = int_stream.recv() => {
                // Treat a single SIGINT as a UI request to shut down cleanly;
                // any subsequent SIGINTs as a forced shutdown.
                if int_received {
                    // There's no way to unregister a signal handler with
                    // Tokio, so instead, report SIGINT as the shutdown
                    // reason via exit code (as if we hadn't registered a handler).
                    std::process::exit(128 + SignalKind::interrupt().as_raw_value());
                } else {
                    info!(target: STARTUP, "Got SIGINT; attempting graceful shutdown. Send again to terminate immediately.");
                    int_received = true;
                    drop(spawn_local(do_clean_shutdown(asm.clone())));
                }
            }

            _ = term_stream.recv() => {
                // Attempt a graceful shutdown on SIGTERM.  Unlike SIGINT,
                // we don't change behavior on repeated signals: SIGKILL
                // is the appropriate follow-up to force shutdown.
                info!(target: STARTUP, "Got SIGTERM; attempting graceful shutdown. Send SIGKILL to terminate immediately.");
                drop(spawn_local(do_clean_shutdown(asm.clone())));
            }
        }
    }
}

fn emit_counts(counters: &Counters, uptime: std::time::Duration) {
    println!("{:>42}\n", "*** Counters ***");
    println!("{:>34}: {:?}", "Uptime", uptime);
    for (key, ref value) in &counters.management {
        println!("{:>34}: {}", key.name(), value.get_count());
    }
    for (key, ref value) in &counters.fastpath {
        println!("{:>34}: {}", key.name(), value.get_count());
    }
}

async fn do_clean_shutdown(asm: Arc<Assembly>) -> ! {
    asm.shutdown().await;
    emit_counts(&asm.counters, asm.get_uptime());
    std::process::exit(0);
}
