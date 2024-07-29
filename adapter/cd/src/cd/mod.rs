mod command_server;
pub use crate::cd::command_server::command_server;

mod config;
pub use crate::cd::config::Config;

mod zpr;
pub use crate::cd::zpr::Zpr;

mod cmonitor;
pub use crate::cd::cmonitor::CMonitor;


use std::{fs, io, sync::Arc};
use tokio::signal;
use tokio::sync::oneshot;
use tracing::{error, info};
use tracing_subscriber;

use tokio_util::sync::CancellationToken;
use tokio::task::JoinSet;

#[tokio::main]
pub async fn tokio_main(config: Arc<Config>) -> io::Result<()> {
    tracing_subscriber::fmt::init();

    info!("cd starts");

    let mut tracker = JoinSet::new();
    let token = CancellationToken::new();
    let zpr = Zpr::new();


    let monitor = CMonitor::new(zpr.clone());

    let monitor_token = token.clone();
    let mut sp_monitor = monitor.clone();

    tracker.spawn(async move {
        match sp_monitor.start(monitor_token).await {
            Ok(()) => {
                info!("cmonitor shut down");
            }
            Err(e) => {
                error!("cmonitor shut down with error: {}", e);
            }
        }
    });

    info!("waiting for cmonitor to start...");
    let mut i = 0;
    while i < 10 {
        if monitor.get_command_channel().is_some() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        i += 1;
    }
    let mon_chan = match monitor.get_command_channel() {
        Some(chan) => chan,
        None => {
            error!("cmonitor failed to start");
            token.cancel();
            return Err(io::Error::new(io::ErrorKind::Other, "cmonitor failed to start"));
        }
    };
    info!("cmonitor running");

    let (cs_shutdown_tx, mut cs_shutdown_rx) = oneshot::channel();
    let cs_config = config.clone();
    let cs_token = token.clone();
    tracker.spawn(async move {
        match command_server(cs_config, zpr.clone(), cs_token, mon_chan).await {
            Ok(()) => {
                info!("command server shut down");
            }
            Err(e) => {
                error!("command server shut down with error: {}", e);
            }
        }
        let _ = cs_shutdown_tx.send(());
    });


    loop {
        tokio::select! {
            _ = &mut cs_shutdown_rx => {
                info!("exiting due to command server shutdown");
                break;
            },
            _ = signal::ctrl_c() => {
                info!("exiting due to signal");
                token.cancel();
                break;
            }
        }
    }


    // wait for all subtasks to stop
    while let Some(_) = tracker.join_next().await {}

    // cleanup
    info!("cd preparing for exit");
    let _ = fs::remove_file(&config.socket_path); // don't care
    info!("cd shuts down");
    Ok(())
}
