mod command_server;
pub use crate::cd::command_server::command_server;

mod config;
pub use crate::cd::config::Config;

mod zpr;
pub use crate::cd::zpr::Zpr;

use std::{fs, io, sync::Arc};
use tokio::signal;
use tokio::sync::oneshot;
use tracing::{error, info};
use tracing_subscriber;

use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[tokio::main]
pub async fn tokio_main(config: Arc<Config>) -> io::Result<()> {
    tracing_subscriber::fmt::init();

    info!("cd starts");

    let tracker = TaskTracker::new();
    let token = CancellationToken::new();
    let zpr = Zpr::new();

    let (cs_shutdown_tx, mut cs_shutdown_rx) = oneshot::channel();
    let cs_config = config.clone();
    let cs_token = token.clone();
    tracker.spawn(async move {
        match command_server(cs_config, zpr.clone(), cs_token).await {
            Ok(()) => {
                info!("command server shut down");
            }
            Err(e) => {
                error!("command server shut down with error: {}", e);
            }
        }
        let _ = cs_shutdown_tx.send(());
    });

    // Now just waiting for an exit condition:
    tracker.close();
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

    tracker.wait().await;

    // cleanup
    info!("cd preparing for exit");
    let _ = fs::remove_file(&config.socket_path); // don't care
    info!("cd shuts down");
    Ok(())
}
