use std::io;
use tokio::signal;
use tracing::info;

pub const VERSION: &str = "0.1.0";

#[tokio::main]
pub async fn tokio_main() -> io::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting ZPR node v{}", VERSION);
    info!("nothing to do...  ^C to exit.");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("exiting due to signal");
                break;
            }
        }
    }

    // cleanup
    info!("node preparing for exit");
    // ...
    info!("node shuts down");
    Ok(())
}
