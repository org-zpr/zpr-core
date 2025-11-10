use clap::Parser;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use tokio::task::JoinSet;
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

use libnode2::vsconn::{VSConn, VSConnectRequest};

/// ln2: test tool for libnode2
///
/// This will attempt to register as a node to the visa service.
///
#[derive(Parser, Debug)]
#[command(name = "ln2")]
#[command(version, verbatim_doc_comment)]
struct Args {
    /// Address of the visa service VS-API endpoint in 'HOST:PORT' format.
    #[arg(short = 'a', long, default_value = "[fd5a:5052::1]:5002")]
    vs_addr: String,

    /// Value to present to visa service as the node's common name.
    #[arg(short, long)]
    node_cn: String,

    /// Path to the nodes private key.
    #[arg(short, long)]
    private_key: PathBuf,

    /// Nodes ZPR address to present to the visa service.
    #[arg(long, default_value = "fd5a:5052:90de::1")]
    self_addr: String,

    /// Node AAA prefix to present to the visa service.
    #[arg(long, default_value = "fd5a:505s:90de:0:3000::/64")]
    aaa_prefix: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    enable_logging();

    let vs_sa: SocketAddr = args.vs_addr.parse().expect("failed to parse vs-addr");
    let node_zpr_addr: IpAddr = args.self_addr.parse().expect("failed to parse self_addr");

    let mut vsc = VSConn::new(
        8,
        vs_sa,
        args.node_cn,
        load_private_key(&args.private_key).expect("failed to load private key"),
    );

    let handle = vsc.handle();

    let local_set = tokio::task::LocalSet::new();
    let _local_set_guard = local_set.enter();
    let mut js = JoinSet::new();

    js.spawn_local(async move {
        info!("starting the VSConn");
        vsc.run().await.map_err(|e| {
            error!("VSConn run loop exited with error: {:?}", e);
            e
        })
    });

    js.spawn(async move {
        // Pause briefly to allow VSConn to start up.
        info!("allowing VSConn to start up...");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let request = VSConnectRequest {
            zpr_addr: node_zpr_addr,
            aaa_prefix: args.aaa_prefix,
        };

        info!("requesting a connect");
        match handle.connect(request).await {
            Ok(resp) => {
                info!("Connection response: {:?}", resp);
            }
            Err(e) => {
                error!("Connection failed: {:?}", e);
            }
        }

        info!("pausing before shutdown");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        info!("requesting a stop");
        match handle.stop(true).await {
            Ok(_) => {
                info!("stopped VSConn");
            }
            Err(e) => {
                error!("failed to stop VSConn: {:?}", e);
            }
        }

        Ok(())
    });

    local_set
        .run_until(async move {
            while let Some(res) = js.join_next().await {
                match res {
                    Ok(_) => (),
                    Err(e) => {
                        error!("task failed: {:?}", e);
                    }
                }
            }
        })
        .await;
}

fn load_private_key(keyfile: &Path) -> Result<PKey<Private>, Box<dyn std::error::Error>> {
    let key_data = fs::read(keyfile)?;
    let rsa = Rsa::private_key_from_pem(&key_data)?;
    let pkey = PKey::from_rsa(rsa)?;
    Ok(pkey)
}

pub fn enable_logging() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(LevelFilter::from_level(Level::DEBUG)),
    )
    .expect("setting default subscriber failed");
}
