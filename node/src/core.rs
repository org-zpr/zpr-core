use std::io;

use tracing::{error, info};

use tokio::signal;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::vs::VSConn;
use crate::vs::VSOutput::{PushedRevocation, PushedVisa};

pub const VERSION: &str = "0.1.0";

const VS_OUTPUT_CHANNEL_SIZE: usize = 32;

/// CoreOpts is for debug options we want to pass to the node, but not include in
/// the config file.
#[derive(Debug, Clone)]
pub struct CoreOpts {
    /// Force the node to immediately open a connection to the visa service at the provided HOST:PORT.
    vsforceconnect: Option<String>,
}

impl CoreOpts {
    pub fn new() -> CoreOpts {
        CoreOpts {
            vsforceconnect: None,
        }
    }

    pub fn set_vsforceconnect(&mut self, hostport: &str) {
        self.vsforceconnect = Some(hostport.to_string());
    }
}

#[tokio::main]
pub async fn tokio_main(nconfig: config::Configuration, opts: CoreOpts) -> io::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting ZPR node v{}", VERSION);

    let ctoken = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let (cs_shutdown_tx, mut cs_shutdown_rx) = oneshot::channel();

    let o_vsforceconnect = opts.vsforceconnect.is_some();

    if o_vsforceconnect {
        info!("DEBUG: force connect to visa service");

        let (tx, mut rx) = mpsc::channel(VS_OUTPUT_CHANNEL_SIZE);

        let vs_conn = VSConn::new(
            tx.clone(),
            &opts.vsforceconnect.unwrap(),
            &nconfig.get_cert_path(),
            &nconfig.get_key_path(),
            nconfig.get_node_addr(),
        )?;
        for (k, v) in nconfig.get_claims() {
            vs_conn.add_claim(&k, &v);
        }
        let another_vs_conn = vs_conn.clone();

        let vs_ctoken = ctoken.clone();
        tasks.spawn(async move {
            let init_ok = match vs_conn.initialize() {
                Ok(_) => {
                    info!("visa service initialized OK");
                    true
                }
                Err(e) => {
                    error!("failed to connect to visa service: {}", e);
                    false
                }
            };
            if init_ok {
                match vs_conn.run(vs_ctoken).await {
                    Ok(_) => {
                        info!("visa service exits without error");
                    }
                    Err(e) => {
                        error!("visa service exits with error: {}", e);
                    }
                }
            }
            let _ = cs_shutdown_tx.send(()); // visa service exits.
        });

        // XXXX ---------------------- DEBUG
        use tokio::time::{self, Duration};
        let dbg_ctoken = ctoken.clone();

        tasks.spawn(async move {
            let mut interval = time::interval(Duration::from_millis(3000));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let n: f64 = rand::random();  // <--- TODO: remove RAND crate when done testing
                        if n < 0.33 {
                            match another_vs_conn.request_visa().await {
                                Ok(_) => {
                                    info!("DEBUG: visa request sent");
                                }
                                Err(e) => {
                                    error!("DEBUG: failed to get visa: {}", e);
                                }
                            }
                        } else if n < 0.66 {
                            match another_vs_conn.authorize_connect().await {
                                Ok(_) => {
                                    info!("DEBUG: authorized connect");
                                }
                                Err(e) => {
                                    error!("DEBUG: failed to authorize connect: {}", e);
                                }
                            }
                        } else {
                            match another_vs_conn.agent_disconnect().await {
                                Ok(_) => {
                                    info!("DEBUG: agent disconnect");
                                }
                                Err(e) => {
                                    error!("DEBUG: failed to agent disconnect: {}", e);
                                }
                            }
                        }
                    }
                    Some(vs_output) = rx.recv() => {
                        match vs_output {
                            PushedVisa ( visa ) => {
                                info!("DEBUG: visa received, issuer_id: {}", visa.issuer_id);
                            }
                            PushedRevocation ( revocation ) => {
                                info!("DEBUG: revocation received, issuer_id: {}", revocation.issuer_id);
                            }
                        }
                    }
                    _ = dbg_ctoken.cancelled() => {
                        break;
                    }
                }
            }
        });
        // XXXX ---------------------- DEBUG ^^^^^
    } else {
        info!("nothing to do...  ^C to exit");
    }

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("exiting due to signal");
            ctoken.cancel();
        }
        _ = &mut cs_shutdown_rx => {
            info!("visa service exited");
        }
    }

    info!("node preparing for exit");

    // and wait for all tasks to die
    while let Some(_) = tasks.join_next().await {}

    // cleanup
    // ...

    info!("node shuts down");
    Ok(())
}
