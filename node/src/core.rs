use std::io;

use tracing::{error, info};

use tokio::signal;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::vs::VSConn;
use crate::vs::VSOutput::{PushedRevocation, PushedVisa};

use crate::vs::vss;

pub const VERSION: &str = "0.1.0";

const VS_OUTPUT_CHANNEL_SIZE: usize = 32;
const VSS_OUTPUT_CHANNEL_SIZE: usize = 32;

const DEFAULT_VSS_PORT: u16 = 8183;

/// CoreOpts is for debug options we want to pass to the node, but not include in
/// the config file.
#[derive(Debug, Clone)]
pub struct CoreOpts {
    /// Force the node to immediately open a connection to the visa service at the provided HOST:PORT.
    vsforceconnect: Option<String>,

    // Ovverride the default VSS listen address. Format 'ADDR:PORT'.
    vssforcelisten: Option<String>,
}

impl CoreOpts {
    pub fn new() -> CoreOpts {
        CoreOpts {
            vsforceconnect: None,
            vssforcelisten: None,
        }
    }

    pub fn set_vsforceconnect(&mut self, hostport: &str) {
        self.vsforceconnect = Some(hostport.to_string());
    }

    pub fn set_vssforcelisten(&mut self, hostport: &str) {
        self.vssforcelisten = Some(hostport.to_string());
    }
}

#[tokio::main]
pub async fn tokio_main(nconfig: config::Configuration, opts: CoreOpts) -> io::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting ZPR node v{}", VERSION);

    let ctoken = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let (cs_shutdown_tx, mut cs_shutdown_rx) = oneshot::channel();

    // This channel is for messages from the visa-support-service.
    let (vss_tx, mut vss_rx) = mpsc::channel(VSS_OUTPUT_CHANNEL_SIZE);

    // The visa support service normally is started up on the ZPR public address of the node.
    // But for debug, you can override that.
    let vss_addr = match opts.vssforcelisten {
        Some(addr) => addr,
        None => format!("[{}]:{}", nconfig.get_node_addr(), DEFAULT_VSS_PORT),
    };

    // Thread is detached when handle drops out of scope which is during a node shutdown.
    // In the future that may not always be the case so we will need a better way to deal with
    // this thrift server.
    let vss_addr_for_vss = vss_addr.clone();
    let _vss_handle = std::thread::spawn(move || {
        vss::start_vss_server(vss_tx, &vss_addr_for_vss);
    });

    let o_vsforceconnect = opts.vsforceconnect.is_some();

    // This force-connect thing makes it possible to have this connect to the visa service
    // during development.  I think this will go away or be refactored before version 1.0.
    // But to test this out, do something like:
    //
    //    start visa service:
    //    ./build/visaservice -c /path/to/config.yaml -p /path/to/a/policy.bin --issuer vs1 -l 127.0.0.1:31337 --verbose
    //
    //    then start the node:
    //    ./target/debug/node -f -c /path/to/config.toml --vsforceconnect 127.0.0.1:31337
    //
    if o_vsforceconnect {
        info!("DEBUG: force connect to visa service");

        let (tx, mut rx) = mpsc::channel(VS_OUTPUT_CHANNEL_SIZE);

        let vs_conn = VSConn::new(
            tx.clone(),
            &opts.vsforceconnect.unwrap(),
            &nconfig.get_cert_path(),
            &nconfig.get_key_path(),
            nconfig.get_node_addr(),
            &vss_addr,
        )?;
        for (k, v) in nconfig.get_claims() {
            vs_conn.add_claim(&k, &v);
        }

        let vs_ctoken = ctoken.clone();
        tasks.spawn(async move {
            let init_ok = match vs_conn.initialize(None) {
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

        // Fire up another task to watch the output channel...
        let dbg_ctoken = ctoken.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
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
    } else {
        info!("nothing to do...  ^C to exit");
    }

    loop {
        //  main node runloop
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("exiting due to signal");
                ctoken.cancel();
                break;
            }
            _ = &mut cs_shutdown_rx => {
                info!("visa service exited");
                ctoken.cancel();
                break;
            }
            Some(vss_msg) = vss_rx.recv() => {
                info!("VSConn::run received VSS message: {:?}", vss_msg);
            }
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
