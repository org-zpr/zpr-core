use std::io;
use std::net::SocketAddr;

use tracing::{error, info};

use tokio::signal;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config;

use crate::zdp::server::ZDPServer;
use libnode::vsconn::{new_node_agent, VSConn, VSOutput};
use libnode::vss;

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

    let another_opts = opts.clone();

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
        vs_force_connect(
            &vss_addr,
            &mut tasks,
            &nconfig,
            another_opts,
            ctoken.clone(),
            cs_shutdown_tx,
        )
        .await?;
    } else {
        info!("nothing to do...  ^C to exit");
    }

    if nconfig.is_dock_enabled() {
        info!("setting up dock at {}", nconfig.get_dock_listen_addr());
        let zctok = ctoken.clone();

        let listen_addr: SocketAddr = match nconfig.get_dock_listen_addr().parse() {
            Ok(addr) => addr,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid listen address",
                ));
            }
        };
        let zserver = ZDPServer::new(
            &listen_addr,
            nconfig.get_noise_private_key(),
            &nconfig.get_noise_cert_path(),
            &nconfig.get_ca_cert_path(),
        );
        tasks.spawn(async move {
            match zserver.run(zctok).await {
                Ok(_) => {
                    info!("dock server exits without error");
                }
                Err(e) => {
                    error!("dock server exits with error: {}", e);
                }
            }
        });
    } else {
        info!("dock is not enabled");
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
                match vss_msg {
                    vss::VSSMsg::PolicyInstall(pi) => {
                        info!("VSS policy install: {:?}", pi);
                    }
                    vss::VSSMsg::PushedVisa(v) => {
                        info!("VSS pushed visa: issuer_id={:?}", v.issuer_id);
                    }
                    _ => {
                        info!("VSConn::run received VSS message: {:?}", vss_msg);
                    }
                }
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

async fn vs_force_connect(
    vss_addr: &str,
    tasks: &mut JoinSet<()>,
    nconfig: &config::Configuration,
    opts: CoreOpts,
    ctoken: CancellationToken,
    cs_shutdown_tx: oneshot::Sender<()>,
) -> io::Result<()> {
    info!("DEBUG: force connect to visa service");

    let (tx, mut rx) = mpsc::channel(VS_OUTPUT_CHANNEL_SIZE);

    let node_agent = new_node_agent(&nconfig.get_node_addr(), nconfig.get_node_name(), &nconfig.get_claims());

    let vs_conn = VSConn::new(
        node_agent,
        tx.clone(),
        &opts.vsforceconnect.unwrap(),
        &nconfig.get_rsa_cert_path(),
        &nconfig.get_rsa_private_key_path(),
        &nconfig.get_node_addr(),
        Some(vss_addr),
    )
    .or_else(|e| {
        error!("VSConn::new failed: {}", e);
        Err(io::Error::new(io::ErrorKind::Other, "VSConn::new failed"))
    })?;

    let vs_ctoken = ctoken.clone();
    tasks.spawn(async move {
        match vs_conn.run(vs_ctoken).await {
            Ok(_) => {
                info!("visa service exits without error");
            }
            Err(e) => {
                error!("visa service exits with error: {}", e);
            }
        }

        let _ = cs_shutdown_tx.send(()); // visa service exits.
    });

    // Now we fire up another task to watch for output messages from
    // the visa service.
    let dbg_ctoken = ctoken.clone();
    tasks.spawn(async move {
        loop {
            tokio::select! {
                Some(vs_output) = rx.recv() => {
                    match vs_output {
                      VSOutput::PingSuccess(config_id, policy_version) => {
                          info!("*=> PingSuccess: config={} policy={}", config_id, policy_version);
                      },
                      VSOutput::VisaResponse(r) => {
                          info!("*=> VisaResponse: {:?}", r);
                      },
                      VSOutput::ConnectResponse(r) => {
                        info!("*=> ConnectResponse: {:?}", r);
                      }
                      VSOutput::AgentDisconnect(r) => {
                        info!("*=> AgentDisconnect: {:?}", r);
                      }
                    }
                }
                _ = dbg_ctoken.cancelled() => {
                    break;
                }
            }
        }
    });

    Ok(())
}
