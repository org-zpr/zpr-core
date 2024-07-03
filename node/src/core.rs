use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::signal;
use tracing::{info, error};


use tokio::task::JoinSet;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::vs::VSConn;

pub const VERSION: &str = "0.1.0";


#[derive(Debug, Clone)]
pub struct CoreOpts {
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


    if opts.vsforceconnect.is_some() {
        info!("DEBUG: force connect to visa service");

        let v = String::from("fc00:3001:abd5::3836");

        // The node address is one of the claims.
        let node_addr: IpAddr = match nconfig.get_claim("zpr.addr") {
            Some(s) => {
                match s.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        info!("HEY HEY v is equal to {}", v);
                        error!("failed to parse zpr.addr claim: {}: {}", s, e);
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "failed to parse zpr.addr claim"));
                    }
                }
            }
            None => {
                error!("zpr.addr claim not found in config");
                return Err(io::Error::new(io::ErrorKind::InvalidData, "zpr.addr claim not found in config"));
            }
        };


        let vs_conn = VSConn::new(&opts.vsforceconnect.unwrap(), &nconfig.get_cert_path(), &nconfig.get_key_path(), node_addr)?;
        for (k, v) in nconfig.get_claims() {
            vs_conn.add_claim(&k, &v);
        }


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
        

    } else {
        info!("nothing to do...  ^C to exit");
    }

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("exiting due to signal");
                ctoken.cancel();
                break;
            }
            _ = &mut cs_shutdown_rx => {
                info!("visa service exited");
                break;
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
