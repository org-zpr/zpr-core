use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use tokio::sync::mpsc::{self, Sender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use std::sync::{Arc, Mutex};

use tracing::info;

pub use crate::cd::zpr::{ConfigState, Zpr};
use crate::cd::config::CryptoConfig;

pub use crate::zdp::client;

pub enum Command {
    Connect(String),    // takes configuration name
    Disconnect(String), // takes configuration name
}

#[derive(Debug, Clone)]
pub struct CMonitor {
    shared: Arc<CMShared>,
}

#[derive(Debug)]
pub struct CMShared {
    state: Mutex<CMState>,
}

#[derive(Debug)]
pub struct CMState {
    cmd_tx: Option<Sender<Command>>,
    zpr: Zpr,
    cli: ClientState,
}

#[derive(Debug, Clone)]
struct ClientState {
    client: Option<ClientRec>,
}

#[derive(Debug, Clone)]
struct ClientRec {
    addr: String, // form of 'host:port'
    config_name: String,
    ctok: CancellationToken,
    client_handle: Arc<JoinHandle<io::Result<()>>>,
}

impl CMonitor {
    pub fn new(zpr: Zpr) -> CMonitor {
        CMonitor {
            shared: Arc::new(CMShared {
                state: Mutex::new(CMState {
                    cmd_tx: None,
                    zpr,
                    cli: ClientState { client: None },
                }),
            }),
        }
    }

    /// Get the channel for sending commands into this monitor.
    /// The channel is created early in the start function.
    pub fn get_command_channel(&self) -> Option<Sender<Command>> {
        let state = self.shared.state.lock().unwrap();
        match &state.cmd_tx {
            Some(tx) => Some(tx.clone()),
            None => None,
        }
    }

    /// Starts the monitor does not return until it is cancelled or an unrecoverable error occurs.
    pub async fn start(&mut self, token: CancellationToken) -> io::Result<()> {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        {
            let mut state = self.shared.state.lock().unwrap();
            state.cmd_tx = Some(cmd_tx);
        }
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    info!("CMonitor - cancelled");
                    break;
                }
                Some(cmd) =cmd_rx.recv() => {
                    match cmd {
                        Command::Connect(configuration) => {
                            match self.do_connect(configuration).await {
                                Ok(()) => {},
                                Err(e) => {
                                    info!("CMonitor - do_connect error: {}", e);
                                }
                            }
                        }
                        Command::Disconnect(configuration) => {
                            match self.do_disconnect(configuration).await {
                                Ok(()) => {},
                                Err(e) => {
                                    info!("CMonitor - do_disconnect error: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // In the future a single adapter could have multiple active client
    // connections (to different ZPR nets).  For now we support just one.
    async fn do_connect(&mut self, configuration: String) -> io::Result<()> {
        info!("CMonitor - do_connect - config = {}", configuration);

        let zpr: Zpr;
        let addr_port: String;
        let crypto: CryptoConfig;
        let old_cli: Option<ClientRec>;
        {
            let state = self.shared.state.lock().unwrap();
            zpr = state.zpr.clone();
            addr_port = match zpr.get_connect_string(&configuration) {
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "No connection string found",
                    ));
                }
                Some(ap) => ap,
            };
            crypto = match zpr.get_crypto_config(&configuration) {
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "No crypto config found",
                    ));
                }
                Some(c) => c,
            };
            old_cli = state.cli.client.clone();
        }

        match old_cli {
            Some(crec) => {
                if crec.addr == addr_port {
                    info!("already connected to {}", addr_port);
                    return Ok(());
                }
                info!("disconnecting from {}", crec.addr);

                // TODO: Possibly this state value should live here in cmonitor?
                let _ = zpr.set_status(&crec.config_name, ConfigState::Disconnecting);
                crec.ctok.cancel();
                // TODO: Hmm, I can't seem to join() the handle
                drop(crec.client_handle);

                let _ = zpr.set_status(&crec.config_name, ConfigState::Disconnected);
                // get the lock again and update state
                let mut state = self.shared.state.lock().unwrap();
                state.cli.client = None;
            }
            None => {} // fine
        }

        let _ = zpr.set_status(&configuration, ConfigState::Connecting);

        // placholder code

        let ctok = CancellationToken::new();
        let passed_ctok = ctok.clone();
        let dock_addr: SocketAddr = match addr_port.parse() {
            Ok(addr) => addr,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid dock address: {}", e),
                ));
            }
        };

        let handle: JoinHandle<io::Result<()>> = tokio::spawn(async move {
            let cli = client::ZDPClient::new(&dock_addr, crypto);
            cli.run(passed_ctok).await // blocking, long running
        });
        // well hopefully that launched!

        let _ = zpr.set_status(&configuration, ConfigState::Connected(Instant::now()));

        let mut state = self.shared.state.lock().unwrap();
        state.cli.client = Some(ClientRec {
            addr: addr_port.clone(),
            config_name: configuration.clone(),
            ctok: ctok.clone(),
            client_handle: Arc::new(handle),
        });

        Ok(())
    }

    async fn do_disconnect(&mut self, configuration: String) -> io::Result<()> {
        info!("CMonitor - do_disconnect - config = {}", configuration);

        let zpr: Zpr;
        let old_cli: Option<ClientRec>;
        {
            let state = self.shared.state.lock().unwrap();
            zpr = state.zpr.clone();
            old_cli = state.cli.client.clone();
        }

        match old_cli {
            Some(crec) => {
                if crec.config_name != configuration {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Not connected to {}", configuration),
                    ));
                }
                info!("disconnecting from {}", crec.addr);
                let _ = zpr.set_status(&crec.config_name, ConfigState::Disconnecting);
                crec.ctok.cancel();
                drop(crec.client_handle);
                let _ = zpr.set_status(&crec.config_name, ConfigState::Disconnected);
                let mut state = self.shared.state.lock().unwrap();
                state.cli.client = None;
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Not connected to {}", configuration),
                ));
            }
        }
        Ok(())
    }
}
