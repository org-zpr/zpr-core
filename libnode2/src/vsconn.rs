use vsapi::vs_capnp as vsapi2;

use core::time;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::*;
use tracing::*;

use crate::error::VSApiError;
use crate::logging::targets::VS_RPC;

#[derive(Debug)]
pub struct VSConnectRequest {
    pub cn: String,
    pub node_zpr_addr: IpAddr,
    pub node_private_rsa_key: PKey<Private>,
    pub aaa_prefix: String,
}

/// Returns no error if call to VSAPI authenticate was successful.
type VSConnectResponse = Result<(), VSApiError>;

// The async "commands" that can be sent into the running visa service client.
#[derive(Debug)]
enum VS2Command {
    /// Stop the local vs-api run loop, optionally de-register from the visa service first.
    Stop(bool),

    /// Run through the connect sequence. If connect succeeds the VSHandle is kept internally.
    Connect(VSConnectRequest, oneshot::Sender<VSConnectResponse>),
}

pub struct VSConn {
    cmd_tx: mpsc::Sender<VS2Command>,
    cmd_rx: mpsc::Receiver<VS2Command>,
    vs_addr: SocketAddr,
    node_cn: String,
    node_private_key: PKey<Private>,
}

#[derive(Clone)]
pub struct VSConnHandle {
    cmd_tx: mpsc::Sender<VS2Command>,
}

impl VSConn {
    pub fn new(
        buffer_size: usize,
        vs_addr: SocketAddr,
        node_cn: String,
        node_private_key: PKey<Private>,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(buffer_size);
        VSConn {
            cmd_tx,
            cmd_rx,
            vs_addr,
            node_cn,
            node_private_key,
        }
    }

    pub async fn run(&mut self) -> Result<(), VSApiError> {
        // First spin up a connection to the Capn Proto service on the VS.
        info!(target: VS_RPC, "VS RPC service connecting to {} (capnp)", self.vs_addr);

        let sock = tokio::net::TcpStream::connect(self.vs_addr).await?;
        sock.set_nodelay(true)?;

        let (reader, writer) = sock.into_split();

        let network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Client,
            capnp::message::ReaderOptions::new(),
        );

        let mut rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), None);

        let vs_service: vsapi2::visa_service::Client =
            rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);

        tokio::task::LocalSet::new()
            .run_until(async move {
                tokio::task::spawn_local(rpc_system);

                let mut vs_handle = None;

                // Then loop over commands.
                while let Some(cmd) = self.cmd_rx.recv().await {
                    match cmd {
                        VS2Command::Stop(deregister) => {}

                        VS2Command::Connect(req, resp_tx) => {
                            // Not sure what to do if we already have a handle. For now we error out.
                            if vs_handle.is_some() {
                                let cerr = VSApiError::CommandFailed(
                                    "connect called but already connected to VS-API".to_string(),
                                );
                                resp_tx.send(Err(cerr))?;
                                continue;
                            }

                            let mut vs_request = vs_service.connect_request();

                            let vscr_bldr = vs_request.get().init_req();
                            vscr_bldr.set_cn(&self.node_cn);
                            vscr_bldr.set_ctype(vsapi2::VSConnT::Reset);
                            // TODO: Set the params: (aaa-prefix, zpr-addr)

                            let vs_request_response = vs_request.send().promise.await?;

                            let gate_or_error = vs_request_response.get()?.get_resp()?;

                            let vs_gate_svc: vsapi2::v_s_gate::Client =
                                match gate_or_error.which()? {
                                    vsapi2::result::Which::Ok(vs_gate_obj) => vs_gate_obj?,
                                    vsapi2::result::Which::Error(err_obj) => {
                                        let err_code: u16 = err_obj?.get_code()?.into();
                                        let err_msg = err_obj?.get_message()?.to_string()?;
                                        let retry = err_obj?.get_retry_in();

                                        let cerr = VSApiError::CodedError(err_code, err_msg, retry);
                                        resp_tx.send(Err(cerr))?; // <-- error handling?
                                        continue;
                                    }
                                };

                            // Now we have a gate we can request a challenge.
                            let gate_request = vs_gate_svc.challenge_request();
                            let gate_response = gate_request.send().promise.await?;
                            let challenge = gate_response.get()?.get_challenge()?;

                            let chal_data = challenge.get_bytes()?;
                            let timestamp = unix_ts();

                            let signed_payload = {
                                let alg = challenge.get_alg()?;
                                // TODO: check the alg is as expected.

                                sign_payload(
                                    timestamp,
                                    self.node_cn,
                                    chal_data,
                                    self.node_private_key,
                                )
                            };

                            // Now authenticate with the gate.
                            let mut gate_request = vs_gate_svc.authenticate_request();
                            let auth_bldr = gate_request.get().init_cresp();
                            auth_bldr.set_challenge(chal_data);
                            auth_bldr.set_timestamp(timestamp);
                            auth_bldr.set_bytes(&signed_payload);

                            let gate_response = gate_request.send().promise.await?;
                            let handle_or_error = gate_response.get()?.get_res()?;

                            let vs_handle_svc: vsapi2::v_s_handle::Client =
                                match handle_or_error.which()? {
                                    vsapi2::result::Which::Ok(handle_obj) => handle_obj?,
                                    vsapi2::result::Which::Error(err_obj) => {
                                        let err_code: u16 = err_obj?.get_code()?.into();
                                        let err_msg = err_obj?.get_message()?.to_string()?;
                                        let retry = err_obj?.get_retry_in();

                                        let cerr = VSApiError::CodedError(err_code, err_msg, retry);
                                        resp_tx.send(Err(cerr))?; // <-- error handling?
                                        continue;
                                    }
                                };

                            // Ok we now have an authenticated handle to the VS.
                            vs_handle = Some(vs_handle_svc);

                            if let Err(e) = resp_tx.send(Ok(())) {
                                error!(target: VS_RPC, "failed to send connect response: {:?}", e);
                            }
                        }
                    }
                }

                Ok(())
            })
            .await;
        Ok(())
    }

    pub fn handle(&self) -> VSConnHandle {
        VSConnHandle {
            cmd_tx: self.cmd_tx.clone(),
        }
    }
}

fn unix_ts() -> u64 {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn sign_payload(
    timestamp: u64,
    cn: String,
    challenge_data: &[u8],
    private_key: PKey<Private>,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(cn.as_bytes());
    data.extend_from_slice(challenge_data);

    let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
    signer.update(&data).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    signature
}

impl VSConnHandle {
    // Push a command onto the command channel.
    async fn send_command(&self, cmd: VS2Command) -> Result<(), VSApiError> {
        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| VSApiError::ConnClosed)
    }

    pub async fn connect(&self, req: VSConnectRequest) -> Result<(), VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::Connect(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn stop(&self, deregister: bool) -> Result<(), VSApiError> {
        let cmd = VS2Command::Stop(deregister);
        self.send_command(cmd).await
    }
}
