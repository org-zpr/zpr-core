use zpr::vsapi::v1 as vsapi2;

use ipnet::IpNet;
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

const PARAM_ZPR_ADDR: &str = "zpr_addr";
const PARAM_AAA_PREFIX: &str = "aaa_prefix";

#[derive(Debug)]
pub struct VSConnectRequest {
    /// Connect will fail if this does not match policy.
    pub zpr_addr: IpAddr,
    pub aaa_prefix: IpNet,
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

                let mut vs_handle: Option<vsapi2::v_s_handle::Client> = None;

                // Then loop over commands.
                while let Some(cmd) = self.cmd_rx.recv().await {
                    match cmd {
                        VS2Command::Stop(deregister) => {
                            debug!(target: VS_RPC, "VSConn: stop");
                            if deregister && let Some(ref handle) = vs_handle {
                                let mut disconnect_request = handle.notify_disconnect_request();
                                let mut dnotice_bldr = disconnect_request.get().init_req();

                                // We are disconnecting "self" so we do not set a ZPR addr.

                                dnotice_bldr
                                    .set_reason_code(vsapi2::DisconnectReason::NodeShutdown);

                                debug!(target: VS_RPC, "VS-API -> notify_disconnect");
                                let disconnect_request_response =
                                    disconnect_request.send().promise.await?;
                                let ok_or_err = disconnect_request_response.get()?.get_res()?;
                                match ok_or_err.which()? {
                                    vsapi2::ok_or_error::Which::Ok(_) => {
                                        info!(target: VS_RPC, "VS API notify_disconnect succeeded");
                                    }
                                    vsapi2::ok_or_error::Which::Error(err_obj) => {
                                        let err_obj = err_obj?;
                                        let err = new_coded_error(err_obj);

                                        // There is no back channel for the Stop command so we just log the error.
                                        error!(
                                            target: VS_RPC,
                                            "VS API notify_disconnect failed: {:?}", err
                                        );
                                    }
                                }
                            }

                            break;
                        }

                        VS2Command::Connect(req, resp_tx) => {
                            debug!(target: VS_RPC, "VSConn: connect");
                            let resp = if vs_handle.is_some() {
                                Err(VSApiError::CommandFailed(
                                    "connect called but already connected to VS-API".to_string(),
                                ))
                            } else {
                                self.do_connect(&vs_service, req).await
                            };

                            let retval = match resp {
                                Ok(handle) => {
                                    info!(target: VS_RPC, "VS API connect succeeded");
                                    vs_handle = Some(handle);
                                    Ok(())
                                }
                                Err(e) => {
                                    error!(target: VS_RPC, "VS API connect failed: {:?}", e);
                                    Err(e)
                                }
                            };

                            if let Err(e) = resp_tx.send(retval) {
                                error!(target: VS_RPC, "failed to send connect response: {:?}", e);
                            }
                        }
                    }
                }
                info!(target: VS_RPC, "VSConn: exiting run loop");
                Ok::<(), VSApiError>(())
            })
            .await
    }

    pub fn handle(&self) -> VSConnHandle {
        VSConnHandle {
            cmd_tx: self.cmd_tx.clone(),
        }
    }

    async fn do_connect(
        &self,
        vs_service: &vsapi2::visa_service::Client,
        req: VSConnectRequest,
    ) -> Result<vsapi2::v_s_handle::Client, VSApiError> {
        let mut vs_request = vs_service.connect_request();

        let mut vscr_bldr = vs_request.get().init_req();
        vscr_bldr.set_cn(&self.node_cn);
        vscr_bldr.set_ctype(vsapi2::VSConnT::Reset);

        // We set two params: the zpr_address for the node and the aaa-prefix.
        let mut params_bldr = vscr_bldr.init_params(2);
        {
            let mut param0 = params_bldr.reborrow().get(0);
            param0.set_name(PARAM_ZPR_ADDR);
            match req.zpr_addr {
                IpAddr::V4(av4) => {
                    param0.set_ptype(vsapi2::ParamT::Ipv4);
                    param0.set_value(&av4.octets());
                }
                IpAddr::V6(av6) => {
                    param0.set_ptype(vsapi2::ParamT::Ipv6);
                    param0.set_value(&av6.octets());
                }
            }
        }
        {
            let mut param1 = params_bldr.reborrow().get(1);
            param1.set_ptype(vsapi2::ParamT::String);
            param1.set_name(PARAM_AAA_PREFIX);
            param1.set_value(&req.aaa_prefix.to_string().as_bytes());
        }

        debug!(target: VS_RPC, "VS-API -> connect");

        let vs_request_response = vs_request.send().promise.await?;
        let gate_or_error = vs_request_response.get()?.get_resp()?;

        let vs_gate_svc: vsapi2::v_s_gate::Client = match gate_or_error.which()? {
            vsapi2::result::Which::Ok(vs_gate_obj) => vs_gate_obj?,
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                return Err(new_coded_error(err_obj));
            }
        };

        // Now we have a gate we can request a challenge.
        let gate_request = vs_gate_svc.challenge_request();

        debug!(target: VS_RPC, "VS-API -> challenge");
        let gate_response = gate_request.send().promise.await?;
        let challenge = gate_response.get()?.get_challenge()?;

        let chal_data = challenge.get_bytes()?;
        let timestamp = unix_ts();

        let signed_payload = {
            let alg = challenge.get_alg()?;
            if alg != vsapi2::ChallengeAlg::RsaSha256Pkcs1v15 {
                return Err(VSApiError::CommandFailed(format!(
                    "unsupported challenge alg: {:?}",
                    alg
                )));
            }
            sign_payload(
                timestamp,
                &self.node_cn,
                chal_data,
                self.node_private_key.clone(),
            )
        };

        // Now authenticate with the gate.
        let mut gate_request = vs_gate_svc.authenticate_request();
        let mut auth_bldr = gate_request.get().init_cresp();
        auth_bldr.set_challenge(chal_data);
        auth_bldr.set_timestamp(timestamp);
        auth_bldr.set_bytes(&signed_payload);

        debug!(target: VS_RPC, "VS-API -> authenticate");
        let gate_response = gate_request.send().promise.await?;
        let handle_or_error = gate_response.get()?.get_res()?;

        let vs_handle_svc: vsapi2::v_s_handle::Client = match handle_or_error.which()? {
            vsapi2::result::Which::Ok(handle_obj) => handle_obj?,
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                return Err(new_coded_error(err_obj));
            }
        };

        // Ok we now have an authenticated handle to the VS.
        Ok(vs_handle_svc)
    }
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

/// Get a unix timestamp in seconds.
fn unix_ts() -> u64 {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Perform our node sign operation.
fn sign_payload(
    timestamp: u64,
    cn: &str,
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

/// Create a VSApiError::CodedError from a capn proto vsapi2::error::Reader.
fn new_coded_error(rdr: vsapi2::error::Reader) -> VSApiError {
    let err_code: u16 = match rdr.get_code() {
        Ok(c) => c.into(),
        Err(_) => u16::MAX,
    };
    let err_msg = match rdr.get_message() {
        Ok(m) => m.to_string().unwrap(),
        Err(_) => String::from("(no message)"),
    };
    let retry = rdr.get_retry_in();
    VSApiError::CodedError(err_code, err_msg, retry)
}
