use zpr::vsapi::v1 as vsapi2;

use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_rustls::TlsConnector;
use tokio_util::compat::*;
use tracing::*;

use crate::error::VSApiError;
use crate::logging::targets::VS_RPC;
use zpr::vsapi_types::{
    ConnectRequest, Connection, DenyCode, DisconnectReason, PacketDesc, Visa, VisaOp,
};
use zpr::write_to::WriteTo;

const PARAM_ZPR_ADDR: &str = "zpr_addr";

const LIFECYCLE_EVENT_BUFFER_SIZE: usize = 64;

const VSAPI_PING_INTERVAL: Duration = Duration::from_secs(5);
const VSAPI_MAX_PING_FAILURES: u32 = 2;

#[derive(Debug)]
pub struct VSConnectRequest {
    /// Connect will fail if this does not match policy.
    pub zpr_addr: IpAddr,
}

#[derive(Debug)]
pub struct VSVisaRequest {
    pub pdesc: PacketDesc,
    pub previous_id: Option<u64>,
}

#[derive(Debug)]
pub enum VSVisaDecision {
    Allowed(Visa),
    Denied(DenyCode),
}

#[derive(Debug)]
pub struct VSDisconnectNotice {
    /// None = node itself, Some = specific adapter
    pub zpr_addr: Option<IpAddr>,
    pub reason: DisconnectReason,
}

/// Returns no error if call to VSAPI authenticate was successful.
type VSConnectResponse = Result<(), VSApiError>;
type VSVisaResponse = Result<VSVisaDecision, VSApiError>;
type VSRegisterVssResponse = Result<Vec<VisaOp>, VSApiError>;
type VSAuthorizeConnectResponse = Result<Connection, VSApiError>;
type VSNotifyDisconnectResponse = Result<(), VSApiError>;
type VSPingResponse = Result<(), VSApiError>;

// The async "commands" that can be sent into the running visa service client.
#[derive(Debug)]
enum VS2Command {
    /// Stop the local vs-api run loop, optionally de-register from the visa service first.
    Stop(bool),

    /// Run through the connect sequence. If connect succeeds the VSHandle is kept internally.
    Connect(VSConnectRequest, oneshot::Sender<VSConnectResponse>),

    VisaRequest(VSVisaRequest, oneshot::Sender<VSVisaResponse>),

    RegisterVss(SocketAddr, oneshot::Sender<VSRegisterVssResponse>),

    AuthorizeConnect(ConnectRequest, oneshot::Sender<VSAuthorizeConnectResponse>),

    NotifyDisconnect(
        VSDisconnectNotice,
        oneshot::Sender<VSNotifyDisconnectResponse>,
    ),

    Ping(oneshot::Sender<VSPingResponse>),
}

#[derive(Debug, Clone, Copy)]
pub enum VSConnLifecycleEvent {
    /// Means we have established a network connection to the Cap'n Proto service.
    RunLoopStarts,

    /// Means that the node connect-request was successful.
    ConnectedToVsApi,

    /// When run loop has stopped.
    RunLoopExits,
}

pub struct VSConn {
    cmd_tx: mpsc::Sender<VS2Command>,
    cmd_rx: mpsc::Receiver<VS2Command>,
    vs_addr: SocketAddr,
    node_cn: String,
    node_private_key: PKey<Private>,
    life_tx: broadcast::Sender<VSConnLifecycleEvent>,
    connect_count: u64,
}

#[derive(Clone)]
pub struct VSConnHandle {
    cmd_tx: mpsc::Sender<VS2Command>,
}

struct VSCommandState {
    vs_service: vsapi2::visa_service::Client,
    vs_handle: Option<vsapi2::v_s_handle::Client>,
}

impl VSCommandState {
    pub fn new(vs_service: vsapi2::visa_service::Client) -> Self {
        VSCommandState {
            vs_service,
            vs_handle: None,
        }
    }

    /// This is used synchronously in the command handlers to check if
    /// we are currently connected to the VS API.
    fn is_connected(&self) -> bool {
        self.vs_handle.is_some()
    }
}

impl VSConn {
    /// Create a new VSConn.
    ///
    /// Use [VSConn::subscribe_lifecycle_events] to get a receiver for lifecycle events such as when
    /// we connect to the VS API and when the run loop starts or exits.
    ///
    /// `buffer_size` determines how many commands can be buffered to send to the run loop before
    /// [VSConnHandle] starts blocking.
    pub fn new(
        buffer_size: usize,
        vs_addr: SocketAddr,
        node_cn: String,
        node_private_key: PKey<Private>,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(buffer_size);
        let (life_tx, _) = broadcast::channel(LIFECYCLE_EVENT_BUFFER_SIZE);
        VSConn {
            cmd_tx,
            cmd_rx,
            vs_addr,
            node_cn,
            node_private_key,
            life_tx,
            connect_count: 0,
        }
    }

    /// Subscribe to recieve broadcast lifecycle events from this VSConn.
    pub fn subscribe_lifecycle_events(&self) -> broadcast::Receiver<VSConnLifecycleEvent> {
        self.life_tx.subscribe()
    }

    /// Best-effort send a lifecycle event, just log if the send fails (no receivers).
    fn send_lifecycle_event(&self, event: VSConnLifecycleEvent) {
        match self.life_tx.send(event) {
            Ok(_) => debug!(target: VS_RPC, "sent lifecycle event: {:?}", event),
            Err(e) => {
                info!(target: VS_RPC, "failed to send lifecycle event: {:?}: {:?}", event, e);
            }
        }
    }

    /// Just like [VSConn::run] but will attempt to reconnect if the connection to the VS is lost, after
    /// pausing for `reconnect_after`.
    /// Sending a [VS2Command::Stop] will break the reconnect loop and cause this to return.
    pub async fn run_with_reconnect(
        &mut self,
        reconnect_after: Duration,
    ) -> Result<(), VSApiError> {
        loop {
            match self.run().await {
                Ok(_) => {
                    break;
                }
                Err(e) => {
                    error!(target: VS_RPC, "VSConn: run loop exited with error: {:?}", e);
                    info!(target: VS_RPC, "VSConn: reconnecting in {} seconds...", reconnect_after.as_secs());
                    tokio::time::sleep(reconnect_after).await;
                }
            }
        }
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), VSApiError> {
        // First spin up a connection to the Capn Proto service on the VS.
        info!(target: VS_RPC, "VS RPC service connecting to {} (capnp)", self.vs_addr);

        let sock = tokio::net::TcpStream::connect(self.vs_addr).await?;
        sock.set_nodelay(true)?;

        let connector = tls_connect();
        let tls = connector.connect(self.vs_addr.ip().into(), sock).await?;
        let (reader, writer) = tokio::io::split(tls);
        debug!(target: VS_RPC, "VS RPC service connected to {} (TLS)", self.vs_addr);

        let network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Client,
            capnp::message::ReaderOptions::new(),
        );

        let mut rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), None);

        let vs_service: vsapi2::visa_service::Client =
            rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);

        let mut cmd_state = VSCommandState::new(vs_service);

        tokio::task::LocalSet::new()
            .run_until(async move {
                tokio::task::spawn_local(rpc_system);

                self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopStarts);
                //let mut ping_interval = tokio::time::interval(VSAPI_PING_INTERVAL);

                let ping_timeout = tokio::time::sleep(VSAPI_PING_INTERVAL);
                tokio::pin!(ping_timeout);
                let mut ping_failures = 0;

                // Then loop over commands and periodically ping.
                loop {
                    tokio::select! {
                        // If we get a command, handle it.
                        cmd = self.cmd_rx.recv() => {
                            match cmd {
                                Some(cmd) => {
                                    let is_stop_cmd = matches!(cmd, VS2Command::Stop(_));
                                    match self.handle_command(&mut cmd_state, cmd).await {
                                        Ok(_) => {}
                                        Err(e) => {
                                            error!(target: VS_RPC, "VSConn: handle_command error: {:?}", e);
                                            self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopExits);
                                            return Err(e.into());
                                        }
                                    };
                                    if is_stop_cmd {
                                        break;
                                    }
                                }
                                None => {
                                    info!(target: VS_RPC, "VSConn: command channel closed, exiting run loop");
                                    // TODO: What is the cause here? Is this an error or just an exit?
                                    break;
                                }
                            }
                        }

                        // If the ping interval elapses, do a ping (not implemented yet).
                        () = &mut ping_timeout => {
                            if !cmd_state.is_connected() {
                                // Not connected, just reset the ping timer.
                                ping_timeout.as_mut().reset(tokio::time::Instant::now() + VSAPI_PING_INTERVAL);
                                continue;
                            }
                            match self.do_ping(cmd_state.vs_handle.as_ref().unwrap()).await {
                                Ok(_) => {
                                    trace!(target: VS_RPC, "VSConn: ping successful");
                                    ping_failures = 0;
                                    ping_timeout.as_mut().reset(tokio::time::Instant::now() + VSAPI_PING_INTERVAL);
                                }
                                Err(e) => {
                                    ping_failures += 1;
                                    warn!(target: VS_RPC, "VSConn: ping error (count = {ping_failures}): {:?}", e);
                                    if ping_failures >= VSAPI_MAX_PING_FAILURES {
                                        error!(target: VS_RPC, "VSConn: maximum ping failures reached, exiting run loop");
                                        self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopExits);
                                        return Err(VSApiError::Timeout("ping".to_string()).into());
                                    }
                                    ping_timeout.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(1));
                                }
                            }
                        }
                    }
                }

                info!(target: VS_RPC, "VSConn: exiting run loop (non-error)");
                self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopExits);
                Ok::<(), VSApiError>(())
            })
            .await
    }

    pub fn handle(&self) -> VSConnHandle {
        VSConnHandle {
            cmd_tx: self.cmd_tx.clone(),
        }
    }

    async fn handle_command(
        &mut self,
        cmd_state: &mut VSCommandState,
        cmd: VS2Command,
    ) -> Result<(), VSApiError> {
        match cmd {
            VS2Command::Stop(deregister) => {
                debug!(target: VS_RPC, "VSConn: stop");
                if deregister && let Some(ref handle) = cmd_state.vs_handle {
                    let mut disconnect_request = handle.notify_disconnect_request();
                    let mut dnotice_bldr = disconnect_request.get().init_req();

                    // We are disconnecting "self" so we do not set a ZPR addr.

                    dnotice_bldr.set_reason_code(vsapi2::DisconnectReason::NodeShutdown);

                    debug!(target: VS_RPC, "VS-API -> notify_disconnect");
                    let disconnect_request_response = disconnect_request.send().promise.await?;
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
                Ok(())
            }

            VS2Command::Connect(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: connect");
                let resp = if cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "connect called but already connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_connect(&cmd_state.vs_service, req).await
                };

                let retval = match resp {
                    Ok(handle) => {
                        info!(target: VS_RPC, "VS API connect succeeded");
                        cmd_state.vs_handle = Some(handle);
                        self.connect_count = self.connect_count.saturating_add(1);
                        self.send_lifecycle_event(VSConnLifecycleEvent::ConnectedToVsApi);
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
                Ok(())
            }

            VS2Command::VisaRequest(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: visa_request");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_visa_request(cmd_state.vs_handle.as_ref().unwrap(), req)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send visa_request response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::RegisterVss(saddr, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: register_vss");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_register_vss(cmd_state.vs_handle.as_ref().unwrap(), saddr)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send register_vss response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::AuthorizeConnect(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: authorize_connect");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_authorize_connect(cmd_state.vs_handle.as_ref().unwrap(), req)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send authorize_connect response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::NotifyDisconnect(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: notify_disconnect");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_notify_disconnect(cmd_state.vs_handle.as_ref().unwrap(), req)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send notify_disconnect response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::Ping(resp_tx) => {
                debug!(target: VS_RPC, "VSConn: ping");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_ping(cmd_state.vs_handle.as_ref().unwrap()).await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send ping response: {:?}", e);
                }
                Ok(())
            }
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

        let ctype = if self.connect_count > 0 {
            vsapi2::VSConnT::Reconnect
        } else {
            vsapi2::VSConnT::Reset
        };
        vscr_bldr.set_ctype(ctype);

        // We set one param: the zpr_address for the node.
        let mut params_bldr = vscr_bldr.init_params(1);
        {
            let mut param0 = params_bldr.reborrow().get(0);
            param0.set_name(PARAM_ZPR_ADDR);
            match req.zpr_addr {
                IpAddr::V4(av4) => {
                    param0.set_ptype(vsapi2::ParamT::Ipv4);
                    param0.set_value_data(&av4.octets());
                }
                IpAddr::V6(av6) => {
                    param0.set_ptype(vsapi2::ParamT::Ipv6);
                    param0.set_value_data(&av6.octets());
                }
            }
        }

        debug!(target: VS_RPC, "VS-API -> connect (type = {:?})", ctype);

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

    async fn do_visa_request(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: VSVisaRequest, // TODO: VSVisaRequest should use a PacketDesc from vs-dt, then implement write_to on it.
    ) -> Result<VSVisaDecision, VSApiError> {
        let mut vr_request = vs_h.visa_request_request();
        let mut vrr_bldr = vr_request.get().init_req();
        vrr_bldr.set_previous_id(0);
        let mut pd_bldr = vrr_bldr.init_packet();
        req.pdesc.write_to(&mut pd_bldr);
        let vr_response = vr_request.send().promise.await?;
        let allow_deny_error = vr_response.get()?.get_resp()?;

        match allow_deny_error.which()? {
            vsapi2::visa_response::Which::Allow(v) => {
                let cp_visa = v?;
                let visa = Visa::try_from(cp_visa)?;
                Ok(VSVisaDecision::Allowed(visa))
            }
            vsapi2::visa_response::Which::Deny(dcode) => {
                let dcode = dcode?;
                let deny_code = DenyCode::from(dcode);
                Ok(VSVisaDecision::Denied(deny_code))
            }
            vsapi2::visa_response::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(new_coded_error(err_obj))
            }
        }
    }

    async fn do_authorize_connect(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: ConnectRequest,
    ) -> Result<Connection, VSApiError> {
        let mut ac_request = vs_h.authorize_connect_request();
        let mut cr_bldr = ac_request.get().init_req();
        req.write_to(&mut cr_bldr);

        debug!(target: VS_RPC, "VS-API -> authorize_connect");
        let ac_response = ac_request.send().promise.await?;
        let conn_or_error = ac_response.get()?.get_resp()?;

        match conn_or_error.which()? {
            vsapi2::result::Which::Ok(conn) => {
                let conn = conn?;
                let connection = Connection::try_from(conn)?;
                Ok(connection)
            }
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(new_coded_error(err_obj))
            }
        }
    }

    async fn do_notify_disconnect(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: VSDisconnectNotice,
    ) -> Result<(), VSApiError> {
        let mut nd_request = vs_h.notify_disconnect_request();
        let mut dn_bldr = nd_request.get().init_req();

        if let Some(addr) = req.zpr_addr {
            let mut addr_bldr = dn_bldr.reborrow().init_zpr_addr();
            addr.write_to(&mut addr_bldr);
        }
        dn_bldr.set_reason_code(req.reason.into());

        debug!(target: VS_RPC, "VS-API -> notify_disconnect");
        let nd_response = nd_request.send().promise.await?;
        let ok_or_err = nd_response.get()?.get_res()?;

        match ok_or_err.which()? {
            vsapi2::ok_or_error::Which::Ok(_) => Ok(()),
            vsapi2::ok_or_error::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(new_coded_error(err_obj))
            }
        }
    }

    async fn do_register_vss(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        saddr: SocketAddr,
    ) -> Result<Vec<VisaOp>, VSApiError> {
        let mut rvs_request = vs_h.register_vss_request();
        let mut saddr_bldr = rvs_request.get().init_addr();
        saddr_bldr.set_port(saddr.port());

        let mut ip_bldr = saddr_bldr.init_addr();
        saddr.ip().write_to(&mut ip_bldr);

        let rvs_response = rvs_request.send().promise.await?;
        let ops_or_error = rvs_response.get()?.get_res()?;

        match ops_or_error.which()? {
            vsapi2::result::Which::Ok(ops_list) => {
                let ops_list = ops_list?;
                let mut visa_ops = Vec::new();
                for i in 0..ops_list.len() {
                    let cp_visa_op = ops_list.get(i);
                    let visa_op = VisaOp::try_from(cp_visa_op)?;
                    visa_ops.push(visa_op);
                }
                Ok(visa_ops)
            }
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(new_coded_error(err_obj))
            }
        }
    }

    async fn do_ping(&self, vs_h: &vsapi2::v_s_handle::Client) -> Result<(), VSApiError> {
        let ping_request = vs_h.ping_request();
        trace!(target: VS_RPC, "VS-API -> ping");
        let ping_response = ping_request.send().promise.await?;
        let ok_or_err = ping_response.get()?.get_res()?;

        match ok_or_err.which()? {
            vsapi2::ok_or_error::Which::Ok(_) => Ok(()),
            vsapi2::ok_or_error::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(new_coded_error(err_obj))
            }
        }
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

    pub async fn visa_request(&self, req: VSVisaRequest) -> Result<VSVisaDecision, VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::VisaRequest(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn register_vss(&self, saddr: SocketAddr) -> Result<Vec<VisaOp>, VSApiError> {
        if saddr.port() == 0 {
            return Err(VSApiError::CommandFailed(
                "cannot register VSS with port 0".to_string(),
            ));
        }
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::RegisterVss(saddr, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn authorize_connect(&self, req: ConnectRequest) -> Result<Connection, VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::AuthorizeConnect(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn notify_disconnect(&self, req: VSDisconnectNotice) -> Result<(), VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::NotifyDisconnect(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn ping(&self) -> Result<(), VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::Ping(resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
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

#[derive(Debug)]
struct NoVerification;

// Implement the dangerous trait ServerCertVerifier NoVerification which will
// just always approve the connection
impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ]
    }
}

// Create a dangerous connector - the verifier will always approve
// TODO decide if we want to use an actual certificate
fn tls_connect() -> TlsConnector {
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerification))
        .with_no_client_auth();

    TlsConnector::from(Arc::new(cfg))
}
