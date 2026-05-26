use zpr::vsapi::v1 as vsapi2;
use zpr::vsapi_types::ApiResponseError;

use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
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
    ConnectRequest, Connection, DisconnectNotice, NodeConnect, StateFlag, Visa, VisaDecision,
    VisaOp, VisaRequest, VisaResponse,
};
use zpr::write_to::WriteTo;

/// Boxed async connect factory: given a SocketAddr, returns a future that resolves to a TcpStream.
/// The default implementation calls `tokio::net::TcpStream::connect`; tests may inject a stub.
type ConnectFn = Box<
    dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = std::io::Result<tokio::net::TcpStream>>>>,
>;

const PARAM_ZPR_ADDR: &str = "zpr_addr";

const LIFECYCLE_EVENT_BUFFER_SIZE: usize = 64;

const VSAPI_PING_INTERVAL: Duration = Duration::from_secs(5);
const VSAPI_MAX_PING_FAILURES: u32 = 2;

/// Minimum (and initial) timeout for a ping RPC call.
const PING_MIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Default timeout for a single Cap'n Proto RPC call.
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for connect/challenge/authenticate — longer due to crypto.
const DEFAULT_CONNECT_RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// 4 no error if call to VSAPI authenticate was successful.
type VSVisaResponse = Result<VisaDecision, VSApiError>;
type VSConnectResponse = Result<(), VSApiError>;
type VSRegisterVssResponse = Result<Vec<VisaOp>, VSApiError>;
type VSAuthorizeConnectResponse = Result<Connection, VSApiError>;
type VSNotifyDisconnectResponse = Result<(), VSApiError>;
type VSPingResponse = Result<(), VSApiError>;
type VSVisaIdsResponse = Result<Vec<u64>, VSApiError>;
type VSVisaByIdResponse = Result<Vec<Visa>, VSApiError>;

// The async "commands" that can be sent into the running visa service client.
#[derive(Debug)]
enum VS2Command {
    /// Stop the local vs-api run loop, optionally de-register from the visa service first.
    Stop(bool),

    /// Run through the connect sequence. If connect succeeds the VSHandle is kept internally.
    Connect(NodeConnect, oneshot::Sender<VSConnectResponse>),

    VisaRequest(VisaRequest, oneshot::Sender<VSVisaResponse>),

    RegisterVss(SocketAddr, oneshot::Sender<VSRegisterVssResponse>),

    AuthorizeConnect(ConnectRequest, oneshot::Sender<VSAuthorizeConnectResponse>),

    NotifyDisconnect(
        DisconnectNotice,
        oneshot::Sender<VSNotifyDisconnectResponse>,
    ),

    Ping(oneshot::Sender<VSPingResponse>),

    VisaIdsRequest(oneshot::Sender<VSVisaIdsResponse>),

    VisaByIdsRequest(Vec<u64>, oneshot::Sender<VSVisaByIdResponse>),
}

#[derive(Debug, Clone, Copy)]
pub enum VSConnLifecycleEvent {
    /// Means we have established a network connection to the Cap'n Proto service.
    RunLoopStarts,

    /// Means that the node connect-request was successful.
    ConnectedToVsApi(StateFlag),

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
    connect_fn: ConnectFn,
}

/// Handle for sending commands to a running [VSConn].
///
/// All async methods return [`VSApiError::ConnClosed`] in two situations:
/// - The run loop has exited (the underlying command channel is closed).
/// - A command was sent while the run loop was busy establishing a TCP
///   connection or waiting out a reconnect delay; in those windows the
///   command is discarded immediately rather than queued. Callers should
///   treat `ConnClosed` as a transient error and retry once a new
///   [`VSConnLifecycleEvent::RunLoopStarts`] event is observed.
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
            connect_fn: Box::new(|addr| Box::pin(tokio::net::TcpStream::connect(addr))),
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
    ///
    /// Note that "reconnect" here just means that we attempt to re-open the base Cap'n Proto connection.
    /// We rely on external code to call us with an API level "connect" command.  To know when reconnects
    /// and such are happening, follow the lifecycle events.
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
                    let timeout = tokio::time::sleep(reconnect_after);
                    tokio::pin!(timeout);
                    // loop in case we get woken by the command channel
                    loop {
                        tokio::select! {
                            biased; // in case of tie this bias here means we prioritize Stop (first branch) if we get it.

                            cmd = self.cmd_rx.recv() => match cmd {
                                Some(VS2Command::Stop(_)) | None => {
                                    info!(target: VS_RPC, "VSConn: stop received during reconnect delay, exiting");
                                    return Ok(());
                                }
                                Some(other) => drop(other),
                            },

                            _ = &mut timeout => break,
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), VSApiError> {
        // First spin up a connection to the Capn Proto service on the VS.
        info!(target: VS_RPC, "VS RPC service connecting to {} (capnp)", self.vs_addr);

        // Interruptible TCP connect: poll cmd_rx alongside the connect future so that a Stop
        // command received while blocked in connect (e.g. during a 2-minute TCP ETIMEDOUT) causes
        // a clean exit rather than an indefinite hang.
        let sock = {
            let mut connect_fut = (self.connect_fn)(self.vs_addr);
            loop {
                tokio::select! {
                    result = &mut connect_fut => break result?,
                    cmd = self.cmd_rx.recv() => match cmd {
                        Some(VS2Command::Stop(_)) | None => {
                            info!(target: VS_RPC, "VSConn: stop received during TCP connect, exiting cleanly");
                            self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopExits);
                            return Ok(());
                        }
                        // Any other command arrived before connection is established; drop it so
                        // its oneshot sender is closed and the caller receives ConnClosed.
                        Some(other) => drop(other),
                    }
                }
            }
        };
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
                            let Some(cmd) = cmd else {
                                info!(target: VS_RPC, "VSConn: command channel closed, exiting run loop");
                                break;
                            };
                            let is_stop_cmd = matches!(cmd, VS2Command::Stop(_));
                            if let Err(e) = self.handle_command(&mut cmd_state, cmd).await {
                                error!(target: VS_RPC, "VSConn: handle_command error: {:?}", e);
                                self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopExits);
                                return Err(e.into());
                            }
                            if is_stop_cmd {
                                break;
                            }
                        }

                        // If the ping interval elapses, do a ping (not implemented yet).
                        () = &mut ping_timeout => {
                            if !cmd_state.is_connected() {
                                // Not connected, just reset the ping timer.
                                ping_timeout.as_mut().reset(tokio::time::Instant::now() + VSAPI_PING_INTERVAL);
                                ping_failures = 0;
                                continue;
                            }
                            // Back off a bit if we experienced an error last time.
                            let next_ping_timeout = PING_MIN_TIMEOUT + Duration::from_secs(ping_failures as u64);
                            match self.do_ping(cmd_state.vs_handle.as_ref().unwrap(), next_ping_timeout).await {
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
                    let disconnect_request_response = rpc_with_timeout(
                        "notify_disconnect",
                        DEFAULT_RPC_TIMEOUT,
                        disconnect_request.send().promise,
                    )
                    .await?;
                    let ok_or_err = disconnect_request_response.get()?.get_res()?;
                    match ok_or_err.which()? {
                        vsapi2::ok_or_error::Which::Ok(_) => {
                            info!(target: VS_RPC, "VS API notify_disconnect succeeded");
                        }
                        vsapi2::ok_or_error::Which::Error(err_obj) => {
                            let err_obj = err_obj?;
                            let err = ApiResponseError::try_from(err_obj);

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
                let stateflag = req.state.clone();
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
                        self.send_lifecycle_event(VSConnLifecycleEvent::ConnectedToVsApi(
                            stateflag,
                        ));
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
                    self.do_ping(cmd_state.vs_handle.as_ref().unwrap(), PING_MIN_TIMEOUT)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send ping response: {:?}", e);
                }
                Ok(())
            }
            VS2Command::VisaIdsRequest(resp_tx) => {
                debug!(target: VS_RPC, "VSConn: visa_ids_request");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_visa_ids_request(cmd_state.vs_handle.as_ref().unwrap())
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send visa_ids_request response: {:?}", e);
                }
                Ok(())
            }
            VS2Command::VisaByIdsRequest(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: visa_by_ids_request");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_visa_by_ids_request(cmd_state.vs_handle.as_ref().unwrap(), req)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send visa_by_ids_request response: {:?}", e);
                }
                Ok(())
            }
        }
    }

    async fn do_connect(
        &self,
        vs_service: &vsapi2::visa_service::Client,
        req: NodeConnect,
    ) -> Result<vsapi2::v_s_handle::Client, VSApiError> {
        let mut vs_request = vs_service.connect_request();

        let mut vscr_bldr = vs_request.get().init_req();
        vscr_bldr.set_cn(&self.node_cn);

        let ctype = match req.state {
            StateFlag::HasState => vsapi2::VSConnT::Reconnect,
            StateFlag::NoState => vsapi2::VSConnT::Reset,
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

        let vs_request_response = rpc_with_timeout(
            "connect",
            DEFAULT_CONNECT_RPC_TIMEOUT,
            vs_request.send().promise,
        )
        .await?;
        let gate_or_error = vs_request_response.get()?.get_resp()?;

        let vs_gate_svc: vsapi2::v_s_gate::Client = match gate_or_error.which()? {
            vsapi2::result::Which::Ok(vs_gate_obj) => vs_gate_obj?,
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                return Err(ApiResponseError::try_from(err_obj)?.into());
            }
        };

        // Now we have a gate we can request a challenge.
        let gate_request = vs_gate_svc.challenge_request();

        debug!(target: VS_RPC, "VS-API -> challenge");
        let gate_response = rpc_with_timeout(
            "challenge",
            DEFAULT_CONNECT_RPC_TIMEOUT,
            gate_request.send().promise,
        )
        .await?;
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
        let gate_response = rpc_with_timeout(
            "authenticate",
            DEFAULT_CONNECT_RPC_TIMEOUT,
            gate_request.send().promise,
        )
        .await?;
        let handle_or_error = gate_response.get()?.get_res()?;

        let vs_handle_svc: vsapi2::v_s_handle::Client = match handle_or_error.which()? {
            vsapi2::result::Which::Ok(handle_obj) => handle_obj?,
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                return Err(ApiResponseError::try_from(err_obj)?.into());
            }
        };

        // Ok we now have an authenticated handle to the VS.
        Ok(vs_handle_svc)
    }

    async fn do_visa_request(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: VisaRequest, // TODO: VisaRequest should use a PacketDesc from vs-dt, then implement write_to on it.
    ) -> Result<VisaDecision, VSApiError> {
        let mut vr_request = vs_h.visa_request_request();
        let mut vrr_bldr = vr_request.get().init_req();
        vrr_bldr.set_previous_id(0);
        let mut pd_bldr = vrr_bldr.init_packet();
        req.pdesc.write_to(&mut pd_bldr);
        let vr_response = rpc_with_timeout(
            "visa_request",
            DEFAULT_RPC_TIMEOUT,
            vr_request.send().promise,
        )
        .await?;

        let allow_deny_error: vsapi2::visa_response::Reader<'_> = vr_response.get()?.get_resp()?;
        let vr = VisaResponse::try_from(allow_deny_error)?;
        Ok(VisaDecision::try_from(vr)?)
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
        let ac_response = rpc_with_timeout(
            "authorize_connect",
            DEFAULT_RPC_TIMEOUT,
            ac_request.send().promise,
        )
        .await?;
        let conn_or_error = ac_response.get()?.get_resp()?;

        match conn_or_error.which()? {
            vsapi2::result::Which::Ok(conn) => {
                let conn = conn?;
                let connection = Connection::try_from(conn)?;
                Ok(connection)
            }
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }

    async fn do_notify_disconnect(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: DisconnectNotice,
    ) -> Result<(), VSApiError> {
        let mut nd_request = vs_h.notify_disconnect_request();
        let mut dn_bldr = nd_request.get().init_req();

        if let Some(addr) = req.zpr_addr {
            let mut addr_bldr = dn_bldr.reborrow().init_zpr_addr();
            addr.write_to(&mut addr_bldr);
        }
        dn_bldr.set_reason_code(req.reason.into());

        debug!(target: VS_RPC, "VS-API -> notify_disconnect");
        let nd_response = rpc_with_timeout(
            "notify_disconnect",
            DEFAULT_RPC_TIMEOUT,
            nd_request.send().promise,
        )
        .await?;
        let ok_or_err = nd_response.get()?.get_res()?;

        match ok_or_err.which()? {
            vsapi2::ok_or_error::Which::Ok(_) => Ok(()),
            vsapi2::ok_or_error::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
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

        let rvs_response = rpc_with_timeout(
            "register_vss",
            DEFAULT_RPC_TIMEOUT,
            rvs_request.send().promise,
        )
        .await?;
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
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }

    async fn do_ping(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        with_timeout: Duration,
    ) -> Result<(), VSApiError> {
        trace!(target: VS_RPC, "VS-API -> ping");
        let ping_response_rdr =
            rpc_with_timeout("ping", with_timeout, vs_h.ping_request().send().promise).await?;
        match ping_response_rdr.get()?.get_res()?.which()? {
            vsapi2::ok_or_error::Which::Ok(_) => Ok(()),
            vsapi2::ok_or_error::Which::Error(err_rdr) => {
                Err(ApiResponseError::try_from(err_rdr?)?.into())
            }
        }
    }

    async fn do_visa_ids_request(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
    ) -> Result<Vec<u64>, VSApiError> {
        debug!(target: VS_RPC, "VS-API -> visa_ids_request");
        let visa_ids_reqponse_rdr = rpc_with_timeout(
            "visa_ids_request",
            DEFAULT_RPC_TIMEOUT,
            vs_h.visa_ids_request_request().send().promise,
        )
        .await?;
        let ok_or_error = visa_ids_reqponse_rdr.get()?.get_res()?;
        match ok_or_error.which()? {
            vsapi2::result::Which::Ok(ids_list_rdr) => {
                let ids: Vec<u64> = ids_list_rdr?.iter().collect();
                Ok(ids)
            }
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }

    async fn do_visa_by_ids_request(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: Vec<u64>,
    ) -> Result<Vec<Visa>, VSApiError> {
        debug!(target: VS_RPC, "VS-API -> visa_by_ids_request");
        let mut visa_by_id_req = vs_h.visa_request_by_id_request();
        let mut req_builder = visa_by_id_req.get().init_req(req.len() as u32);

        for (i, id) in req.iter().enumerate() {
            req_builder.set(i as u32, *id);
        }

        let visa_by_ids_reqponse_rdr = rpc_with_timeout(
            "visa_by_ids_request",
            DEFAULT_RPC_TIMEOUT,
            visa_by_id_req.send().promise,
        )
        .await?;

        let ok_or_error = visa_by_ids_reqponse_rdr.get()?.get_res()?;
        match ok_or_error.which()? {
            vsapi2::result::Which::Ok(visa_list_rdr) => {
                let mut visas: Vec<Visa> = Vec::new();
                for visa_rdr in visa_list_rdr?.iter() {
                    visas.push(Visa::try_from(visa_rdr)?);
                }
                Ok(visas)
            }
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
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

    pub async fn connect(&self, req: NodeConnect) -> Result<(), VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::Connect(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn stop(&self, deregister: bool) -> Result<(), VSApiError> {
        let cmd = VS2Command::Stop(deregister);
        self.send_command(cmd).await
    }

    pub async fn visa_request(&self, req: VisaRequest) -> Result<VisaDecision, VSApiError> {
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

    pub async fn notify_disconnect(&self, req: DisconnectNotice) -> Result<(), VSApiError> {
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

    pub async fn visa_id_request(&self) -> Result<Vec<u64>, VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::VisaIdsRequest(resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn visa_by_id_request(&self, req: Vec<u64>) -> Result<Vec<Visa>, VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::VisaByIdsRequest(req, resp_tx);
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

/// Wrap a Cap'n Proto RPC future with a timeout, mapping errors to VSApiError.
async fn rpc_with_timeout<F, T>(
    name: &'static str,
    duration: Duration,
    fut: F,
) -> Result<T, VSApiError>
where
    F: Future<Output = Result<T, capnp::Error>>,
{
    match tokio::time::timeout(duration, fut).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(capnp_err)) => Err(capnp_err.into()),
        Err(_elapsed) => Err(VSApiError::Timeout(name.to_string())),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    impl VSConn {
        /// Construct a VSConn with a custom connect function.
        /// Intended only for unit tests that need to inject a stub TCP connector (e.g. a pending
        /// future that never resolves, to simulate a hung connection attempt).
        fn new_for_test(
            vs_addr: SocketAddr,
            node_cn: String,
            node_private_key: PKey<Private>,
            connect_fn: ConnectFn,
        ) -> Self {
            let (cmd_tx, cmd_rx) = mpsc::channel(16);
            let (life_tx, _) = broadcast::channel(LIFECYCLE_EVENT_BUFFER_SIZE);
            VSConn {
                cmd_tx,
                cmd_rx,
                vs_addr,
                node_cn,
                node_private_key,
                life_tx,
                connect_fn,
            }
        }
    }

    fn test_key() -> PKey<Private> {
        let rsa = openssl::rsa::Rsa::generate(1024).unwrap();
        PKey::from_rsa(rsa).unwrap()
    }

    /// Connect function that always fails immediately with ConnectionRefused.
    /// Used to drive run_with_reconnect into the sleep/retry branch.
    fn refusing_connect_fn() -> ConnectFn {
        Box::new(|_addr| {
            Box::pin(async {
                Err::<tokio::net::TcpStream, _>(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "test stub",
                ))
            })
        })
    }

    /// Connect function that never resolves — simulates a TCP connect blocked waiting for a
    /// SYN-ACK that will never arrive (e.g. firewall drop / ETIMEDOUT scenario).
    fn pending_connect_fn() -> ConnectFn {
        Box::new(|_addr| Box::pin(std::future::pending::<std::io::Result<tokio::net::TcpStream>>()))
    }

    fn test_vsconn(connect_fn: ConnectFn) -> VSConn {
        VSConn::new_for_test(
            "127.0.0.1:1".parse().unwrap(),
            "test-node".to_string(),
            test_key(),
            connect_fn,
        )
    }

    /// Before fix: run_with_reconnect blocks in tokio::time::sleep(reconnect_after) even when a
    /// Stop command is already in the channel, causing a full 30-second delay.
    /// After fix: the select! between the sleep and cmd_rx delivers Stop immediately.
    #[tokio::test]
    async fn stop_during_reconnect_delay_exits_promptly() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let mut vsconn = test_vsconn(refusing_connect_fn());
                let handle = vsconn.handle();

                let task = tokio::task::spawn_local(async move {
                    vsconn.run_with_reconnect(Duration::from_secs(30)).await
                });

                // Wait for the first failed connect and entry into the reconnect sleep.
                tokio::time::sleep(Duration::from_millis(50)).await;

                handle.stop(false).await.unwrap();

                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .expect(
                        "run_with_reconnect hung past 2s — was sleeping for 30s without the fix",
                    )
                    .expect("task panicked")
                    .expect("run_with_reconnect returned an error");
            })
            .await;
    }

    /// Before fix: run_with_reconnect → run() blocks in (connect_fn)() with no cmd_rx polling,
    /// so the Stop command is never processed until the connect times out.
    /// After fix: run() selects between the connect future and cmd_rx; Stop causes a clean exit.
    #[tokio::test]
    async fn stop_during_tcp_connect_exits_promptly() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let mut vsconn = test_vsconn(pending_connect_fn());
                let handle = vsconn.handle();

                let task = tokio::task::spawn_local(async move {
                    vsconn.run_with_reconnect(Duration::from_secs(30)).await
                });

                // Give the connect a moment to start.
                tokio::time::sleep(Duration::from_millis(50)).await;

                handle.stop(false).await.unwrap();

                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .expect("run_with_reconnect hung past 2s — was blocked in connect() without the fix")
                    .expect("task panicked")
                    .expect("run_with_reconnect returned an error");
            })
            .await;
    }
}
