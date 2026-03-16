//! VSS (Visa Support Service) module implements a Cap'n Proto VSS server.
//! Arriving VSS messages are placed on a channel to be handled by (presumably) the PH.
//!

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::*;
use tracing::{debug, error, info, trace, warn};
use zpr::vsapi::v1;
use zpr::vsapi_types::{ApiResponseError, ErrorCode, Param, ServiceDescriptor, VisaOp};
use zpr::write_to::WriteTo;

use crate::error::VSApiError;
use crate::logging::targets::VSS_RPC;

// TODO: Move/implement this in zpr-common
pub struct Ack {
    pub ok: bool,
    pub error: ApiResponseError,
    pub processed: u32,
}

#[derive(Debug)]
pub enum ListProcessingResponse {
    Ack { processed: u32 },                  // All items processed
    Failed { processed: u32, e: ErrorCode }, // Zero or more items processed (but not all), with error
}

pub type SetServicesResponse = Result<(), ApiResponseError>;
pub type ConfigureResponse = Result<(), ApiResponseError>;

/// VSS Messages arrive from the visa service.
#[derive(Debug)]
pub enum VSSMessage {
    PushVisaOp(Vec<VisaOp>, oneshot::Sender<ListProcessingResponse>),
    RevokeAuth(Vec<IpAddr>, oneshot::Sender<ListProcessingResponse>),
    SetServices(
        Vec<ServiceDescriptor>, // TODO: need to get TYPE into service descriptor
        oneshot::Sender<SetServicesResponse>,
    ),
    Configure(Vec<Param>, oneshot::Sender<ConfigureResponse>),
}

/// Launch the VSS. Pings are responded to internally. Other VSS messages are sent
/// over the provided channel.
///
/// This needs to run in a LocalSet (uses spawn_local).
pub async fn launch_vss(
    saddr: &SocketAddr,
    from_vs: mpsc::Sender<VSSMessage>,
) -> Result<(), VSApiError> {
    info!(target: VSS_RPC, "VSS starts on {}", saddr);

    let acceptor = match tls_acceptor(*saddr) {
        Ok(l) => l,
        Err(e) => return Err(VSApiError::TLSError(format!("TCP Bind failed {}", e))),
    };
    debug!(target: VSS_RPC, "TLS acceptor on {}", saddr);

    let listener = tokio::net::TcpListener::bind(*saddr).await?;
    debug!(target: VSS_RPC, "TCP listener on {}", saddr);

    loop {
        let (sock, addr) = listener.accept().await?;
        info!(target: VSS_RPC, "connection from {}", addr);
        if let Err(e) = sock.set_nodelay(true) {
            warn!(target: VSS_RPC, "set_nodelay failed: {}", e);
        }

        let tls = acceptor.accept(sock).await?;
        info!(target: VSS_RPC, "TLS connection");
        let (reader, writer) = tokio::io::split(tls);
        // let (reader, writer) = sock.into_split();

        let network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
            capnp::message::ReaderOptions::new(),
        );

        let vs_service: v1::visa_support_service::Client =
            capnp_rpc::new_client(VisaSupportServiceImpl {
                msg_tx: from_vs.clone(),
                remote: addr,
            });

        let rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), Some(vs_service.client));

        tokio::task::spawn_local(async move {
            let err = rpc_system.await;
            err
        });
    }
    // TODO: Some way to cancel this loop?
}

// This function creates a certificate, and the clients will not require verification of the
// cert. In the future, we may actually want to share a cert between the VSAPI and VSS in VS/VSConn in Libnode2
fn tls_acceptor(listen: SocketAddr) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let self_signed_cert = rcgen::generate_simple_self_signed(vec![listen.to_string()])?;
    // Create self signed certificate that does not require client authentication
    let cert_der = self_signed_cert.cert.der();
    let key_der = self_signed_cert.signing_key.serialize_der();

    // Convert the cert into a format the
    let chain = vec![CertificateDer::from(cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;

    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

struct VisaSupportServiceImpl {
    msg_tx: mpsc::Sender<VSSMessage>,
    remote: SocketAddr,
}

use std::cell::RefCell;

struct VSSHandleImpl {
    msg_tx: mpsc::Sender<VSSMessage>,
    remote: SocketAddr,
    data: RefCell<ClientData>,
}

// Per-connection state that we may need to modify.
struct ClientData {
    last_ping: Option<std::time::Instant>,
}

impl ClientData {
    fn new() -> Self {
        ClientData { last_ping: None }
    }
}

impl VSSHandleImpl {
    /// Returns VsApiError::ConnClosed if the message could not be sent.
    async fn send_message(&self, msg: VSSMessage) -> Result<(), VSApiError> {
        if let Err(e) = self.msg_tx.send(msg).await {
            error!(target: VSS_RPC, "failed to send incoming VSS message to handler: {}", e);
            return Err(VSApiError::ConnClosed);
        }
        Ok(())
    }

    /// This populates the Cap'n Proto ACK results based on the response received for the list operation.
    /// Used for processing responses to pushed visa-ops and auth-revokes.
    async fn handle_list_processing_result(
        &self,
        resp_rx: oneshot::Receiver<ListProcessingResponse>,
        ack_builder: &mut v1::ack::Builder<'_>,
    ) {
        match resp_rx.await {
            Ok(ListProcessingResponse::Ack { processed }) => {
                //let mut res_builder = results.get().init_ack();
                ack_builder.set_ok(true);
                ack_builder.set_processed(processed);
            }
            Ok(ListProcessingResponse::Failed {
                processed,
                e: err_code,
            }) => {
                ack_builder.set_ok(processed > 0);
                ack_builder.set_processed(processed);
                let mut err_builder = ack_builder.reborrow().init_error();
                ApiResponseError::new_code_msg(err_code, "failed to process all elements")
                    .write_to(&mut err_builder);
            }
            Err(e) => {
                warn!(target: VSS_RPC, "failed to receive list processing response from handler: {}", e);
                ack_builder.set_ok(false);
                ack_builder.set_processed(0);
                let mut err_builder = ack_builder.reborrow().init_error();
                ApiResponseError::new_code_msg(
                    ErrorCode::Internal,
                    "failed to receive response from VSS handler",
                )
                .write_to(&mut err_builder);
            }
        }
    }

    /// Populate ACK results with error condition and indicate zero processed.
    fn build_ack_zero_with_error(
        &self,
        ack_builder: &mut v1::ack::Builder<'_>,
        api_error: &ApiResponseError,
    ) {
        ack_builder.set_ok(false);
        ack_builder.set_processed(0);
        let mut err_builder = ack_builder.reborrow().init_error();
        api_error.write_to(&mut err_builder);
    }
}

impl v1::visa_support_service::Server for VisaSupportServiceImpl {
    async fn connect(
        self: Rc<Self>,
        _params: v1::visa_support_service::ConnectParams,
        mut results: v1::visa_support_service::ConnectResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSS_RPC, "connect called by {}", self.remote);

        // The connect request params is just a formality for now, so we don't bother reading it.

        // Our logic should be: permit a connection from the VS to this VSS if we don't already
        // have one open. Or maybe better, if this is a new request from same VS, drop the old one.
        // TODO: Add logic around connecting multiple times.

        let vss_handle: v1::v_s_s_handle::Client = capnp_rpc::new_client(VSSHandleImpl {
            msg_tx: self.msg_tx.clone(),
            remote: self.remote.clone(),
            data: RefCell::new(ClientData::new()),
        });

        let mut resp_builder = results.get().init_resp();
        resp_builder.set_ok(vss_handle)?;

        Ok(())
    }
}

impl v1::v_s_s_handle::Server for VSSHandleImpl {
    async fn push_visa_op(
        self: Rc<Self>,
        params: v1::v_s_s_handle::PushVisaOpParams,
        mut results: v1::v_s_s_handle::PushVisaOpResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSS_RPC, "push_visa_op called by {}", self.remote);

        let ops_rdr = params.get()?.get_ops()?;

        let mut ops: Vec<VisaOp> = Vec::new();
        for op_rdr in ops_rdr.iter() {
            match VisaOp::try_from(op_rdr) {
                Ok(vop) => ops.push(vop),
                Err(e) => {
                    warn!(target: VSS_RPC, "received invalid VisaOp from vs: {}", e);
                    let mut ack_builder = results.get().init_ack();
                    self.build_ack_zero_with_error(
                        &mut ack_builder,
                        &ApiResponseError::new_code_msg(
                            ErrorCode::ParamError,
                            "failed to parse a VisaOp",
                        ),
                    );
                    return Ok(()); // Exit early with error
                }
            }
        }

        if ops.is_empty() {
            warn!(target: VSS_RPC, "push_visa_op called with empty ops list from {}", self.remote);
            let mut ack_builder = results.get().init_ack();
            self.build_ack_zero_with_error(
                &mut ack_builder,
                &ApiResponseError::new_code_msg(
                    ErrorCode::InvalidOperation,
                    "empty VisaOp list provided",
                ),
            );
            return Ok(()); // Exit early with error
        }

        let (resp_tx, resp_rx) = oneshot::channel();
        if let Err(e) = self
            .send_message(VSSMessage::PushVisaOp(ops, resp_tx))
            .await
        {
            // Probably our handler has gone away.
            // TODO: Shut down this VSS service connection. How?
            error!("failed to send PushVisaOp message to handler: {}", e);
            let mut ack_builder = results.get().init_ack();
            self.build_ack_zero_with_error(
                &mut ack_builder,
                &ApiResponseError::new_code_msg(ErrorCode::Internal, "message processing failed"),
            );
            return Ok(()); // Exit early with error
        }

        let mut ack_builder = results.get().init_ack();
        self.handle_list_processing_result(resp_rx, &mut ack_builder)
            .await;

        Ok(())
    }

    async fn revoke_authentication(
        self: Rc<Self>,
        params: v1::v_s_s_handle::RevokeAuthenticationParams,
        mut results: v1::v_s_s_handle::RevokeAuthenticationResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSS_RPC, "revoke_authentication called by {}", self.remote);

        let addrs_rdr = params.get()?.get_addrs()?;

        let mut addrs = Vec::new();
        for addr_rdr in addrs_rdr.iter() {
            match IpAddr::try_from(addr_rdr) {
                Ok(ip) => addrs.push(ip),
                Err(e) => {
                    warn!(target: VSS_RPC, "received invalid IpAddr from vs: {}", e);
                    let mut ack_builder = results.get().init_ack();
                    self.build_ack_zero_with_error(
                        &mut ack_builder,
                        &ApiResponseError::new_code_msg(
                            ErrorCode::ParamError,
                            "failed to parse an IpAddr",
                        ),
                    );
                    return Ok(()); // Exit early with error
                }
            }
        }

        if addrs.is_empty() {
            warn!(target: VSS_RPC, "revoke_authentication called with empty addr list from {}", self.remote);
            let mut ack_builder = results.get().init_ack();
            self.build_ack_zero_with_error(
                &mut ack_builder,
                &ApiResponseError::new_code_msg(
                    ErrorCode::InvalidOperation,
                    "empty IpAddr list provided",
                ),
            );
            return Ok(()); // Exit early with error
        }

        let (resp_tx, resp_rx) = oneshot::channel();
        if let Err(e) = self
            .send_message(VSSMessage::RevokeAuth(addrs, resp_tx))
            .await
        {
            // Probably our handler has gone away.
            // TODO: Shut down this VSS service connection. How?
            error!("failed to send RevokeAuth message to handler: {}", e);
            let mut ack_builder = results.get().init_ack();
            self.build_ack_zero_with_error(
                &mut ack_builder,
                &ApiResponseError::new_code_msg(ErrorCode::Internal, "message processing failed"),
            );
            return Ok(()); // Exit early with error
        }

        let mut ack_builder = results.get().init_ack();
        self.handle_list_processing_result(resp_rx, &mut ack_builder)
            .await;

        Ok(())
    }

    async fn set_services(
        self: Rc<Self>,
        params: v1::v_s_s_handle::SetServicesParams,
        mut results: v1::v_s_s_handle::SetServicesResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSS_RPC, "set_services called by {}", self.remote);

        let params_rdr = params.get()?;
        let services_rdr = params_rdr.get_svcs()?;

        let mut services = Vec::new();
        for svc_rdr in services_rdr.iter() {
            match ServiceDescriptor::try_from(svc_rdr) {
                Ok(svc) => services.push(svc),
                Err(e) => {
                    warn!(target: VSS_RPC, "received invalid ServiceDescriptor from vs: {}", e);
                    let res_builder = results.get().init_res();
                    let mut err_builder = res_builder.init_error();
                    ApiResponseError::new_code_msg(
                        ErrorCode::ParamError,
                        "failed to parse a ServiceDescriptor",
                    )
                    .write_to(&mut err_builder);
                    return Ok(()); // Exit early with error
                }
            }
        }

        let (resp_tx, resp_rx) = oneshot::channel();
        if let Err(e) = self
            .send_message(VSSMessage::SetServices(services, resp_tx))
            .await
        {
            // Probably our handler has gone away.
            // TODO: Shut down this VSS service connection. How?
            error!("failed to send SetServices message to handler: {}", e);
            let res_builder = results.get().init_res();
            let mut err_builder = res_builder.init_error();
            ApiResponseError::new_code_msg(ErrorCode::Internal, "message processing failed")
                .write_to(&mut err_builder);
            return Ok(()); // Exit early with error
        }

        match resp_rx.await {
            Ok(Ok(())) => {
                let mut res_builder = results.get().init_res();
                res_builder.set_ok(());
            }
            Ok(Err(api_err)) => {
                let res_builder = results.get().init_res();
                let mut err_builder = res_builder.init_error();
                api_err.write_to(&mut err_builder);
            }
            Err(e) => {
                error!("failed to receive SetServices response from handler: {}", e);
                let res_builder = results.get().init_res();
                let mut err_builder = res_builder.init_error();
                ApiResponseError::new_code_msg(
                    ErrorCode::Internal,
                    "failed to receive response from VSS handler",
                )
                .write_to(&mut err_builder);
            }
        }

        Ok(())
    }

    async fn configure(
        self: Rc<Self>,
        params: v1::v_s_s_handle::ConfigureParams,
        mut results: v1::v_s_s_handle::ConfigureResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSS_RPC, "configure called by {}", self.remote);

        let params_rdr = params.get()?;
        let pargs_rdr = params_rdr.get_params()?;

        let mut cfg_params = Vec::new();
        for parg_rdr in pargs_rdr.iter() {
            match Param::try_from(parg_rdr) {
                Ok(p) => cfg_params.push(p),
                Err(e) => {
                    warn!(target: VSS_RPC, "received invalid Param from vs: {}", e);
                    let res_builder = results.get().init_res();
                    let mut err_builder = res_builder.init_error();
                    ApiResponseError::new_code_msg(
                        ErrorCode::ParamError,
                        "failed to parse a configuration parameter",
                    )
                    .write_to(&mut err_builder);
                    return Ok(()); // Exit early with error
                }
            }
        }

        let (resp_tx, resp_rx) = oneshot::channel();
        if let Err(e) = self
            .send_message(VSSMessage::Configure(cfg_params, resp_tx))
            .await
        {
            // Probably our handler has gone away.
            error!("failed to send Configure message to handler: {}", e);
            let res_builder = results.get().init_res();
            let mut err_builder = res_builder.init_error();
            ApiResponseError::new_code_msg(ErrorCode::Internal, "message processing failed")
                .write_to(&mut err_builder);
            return Ok(()); // Exit early with error
        }

        match resp_rx.await {
            Ok(Ok(())) => {
                let mut res_builder = results.get().init_res();
                res_builder.set_ok(());
            }
            Ok(Err(api_err)) => {
                let res_builder = results.get().init_res();
                let mut err_builder = res_builder.init_error();
                api_err.write_to(&mut err_builder);
            }
            Err(e) => {
                error!("failed to receive Configure response from handler: {}", e);
                let res_builder = results.get().init_res();
                let mut err_builder = res_builder.init_error();
                ApiResponseError::new_code_msg(
                    ErrorCode::Internal,
                    "failed to receive response from VSS handler",
                )
                .write_to(&mut err_builder);
            }
        }

        Ok(())
    }

    async fn ping(
        self: Rc<Self>,
        _params: v1::v_s_s_handle::PingParams,
        mut results: v1::v_s_s_handle::PingResults,
    ) -> Result<(), capnp::Error> {
        trace!(target: VSS_RPC, "ping called by {}", self.remote);
        let mut res_builder = results.get().init_res();
        res_builder.set_ok(());
        self.data.borrow_mut().last_ping = Some(std::time::Instant::now());
        Ok(())
    }
}
