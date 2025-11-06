use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::SystemTime;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::*;

use crate::claims;
use crate::errors::{VSClientError, VSError};
use crate::logging::targets::VS_RPC;

use crate::vsapi_compat as vsapi; // TODO: remove

#[derive(Debug)]
pub struct VisaRequest {
    pub source_tether_addr: IpAddr,
    pub l3_type: zpr::L3Type,
    pub packet: Vec<u8>,
}
type VisaRequestResponse = Result<vsapi::VisaResponse, VSClientError>;
type AuthorizeConnectResponse = Result<vsapi::ConnectResponse, VSClientError>;
type DisconnectStatus = Result<(), VSClientError>;
type RequestServicesResponse = Result<vsapi::ServicesResponse, VSClientError>;

// The async "commands" that can be sent into the running visa service client.
#[derive(Debug)]
#[allow(dead_code)]
enum VSCommand {
    Stop(bool), // Stop the run loop, optionally de-register from the visa service first.
    RequestVisa(VisaRequest, oneshot::Sender<VisaRequestResponse>),
    AuthorizeConnect(
        vsapi::ConnectRequest,
        oneshot::Sender<AuthorizeConnectResponse>,
    ),
    ActorDisconnect(IpAddr, oneshot::Sender<DisconnectStatus>), // takes a ZPR address assigned to the actor
    RequestServices(oneshot::Sender<RequestServicesResponse>),
}

#[derive(Debug)]
pub enum VSOutput {
    PingSuccess(u64, u64), // (CONFIG_ID, POLICY_VERSION)
}

pub struct VSConn {
    //service_addr: String, // visa service address, format "HOST:PORT"
    //node_cert_pem_data: String,
    cmd_tx: mpsc::Sender<VSCommand>,
    //cmd_rx: mpsc::Receiver<VSCommand>,
    //output_tx: mpsc::Sender<VSOutput>,
    //client_fac: vscli::VSClientFactory,
    //vss_service_addr: SocketAddr, // visa support service listen address
    //actor: vsapi::Actor,
}

#[derive(Clone)]
pub struct VSConnHandle {
    cmd_tx: mpsc::Sender<VSCommand>,
}

/// Helper function to create a basic node actor. Probably only useful for early versions
/// of the node.  In the future the node will create it's own actor datastructure and
/// had it to [VSConn::new].
pub fn new_node_actor(node_addr: IpAddr, claims: &BTreeMap<String, String>) -> vsapi::Actor {
    // In prototype, the node zpr address is the same as its tether address. May not be true going forward.
    let zaddr_bytes = match node_addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    let taddr_bytes = zaddr_bytes.clone();

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut augmented_claims = BTreeMap::new();
    for (k, v) in claims {
        augmented_claims.insert(k.clone(), v.clone());
    }
    augmented_claims.insert(claims::KATTR_EPID.into(), node_addr.to_string());

    vsapi::Actor {
        actor_type: Some(vsapi::ActorType::NODE),
        attrs: Some(augmented_claims),
        auth_expires: Some((timestamp + 60 * 60) as i64),
        zpr_addr: Some(zaddr_bytes),
        tether_addr: Some(taddr_bytes),
        ident: Some(String::from("ident-not-generated")), // TODO
        provides: None,
    }
}

impl VSConn {
    /// Create a new Visa Service Connection manager.
    ///
    /// - `node_actor` is the node's Actor representation.  See [new_node_actor] for a helper function to create this.
    /// - `output_tx` is the channel to send output messages to the node. The only message left is PING_SUCCESS.
    /// - `service_addr` is ADDR:PORT of the visa service (ADDR should be a ZPR address)
    /// - `node_cert_file` is the path to the node's signed (for now) EC certificate file
    /// - `node_zpr_addr` node ZPR address (not substrate address) as set by network admin
    /// - `vss_service_addr` optionally override the default listen address for the visa
    ///   support service. If not set, then we will advertise `<NODE_ZPR_ADDR>:<DEFAULT_VSS_PORT>`.
    //
    pub fn new(
        _node_actor: vsapi::Actor,
        _output_tx: mpsc::Sender<VSOutput>,
        _service_addr: &str,
        _node_cert_file: &Path,
        _node_zpr_addr: IpAddr,
        _vss_service_addr: Option<SocketAddr>,
    ) -> Result<VSConn, VSError> {
        Err(VSError::NotImplemented)
    }

    pub async fn run(&mut self, ctok: CancellationToken) -> Result<(), VSError> {
        Err(VSError::NotImplemented)
    }

    /// Creates a handle which can be used to issue commands to this connection.
    pub fn handle(&self) -> VSConnHandle {
        VSConnHandle {
            cmd_tx: self.cmd_tx.clone(),
        }
    }
}

impl VSConnHandle {
    /// Attempt to enqueue an async command to the runloop.
    /// Returns an error if the command could not be enqueued.
    async fn send_command(&self, cmd: VSCommand) -> Result<(), VSClientError> {
        if let Err(e) = self.cmd_tx.send(cmd).await {
            error!(target: VS_RPC, "VSConn::send_command failed to queue: {e}");
            return Err(VSClientError::ConnClosed);
        }
        Ok(())
    }

    /// Perform an async visa request.
    ///
    /// ## Errors
    /// - [VSError::EnqueueError] if the request could not be enqueued.
    pub async fn request_visa(&self, req: VisaRequest) -> VisaRequestResponse {
        let (tx, rx) = oneshot::channel();
        self.send_command(VSCommand::RequestVisa(req, tx)).await?;
        rx.await.map_err(|_| VSClientError::ConnClosed)?
    }

    /// Perform an async authorize_connect.
    ///
    /// ## Errors
    /// - [VSError::EnqueueError] if the request could not be enqueued.
    pub async fn authorize_connect(&self, req: vsapi::ConnectRequest) -> AuthorizeConnectResponse {
        let (tx, rx) = oneshot::channel();
        self.send_command(VSCommand::AuthorizeConnect(req, tx))
            .await?;
        rx.await.map_err(|_| VSClientError::ConnClosed)?
    }

    /// Async message to visa service noting that an actor has disconnected.
    ///
    /// ## Errors
    /// - [VSError::EnqueueError] if the request could not be enqueued.
    pub async fn actor_disconnect(&self, zpr_addr: IpAddr) -> DisconnectStatus {
        let (tx, rx) = oneshot::channel();
        self.send_command(VSCommand::ActorDisconnect(zpr_addr, tx))
            .await?;
        rx.await.map_err(|_| VSClientError::ConnClosed)?
    }

    /// Perform async RequestServices request on the VS API.
    pub async fn request_services(&self) -> RequestServicesResponse {
        let (tx, rx) = oneshot::channel();
        self.send_command(VSCommand::RequestServices(tx)).await?;
        rx.await.map_err(|_| VSClientError::ConnClosed)?
    }

    /// Stop the VSConn run loop, optionally try to send a deregister message first.
    pub async fn stop(&self, and_deregister: bool) -> Result<(), VSClientError> {
        self.send_command(VSCommand::Stop(and_deregister)).await
    }
}
