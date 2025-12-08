//! The Visa Service Connection Manager
//!
//! Manage access to the visa service on behalf of the node. Makes use of the thrift
//! generated client code to communicate with the visa service.
//!

use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::SystemTime;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::claims;
use crate::errors::{VSClientError, VSError};
use crate::logging::targets::VS_RPC;
use crate::vscli::{self, VSClientI};
use crate::vss::DEFAULT_VSS_PORT;
use zpr::vsapi_types::{ConnectRequest, Connection, VisaResponse};

use vsapi;
use zpr::packet_info::L3Type;

const PING_INTERVAL: Duration = Duration::from_millis(10000);
const MAX_PING_ERRORS: u32 = 5;

#[derive(Debug)]
pub struct VisaRequest {
    pub source_tether_addr: IpAddr,
    pub l3_type: L3Type,
    pub packet: Vec<u8>,
}

type VisaRequestResponse = Result<VisaResponse, VSClientError>;
type AuthorizeConnectResponse = Result<Connection, VSClientError>;
type DisconnectStatus = Result<(), VSClientError>;
type RequestServicesResponse = Result<vsapi::ServicesResponse, VSClientError>;

// The async "commands" that can be sent into the running visa service client.
#[derive(Debug)]
#[allow(dead_code)]
enum VSCommand {
    Stop(bool), // Stop the run loop, optionally de-register from the visa service first.
    RequestVisa(VisaRequest, oneshot::Sender<VisaRequestResponse>),
    AuthorizeConnect(ConnectRequest, oneshot::Sender<AuthorizeConnectResponse>),
    ActorDisconnect(IpAddr, oneshot::Sender<DisconnectStatus>), // takes a ZPR address assigned to the actor
    RequestServices(oneshot::Sender<RequestServicesResponse>),
}

// This will change a bit too. This is for output messages from the visa service. These are asynchronous
// messages so the request/response pairs will need to include an operation ID or some such so that the
// node can match responses to requests.
#[derive(Debug)]
pub enum VSOutput {
    PingSuccess(u64, u64), // (CONFIG_ID, POLICY_VERSION)
}

pub struct VSConn {
    service_addr: String, // visa service address, format "HOST:PORT"
    node_cert_pem_data: String,
    cmd_tx: mpsc::Sender<VSCommand>,
    cmd_rx: mpsc::Receiver<VSCommand>,
    output_tx: mpsc::Sender<VSOutput>,
    client_fac: vscli::VSClientFactory,
    vss_service_addr: SocketAddr, // visa support service listen address
    actor: vsapi::Actor,
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

/// The VSConn will manage all communication with the visa service on behalf of the node.
/// To clealy shutdown the visa service, cancel the token passed to `run' function.
///
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
        node_actor: vsapi::Actor,
        output_tx: mpsc::Sender<VSOutput>,
        service_addr: &str,
        node_cert_file: &Path,
        node_zpr_addr: IpAddr,
        vss_service_addr: Option<SocketAddr>,
    ) -> Result<VSConn, VSError> {
        let mut certfile = match File::open(node_cert_file) {
            Ok(f) => f,
            Err(e) => return Err(e.into()),
        };
        let mut cert_pem_data = String::new();
        certfile.read_to_string(&mut cert_pem_data)?;

        let vss_service_addr =
            vss_service_addr.unwrap_or_else(|| SocketAddr::new(node_zpr_addr, DEFAULT_VSS_PORT));

        let (cmd_tx, cmd_rx) = mpsc::channel(16);

        let vs_conn = VSConn {
            service_addr: service_addr.to_string(),
            node_cert_pem_data: cert_pem_data,
            cmd_tx,
            cmd_rx,
            output_tx,
            client_fac: vscli::default_vsclient_factory,
            vss_service_addr,
            actor: node_actor,
        };

        Ok(vs_conn)
    }

    #[cfg(test)]
    fn set_client_factory(&mut self, fac: vscli::VSClientFactory) {
        self.client_fac = fac;
    }

    /// Registers with visa service and obtains an API key.
    /// Blocking network call.
    fn initialize(&self, client: &mut Box<dyn VSClientI>) -> Result<(), VSError> {
        debug!(target: VS_RPC, "VSConn::initialize starts");

        let _apikey =
            match client.authenticate(&self.actor, &self.node_cert_pem_data, self.vss_service_addr)
            {
                Ok(k) => k,
                Err(e) => return Err(e.into()),
            };

        Ok(())
    }

    /// Start the run loop. Does not return until we are disconnected from the visa service or the passed
    /// token is cancelled.
    ///
    /// This little run loop is fairly basic: all requests of the visa service run one at a time and
    /// in order.
    ///
    /// There are two quick ways to stop the run loop:
    /// - Cancel the passed `ctok` token, which also attempts to first de-register from the visa service.
    /// - Send a [VSCommand::Stop] command, which optionally attempts to de-register from the visa service.
    pub async fn run(&mut self, ctok: CancellationToken) -> Result<(), VSError> {
        info!(target: VS_RPC, "VSConn::run starts");

        // All use of the client is in our little loop. So we honor its non-multithreaded aspect.
        let mut client = match (self.client_fac)(&self.service_addr) {
            Ok(c) => c,
            Err(e) => return Err(e.into()),
        };
        debug!(target: VS_RPC, "client created successfully");
        self.initialize(&mut client)?;
        debug!(target: VS_RPC, "initialize completed successfully");

        let mut deregister_at_exit = true;
        let mut interval = time::interval(PING_INTERVAL);
        let mut ping_errors = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match client.ping_vs() {
                        Ok(ping_resp) => {
                            ping_errors = 0;
                            match self.output_tx.send(VSOutput::PingSuccess(ping_resp.configuration.unwrap() as u64, ping_resp.policy_version.unwrap() as u64)).await {
                                Ok(_) => {}
                                Err(e) => {
                                    error!(target: VS_RPC, "failed to send ping success message: {e}");
                                    return Err(VSError::EnqueueError);
                                }
                            }
                        }
                        Err(e) => {
                            error!(target: VS_RPC, "VSConn::run ping failed: {e}");
                            ping_errors += 1;
                            if ping_errors > MAX_PING_ERRORS {
                                error!(target: VS_RPC, "too many ping errors, assuming we are disconnected");
                                return Err(VSError::Disconnect);
                            }
                        }
                    }
                }
                _ = ctok.cancelled() => {
                    info!(target: VS_RPC, "VSConn::run cancelled");
                    break;
                }

                // Handle one of the "async" requests.
                Some(cmd) = self.cmd_rx.recv() => {
                    match cmd {
                        VSCommand::Stop(de_register) => {
                            info!(target: VS_RPC, "VSConn::run received stop command");
                            deregister_at_exit = de_register;
                            break;
                        },
                        // send errors simply mean requestor ignored reply; ignore them
                        VSCommand::RequestVisa(req, resp_chan) => { let _ = resp_chan.send(Self::handle_request_visa(&mut client, req)); },
                        VSCommand::AuthorizeConnect(cr, resp_chan) => { let _ = resp_chan.send(Self::handle_authorize_connect(&mut client, cr.try_into()?)); },
                        VSCommand::ActorDisconnect(ipa, resp_chan) => { let _ = resp_chan.send(Self::handle_actor_disconnect(&mut client, ipa)); },
                        VSCommand::RequestServices(resp_chan) => { let _ = resp_chan.send(Self::handle_request_services(&mut client)); },
                    }
                }
            }
        } // loop
        if deregister_at_exit {
            if let Err(e) = client.de_register() {
                error!(target: VS_RPC, "failed to de-register: {e}");
            }
        }
        Ok(())
    }

    fn handle_request_visa(
        client: &mut Box<dyn VSClientI>,
        req: VisaRequest,
    ) -> VisaRequestResponse {
        match client.request_visa(req.source_tether_addr, req.l3_type, req.packet) {
            Ok(vr) => Ok(vr),
            Err(e) => {
                error!(target: VS_RPC, "failed to request visa: {e}");
                Err(e)
            }
        }
    }

    fn handle_request_services(client: &mut Box<dyn VSClientI>) -> RequestServicesResponse {
        match client.request_services() {
            Ok(sr) => Ok(sr),
            Err(e) => {
                error!(target: VS_RPC, "failed to request services: {e}");
                Err(e)
            }
        }
    }

    fn handle_authorize_connect(
        client: &mut Box<dyn VSClientI>,
        cr: vsapi::ConnectRequest,
    ) -> AuthorizeConnectResponse {
        match client.authorize_connect(cr) {
            Ok(acr) => {
                let connection = Connection::try_from(acr)?;
                Ok(connection)
            }
            Err(e) => {
                error!(target: VS_RPC, "failed to authorize connect: {e}");
                Err(e)
            }
        }
    }

    fn handle_actor_disconnect(client: &mut Box<dyn VSClientI>, ipa: IpAddr) -> DisconnectStatus {
        match client.actor_disconnect(ipa) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!(target: VS_RPC, "failed to call actor disconnect: {e}");
                Err(e)
            }
        }
    }

    /// Creates a handle which can be used to issue commands to this connection.
    pub fn handle(&self) -> VSConnHandle {
        VSConnHandle {
            cmd_tx: self.cmd_tx.clone(),
        }
    }
}

#[derive(Clone)]
pub struct VSConnHandle {
    cmd_tx: mpsc::Sender<VSCommand>,
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
    pub async fn authorize_connect(&self, req: ConnectRequest) -> AuthorizeConnectResponse {
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

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::*;

    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use rand::Rng;
    use std::env;
    use std::fs;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use zpr::vsapi_types::DenyCode;

    const CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIICETCB+qADAgECAhRmhbwsq9blyxg3Xv5jTvvsJu9/GzANBgkqhkiG9w0BAQsF
ADAYMRYwFAYDVQQDDA1hdXRob3JpdHkuenByMB4XDTI0MTAwMzE5NTQxN1oXDTI1
MTAwMzE5NTQxN1owFzEVMBMGA1UEAwwMbm9kZS56cHIub3JnMCowBQYDK2VuAyEA
GExPGh5RE/nKo8WoN8EqknDDNIEjWBL6PZm08Uhvn0yjTzBNMAsGA1UdDwQEAwID
CDAdBgNVHQ4EFgQUC/Iy9kW1XLoVaA2HYBKqeuiTWNYwHwYDVR0jBBgwFoAURKj/
0t1WK6I3pa9lXmtNRPPpCLQwDQYJKoZIhvcNAQELBQADggEBAG8UlDbtKi6HBLxD
CRgc9LEo80oN0xNme3f/4CMVHOIQnCSVRdgJs4ZhsAnC0rAYam114xeHScb33Irh
nAGd5LdH+X1HpybgS68j9LLfv+waPtSu4EqITOpFKjyOOPhsU0xbHiv2jATcSaQQ
/+n6LMti5MIJyLdiKEwwoPpCRNOBcpELtvrqZKui3sOeauXHcf4hxMcfvcwlypqj
IbgoFcYvTXzozxPIxzpnN+sCFi1FrEI+1ficUQy1Y9q0XM5zv0IF7htI3BE8eu6z
vyUd02GeTskiSa4qzRVh0qG2tcj/FyepN82qII6Lt7xoWEa005T3aaFOcSD2tzzn
s5JVZ48=
-----END CERTIFICATE-----
"#;

    struct TempFile {
        path: String,
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    impl TempFile {
        fn new_pem(contents: &str) -> TempFile {
            let mut rng = rand::thread_rng();
            let tstamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let dir = env::temp_dir();
            let num: u32 = rng.r#gen();
            let path = dir.join(format!("org_zpr_node_vs_test_{}_{}.pem", num, tstamp));
            fs::write(&path, contents).expect("Unable to write file");
            TempFile {
                path: path.to_str().unwrap().to_string(),
            }
        }

        fn get_path(&self) -> &Path {
            Path::new(self.path.as_str())
        }
    }

    // Due to the way the client is instantiated through the simple factory function
    // we keep track our our test state in these static variables here.
    //
    // Turns out that `cargo test` likes to run tests in parallel which is not
    // good for our static state which is shared with all these tests. So there is a
    // MUTEX to protect it which each test acquires for the duration of its run.
    //
    //
    struct TestState {
        auth_count: u32,
        ping_count: u32,
        de_register_count: u32,
        disconnect_count: u32,
        request_services_count: u32,
        next_error: Option<VSClientError>,
    }

    enum CounterT {
        Auth,
        Ping,
        DeRegister,
        ActorDisconnect,
        RequestServices,
    }

    static RUN_LOCK: Mutex<u32> = Mutex::new(0); // Each test holds this while running.

    static TEST_STATE: Mutex<TestState> = Mutex::new(TestState {
        auth_count: 0,
        ping_count: 0,
        de_register_count: 0,
        disconnect_count: 0,
        request_services_count: 0,
        next_error: None,
    });

    fn reset_state() {
        let mut test_state = TEST_STATE.lock().unwrap();
        test_state.auth_count = 0;
        test_state.ping_count = 0;
        test_state.de_register_count = 0;
        test_state.disconnect_count = 0;
        test_state.request_services_count = 0;
        test_state.next_error = None;
    }

    fn get_counter(c: CounterT) -> u32 {
        let test_state = TEST_STATE.lock().unwrap();
        match c {
            CounterT::Auth => test_state.auth_count,
            CounterT::Ping => test_state.ping_count,
            CounterT::DeRegister => test_state.de_register_count,
            CounterT::ActorDisconnect => test_state.disconnect_count,
            CounterT::RequestServices => test_state.request_services_count,
        }
    }

    fn incr(c: CounterT) {
        let mut test_state = TEST_STATE.lock().unwrap();
        match c {
            CounterT::Auth => test_state.auth_count += 1,
            CounterT::Ping => test_state.ping_count += 1,
            CounterT::DeRegister => test_state.de_register_count += 1,
            CounterT::ActorDisconnect => test_state.disconnect_count += 1,
            CounterT::RequestServices => test_state.request_services_count += 1,
        }
    }

    fn set_next_error(e: VSClientError) {
        TEST_STATE.lock().unwrap().next_error = Some(e);
    }

    fn take_next_error() -> Option<VSClientError> {
        TEST_STATE.lock().unwrap().next_error.take()
    }

    #[derive(Debug)]
    struct TestVSCli {}

    impl VSClientI for TestVSCli {
        fn authenticate(
            &mut self,
            _actor: &vsapi::Actor,
            _cert_pem_data: &str,
            _vss_service_addr: SocketAddr,
        ) -> Result<String, VSClientError> {
            incr(CounterT::Auth);
            if let Some(e) = take_next_error() {
                return Err(e);
            }
            Ok(String::from("le_key"))
        }

        fn ping_vs(&mut self) -> Result<vsapi::Pong, VSClientError> {
            incr(CounterT::Ping);
            if let Some(e) = take_next_error() {
                return Err(e);
            }
            Ok(vsapi::Pong {
                configuration: Some(1),
                policy_version: Some(2),
            })
        }

        fn de_register(&mut self) -> Result<(), VSClientError> {
            incr(CounterT::DeRegister);
            if let Some(e) = take_next_error() {
                return Err(e);
            }
            Ok(())
        }

        fn request_visa(
            &mut self,
            source_tether_addr: IpAddr,
            l3_type: L3Type,
            _packet: Vec<u8>,
        ) -> Result<VisaResponse, VSClientError> {
            if let Some(e) = take_next_error() {
                return Err(e);
            }
            let vrr = vsapi::VisaResponse {
                status: Some(vsapi::StatusCode::FAIL),
                visa: None,
                reason: Some(format!("addr: {}, type: {}", source_tether_addr, l3_type)),
            };
            let v = VisaResponse::try_from(vrr)?;
            Ok(v)
        }

        fn authorize_connect(
            &mut self,
            req: vsapi::ConnectRequest,
        ) -> Result<vsapi::ConnectResponse, VSClientError> {
            if let Some(e) = take_next_error() {
                return Err(e);
            }
            let mut attrs = BTreeMap::new();
            match req.claims {
                Some(c) => {
                    for (k, v) in c {
                        attrs.insert(k, v);
                    }
                }
                None => {}
            };
            let agnt = vsapi::Actor {
                actor_type: Some(vsapi::ActorType::ADAPTER),
                attrs: Some(attrs),
                auth_expires: Some(0),
                zpr_addr: None,
                tether_addr: None,
                ident: None,
                provides: None,
            };
            let cr = vsapi::ConnectResponse {
                connection_id: req.connection_id,
                status: Some(vsapi::StatusCode::SUCCESS),
                actor: Some(agnt),
                reason: Some(format!("")),
            };
            Ok(cr)
        }

        fn actor_disconnect(&mut self, _actor_zpr_addr: IpAddr) -> Result<(), VSClientError> {
            incr(CounterT::ActorDisconnect);
            if let Some(e) = take_next_error() {
                return Err(e);
            }
            Ok(())
        }

        fn request_services(&mut self) -> Result<vsapi::ServicesResponse, VSClientError> {
            incr(CounterT::RequestServices);
            if let Some(e) = take_next_error() {
                return Err(e);
            }
            let response = vsapi::ServicesResponse {
                services: Some(vsapi::ServicesList {
                    expiration: Some(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64
                            + 3600,
                    ), // +1 hour
                    services: None,
                }),
            };
            Ok(response)
        }
    }

    fn testvscli_factory(_service_addr: &str) -> Result<Box<dyn VSClientI>, VSClientError> {
        Ok(Box::new(TestVSCli {}))
    }

    #[tokio::test]
    async fn test_start_and_stop_and_ping() {
        let _lockval = RUN_LOCK.lock().unwrap();
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);

        let node_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let (tx, mut _rx) = mpsc::channel(8);

        let mut claims = BTreeMap::new();
        claims.insert(String::from("foo"), String::from("fee"));
        let agnt = new_node_actor(node_addr, &claims);

        let mut conn = VSConn::new(
            agnt,
            tx,
            "127.0.0.1:0",
            certfile.get_path(),
            node_addr,
            None,
        )
        .unwrap();

        conn.set_client_factory(testvscli_factory);

        let ctoken = CancellationToken::new();
        let vs_tok = ctoken.clone();
        tokio::spawn(async move {
            let _ = conn.run(vs_tok).await;
        });

        tokio::time::sleep(Duration::from_millis(500)).await;

        ctoken.cancel(); // stop the vs

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(get_counter(CounterT::Auth), 1);
        assert_eq!(get_counter(CounterT::DeRegister), 1);
        assert_eq!(get_counter(CounterT::Ping), 1);
    }

    #[tokio::test]
    async fn test_stop_command_stops_run_loop() {
        let _lockval = RUN_LOCK.lock().unwrap();
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);

        let node_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let (tx, mut _rx) = mpsc::channel(8);

        let mut claims = BTreeMap::new();
        claims.insert(String::from("foo"), String::from("fee"));
        let agnt = new_node_actor(node_addr, &claims);

        let mut conn = VSConn::new(
            agnt,
            tx,
            "127.0.0.1:0",
            certfile.get_path(),
            node_addr,
            None,
        )
        .unwrap();

        conn.set_client_factory(testvscli_factory);
        let conn_handle = conn.handle();

        let ctoken = CancellationToken::new();
        let vs_tok = ctoken.clone();

        // Spawn the run loop in a separate task
        let run_task = tokio::spawn(async move { conn.run(vs_tok).await });

        // Give the run loop a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send the Stop command
        let _ = conn_handle.cmd_tx.send(VSCommand::Stop(true)).await;

        // Wait for the run loop to exit
        match timeout(Duration::from_millis(500), run_task).await {
            Ok(res) => {
                assert!(res.is_ok(), "Run loop did not exit cleanly");
            }
            Err(_) => {
                panic!("Run loop did not stop after Stop command (timeout)");
            }
        }
    }

    #[tokio::test]
    async fn test_request_services() {
        let _lockval = RUN_LOCK.lock().unwrap();
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);

        let node_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let (tx, mut _rx) = mpsc::channel(8);

        let mut claims = BTreeMap::new();
        claims.insert(String::from("foo"), String::from("fee"));
        let agnt = new_node_actor(node_addr, &claims);

        let mut conn = VSConn::new(
            agnt,
            tx,
            "127.0.0.1:0",
            certfile.get_path(),
            node_addr,
            None,
        )
        .unwrap();

        conn.set_client_factory(testvscli_factory);
        let conn_h = conn.handle();

        let ctoken = CancellationToken::new();
        let vs_tok = ctoken.clone();
        tokio::spawn(async move {
            let _ = conn.run(vs_tok).await;
        });

        tokio::time::sleep(Duration::from_millis(500)).await;

        let _svc_resp = conn_h.request_services().await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        ctoken.cancel(); // stop the vs

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(get_counter(CounterT::Auth), 1);
        assert_eq!(get_counter(CounterT::RequestServices), 1);
        assert_eq!(get_counter(CounterT::DeRegister), 1);
        assert_eq!(get_counter(CounterT::Ping), 1);
    }

    #[tokio::test]
    async fn test_visa_req_resp() {
        let _lockval = RUN_LOCK.lock().unwrap();
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);

        let node_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let (tx, mut rx) = mpsc::channel(8);

        let mut claims = BTreeMap::new();
        claims.insert(String::from("foo"), String::from("fee"));
        let agnt = new_node_actor(node_addr, &claims);

        let mut conn = VSConn::new(
            agnt,
            tx,
            "127.0.0.1:0",
            certfile.get_path(),
            node_addr,
            None,
        )
        .unwrap();

        conn.set_client_factory(testvscli_factory);

        let ctoken = CancellationToken::new();
        let vs_tok = ctoken.clone();
        let conn_handle = conn.handle();
        tokio::spawn(async move {
            let _ = conn.run(vs_tok).await;
        });

        // Should get a ping message
        match timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(resp) => {
                let output = resp.unwrap();
                if !matches!(output, VSOutput::PingSuccess(_, _)) {
                    panic!("expected ping message, not {:?}", output);
                }
            }
            _ => {
                panic!("expected ping message, but got nothing (timeout)");
            }
        }

        let req = VisaRequest {
            source_tether_addr: node_addr,
            l3_type: L3Type::Ipv4,
            packet: vec![1, 2, 3, 4],
        };
        let resp = conn_handle.request_visa(req);

        match timeout(Duration::from_millis(100), resp).await {
            Ok(resp) => {
                let vr = resp.unwrap();

                if let VisaResponse::Deny(denied) = vr {
                    assert_eq!(denied.code, DenyCode::Fail);
                    assert!(denied.reason.is_some());
                    let reason = denied.reason.unwrap();
                    assert!(reason.contains(&node_addr.to_string()));
                    assert!(reason.contains(format!("type: {}", L3Type::Ipv4).as_str()));
                } else {
                    assert!(false);
                }
            }
            _ => {
                panic!("expected visa-response message, but got nothing (timeout)");
            }
        }

        {
            // Run again check that we get the error:
            let req = VisaRequest {
                source_tether_addr: node_addr,
                l3_type: L3Type::Ipv4,
                packet: vec![1, 2, 3, 4],
            };
            set_next_error(VSClientError::NoAPIKey);
            let resp = conn_handle.request_visa(req);
            match timeout(Duration::from_millis(100), resp).await {
                Ok(resp) => {
                    assert!(matches!(resp.unwrap_err(), VSClientError::NoAPIKey));
                }
                _ => {
                    panic!("expected visa-response message, but got nothing (timeout)");
                }
            }
        }

        ctoken.cancel(); // stop the vs
    }

    #[tokio::test]
    async fn test_connect_request() {
        let _lockval = RUN_LOCK.lock().unwrap();
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);

        let node_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let (tx, mut rx) = mpsc::channel(8);

        let mut claims = BTreeMap::new();
        claims.insert(String::from("foo"), String::from("fee"));
        let agnt = new_node_actor(node_addr, &claims);

        let mut conn = VSConn::new(
            agnt,
            tx,
            "127.0.0.1:0",
            certfile.get_path(),
            node_addr,
            None,
        )
        .unwrap();

        conn.set_client_factory(testvscli_factory);

        let ctoken = CancellationToken::new();
        let vs_tok = ctoken.clone();
        let conn_handle = conn.handle();
        tokio::spawn(async move {
            let _ = conn.run(vs_tok).await;
        });

        // Should get a ping message
        match timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(resp) => {
                let output = resp.unwrap();
                if !matches!(output, VSOutput::PingSuccess(_, _)) {
                    panic!("expected ping message, not {:?}", output);
                }
            }
            _ => {
                panic!("expected ping message, but got nothing (timeout)");
            }
        }

        let mut claims = BTreeMap::new();
        claims.insert("foo".to_string(), "fee".to_string());
        claims.insert("hello".to_string(), "goodbye".to_string());

        let req = vsapi::ConnectRequest {
            connection_id: Some(456),
            dock_addr: Some(vec![10, 0, 0, 1]),
            claims: Some(claims.clone()),
            challenge: Some(vec![1, 2, 3, 4]),
            challenge_responses: Some(vec![vec![5, 6, 7, 8]]),
        };
        let resp = conn_handle.authorize_connect(req.try_into().unwrap());

        match timeout(Duration::from_millis(100), resp).await {
            Ok(_resp) => {
                // let cresp = resp.unwrap();
                // assert!(cresp.actor.is_some());
                // let agnt = cresp.actor.unwrap();
                // let attrs = agnt.attrs.unwrap();
                // for (k, v) in attrs {
                //     assert_eq!(v, *(claims.get(&k).unwrap()));
                // }
            }
            _ => {
                panic!("expected connect-response message, but got nothing (timeout)");
            }
        }

        {
            // Run again check that we get the error:
            let req = vsapi::ConnectRequest {
                connection_id: None,
                dock_addr: Some(vec![10, 0, 0, 1]),
                claims: Some(claims.clone()),
                challenge: None,
                challenge_responses: Some(vec![vec![5, 6, 7, 8]]),
            };
            set_next_error(VSClientError::NoAPIKey);
            let resp = conn_handle.authorize_connect(req.try_into().unwrap());
            match timeout(Duration::from_millis(100), resp).await {
                Ok(resp) => {
                    assert!(matches!(resp.unwrap_err(), VSClientError::NoAPIKey));
                }
                _ => {
                    panic!("expected connect-response message, but got nothing (timeout)");
                }
            }
        }

        ctoken.cancel(); // stop the vs
    }

    #[tokio::test]
    async fn test_actor_disconnect() {
        let _lockval = RUN_LOCK.lock().unwrap();
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);

        let node_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let (tx, mut rx) = mpsc::channel(8);

        let mut claims = BTreeMap::new();
        claims.insert(String::from("foo"), String::from("fee"));
        let agnt = new_node_actor(node_addr, &claims);

        let mut conn = VSConn::new(
            agnt,
            tx,
            "127.0.0.1:0",
            certfile.get_path(),
            node_addr,
            None,
        )
        .unwrap();

        conn.set_client_factory(testvscli_factory);

        let ctoken = CancellationToken::new();
        let vs_tok = ctoken.clone();
        let conn_handle = conn.handle();
        tokio::spawn(async move {
            let _ = conn.run(vs_tok).await;
        });

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Should get a ping message
        match timeout(Duration::from_millis(10), rx.recv()).await {
            Ok(resp) => {
                let output = resp.unwrap();
                if !matches!(output, VSOutput::PingSuccess(_, _)) {
                    panic!("expected ping message, not {:?}", output);
                }
            }
            _ => {
                panic!("expected ping message, but got nothing (timeout)");
            }
        }

        assert_eq!(get_counter(CounterT::ActorDisconnect), 0);

        let resp = conn_handle.actor_disconnect(node_addr);

        tokio::time::sleep(Duration::from_millis(100)).await;

        match timeout(Duration::from_millis(10), resp).await {
            Ok(resp) => {
                assert!(resp.is_ok());
            }
            _ => {
                panic!("expected actor-disconnect-response message, but got nothing (timeout)");
            }
        }
        assert_eq!(get_counter(CounterT::ActorDisconnect), 1);

        // Run disconnect again check that we get the error:
        set_next_error(VSClientError::NoAPIKey);
        let resp = conn_handle.actor_disconnect(node_addr);

        match timeout(Duration::from_millis(100), resp).await {
            Ok(resp) => {
                assert!(matches!(resp.unwrap_err(), VSClientError::NoAPIKey));
            }
            _ => {
                panic!("expected actor-disconnect-response message, but got nothing (timeout)");
            }
        }

        ctoken.cancel(); // stop the vs
    }
}
