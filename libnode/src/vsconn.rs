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
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::errors::{VSClientError, VSError};
use crate::vsapi;
use crate::vscli::{self, VSClientI};
use crate::vss::DEFAULT_VSS_PORT;

use zpr;

const PING_INTERVAL: Duration = Duration::from_millis(10000);
const MAX_PING_ERRORS: u32 = 5;

#[derive(Debug)]
pub struct VisaRequest {
    pub request_id: u32,
    pub source_tether_addr: IpAddr,
    pub l3_type: zpr::L3Type,
    pub packet: Vec<u8>,
}

#[derive(Debug)]
pub struct VisaRequestResponse {
    /// Copied from `VisaRequest`
    pub request_id: u32,

    /// If an API error orccess error occurred, this will be set.
    pub api_error: Option<VSClientError>,

    /// Response from visa service -- Even if this is some, it may not be a successful request.
    pub response: Option<vsapi::VisaResponse>,
}

#[derive(Debug)]
pub struct AuthorizeConnectResponse {
    /// Copied from the thrift ConnectRequest
    pub connection_id: i32,

    /// If an API error orccess error occurred, this will be set.
    pub api_error: Option<VSClientError>,

    /// If we got a response from the visa service, it will be here.
    pub response: Option<vsapi::ConnectResponse>,
}

#[derive(Debug)]
pub struct DisconnectStatus {
    pub zpr_addr: IpAddr,
    pub api_error: Option<VSClientError>,
}

// The async "commands" that can be sent into the running visa service client.
#[derive(Debug)]
#[allow(dead_code)]
enum VSCommand {
    RequestVisa(VisaRequest, oneshot::Sender<VisaRequestResponse>),
    AuthorizeConnect(
        vsapi::ConnectRequest,
        oneshot::Sender<AuthorizeConnectResponse>,
    ),
    AgentDisconnect(IpAddr, oneshot::Sender<DisconnectStatus>), // takes a ZPR address assigned to the agent
}

// This will change a bit too. This is for output messages from the visa service. These are asynchronous
// messages so the request/response pairs will need to include an operation ID or some such so that the
// node can match responses to requests.
#[derive(Debug)]
pub enum VSOutput {
    PingSuccess(u64, u64), // (CONFIG_ID, POLICY_VERSION)
}

#[derive(Clone)]
pub struct VSConn {
    shared: Arc<Shared>,
}

struct Shared {
    state: Mutex<State>,
}

struct State {
    service_addr: String, // visa service address, format "HOST:PORT"
    node_cert_pem_data: String,
    cmd_tx: Option<mpsc::Sender<VSCommand>>,
    output_tx: mpsc::Sender<VSOutput>,
    client_fac: vscli::VSClientFactory,
    vss_service_addr: SocketAddr, // visa support service listen address
    agent: vsapi::Agent,
}

/// Helper function to create a basic node agent. Probably only useful for early versions
/// of the node.  In the future the node will create it's own agent datastructure and
/// had it to [VSConn::new].
pub fn new_node_agent(
    node_addr: &IpAddr,
    node_name: &str,
    claims: &BTreeMap<String, String>,
) -> vsapi::Agent {
    let provides = vec![format!("/zpr/{}", node_name)];

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
    augmented_claims.insert(String::from("zpr.addr"), node_addr.to_string());

    vsapi::Agent {
        agent_type: Some(vsapi::AgentType::NODE),
        attrs: Some(augmented_claims),
        auth_expires: Some((timestamp + 60 * 60) as i64),
        zpr_addr: Some(zaddr_bytes),
        tether_addr: Some(taddr_bytes),
        ident: Some(String::from("ident-not-generated")), // TODO
        provides: Some(provides),
    }
}

/// The VSConn will manage all communication with the visa service on behalf of the node.
/// To clealy shutdown the visa service, cancel the token passed to `run' function.
///
impl VSConn {
    /// Create a new Visa Service Connection manager.
    ///
    /// - `node_agent` is the node's Agent representation.  See [new_node_agent] for a helper function to create this.
    /// - `output_tx` is the channel to send output messages to the node.
    /// - `service_addr` is ADDR:PORT of the visa service (ADDR should be a ZPR address)
    /// - `node_cert_file` is the path to the node's signed (for now) EC certificate file
    /// - `node_zpr_addr` node ZPR address (not substrate address) as set by network admin
    /// - `vss_service_addr` optionally override the default listen address for the visa
    ///   support service. If not set, then we will advertise `<NODE_ZPR_ADDR>:<DEFAULT_VSS_PORT>`.
    //
    pub fn new(
        node_agent: vsapi::Agent,
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

        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                service_addr: service_addr.to_string(),
                node_cert_pem_data: cert_pem_data,
                cmd_tx: None,
                output_tx: output_tx,
                client_fac: vscli::default_vsclient_factory,
                vss_service_addr,
                agent: node_agent,
            }),
        });

        Ok(VSConn { shared })
    }

    #[cfg(test)]
    fn set_client_factory(&self, fac: vscli::VSClientFactory) {
        let mut state = self.shared.state.lock().unwrap();
        state.client_fac = fac;
    }

    /// Registers with visa service and obtains an API key.
    /// Blocking network call.
    fn initialize(&self, client: &mut Box<dyn VSClientI>) -> Result<(), VSError> {
        info!("VSConn::initialize starts");

        let pem_data: String;
        let vss_svc_addr;
        let agnt: vsapi::Agent;
        {
            let state = self.shared.state.lock().unwrap();
            pem_data = state.node_cert_pem_data.clone();
            vss_svc_addr = state.vss_service_addr;
            agnt = state.agent.clone();
        }

        let _apikey = match client.authenticate(agnt, &pem_data, vss_svc_addr) {
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
    pub async fn run(&self, ctok: CancellationToken) -> Result<(), VSError> {
        info!("VSConn::run starts");

        let (tx, mut rx) = mpsc::channel(16);
        let fac: vscli::VSClientFactory;
        let service_addr: String;
        let output_tx: mpsc::Sender<VSOutput>;
        {
            let mut state = self.shared.state.lock().unwrap(); // TAKES LOCK (drops when state goes out of scope)
            state.cmd_tx = Some(tx.clone());
            output_tx = state.output_tx.clone();
            fac = state.client_fac.clone();
            service_addr = state.service_addr.clone();
        }

        // All use of the client is in our little loop. So we honor its non-multithreaded aspect.
        let mut client = match (fac)(&service_addr) {
            Ok(c) => c,
            Err(e) => return Err(e.into()),
        };
        self.initialize(&mut client)?;

        let mut interval = time::interval(PING_INTERVAL);
        let mut ping_errors = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match client.ping_vs() {
                        Ok(ping_resp) => {
                            ping_errors = 0;
                            match output_tx.send(VSOutput::PingSuccess(ping_resp.configuration.unwrap() as u64, ping_resp.policy_version.unwrap() as u64)).await {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("failed to send ping success message: {}", e);
                                    return Err(VSError::EnqueueError);
                                }
                            }
                        }
                        Err(e) => {
                            error!("VSConn::run ping failed: {}", e);
                            ping_errors += 1;
                            if ping_errors > MAX_PING_ERRORS {
                                error!("too many ping errors, assuming we are disconnected");
                                return Err(VSError::Disconnect);
                            }
                        }
                    }
                }
                _ = ctok.cancelled() => {
                    info!("VSConn::run cancelled");
                    if let Err(e) = client.de_register() {
                        error!("failed to de-register: {}", e);
                    }
                    break;
                }

                // Handle one of the "async" requests.
                Some(cmd) = rx.recv() => {
                    match cmd {
                        // send errors simply mean requestor ignored reply; ignore them
                        VSCommand::RequestVisa(req, resp_chan) => { let _ = resp_chan.send(self.handle_request_visa(&mut client, req)); },
                        VSCommand::AuthorizeConnect(cr, resp_chan) => { let _ = resp_chan.send(self.handle_authorize_connect(&mut client, cr)); },
                        VSCommand::AgentDisconnect(ipa, resp_chan) => { let _ = resp_chan.send(self.handle_agent_disconnect(&mut client, ipa)); },
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_request_visa(
        &self,
        client: &mut Box<dyn VSClientI>,
        req: VisaRequest,
    ) -> VisaRequestResponse {
        match client.request_visa(req.source_tether_addr, req.l3_type, req.packet) {
            Ok(vr) => VisaRequestResponse {
                request_id: req.request_id,
                api_error: None,
                response: Some(vr),
            },
            Err(e) => {
                error!("failed to request visa: {}", e);
                VisaRequestResponse {
                    request_id: req.request_id,
                    api_error: Some(e),
                    response: None,
                }
            }
        }
    }

    fn handle_authorize_connect(
        &self,
        client: &mut Box<dyn VSClientI>,
        cr: vsapi::ConnectRequest,
    ) -> AuthorizeConnectResponse {
        let id = match cr.connection_id {
            Some(i) => i,
            None => 0,
        };
        match client.authorize_connect(cr) {
            Ok(acr) => AuthorizeConnectResponse {
                connection_id: id,
                api_error: None,
                response: Some(acr),
            },
            Err(e) => {
                error!("failed to authorize connect: {}", e);
                AuthorizeConnectResponse {
                    connection_id: id,
                    api_error: Some(e),
                    response: None,
                }
            }
        }
    }

    fn handle_agent_disconnect(
        &self,
        client: &mut Box<dyn VSClientI>,
        ipa: IpAddr,
    ) -> DisconnectStatus {
        match client.agent_disconnect(ipa) {
            Ok(_) => DisconnectStatus {
                zpr_addr: ipa,
                api_error: None,
            },
            Err(e) => {
                error!("ailed to call agent disconnect: {}", e);
                DisconnectStatus {
                    zpr_addr: ipa,
                    api_error: Some(e),
                }
            }
        }
    }

    /// Attempt to enqueue an async command to the runloop.
    /// Returns an error if the command could not be enqueued.
    async fn send_command(&self, cmd: VSCommand) -> Result<(), VSError> {
        // Extract the tx channel from the state, but must do so without keeping lock across the await later.
        let tx_chan: mpsc::Sender<VSCommand>;
        {
            let state = self.shared.state.lock().unwrap(); // TAKES LOCK (drops when state goes out of scope)
            if let Some(tx) = &state.cmd_tx {
                tx_chan = tx.clone();
            } else {
                error!("VSConn::send_command called but no command channel available");
                return Err(VSError::EnqueueError);
            }
        }

        if let Err(e) = tx_chan.send(cmd).await {
            error!("VSConn::send_command failed to queue: {}", e);
            return Err(VSError::EnqueueError);
        }
        Ok(())
    }

    /// Perform an async visa request. The response will have a request_id matching the request.
    ///
    /// ## Errors
    /// - [VSError::EnqueueError] if the request could not be enqueued.
    pub async fn request_visa(&self, req: VisaRequest) -> Result<VisaRequestResponse, VSError> {
        let (tx, rx) = oneshot::channel();
        self.send_command(VSCommand::RequestVisa(req, tx)).await?;
        rx.await.map_err(|_| VSError::Disconnect)
    }

    /// Perform an async authorize_connect. The response will have a connection_id matching the request.
    ///
    /// ## Errors
    /// - [VSError::EnqueueError] if the request could not be enqueued.
    pub async fn authorize_connect(
        &self,
        req: vsapi::ConnectRequest,
    ) -> Result<AuthorizeConnectResponse, VSError> {
        let (tx, rx) = oneshot::channel();
        self.send_command(VSCommand::AuthorizeConnect(req, tx))
            .await?;
        rx.await.map_err(|_| VSError::Disconnect)
    }

    /// Async message to visa service noting that an agent has disconnected. The response is
    /// a [DisconnectStatus].
    ///
    /// ## Errors
    /// - [VSError::EnqueueError] if the request could not be enqueued.
    pub async fn agent_disconnect(&self, zpr_addr: IpAddr) -> Result<DisconnectStatus, VSError> {
        let (tx, rx) = oneshot::channel();
        self.send_command(VSCommand::AgentDisconnect(zpr_addr, tx))
            .await?;
        rx.await.map_err(|_| VSError::Disconnect)
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
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
            let num: u32 = rng.gen();
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
        next_error: Option<VSClientError>,
    }

    enum CounterT {
        Auth,
        Ping,
        DeRegister,
        AgentDisconnect,
    }

    static mut RUN_LOCK: Mutex<u32> = Mutex::new(0); // Each test holds this while running.

    static mut TEST_STATE: TestState = TestState {
        auth_count: 0,
        ping_count: 0,
        de_register_count: 0,
        disconnect_count: 0,
        next_error: None,
    };

    fn reset_state() {
        unsafe {
            TEST_STATE.auth_count = 0;
            TEST_STATE.ping_count = 0;
            TEST_STATE.de_register_count = 0;
            TEST_STATE.disconnect_count = 0;
            TEST_STATE.next_error = None;
        }
    }

    fn get_counter(c: CounterT) -> u32 {
        unsafe {
            match c {
                CounterT::Auth => TEST_STATE.auth_count,
                CounterT::Ping => TEST_STATE.ping_count,
                CounterT::DeRegister => TEST_STATE.de_register_count,
                CounterT::AgentDisconnect => TEST_STATE.disconnect_count,
            }
        }
    }

    fn incr(c: CounterT) {
        unsafe {
            match c {
                CounterT::Auth => TEST_STATE.auth_count += 1,
                CounterT::Ping => TEST_STATE.ping_count += 1,
                CounterT::DeRegister => TEST_STATE.de_register_count += 1,
                CounterT::AgentDisconnect => TEST_STATE.disconnect_count += 1,
            }
        }
    }

    fn set_next_error(e: VSClientError) {
        unsafe {
            TEST_STATE.next_error = Some(e);
        }
    }

    fn take_next_error() -> Option<VSClientError> {
        unsafe { TEST_STATE.next_error.take() }
    }

    #[derive(Debug)]
    struct TestVSCli {}

    impl VSClientI for TestVSCli {
        fn authenticate(
            &mut self,
            _agent: vsapi::Agent,
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
            l3_type: zpr::L3Type,
            _packet: Vec<u8>,
        ) -> Result<vsapi::VisaResponse, VSClientError> {
            if let Some(e) = take_next_error() {
                return Err(e);
            }
            let vrr = vsapi::VisaResponse {
                status: Some(vsapi::StatusCode::FAIL),
                visa: None,
                reason: Some(format!("addr: {}, type: {}", source_tether_addr, l3_type)),
            };
            Ok(vrr)
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
            let agnt = vsapi::Agent {
                agent_type: Some(vsapi::AgentType::ADAPTER),
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
                agent: Some(agnt),
                reason: Some(format!("")),
            };
            Ok(cr)
        }

        fn agent_disconnect(&mut self, _agent_zpr_addr: IpAddr) -> Result<(), VSClientError> {
            incr(CounterT::AgentDisconnect);
            if let Some(e) = take_next_error() {
                return Err(e);
            }
            Ok(())
        }
    }

    fn testvscli_factory(_service_addr: &str) -> Result<Box<dyn VSClientI>, VSClientError> {
        Ok(Box::new(TestVSCli {}))
    }

    #[tokio::test]
    async fn test_start_and_stop_and_ping() {
        let _lockval = unsafe { RUN_LOCK.lock().unwrap() };
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);

        let node_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let (tx, mut _rx) = mpsc::channel(8);

        let mut claims = BTreeMap::new();
        claims.insert(String::from("foo"), String::from("fee"));
        let agnt = new_node_agent(&node_addr, "n0", &claims);

        let conn = VSConn::new(
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
    async fn test_visa_req_resp() {
        let _lockval = unsafe { RUN_LOCK.lock().unwrap() };
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);

        let node_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let (tx, mut rx) = mpsc::channel(8);

        let mut claims = BTreeMap::new();
        claims.insert(String::from("foo"), String::from("fee"));
        let agnt = new_node_agent(&node_addr, "n0", &claims);

        let conn = VSConn::new(
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
        let sp_conn = conn.clone();
        tokio::spawn(async move {
            let _ = sp_conn.run(vs_tok).await;
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
            request_id: 123,
            source_tether_addr: node_addr,
            l3_type: zpr::L3Type::Ipv4,
            packet: vec![1, 2, 3, 4],
        };
        let resp = conn.request_visa(req);

        match timeout(Duration::from_millis(100), resp).await {
            Ok(resp) => {
                let vrr = resp.unwrap();
                assert_eq!(vrr.request_id, 123);
                assert!(vrr.api_error.is_none());
                assert!(vrr.response.is_some());
                let vr = vrr.response.unwrap();
                assert_eq!(vr.status, Some(vsapi::StatusCode::FAIL));
                assert!(vr.reason.is_some());
                let reason = vr.reason.unwrap();
                assert!(reason.contains(&node_addr.to_string()));
                assert!(reason.contains(format!("type: {}", zpr::L3Type::Ipv4).as_str()));
            }
            _ => {
                panic!("expected visa-response message, but got nothing (timeout)");
            }
        }

        {
            // Run again check that we get the error:
            let req = VisaRequest {
                request_id: 123,
                source_tether_addr: node_addr,
                l3_type: zpr::L3Type::Ipv4,
                packet: vec![1, 2, 3, 4],
            };
            set_next_error(VSClientError::NoAPIKey);
            let resp = conn.request_visa(req);
            match timeout(Duration::from_millis(100), resp).await {
                Ok(resp) => {
                    let vrr = resp.unwrap();
                    assert_eq!(vrr.request_id, 123);
                    assert!(vrr.api_error.is_some());
                    assert!(matches!(vrr.api_error.unwrap(), VSClientError::NoAPIKey));
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
        let _lockval = unsafe { RUN_LOCK.lock().unwrap() };
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);

        let node_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let (tx, mut rx) = mpsc::channel(8);

        let mut claims = BTreeMap::new();
        claims.insert(String::from("foo"), String::from("fee"));
        let agnt = new_node_agent(&node_addr, "n0", &claims);

        let conn = VSConn::new(
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
        let sp_conn = conn.clone();
        tokio::spawn(async move {
            let _ = sp_conn.run(vs_tok).await;
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
        let resp = conn.authorize_connect(req);

        match timeout(Duration::from_millis(100), resp).await {
            Ok(resp) => {
                let cr = resp.unwrap();
                assert_eq!(cr.connection_id, 456);
                assert!(cr.api_error.is_none());
                assert!(cr.response.is_some());
                let cresp = cr.response.unwrap();
                assert!(cresp.agent.is_some());
                let agnt = cresp.agent.unwrap();
                let attrs = agnt.attrs.unwrap();
                for (k, v) in attrs {
                    assert_eq!(v, *(claims.get(&k).unwrap()));
                }
            }
            _ => {
                panic!("expected connect-response message, but got nothing (timeout)");
            }
        }

        {
            // Run again check that we get the error:
            let req = vsapi::ConnectRequest {
                connection_id: Some(456),
                dock_addr: None,
                claims: None,
                challenge: None,
                challenge_responses: None,
            };
            set_next_error(VSClientError::NoAPIKey);
            let resp = conn.authorize_connect(req);
            match timeout(Duration::from_millis(100), resp).await {
                Ok(resp) => {
                    let cr = resp.unwrap();
                    assert_eq!(cr.connection_id, 456);
                    assert!(cr.api_error.is_some());
                    assert!(matches!(cr.api_error.unwrap(), VSClientError::NoAPIKey));
                }
                _ => {
                    panic!("expected connect-response message, but got nothing (timeout)");
                }
            }
        }

        ctoken.cancel(); // stop the vs
    }

    #[tokio::test]
    async fn test_agent_disconnect() {
        let _lockval = unsafe { RUN_LOCK.lock().unwrap() };
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);

        let node_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let (tx, mut rx) = mpsc::channel(8);

        let mut claims = BTreeMap::new();
        claims.insert(String::from("foo"), String::from("fee"));
        let agnt = new_node_agent(&node_addr, "n0", &claims);

        let conn = VSConn::new(
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
        let sp_conn = conn.clone();
        tokio::spawn(async move {
            let _ = sp_conn.run(vs_tok).await;
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

        assert_eq!(get_counter(CounterT::AgentDisconnect), 0);

        let resp = conn.agent_disconnect(node_addr);

        tokio::time::sleep(Duration::from_millis(100)).await;

        match timeout(Duration::from_millis(10), resp).await {
            Ok(resp) => {
                let dr = resp.unwrap();
                assert_eq!(dr.zpr_addr, node_addr);
                assert!(dr.api_error.is_none());
            }
            _ => {
                panic!("expected agent-disconnect-response message, but got nothing (timeout)");
            }
        }
        assert_eq!(get_counter(CounterT::AgentDisconnect), 1);

        // Run disconnect again check that we get the error:
        set_next_error(VSClientError::NoAPIKey);
        let resp = conn.agent_disconnect(node_addr);

        match timeout(Duration::from_millis(100), resp).await {
            Ok(resp) => {
                let dr = resp.unwrap();
                assert_eq!(dr.zpr_addr, node_addr);
                assert!(dr.api_error.is_some());
                assert!(matches!(dr.api_error.unwrap(), VSClientError::NoAPIKey));
            }
            _ => {
                panic!("expected agent-disconnect-response message, but got nothing (timeout)");
            }
        }

        ctoken.cancel(); // stop the vs
    }
}
