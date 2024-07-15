use openssl::pkey::Private;
use openssl::rsa::Rsa;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tokio::sync::mpsc::{self, Sender};
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;

use crate::vs::vscli::{self, VSClientI};
use crate::vsapi;

use tracing::{error, info};

// Node will start up a visa service client process when:
//   1- During a bootstrap when nothing is connected, the well-known visa service adapter connects.
//   2- Another node may open a link to us and tell us how to get to the visa service.
//
// Either way, the next step is registering with the visa service.
// Registration is:
//
//     NODE -> VS:  Hello()
//     NODE <- VS:  HelloResponse(challenge)
//     NODE -> VS:  Authenticate(challenge + challenge_response)
//     NODE <- VS:  Ok(apikey)
//
//   At this point the node is "registered" with the visa service.
//   TODO: The node should call authroize_connect on itself once registered.
//
//   Now the node can request visas or call for connect authorizations.
//
//   Also the node should set up a polling loop to respond to pushed visas and revocations
//   from the visa service.
//


const POLL_INTERVAL: Duration = Duration::from_millis(5000);
const MAX_POLL_ERRORS: u32 = 5;

#[derive(Debug, Clone)]
pub struct VSConn {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    service_addr: String, // visa service listen address, format "HOST:PORT"
    claims: BTreeMap<String, String>,
    node_private_key: Rsa<Private>,
    node_cert_pem_data: String,
    api_key: Option<String>,
    node_addr: IpAddr,
    cmd_tx: Option<mpsc::Sender<VSCommand>>,
    output_tx: Option<mpsc::Sender<VSOutput>>,
    client_fac: vscli::VSClientFactory,
}

// This is a place holder for the async "commands" that can be sent into the running visa service client.
// Clearly there will be arguments attached to these in the future.
// Also need to figure out how the responses are routed back out.
#[derive(Debug)]
#[allow(dead_code)]
enum VSCommand {
    RequestVisa,
    AuthorizeConnect,
    AgentDisconnect,
}

// This will change a bit too. This is for output messages from the visa service. These are asynchronous
// messages so the request/response pairs will need to include an operation ID or some such so that the
// node can match responses to requests.
#[derive(Debug)]
pub enum VSOutput {
    // Eventually this will include visa-accepts/denies, connect-accepts/denies, etc.
    PushedVisa(Visa),
    PushedRevocation(Revocation),
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub struct Visa {
    pub hop_count: u32,
    pub issuer_id: u32,
    pub visa_pb: Vec<u8>, // TODO: Visas are still in serialized protocol buffer format
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Revocation {
    pub issuer_id: u32,
    pub configuration_id: u64,
}






/// The VSConn will manage all communication with the visa service on behalf of the node.
///
/// To use:
/// - Create a new one with `new(...)``
/// - Add any claims from node configuration with `add_claim(...)`
/// - Initialize with `initialize()`
/// - Finally call `run()`
///
/// To clealy shutdown the visa service, cancel the token passed to `run' function.
//
impl VSConn {
    /// - `output_tx` is the channel to send output messages to the node.
    /// - `service_addr` is ADDR:PORT of the visa service (ADDR should be a ZPR address)
    /// - `node_cert_file` is the path to the node's signed certificate file
    /// - `node_key_file` is the path to the node's private key file
    /// - `node_addr` is the ZPR address of the node (from node config file).
    //
    pub fn new(
        output_tx: Sender<VSOutput>,
        service_addr: &str,
        node_cert_file: &str,
        node_key_file: &str,
        node_addr: IpAddr,
    ) -> Result<VSConn, Error> {
        let mut certfile = match File::open(node_cert_file) {
            Ok(f) => f,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("failed to open cert file: {}", e),
                ));
            }
        };
        let mut cert_pem_data = String::new();
        certfile.read_to_string(&mut cert_pem_data)?;

        let mut keyfile = match File::open(node_key_file) {
            Ok(f) => f,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("failed to open private key file: {}", e),
                ));
            }
        };
        let mut key_pem_data = String::new();
        keyfile.read_to_string(&mut key_pem_data)?;

        let private_key = match Rsa::private_key_from_pem(key_pem_data.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to parse private RSA key: {}: {}", node_key_file, e),
                ));
            }
        };

        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                service_addr: service_addr.to_string(),
                claims: BTreeMap::new(),
                node_private_key: private_key,
                node_cert_pem_data: cert_pem_data,
                api_key: None,
                node_addr,
                cmd_tx: None,
                output_tx: Some(output_tx),
                client_fac: vscli::default_vsclient_factory,
            }),
        });

        Ok(VSConn { shared })
    }

    pub fn add_claim(&self, key: &str, value: &str) {
        let mut state = self.shared.state.lock().unwrap();
        state.claims.insert(String::from(key), String::from(value));
    }


    /// Must be callled before run.  This registers with visa service and obtains an API key.
    /// Blocking network call.
    pub fn initialize(&self, fac_override: Option<vscli::VSClientFactory>) -> Result<(), Error> {
        info!("VSConn::initialize starts");

        let mut state = self.shared.state.lock().unwrap(); // TAKES LOCK (drops when state goes out of scope)

        if let Some(f) = fac_override {
            state.client_fac = f;
        }

        let vsc = (state.client_fac)(&state.service_addr);

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let provides = vec![String::from("/zpr/node")];

        // In prototype, the node zpr address is the same as its tether address. May not be true going forward.
        let zaddr_bytes = match state.node_addr {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        let taddr_bytes = zaddr_bytes.clone();

        let agent = vsapi::Agent {
            agent_type: Some(vsapi::AgentType::NODE),
            attrs: Some(state.claims.clone()),
            auth_expires: Some((timestamp + 60 * 60) as i64),
            zpr_addr: Some(zaddr_bytes),
            tether_addr: Some(taddr_bytes),
            ident: Some(String::from("ident-not-generated")), // TODO
            provides: Some(provides),
        };

        let apikey = match vsc.authenticate(
            agent,
            &state.node_cert_pem_data,
            state.node_private_key.clone(),
        ) {
            Ok(k) => k,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to authenticate with visa service: {}", e),
                ));
            }
        };

        state.api_key = Some(apikey);
        Ok(())
    }

    /// Blocking async-friendly call.  Sets ip a polling loop. Eventually will handle all other visa service duties.
    /// Does not return until we are disconnected from the visa service or the passed token is cancelled.
    pub async fn run(&self, ctok: CancellationToken) -> Result<(), Error> {
        info!("VSConn::run starts");

        let (tx, mut rx) = mpsc::channel(16);
        let maybe_apikey: Option<String>;
        let output_tx: Sender<VSOutput>;
        let vsc: Box<dyn VSClientI>;
        {
            let mut state = self.shared.state.lock().unwrap(); // TAKES LOCK (drops when state goes out of scope)
            state.cmd_tx = Some(tx.clone());
            maybe_apikey = state.api_key.clone();
            output_tx = state.output_tx.clone().unwrap();
            vsc = (state.client_fac)(&state.service_addr);
        }

        let apikey = match maybe_apikey {
            Some(k) => k,
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "VSConn::run called but not initialized",
                ));
            }
        };

        let mut interval = time::interval(POLL_INTERVAL);
        let mut poll_errors = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.do_poll(&vsc) {
                        Ok((visas, revokes, more)) => {
                            poll_errors = 0;
                            if more {
                                info!("VSConn::run poll signals there is more data ... ignoring for now");
                            }
                            for v in visas {
                                let _ = output_tx.send(VSOutput::PushedVisa(v)).await;
                            }
                            for r in revokes {
                                let _ = output_tx.send(VSOutput::PushedRevocation(r)).await;
                            }
                        }
                        Err(e) => {
                            error!("VSConn::run poll failed: {}", e);
                            poll_errors += 1;
                            if poll_errors > MAX_POLL_ERRORS {
                                error!("VSConn::run too many poll errors, assuming we are disconnected");
                                break;
                            }
                        }
                    }
                }
                _ = ctok.cancelled() => {
                    info!("VSConn::run cancelled");
                    if let Err(e) = vsc.de_register(&apikey) {
                        error!("VSConn::run failed to de-register: {}", e);
                    }
                    break;
                }
                Some(cmd) = rx.recv() => {
                    info!("VSConn::run received command: {:?}", cmd);
                }
            }
        }
        Ok(())
    }

    async fn send_command(&self, cmd: VSCommand) -> Result<(), Error> {
        // Extract the tx channel from the state, but must do so without keeping lock across the await later.
        let tx_chan: Sender<VSCommand>;
        {
            let state = self.shared.state.lock().unwrap(); // TAKES LOCK (drops when state goes out of scope)
            if let Some(tx) = &state.cmd_tx {
                tx_chan = tx.clone();
            } else {
                error!("VSConn::send_command called but no command channel available");
                return Err(Error::new(
                    ErrorKind::Other,
                    "VSConn::send_command called but no command channel available",
                ));
            }
        }

        if let Err(e) = tx_chan.send(cmd).await {
            error!("VSConn::send_command failed: {}", e);
            return Err(Error::new(ErrorKind::Other, "VSConn::send_command failed"));
        }
        Ok(())
    }

    // Blocking network call -- holds the state lock too.
    fn do_poll(&self, vsc: &Box<dyn VSClientI>) -> Result<(Vec<Visa>, Vec<Revocation>, bool), Error> {
        let state = self.shared.state.lock().unwrap(); // TAKES LOCK (drops when state goes out of scope)
        let apikey = match &state.api_key {
            Some(k) => k,
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "VSConn::do_poll called but not initialized",
                ));
            }
        };

        // let vsc = (state.client_fac)(&state.service_addr);
        match vsc.poll_vs(apikey) {
            Ok(poll_resp) => {
                let mut visas = Vec::<Visa>::new();
                let mut revocations = Vec::<Revocation>::new();
                let more = poll_resp.more.unwrap() > 0;
                if let Some(pr_visas) = poll_resp.visas {
                    for v in pr_visas {
                        visas.push(Visa {
                            hop_count: v.hop_count.unwrap() as u32,
                            issuer_id: v.issuer_id.unwrap() as u32,
                            visa_pb: v.visa_pb.unwrap(),
                        });
                    }
                }
                if let Some(pr_revokes) = poll_resp.revocations {
                    for r in pr_revokes {
                        revocations.push(Revocation {
                            issuer_id: r.issuer_id.unwrap() as u32,
                            configuration_id: r.configuration.unwrap() as u64,
                        });
                    }
                }
                return Ok((visas, revocations, more));
            }
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("VSConn::do_poll failed: {}", e),
                ));
            }
        }
    }

    /// PLACEHOLDER for request-visa operation
    #[allow(dead_code)]
    pub async fn request_visa(&self) -> Result<(), Error> {
        self.send_command(VSCommand::RequestVisa).await
    }

    /// PLACEHOLDER for authorize-connect operation
    #[allow(dead_code)]
    pub async fn authorize_connect(&self) -> Result<(), Error> {
        self.send_command(VSCommand::AuthorizeConnect).await
    }

    /// PLACEHOLDER for agent-disconnect operation
    #[allow(dead_code)]
    pub async fn agent_disconnect(&self) -> Result<(), Error> {
        self.send_command(VSCommand::AgentDisconnect).await
    }
}




#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::*;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use rand::Rng;
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};







    const CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIIEWzCCA0OgAwIBAgIJAMSVUe6Pd/Z7MA0GCSqGSIb3DQEBBQUAMIGGMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCS1kxDjAMBgNVBAcMBVZpbGxlMRAwDgYDVQQKDAdz
dXJlbmV0MRYwFAYDVQQLDA1hdXRob3JpemF0aW9uMRcwFQYDVQQDDA5hdXRoMC5p
bnRlcm5hbDEXMBUGCSqGSIb3DQEJARYIYXV0aEBmb28wHhcNMjQwNjE4MTQzMjI4
WhcNMjUwNjE4MTQzMjI4WjBLMQswCQYDVQQGEwJVUzELMAkGA1UECAwCS1kxCzAJ
BgNVBAoMAllZMQswCQYDVQQLDAJaWjEVMBMGA1UEAwwMdGVzdG5vZGUuenByMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk0x4ui48znwmmnbeVrRMXeiz
DdR2EKbZwsoW/sfePCTa50UJHgA3vPPTGhJTTfjJrVyp2nazpaBuy66h85PQWS2x
FqstxHVTj0+CF4t+YKUyHFZiF2rLWQonO5R43v489NF9JHKH2SgxKMjTsPpJY8sd
yFgUTbiD6G8T/j/ZIojBIkQG2wWNpdjqUDnzeaU32MGHV8iigUrpc3xDqw+RWhKP
kPjoyInoA4tNNrfHrddu61w3FPx6KTN1L8UV9K+BlNW/s3buluYMSi2vW24fjdTn
F3ev2+w+QUcvWP94/pFRiLEDAO+LO3hxFC16qNU33LMvAo8BdJvPG3GbN2+fIwID
AQABo4IBBDCCAQAwgaUGA1UdIwSBnTCBmqGBjKSBiTCBhjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAktZMQ4wDAYDVQQHDAVWaWxsZTEQMA4GA1UECgwHc3VyZW5ldDEW
MBQGA1UECwwNYXV0aG9yaXphdGlvbjEXMBUGA1UEAwwOYXV0aDAuaW50ZXJuYWwx
FzAVBgkqhkiG9w0BCQEWCGF1dGhAZm9vggkA70drsV9niiUwCQYDVR0TBAIwADAL
BgNVHQ8EBAMCBPAwHwYDVR0RBBgwFoIUYXV0aDAuc3BhY2VsYXNlci5uZXQwHQYD
VR0OBBYEFFdtDdU6IP12wNv4YUdyZejdx8EaMA0GCSqGSIb3DQEBBQUAA4IBAQBp
gM2xMYgo6ntaPTV7xhLmAbwlhoKBt3I+i6KQUU9Ec/3AEiiZsyQxcPHAtmeU4han
5JpOK3hUYVH/SaSj2BHqkXH0yfFyIkAf0V1UsfWwcD8OEZffb5yP02RzIWCqdBN7
pdx9gtGwy4l779FNvHGQ8AI4y+cpxwiXyBiXdB3Mv1wG5gUNe4pGk7JWA5lb9XQ9
sOwVMjkwcUsqGr489gqYRWl1mAMz1D2T+U91HavGybvUBlgb/3+dgjksa/ZWTUhD
2CRFn7sqmwcPHLoGV/+yCjjuheyx+z7LrPqyqPfWwrr68udK4Yqz8iiqwMC1b8m0
1Hm6nwN1sHYkYgYgk/Ey
-----END CERTIFICATE-----
"#;

    const KEY_DATA: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCTTHi6LjzOfCaa
dt5WtExd6LMN1HYQptnCyhb+x948JNrnRQkeADe889MaElNN+MmtXKnadrOloG7L
rqHzk9BZLbEWqy3EdVOPT4IXi35gpTIcVmIXastZCic7lHje/jz00X0kcofZKDEo
yNOw+kljyx3IWBRNuIPobxP+P9kiiMEiRAbbBY2l2OpQOfN5pTfYwYdXyKKBSulz
fEOrD5FaEo+Q+OjIiegDi002t8et127rXDcU/HopM3UvxRX0r4GU1b+zdu6W5gxK
La9bbh+N1OcXd6/b7D5BRy9Y/3j+kVGIsQMA74s7eHEULXqo1Tfcsy8CjwF0m88b
cZs3b58jAgMBAAECggEAQYQ8FqPGTBmQmhfRIUOkzAhazAX6VcHBDhERVVXVFW9X
JpLgUUXLhPH2rZwFDaNhIQkcS52MnljTrykHw+21OFVIdUrCWqXM+utkc9CJ77bK
qSwLCVtpAzuu46NQd+8hcctUHEgNAJwN8ZQSBJ/u0MJhhuEWdtNhaJsvi2Ee1WrN
ZvUkpn6SpCHVvEtZjJZL0elQrgk7EMzWSWz/1a8ORzbmBDw5X/0dV/VKCfx1kJ+w
9fmIhfGU3lFT8rOpqcx3MlB+PzRVV4P3hUBirovxBu2TEqp01hvPnb5m6ZGE0U/p
B4LBke3S23iSkYwPaHwcbLVLhF2pruYmXS1hvCZxEQKBgQC3gBWKZZeV8uT0vKN+
FScBk5WLYSq63dUSonszWr0AxN03WsoHjkr4AqB+wtMPI2L7Kpy8whwtTXehqNpT
W+Zz12eVQI2fuGTYZg7zjxN0+H2nRxTOWyVcpW4h1tavzzXAzTDo1jc8DYvMhgXp
IIOMYDbOCQPCnopdE0Xd2QF7NQKBgQDNftHfeNOINkt3RTTI5NY9pTibl/alzqJf
aW8BXEsnKM8BB6ux/sTNE4ejaK7a4xvKhgss+Z0FkM11Ycoa2D5/X9CyXT/cOmhF
E2vt6yyQUSscMQMAaUmma8Gvu5dDF3a7/5liphjafPyFRa275JIxdbDgaCvV62kH
EjPLMjOj9wKBgQCHhe9iwVlNA5EZN2DAM7sVLPybbe3zCPbexmWbLf683KhMw57G
Kc8wkDAcrqLWYVovCe+scOgChV4/ZMeqHQt8rq/vyTdPqQ3BzM5qD1ddYlDbBGJX
bXWQkRVfpJ32RmD6vhDLRbqRfaesK6ed38eIG18emAXQ7Opfh2ZoTGcNqQKBgDKN
/53lwMyi5t/506mUuqxByHJm6VQTSNkGPDvuc8K3hG2xcGkCz3HQWy81YscQ1lZ1
sawn4Jxs6k71dt4x0vZNIS+wRzSr3dkYlRXcJIOApIVz/VQNkwPxQJ42HVlxHVHU
6OxfBoBB/XHgGYS/D8RBOvmKRzaCir0lmj5kJFYzAoGBAKEEaHn0LvmDpHYSUOA4
FgJnFmtHTHcYFaFus/oqwEtylftAsM5h8o5ww2OCJDa2FSxzaayV1wpm2r1HwvDn
p/oYQcQrtBHsdvdZ/8IRR7/9HJNanbhTuKdkdmVjt4rPoUDc2zqzEZUEG33E2Glh
+VS382WYhn8T/WeSmWHmF69D
-----END PRIVATE KEY-----
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

        fn get_path(&self) -> &str {
            self.path.as_str()
        }
    }



    // In an effort to leave the client trait implementation as simple as possible
    // it does not allow for modification of `self`... so we can't have any mutable
    // state in there.  For these tests, we track state in a static variable.
    //
    // Also turns out that `cargo test` likes to run tests in parallel which is not
    // good for our static state which is shared with all these tests. So there is a
    // MUTEX to protect it which the test acquires for the duration of its run.
    //
    // Its a fair amount of hackery for a couple of tests that don't actually test much!
    //
    struct TestState {
        auth_count: u32,
        poll_count: u32,
        de_register_count: u32,
        push_v: Option<Visa>,
    }

    enum CounterT {
        Auth,
        Poll,
        DeRegister,
    }

    static mut RUN_LOCK:Mutex<u32> = Mutex::new(0); // Each test holds this while running.

    static mut TEST_STATE: TestState = TestState {
        auth_count: 0,
        poll_count: 0,
        de_register_count: 0,
        push_v: None
    };

    fn reset_state() {
        unsafe {
            TEST_STATE.auth_count = 0;
            TEST_STATE.poll_count = 0;
            TEST_STATE.de_register_count = 0;
            TEST_STATE.push_v = None;
        }
    }

    fn get_counter(c: CounterT) -> u32 {
        unsafe {
            match c {
                CounterT::Auth => TEST_STATE.auth_count,
                CounterT::Poll => TEST_STATE.poll_count,
                CounterT::DeRegister => TEST_STATE.de_register_count,
            }
        }
    }

    fn incr(c: CounterT) {
        unsafe {
            match c {
                CounterT::Auth => TEST_STATE.auth_count += 1,
                CounterT::Poll => TEST_STATE.poll_count += 1,
                CounterT::DeRegister => TEST_STATE.de_register_count += 1,
            }
        }
    }

    fn get_pushed_visa() -> Option<Visa> {
        unsafe {
            TEST_STATE.push_v.clone()
        }
    }


    #[derive(Debug)]
    struct TestVSCli {}


    impl VSClientI for TestVSCli {
        fn authenticate(
            &self,
            _agent: vsapi::Agent,
            _cert_pem_data: &str,
            _private_key: Rsa<Private>,
        ) -> Result<String, thrift::Error>
        {
            incr(CounterT::Auth);
            Ok(String::from("le_key"))
        }

        fn poll_vs(&self, _apikey: &str) -> Result<vsapi::PollResponse, thrift::Error> {
            incr(CounterT::Poll);
            if let Some(v) = get_pushed_visa() {
                return Ok(vsapi::PollResponse {
                    visas: Some(vec![vsapi::VisaHop {
                        hop_count: Some(v.hop_count as i32),
                        issuer_id: Some(v.issuer_id as i32),
                        visa_pb: Some(v.visa_pb),
                    }]),
                    revocations: None,
                    more: Some(0),
                });
            }

            Ok(vsapi::PollResponse {
                visas: None,
                revocations: None,
                more: Some(0),
            })
        }

        fn de_register(&self, _apikey: &str) -> Result<(), thrift::Error> {
            incr(CounterT::DeRegister);
            Ok(())
        }
    }

    fn testvscli_factory(_service_addr: &str) -> Box<dyn VSClientI> {
        Box::new(TestVSCli{})
    }


    #[tokio::test]
    async fn test_start_and_stop_and_poll() {
        let _lockval = unsafe { RUN_LOCK.lock().unwrap() };
        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);
        let keyfile = TempFile::new_pem(KEY_DATA);

        let (tx, mut _rx) = mpsc::channel(8);
        let conn = VSConn::new(tx, "127.0.0.1:0", certfile.get_path(), keyfile.get_path(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).unwrap();
        conn.add_claim("foo", "fee");
        conn.initialize(Some(testvscli_factory)).unwrap();
        assert_eq!(get_counter(CounterT::Auth), 1);
        assert_eq!(get_counter(CounterT::DeRegister), 0);
        assert_eq!(get_counter(CounterT::Poll), 0);

        let ctoken = CancellationToken::new();
        let vs_tok = ctoken.clone();
        tokio::spawn(async move {
            let _ = conn.run(vs_tok).await;
        });

        tokio::time::sleep(Duration::from_millis(500)).await;

        ctoken.cancel(); // stop the vs

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Does de-register
        assert_eq!(get_counter(CounterT::DeRegister), 1);

        // Does call poll
        assert_eq!(get_counter(CounterT::Poll), 1);
    }

    #[tokio::test]
    async fn test_returns_pushed_visa() {
        let _lockval = unsafe { RUN_LOCK.lock().unwrap() };

        reset_state();
        let certfile = TempFile::new_pem(CERT_DATA);
        let keyfile = TempFile::new_pem(KEY_DATA);

        let (tx, mut rx) = mpsc::channel(8);
        let conn = VSConn::new(tx, "127.0.0.1:0", certfile.get_path(), keyfile.get_path(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).unwrap();
        conn.add_claim("foo", "fee");
        conn.initialize(Some(testvscli_factory)).unwrap();

        let a_visa = Visa {
            hop_count: 1,
            issuer_id: 2,
            visa_pb: Vec::new(),
        };
        unsafe {
            TEST_STATE.push_v = Some(a_visa.clone());
        }

        let ctoken = CancellationToken::new();
        let vs_tok = ctoken.clone();
        tokio::spawn(async move {
            let _ = conn.run(vs_tok).await;
        });

        // Allow it to poll...
        tokio::time::sleep(Duration::from_millis(500)).await;

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(1000)) => {
                assert!(false); // timed out
            }
            Some(output) = rx.recv() =>  match output {
                VSOutput::PushedVisa(visa) => {
                    assert_eq!(visa, a_visa);
                }
                _ => {
                    assert!(false); // Did not get a visa
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        ctoken.cancel(); // stop the vs
    }
}


