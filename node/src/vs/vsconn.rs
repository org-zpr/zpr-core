

use openssl::rsa::Rsa;
use openssl::pkey::Private;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::time::SystemTime;
use std::sync::{Arc, Mutex};
use std::io::{Error, ErrorKind};
use std::net::IpAddr;

use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;
use tokio::sync::mpsc::{self, Sender};


use crate::vs::vscli;
use crate::vsapi;

use tracing::{info, error};



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




#[derive(Debug, Clone)]
pub struct VSConn {
    shared: Arc<Shared>,  // TODO: Do I really need this VSConn to be shared?
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
}


// This is a place holder for the async "commands" that can be sent into the running visa service client.
// Clearly there will be arguments attached to these in the future.
// Also need to figure out how the responses are routed back out.
#[derive(Debug)]
enum VSCommand {
    RequestVisa,
    AuthorizeConnect,
    AgentDisconnect
}



/// The VSConn will manage all communication with the visa service on behalf of the node.
impl VSConn {
    /// - `service_addr` is ADDR:PORT of the visa service (ADDR should be a ZPR address)
    /// - `node_cert_file` is the path to the node's signed certificate file
    /// - `node_key_file` is the path to the node's private key file
    /// - `node_addr` is the ZPR address of the node (from node config file).
    pub fn new(service_addr: &str, node_cert_file: &str, node_key_file: &str, node_addr: IpAddr) -> Result<VSConn, Error> {

        let mut certfile = match File::open(node_cert_file) {
            Ok(f) => f,
            Err(e) => {
                return Err(Error::new(ErrorKind::NotFound, format!("failed to open cert file: {}", e)));
            }
        };
        let mut cert_pem_data = String::new();
        certfile.read_to_string(&mut cert_pem_data)?;

        let mut keyfile = match File::open(node_key_file) {
            Ok(f) => f,
            Err(e) => {
                return Err(Error::new(ErrorKind::NotFound, format!("failed to open private key file: {}", e)));
            }
        };
        let mut key_pem_data = String::new();
        keyfile.read_to_string(&mut key_pem_data)?;

        let private_key = match Rsa::private_key_from_pem(key_pem_data.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                return Err(Error::new(ErrorKind::InvalidData, format!("failed to parse private RSA key: {}: {}", node_key_file, e)));
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
            }),
        });

        Ok(VSConn { shared })
    }

    pub fn add_claim(&self, key: &str, value: &str) {
        let mut state = self.shared.state.lock().unwrap();
        state.claims.insert(key.to_string(), value.to_string());
    }



    /// Must be callled before run.  This registers with visa service and obtains an API key.
    /// Blocking network call.
    pub fn initialize(&self) -> Result<(), Error> {
        info!("VSConn::initialize starts");


        let mut state = self.shared.state.lock().unwrap(); // TAKES LOCK (drops when state goes out of scope)

        
        let vsc = vscli::VSClient::new(&state.service_addr);

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

        let apikey = match vsc.authenticate(agent, &state.node_cert_pem_data, state.node_private_key.clone()) {
            Ok(k) => k,
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, format!("failed to authenticate with visa service: {}", e)));
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
        let svc_addr: String;
        {
            let mut state = self.shared.state.lock().unwrap(); // TAKES LOCK (drops when state goes out of scope)            
            state.cmd_tx = Some(tx.clone());
            maybe_apikey = state.api_key.clone();        
            svc_addr = state.service_addr.clone();
        }

        let apikey = match maybe_apikey {
            Some(k) => k,
            None => {
                return Err(Error::new(ErrorKind::Other, "VSConn::run called but not initialized"));
            }
        };


        let mut interval = time::interval(Duration::from_millis(1000)); // TODO: not hardcode
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    info!("VSConn::run tick!!"); // TODO: polling 
                }
                _ = ctok.cancelled() => {
                    info!("VSConn::run cancelled");
                    let vsc = vscli::VSClient::new(&svc_addr);                    
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
                return Err(Error::new(ErrorKind::Other, "VSConn::send_command called but no command channel available"));
            }
        }

        if let Err(e) = tx_chan.send(cmd).await {
            error!("VSConn::send_command failed: {}", e);
            return Err(Error::new(ErrorKind::Other, "VSConn::send_command failed"));
        }
        Ok(())
    }


    /// PLACEHOLDER for request-visa operation
    pub async fn request_visa(&self) -> Result<(), Error> {
        self.send_command(VSCommand::RequestVisa).await
    }

    /// PLACEHOLDER for authorize-connect operation
    pub async fn authorize_connect(&self) -> Result<(), Error> {
        self.send_command(VSCommand::AuthorizeConnect).await
    }

    /// PLACEHOLDER for agent-disconnect operation
    pub async fn agent_disconnect(&self) -> Result<(), Error>{
        self.send_command(VSCommand::AgentDisconnect).await
    }

}

    