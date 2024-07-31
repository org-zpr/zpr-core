use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};
use thrift::transport::{ReadHalf, WriteHalf};
use thrift::transport::{TFramedReadTransport, TFramedWriteTransport};
use thrift::transport::{TIoChannel, TTcpChannel};

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;

use std::io::prelude::*;
use std::time::SystemTime;

use crate::vsapi;
use vsapi::{TVisaServiceSyncClient, VisaServiceSyncClient};

use tracing::debug;

// ugh!!
type VSClientT = VisaServiceSyncClient<
    TBinaryInputProtocol<TFramedReadTransport<ReadHalf<TTcpChannel>>>,
    TBinaryOutputProtocol<TFramedWriteTransport<WriteHalf<TTcpChannel>>>,
>;

pub struct VSClient {
    service: String,
}

// This is an interface that covers the VSClient wrapper designed to facilitate
// unit testing.  The running node code should use the `default_vsclient_factory`
// function.
pub trait VSClientI: Send {
    fn authenticate(
        &self,
        agent: vsapi::Agent,
        cert_pem_data: &str,
        private_key: Rsa<Private>,
        vss_service_addr: &str,
    ) -> Result<String, thrift::Error>;
    fn ping_vs(&self, apikey: &str) -> Result<vsapi::Pong, thrift::Error>;
    fn de_register(&self, apikey: &str) -> Result<(), thrift::Error>;
}

pub type VSClientFactory = fn(service_addr: &str) -> Box<dyn VSClientI>;

// Wrapper on top of the the THRIFT generated code.
impl VSClient {
    // Not public; use the factory.
    fn new(service: &str) -> VSClient {
        VSClient {
            service: service.to_string(),
        }
    }

    fn newclient(&self) -> thrift::Result<VSClientT> {
        let mut c = TTcpChannel::new();
        c.open(&self.service)?;

        let (i_chan, o_chan) = c.split()?;

        let i_prot = TBinaryInputProtocol::new(TFramedReadTransport::new(i_chan), true);
        let o_prot = TBinaryOutputProtocol::new(TFramedWriteTransport::new(o_chan), true);

        Ok(vsapi::VisaServiceSyncClient::new(i_prot, o_prot))
    }
}

pub fn default_vsclient_factory(service_addr: &str) -> Box<dyn VSClientI> {
    Box::new(VSClient::new(service_addr))
}

impl VSClientI for VSClient {
    fn authenticate(
        &self,
        agent: vsapi::Agent,
        cert_pem_data: &str,
        private_key: Rsa<Private>,
        vss_service_addr: &str,
    ) -> Result<String, thrift::Error> {
        let mut client = self.newclient()?;

        debug!("sending HELLO to {}", self.service);
        let hello_response = client.hello()?;

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let hrchal = hello_response.challenge.unwrap();
        let chal_copy = hrchal.clone(); // we send this one back

        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();

        let mut buf = Vec::new();
        buf.write_all(&hrchal.challenge_data.unwrap()).unwrap();

        signer.update(&buf).unwrap();
        signer.update(&timestamp.to_be_bytes()).unwrap();
        signer
            .update(&hello_response.session_id.unwrap().to_be_bytes())
            .unwrap();

        let hmac = signer.sign_to_vec().unwrap();

        let authreq = vsapi::NodeAuthRequest {
            session_id: hello_response.session_id,
            challenge: Some(chal_copy),
            timestamp: Some(timestamp as i64),
            node_cert: Some(cert_pem_data.into()),
            hmac: Some(hmac),
            vss_service: Some(vss_service_addr.into()),
            node_agent: Some(agent),
        };

        debug!("sending AUTHENTICATE to {}", self.service);
        let apikey = match client.authenticate(authreq) {
            Ok(result) => result,
            Err(e) => {
                return Err(e);
            }
        };

        Ok(apikey)
    }

    fn de_register(&self, apikey: &str) -> Result<(), thrift::Error> {
        let mut client = self.newclient()?;
        debug!("sending DE-REGISTER to {}", self.service);
        match client.de_register(apikey.into()) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn ping_vs(&self, apikey: &str) -> Result<vsapi::Pong, thrift::Error> {
        let mut client = self.newclient()?;
        debug!("sending PING to {}", self.service);
        client.ping(apikey.into())
    }
}
