use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;
use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};
use thrift::transport::{ReadHalf, WriteHalf};
use thrift::transport::{TFramedReadTransport, TFramedWriteTransport};
use thrift::transport::{TIoChannel, TTcpChannel};
use tracing::debug;

use crate::errors::VSClientError;
use crate::m2;
use crate::vsapi;
use vsapi::{TVisaServiceSyncClient, VisaServiceSyncClient};
use zpr;

// ugh!!
type VSClientT = VisaServiceSyncClient<
    TBinaryInputProtocol<TFramedReadTransport<ReadHalf<TTcpChannel>>>,
    TBinaryOutputProtocol<TFramedWriteTransport<WriteHalf<TTcpChannel>>>,
>;

/// Wrapper around the thrift visa service client. Single threaded.
/// Caches the service address and API key.
pub struct VSClient {
    service: String,
    key: Option<String>,
    cli: VSClientT,
}

/// This is an interface that covers the VSClient wrapper designed to facilitate
/// unit testing.  The running node code should use the [default_vsclient_factory]
/// function.
pub trait VSClientI: Send {
    fn authenticate(
        &mut self,
        agent: vsapi::Agent,
        cert_pem_data: &str,
        vss_service_addr: SocketAddr,
    ) -> Result<String, VSClientError>;
    fn ping_vs(&mut self) -> Result<vsapi::Pong, VSClientError>;
    fn de_register(&mut self) -> Result<(), VSClientError>;
    fn request_visa(
        &mut self,
        source_tether_addr: IpAddr,
        l3_type: zpr::L3Type,
        packet: Vec<u8>,
    ) -> Result<vsapi::VisaResponse, VSClientError>;
    fn authorize_connect(
        &mut self,
        req: vsapi::ConnectRequest,
    ) -> Result<vsapi::ConnectResponse, VSClientError>;
    fn agent_disconnect(&mut self, agent_zpr_addr: IpAddr) -> Result<(), VSClientError>;
}

/// Wrapper on top of the the THRIFT generated code.
impl VSClient {
    // Not public; use the factory.
    fn new(service: &str) -> Result<VSClient, VSClientError> {
        // create thrift client:
        let mut c = TTcpChannel::new();
        c.open(service.to_string())?;

        let (i_chan, o_chan) = c.split()?;

        let i_prot = TBinaryInputProtocol::new(TFramedReadTransport::new(i_chan), true);
        let o_prot = TBinaryOutputProtocol::new(TFramedWriteTransport::new(o_chan), true);

        let tcli = vsapi::VisaServiceSyncClient::new(i_prot, o_prot);

        Ok(VSClient {
            service: service.to_string(),
            key: None,
            cli: tcli,
        })
    }
}

/// That which can create a [VSClientI]
pub type VSClientFactory = fn(service_addr: &str) -> Result<Box<dyn VSClientI>, VSClientError>;

/// Convenience function that creates the noraml VSClient set up to communicate using thrift.
/// - `service_addr` address of the visa service thrift endpoint.
pub fn default_vsclient_factory(service_addr: &str) -> Result<Box<dyn VSClientI>, VSClientError> {
    let vsc = VSClient::new(service_addr)?;
    Ok(Box::new(vsc))
}

impl VSClientI for VSClient {
    /// Authenticate with the visa service. Caches the API key internally.
    ///
    /// In prototype, the node would do a signature over the (challenge_data, timestamp, session_id)
    /// using its RSA private key, and send the RSA cert back with the response. Visa service could
    /// check the CERT to ensure blessed by authority, and then check the signature.
    ///
    /// For milestone 2 we do not yet have this quite sorted out and do not want to force people
    /// to create RSA keys.  So we are using just a blake3 HMAC for now over the same 3-tuple.
    /// The HMAC is key'd with the `shared_secret` arg.
    ///
    fn authenticate(
        &mut self,
        agent: vsapi::Agent,
        cert_pem_data: &str,
        vss_service_addr: SocketAddr,
    ) -> Result<String, VSClientError> {
        debug!("sending HELLO to {}", self.service);
        let hello_response = self.cli.hello()?;

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let hrchal = hello_response.challenge.unwrap();
        let chal_copy = hrchal.clone(); // we send this one back

        let hmac =
            m2::milestone2_create_hmac(hrchal, hello_response.session_id.unwrap(), timestamp);

        let authreq = vsapi::NodeAuthRequest {
            session_id: hello_response.session_id,
            challenge: Some(chal_copy),
            timestamp: Some(timestamp as i64),
            node_cert: Some(cert_pem_data.into()),
            hmac: Some(hmac),
            vss_service: Some(vss_service_addr.to_string()),
            node_agent: Some(agent),
        };

        debug!("sending AUTHENTICATE to {}", self.service);
        let apikey = match self.cli.authenticate(authreq) {
            Ok(result) => result,
            Err(e) => return Err(e.into()),
        };
        self.key = Some(apikey.clone());
        Ok(apikey)
    }

    // Synchronous node de-register.
    fn de_register(&mut self) -> Result<(), VSClientError> {
        if self.key.is_none() {
            return Err(VSClientError::NoAPIKey);
        }
        let key = self.key.as_ref().unwrap();
        debug!("sending DE-REGISTER to {}", self.service);
        self.cli.de_register(key.clone())?;
        Ok(())
    }

    /// Synchronous ping.
    fn ping_vs(&mut self) -> Result<vsapi::Pong, VSClientError> {
        if self.key.is_none() {
            return Err(VSClientError::NoAPIKey);
        }
        let key = self.key.as_ref().unwrap();
        debug!("sending PING to {}", self.service);
        match self.cli.ping(key.clone()) {
            Ok(result) => Ok(result),
            Err(e) => Err(e.into()),
        }
    }

    /// Synchronous visa request.
    fn request_visa(
        &mut self,
        source_tether_addr: IpAddr,
        l3_type: zpr::L3Type,
        packet: Vec<u8>,
    ) -> Result<vsapi::VisaResponse, VSClientError> {
        if self.key.is_none() {
            return Err(VSClientError::NoAPIKey);
        }
        let key = self.key.as_ref().unwrap();

        let addr_bytes = match source_tether_addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        let l3t: i8 = match l3_type {
            zpr::L3Type::Ipv4 => 4,
            zpr::L3Type::Ipv6 => 6,
            _ => return Err(VSClientError::UnsupportedTrafficType),
        };

        debug!("sending VISA_REQUEST to {}", self.service);
        match self.cli.request_visa(key.clone(), addr_bytes, l3t, packet) {
            Ok(result) => Ok(result),
            Err(e) => Err(e.into()),
        }
    }

    /// Synchronous authorize connect request.
    fn authorize_connect(
        &mut self,
        req: vsapi::ConnectRequest,
    ) -> Result<vsapi::ConnectResponse, VSClientError> {
        if self.key.is_none() {
            return Err(VSClientError::NoAPIKey);
        }
        let key = self.key.as_ref().unwrap();
        debug!("sending AUTHORIZE_CONNECT to {}", self.service);
        match self.cli.authorize_connect(key.clone(), req) {
            Ok(result) => Ok(result),
            Err(e) => Err(e.into()),
        }
    }

    /// Synchronous agent disconnect request.
    fn agent_disconnect(&mut self, agent_zpr_addr: IpAddr) -> Result<(), VSClientError> {
        if self.key.is_none() {
            return Err(VSClientError::NoAPIKey);
        }
        let key = self.key.as_ref().unwrap();
        let addr_bytes = match agent_zpr_addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        debug!("sending AGENT_DISCONNECT to {}", self.service);
        match self.cli.agent_disconnect(key.clone(), addr_bytes) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
