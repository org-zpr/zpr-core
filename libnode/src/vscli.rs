use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, SystemTime};
use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};
use thrift::transport::{ReadHalf, WriteHalf};
use thrift::transport::{TFramedReadTransport, TFramedWriteTransport};
use thrift::transport::{TIoChannel, TTcpChannel};
use tracing::*;

use crate::errors::VSClientError;
use crate::logging::targets::VS_RPC;
use crate::m2;
use vsapi::{self, TVisaServiceSyncClient, VisaServiceSyncClient};
use zpr;

/// Timeout for connecting to the visa service.
const VS_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

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
        actor: &vsapi::Actor,
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
    fn actor_disconnect(&mut self, actor_zpr_addr: IpAddr) -> Result<(), VSClientError>;
    fn request_services(&mut self) -> Result<vsapi::ServicesResponse, VSClientError>;
}

/// Wrapper on top of the the THRIFT generated code.
impl VSClient {
    // Not public; use the factory.
    fn new(service: &str) -> Result<VSClient, VSClientError> {
        let saddr = service.parse::<SocketAddr>()?;
        let stream = TcpStream::connect_timeout(&saddr, VS_CONNECT_TIMEOUT)?;
        let c = TTcpChannel::with_stream(stream);

        let (i_chan, o_chan) = c.split()?;

        let i_prot = TBinaryInputProtocol::new(TFramedReadTransport::new(i_chan), true);
        let o_prot = TBinaryOutputProtocol::new(TFramedWriteTransport::new(o_chan), true);

        debug!(target: VS_RPC, "VSClient.new creating VisaServiceSyncClient");
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
        actor: &vsapi::Actor,
        cert_pem_data: &str,
        vss_service_addr: SocketAddr,
    ) -> Result<String, VSClientError> {
        debug!(target: VS_RPC, "sending HELLO to {}", self.service);
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
            node_actor: Some(actor.clone()),
        };

        debug!(target: VS_RPC, "sending AUTHENTICATE to {}", self.service);
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
        debug!(target: VS_RPC, "sending DE-REGISTER to {}", self.service);
        self.cli.de_register(key.clone())?;
        Ok(())
    }

    /// Synchronous ping.
    fn ping_vs(&mut self) -> Result<vsapi::Pong, VSClientError> {
        if self.key.is_none() {
            return Err(VSClientError::NoAPIKey);
        }
        let key = self.key.as_ref().unwrap();
        trace!(target: VS_RPC, "sending PING to {}", self.service);
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

        debug!(target: VS_RPC, "sending VISA_REQUEST to {}", self.service);
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
        debug!(target: VS_RPC, "sending AUTHORIZE_CONNECT to {}", self.service);
        match self.cli.authorize_connect(key.clone(), req) {
            Ok(result) => Ok(result),
            Err(e) => Err(e.into()),
        }
    }

    /// Synchronous actor disconnect request.
    fn actor_disconnect(&mut self, actor_zpr_addr: IpAddr) -> Result<(), VSClientError> {
        if self.key.is_none() {
            return Err(VSClientError::NoAPIKey);
        }
        let key = self.key.as_ref().unwrap();
        let addr_bytes = match actor_zpr_addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        debug!(target: VS_RPC, "sending ACTOR_DISCONNECT to {}", self.service);
        match self.cli.actor_disconnect(key.clone(), addr_bytes) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn request_services(&mut self) -> Result<vsapi::ServicesResponse, VSClientError> {
        if self.key.is_none() {
            return Err(VSClientError::NoAPIKey);
        }
        let key = self.key.as_ref().unwrap();
        self.cli.request_services(key.clone()).map_err(|e| e.into())
    }
}
