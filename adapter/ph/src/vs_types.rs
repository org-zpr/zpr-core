use crate::net_defs::IpAddress;

use libnode::vsapi;

use std::convert::TryFrom;
use std::time::SystemTime;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;


/// A parsed [vsapi::ServicesList].  Note that all the services in here will be of
/// type [vsapi::ServiceType::ACTOR_AUTHENTICATION].
#[derive(Debug, Clone)]
pub struct AuthServicesList {
    pub expiration: SystemTime,
    pub services: Vec<ServiceDescriptor>,
}

impl Default for AuthServicesList {
    fn default() -> Self {
        AuthServicesList {
            expiration: SystemTime::UNIX_EPOCH,
            services: Vec::new(),
        }
    }
}

impl AuthServicesList {
    pub fn update(&mut self, expiration: SystemTime, services: Vec<ServiceDescriptor>) {
        self.expiration = expiration;
        self.services = services;
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expiration
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// The list is "valid" it is non-empty and not expired.
    pub fn is_valid(&self) -> bool {
        !self.is_empty() && !self.is_expired()
    }
}


/// A parsed [vsapi::ServiceDescriptor] that we use to keep ASA records.
#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    pub service_id: String,
    pub service_uri: String,
    pub zpr_address: IpAddress,
}

impl TryFrom<vsapi::ServiceDescriptor> for ServiceDescriptor {
    type Error = &'static str;

    fn try_from(value: vsapi::ServiceDescriptor) -> Result<Self, Self::Error> {
        if value.type_ != vsapi::ServiceType::ACTOR_AUTHENTICATION {
            return Err("vsapi::ServiceDescriptor is not of type ACTOR_AUTHENTICATION");
        }
        if value.address.is_none() {
            return Err("vsapi::ServiceDescriptor address is empty");
        }
        let zpraddr = IpAddress::try_from(value.address.unwrap())
            .map_err(|_| "Failed to parse zpr_address in ServiceDescriptor")?;
        Ok(ServiceDescriptor {
            service_id: value.service_id.unwrap_or_default(),
            service_uri: value.uri.unwrap_or_default(),
            zpr_address: zpraddr,
        })
    }
}

impl ServiceDescriptor {
    /// Gently try to convert this ServiceDescriptor into a SocketAddr.
    /// If there are any problems, None is returned.
    pub fn to_socket_addr(&self) -> Option<std::net::SocketAddr> {
        // To create a socket address we need a port, which is on the URI.
        let uri = match Url::parse(&self.service_uri) {
            Ok(u) => u,
            Err(_) => return None, // Invalid URI
        };
        let port = match uri.port() {
            Some(p) => p,
            None => return None, // No port in URI, so no SocketAddr for you
        };
        if self.zpr_address.is_v4() {
            let ip4 = Ipv4Addr::try_from(self.zpr_address).unwrap();
            Some(std::net::SocketAddr::new(IpAddr::V4(ip4), port))
        } else {
            let ip6 = Ipv6Addr::try_from(self.zpr_address).unwrap();
            Some(std::net::SocketAddr::new(IpAddr::V6(ip6), port))
        }
    }
}