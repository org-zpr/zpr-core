use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

use crate::vsapi_types::VsapiTypeError;
use crate::vsapi_types::util::ip::ip_addr_from_vec;

/// Capnp does not have a separate AuthServicesList structure, instead just uses List(ServiceDescriptor)
#[derive(Debug, Clone)]
pub struct AuthServicesList {
    pub expiration: Option<SystemTime>, // 0 value means "no expiration"
    pub services: Vec<ServiceDescriptor>,
}

/// A parsed [vsapi::ServiceDescriptor] that we use to keep ASA records.
#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    pub service_id: String,
    pub service_uri: String,
    pub zpr_address: IpAddr,
}

impl Default for AuthServicesList {
    fn default() -> Self {
        AuthServicesList {
            expiration: Some(SystemTime::UNIX_EPOCH),
            services: Vec::new(),
        }
    }
}

impl AuthServicesList {
    pub fn update(&mut self, expiration: Option<SystemTime>, services: Vec<ServiceDescriptor>) {
        self.expiration = expiration;
        self.services = services;
    }

    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expiration {
            SystemTime::now() >= exp
        } else {
            false
        }
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// The list is "valid" it is non-empty and not expired.
    pub fn is_valid(&self) -> bool {
        !self.is_empty() && !self.is_expired()
    }
}

impl ServiceDescriptor {
    /// Gently try to extract a SocketAddr from this ServiceDescriptor.
    /// If there are any problems, None is returned.
    pub fn get_socket_addr(&self) -> Option<std::net::SocketAddr> {
        // To create a socket address we need a port, which is on the URI.
        let uri = match Url::parse(&self.service_uri) {
            Ok(u) => u,
            Err(_) => return None, // Invalid URI
        };
        let port = match uri.port() {
            Some(p) => p,
            None => return None, // No port in URI, so no SocketAddr for you
        };
        Some(std::net::SocketAddr::new(self.zpr_address.into(), port))
    }
}

impl TryFrom<vsapi::ServicesList> for AuthServicesList {
    type Error = VsapiTypeError;

    /// Returns err if a ServiceDescriptor is badly formatted
    fn try_from(services_list: vsapi::ServicesList) -> Result<Self, Self::Error> {
        let mut expiration = None;
        if services_list.expiration.is_some() {
            expiration =
                Some(UNIX_EPOCH + Duration::from_secs(services_list.expiration.unwrap() as u64));
        }
        let mut services = Vec::new();
        if services_list.services.is_some() {
            for svc in services_list.services.unwrap() {
                services.push(ServiceDescriptor::try_from(svc)?);
            }
        }
        Ok(Self {
            expiration,
            services,
        })
    }
}

impl TryFrom<vsapi::ServiceDescriptor> for ServiceDescriptor {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set
    fn try_from(value: vsapi::ServiceDescriptor) -> Result<Self, Self::Error> {
        if value.type_ != vsapi::ServiceType::ACTOR_AUTHENTICATION {
            return Err(VsapiTypeError::DeserializationError(
                "vsapi::ServiceDescriptor is not of type ACTOR_AUTHENTICATION",
            ));
        }
        if value.address.is_none() {
            return Err(VsapiTypeError::DeserializationError(
                "vsapi::ServiceDescriptor address is empty",
            ));
        }
        let zpraddr = ip_addr_from_vec(value.address.unwrap())?;

        Ok(ServiceDescriptor {
            service_id: value.service_id.unwrap_or_default(),
            service_uri: value.uri.unwrap_or_default(),
            zpr_address: zpraddr,
        })
    }
}
