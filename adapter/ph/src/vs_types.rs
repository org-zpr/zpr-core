use crate::net_defs::IpAddress;

use libnode::vsapi;

use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
use url::Url;

/// A parsed [vsapi::ServicesList].  Note that all the services in here will be of
/// type [vsapi::ServiceType::ACTOR_AUTHENTICATION].
#[derive(Debug, Clone)]
pub struct AuthServicesList {
    pub expiration: Option<SystemTime>, // 0 value means "no expiration"
    pub services: Vec<ServiceDescriptor>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use libnode::vsapi;
    use std::time::Duration;

    // Helper function to create a test ServiceDescriptor
    fn create_test_service_descriptor() -> ServiceDescriptor {
        ServiceDescriptor {
            service_id: "test-service-123".to_string(),
            service_uri: "https://auth.example.com:8443/auth".to_string(),
            zpr_address: IpAddress::new_from_v4([192, 168, 1, 100]),
        }
    }

    // Helper function to create a test ServiceDescriptor with IPv6
    fn create_test_service_descriptor_v6() -> ServiceDescriptor {
        let ipv6_addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        ServiceDescriptor {
            service_id: "test-service-ipv6".to_string(),
            service_uri: "https://auth.example.com:9443/auth".to_string(),
            zpr_address: IpAddress::new_from_std_v6(&ipv6_addr),
        }
    }

    #[test]
    fn test_auth_services_list_update() {
        let mut list = AuthServicesList::default();
        let future_time = Some(SystemTime::now() + Duration::from_secs(3600));
        let services = vec![create_test_service_descriptor()];

        list.update(future_time, services.clone());

        assert_eq!(list.expiration, future_time);
        assert_eq!(list.services.len(), 1);
        assert_eq!(list.services[0].service_id, "test-service-123");
    }

    #[test]
    fn test_auth_services_list_is_expired() {
        let mut list = AuthServicesList::default();

        // Test with past time
        let past_time = Some(SystemTime::now() - Duration::from_secs(3600));
        list.expiration = past_time;
        assert!(list.is_expired());

        // Test with future time
        let future_time = Some(SystemTime::now() + Duration::from_secs(3600));
        list.expiration = future_time;
        assert!(!list.is_expired());
    }

    #[test]
    fn test_auth_services_list_is_empty() {
        let mut list = AuthServicesList::default();
        assert!(list.is_empty());

        list.services.push(create_test_service_descriptor());
        assert!(!list.is_empty());
    }

    #[test]
    fn test_auth_services_list_is_valid() {
        let mut list = AuthServicesList::default();

        // Empty and expired
        assert!(!list.is_valid());

        // Non-empty but expired
        list.services.push(create_test_service_descriptor());
        assert!(!list.is_valid());

        // Non-empty and not expired
        list.expiration = Some(SystemTime::now() + Duration::from_secs(3600));
        assert!(list.is_valid());

        // Empty but not expired
        list.services.clear();
        assert!(!list.is_valid());
    }

    #[test]
    fn test_service_descriptor_try_from_valid() {
        let vsapi_descriptor = vsapi::ServiceDescriptor {
            type_: vsapi::ServiceType::ACTOR_AUTHENTICATION,
            service_id: Some("test-service".to_string()),
            uri: Some("https://example.com:8443/auth".to_string()),
            address: Some(vec![192, 168, 1, 100]),
        };

        let result = ServiceDescriptor::try_from(vsapi_descriptor);
        assert!(result.is_ok());

        let descriptor = result.unwrap();
        assert_eq!(descriptor.service_id, "test-service");
        assert_eq!(descriptor.service_uri, "https://example.com:8443/auth");
        assert_eq!(
            descriptor.zpr_address,
            IpAddress::new_from_v4([192, 168, 1, 100])
        );
    }

    #[test]
    fn test_service_descriptor_try_from_no_address() {
        let vsapi_descriptor = vsapi::ServiceDescriptor {
            type_: vsapi::ServiceType::ACTOR_AUTHENTICATION,
            service_id: Some("test-service".to_string()),
            uri: Some("https://example.com:8443/auth".to_string()),
            address: None,
        };

        let result = ServiceDescriptor::try_from(vsapi_descriptor);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "vsapi::ServiceDescriptor address is empty"
        );
    }

    #[test]
    fn test_service_descriptor_try_from_defaults() {
        let vsapi_descriptor = vsapi::ServiceDescriptor {
            type_: vsapi::ServiceType::ACTOR_AUTHENTICATION,
            service_id: None, // Should use default (empty string)
            uri: None,        // Should use default (empty string)
            address: Some(vec![10, 0, 0, 1]),
        };

        let result = ServiceDescriptor::try_from(vsapi_descriptor);
        assert!(result.is_ok());

        let descriptor = result.unwrap();
        assert_eq!(descriptor.service_id, "");
        assert_eq!(descriptor.service_uri, "");
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_ipv4() {
        let descriptor = create_test_service_descriptor();
        let socket_addr = descriptor.get_socket_addr();

        assert!(socket_addr.is_some());
        let addr = socket_addr.unwrap();
        assert_eq!(addr.port(), 8443);
        assert!(addr.ip().is_ipv4());
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_ipv6() {
        let descriptor = create_test_service_descriptor_v6();
        let socket_addr = descriptor.get_socket_addr();

        assert!(socket_addr.is_some());
        let addr = socket_addr.unwrap();
        assert_eq!(addr.port(), 9443);
        assert!(addr.ip().is_ipv6());
        assert_eq!(addr.ip(), IpAddr::V6("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_invalid_uri() {
        let mut descriptor = create_test_service_descriptor();
        descriptor.service_uri = "not-a-valid-uri".to_string();

        let socket_addr = descriptor.get_socket_addr();
        assert!(socket_addr.is_none());
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_no_port() {
        let mut descriptor = create_test_service_descriptor();
        descriptor.service_uri = "https://example.com/auth".to_string(); // No port

        let socket_addr = descriptor.get_socket_addr();
        assert!(socket_addr.is_none());
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_default_port() {
        let mut descriptor = create_test_service_descriptor();
        descriptor.service_uri = "http://example.com/auth".to_string(); // HTTP default port

        let socket_addr = descriptor.get_socket_addr();
        // This should return None because url.port() returns None for default ports
        assert!(socket_addr.is_none());
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_explicit_port() {
        let mut descriptor = create_test_service_descriptor();
        descriptor.service_uri = "http://example.com:8080/auth".to_string();

        let socket_addr = descriptor.get_socket_addr();
        assert!(socket_addr.is_some());
        assert_eq!(socket_addr.unwrap().port(), 8080);
    }
}
