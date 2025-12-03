//! Our internal visa types. These are shared by ph, libnode2, and several visa service
//! crates.
//!
//! Currently based on a mix of the thrift and capnp protocols, will likely evolve as we move
//! away from thrift exclusively to capnp.
//!

mod auth;
mod error;
mod packet;
mod request;
mod response;
mod services;
mod util;
mod visa;

// PUBLIC API EXPORTS
pub use auth::{AuthBlob, AuthCodeBlob, ChallengeAlg, ZprSelfSignedBlob};
pub use error::VsapiTypeError;
pub use packet::{CommFlag, PacketDesc, VsapiFiveTuple, VsapiIpProtocol, vsapi_ip_number};
pub use request::{Claim, ConnectRequest};
pub use response::{Connection, Denied, DenyCode, ErrorCode, VisaResponse, VisaResponseError};
pub use services::{AuthServicesList, ServiceDescriptor};
pub use util::ip::ip_addr_from_vec;
pub use util::time::visa_expiration_timestamp_to_system_time;
pub use visa::{
    Constraints, DockPep, EndpointT, IcmpPep, KeyFormat, KeySet, TcpUdpPep, Visa, VisaOp,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, SystemTime};

    // Helper function to create a test ServiceDescriptor
    fn create_test_service_descriptor() -> ServiceDescriptor {
        ServiceDescriptor {
            service_id: "test-service-123".to_string(),
            service_uri: "https://auth.example.com:8443/auth".to_string(),
            zpr_address: IpAddr::from([192, 168, 1, 100]),
        }
    }

    // Helper function to create a test ServiceDescriptor with IPv6
    fn create_test_service_descriptor_v6() -> ServiceDescriptor {
        let ipv6_addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        ServiceDescriptor {
            service_id: "test-service-ipv6".to_string(),
            service_uri: "https://auth.example.com:9443/auth".to_string(),
            zpr_address: IpAddr::from(ipv6_addr),
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
        assert_eq!(descriptor.zpr_address, IpAddr::from([192, 168, 1, 100]));
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
