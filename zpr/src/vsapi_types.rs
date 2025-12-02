//! Our internal visa types. These are shared by ph, libnode2, and several visa service
//! crates.
//!
//! Currently based on a mix of the thrift and capnp protocols, will likely evolve as we move
//! away from thrift exclusively to capnp.
//!

use super::{L3Type, l3type_of_addr};
use crate::vsapi::v1;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;
use vsapi;

#[derive(Debug, Error)]
pub enum VsapiTypeError {
    #[error("Serialization error {0}")]
    SerializationError(&'static str),
    #[error("Deserialization error: {0:?}")]
    DeserializationError(&'static str),
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("Cap'n Proto error: {0}")]
    NotInSchema(#[from] capnp::NotInSchema),
    #[error("Cap'n Proto error: {0}")]
    Utf8Error(#[from] core::str::Utf8Error),
    #[error("Error code: {0:?}")]
    CodedError(ErrorCode),
    #[error("IP address conversion error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
}

/// A description of a packet between a sender and reciever.
#[derive(Debug)]
pub struct PacketDesc {
    pub five_tuple: VsapiFiveTuple,
    /// TODO: Can multiple flags be passed with the PacketDesc?
    pub comm_flags: CommFlag,
}

/// Special hint that is passed with a [PacketDesc].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommFlag {
    /// TODO: document this
    BiDirectional,
    /// TODO: document this
    UniDirectional,
    /// Is-a re-request, includes previous visa id.
    ReRequest(u64),
}

#[derive(Debug)]
pub enum VisaResponse {
    Allow(Visa),
    Deny(Denied),
    VSApiError(VisaResponseError),
}

#[derive(Debug)]
pub struct Denied {
    pub code: DenyCode,
    pub reason: Option<String>,
}

// Will be more useful once we transition to capnp, right now we only use Fail
#[derive(Debug, Eq, PartialEq)]
pub enum DenyCode {
    Fail,
    NoReason,
    NoMatch,
    Denied,
    SourceNotFound,
    DestNotFound,
    SourceAuthError,
    DestAuthError,
    QuotaExceeded,
}

#[derive(Debug)]
pub struct VisaResponseError {
    pub code: ErrorCode,
    pub message: String,
    pub retry_in: u32,
}

#[derive(Debug)]
pub enum ErrorCode {
    Internal,
    AuthRequired,
    InvalidOperation,
    OutOfSync,
    NotFound,
    InvalidSignature,
    QuotaExceeded,
    TemporarilyUnavailable,
    AuthError,
    ParamError,
    UnknownStatusCode,
    Fail,
}

impl PacketDesc {
    pub fn new_tcp(source_addr: &str, dest_addr: &str, source_port: u16, dest_port: u16) -> Self {
        let saddr: IpAddr = source_addr.parse().unwrap();
        PacketDesc {
            five_tuple: VsapiFiveTuple::new(
                l3type_of_addr(&saddr),
                saddr,
                dest_addr.parse().unwrap(),
                vsapi_ip_number::TCP,
                source_port,
                dest_port,
            ),
            comm_flags: CommFlag::BiDirectional,
        }
    }

    pub fn new_udp(source_addr: &str, dest_addr: &str, source_port: u16, dest_port: u16) -> Self {
        let saddr: IpAddr = source_addr.parse().unwrap();
        PacketDesc {
            five_tuple: VsapiFiveTuple::new(
                l3type_of_addr(&saddr),
                saddr,
                dest_addr.parse().unwrap(),
                vsapi_ip_number::UDP,
                source_port,
                dest_port,
            ),
            comm_flags: CommFlag::BiDirectional,
        }
    }

    pub fn new_icmp(source_addr: &str, dest_addr: &str, icmp_type: u8, icmp_code: u8) -> Self {
        let saddr: IpAddr = source_addr.parse().unwrap();
        PacketDesc {
            five_tuple: VsapiFiveTuple::new(
                l3type_of_addr(&saddr),
                saddr,
                dest_addr.parse().unwrap(),
                if saddr.is_ipv4() {
                    vsapi_ip_number::ICMP
                } else {
                    vsapi_ip_number::IPV6_ICMP
                },
                icmp_type as u16,
                icmp_code as u16,
            ),
            comm_flags: CommFlag::UniDirectional,
        }
    }

    pub fn is_tcpudp(&self) -> bool {
        self.five_tuple.l4_protocol == vsapi_ip_number::TCP
            || self.five_tuple.l4_protocol == vsapi_ip_number::UDP
    }

    /// Get a reference to the five_tuple source address.
    pub fn source_addr(&self) -> &IpAddr {
        &self.five_tuple.src_address
    }
    /// Get a reference to the five_tuple destination address.
    pub fn dest_addr(&self) -> &IpAddr {
        &self.five_tuple.dst_address
    }
    /// Get the source port (or icmp TYPE)
    pub fn source_port(&self) -> u16 {
        self.five_tuple.src_port
    }
    /// Get the destination port (or icmp CODE)
    pub fn dest_port(&self) -> u16 {
        self.five_tuple.dst_port
    }
    /// Get the L4 protocol number.
    pub fn protocol(&self) -> VsapiIpProtocol {
        self.five_tuple.l4_protocol
    }
}

impl TryFrom<v1::packet_desc::Reader<'_>> for PacketDesc {
    type Error = VsapiTypeError;
    fn try_from(reader: v1::packet_desc::Reader<'_>) -> Result<Self, Self::Error> {
        let src_ip = reader.get_source_addr()?;
        let source = match src_ip.which().unwrap() {
            v1::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4?.try_into()?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            v1::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6?.try_into()?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let dest_ip = reader.get_dest_addr()?;
        let dest = match dest_ip.which().unwrap() {
            v1::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4?.try_into()?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            v1::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6?.try_into()?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let source_port = reader.get_source_port();
        let dest_port = reader.get_dest_port();
        let protocol = reader.get_protocol();
        let comm_flags = match reader.get_comm_type().unwrap() {
            v1::CommType::Bidirectional => CommFlag::BiDirectional,
            v1::CommType::Unidirectional => CommFlag::UniDirectional,
            v1::CommType::Rerequest => CommFlag::ReRequest(0), // TODO
        };

        Ok(PacketDesc {
            five_tuple: VsapiFiveTuple::new(
                l3type_of_addr(&source),
                source,
                dest,
                protocol,
                source_port,
                dest_port,
            ),
            comm_flags,
        })
    }
}

impl TryFrom<v1::visa_response::Reader<'_>> for VisaResponse {
    type Error = VsapiTypeError;

    fn try_from(capnp_visa_response: v1::visa_response::Reader) -> Result<Self, Self::Error> {
        match capnp_visa_response.which()? {
            v1::visa_response::Which::Allow(v) => {
                let visa = v?;
                Ok(Self::Allow(visa.try_into()?))
            }
            v1::visa_response::Which::Deny(c) => {
                let deny_code = DenyCode::from(c?);
                Ok(Self::Deny(Denied::new(deny_code, None)))
            }
            v1::visa_response::Which::Error(e) => {
                let code = ErrorCode::from(e?.get_code()?);
                Err(VsapiTypeError::CodedError(code))
            }
        }
    }
}

impl From<v1::VisaDenyCode> for DenyCode {
    fn from(code: v1::VisaDenyCode) -> Self {
        match code {
            v1::VisaDenyCode::NoReason => DenyCode::NoReason,
            v1::VisaDenyCode::NoMatch => DenyCode::NoMatch,
            v1::VisaDenyCode::Denied => DenyCode::Denied,
            v1::VisaDenyCode::SourceNotFound => DenyCode::SourceNotFound,
            v1::VisaDenyCode::DestNotFound => DenyCode::DestNotFound,
            v1::VisaDenyCode::SourceAuthError => DenyCode::SourceAuthError,
            v1::VisaDenyCode::DestAuthError => DenyCode::DestAuthError,
            v1::VisaDenyCode::QuotaExceeded => DenyCode::QuotaExceeded,
        }
    }
}

impl Into<v1::VisaDenyCode> for DenyCode {
    fn into(self) -> v1::VisaDenyCode {
        match self {
            DenyCode::Fail => v1::VisaDenyCode::NoReason, // No direct mapping (TODO: remove Fail)
            DenyCode::NoReason => v1::VisaDenyCode::NoReason,
            DenyCode::NoMatch => v1::VisaDenyCode::NoMatch,
            DenyCode::Denied => v1::VisaDenyCode::Denied,
            DenyCode::SourceNotFound => v1::VisaDenyCode::SourceNotFound,
            DenyCode::DestNotFound => v1::VisaDenyCode::DestNotFound,
            DenyCode::SourceAuthError => v1::VisaDenyCode::SourceAuthError,
            DenyCode::DestAuthError => v1::VisaDenyCode::DestAuthError,
            DenyCode::QuotaExceeded => v1::VisaDenyCode::QuotaExceeded,
        }
    }
}

impl From<v1::ErrorCode> for ErrorCode {
    fn from(code: v1::ErrorCode) -> Self {
        match code {
            v1::ErrorCode::Internal => ErrorCode::Internal,
            v1::ErrorCode::AuthRequired => ErrorCode::AuthRequired,
            v1::ErrorCode::InvalidOperation => ErrorCode::InvalidOperation,
            v1::ErrorCode::OutOfSync => ErrorCode::OutOfSync,
            v1::ErrorCode::NotFound => ErrorCode::NotFound,
            v1::ErrorCode::InvalidSignature => ErrorCode::InvalidSignature,
            v1::ErrorCode::QuotaExceeded => ErrorCode::QuotaExceeded,
            v1::ErrorCode::TemporarilyUnavailable => ErrorCode::TemporarilyUnavailable,
            v1::ErrorCode::AuthError => ErrorCode::AuthError,
            v1::ErrorCode::ParamError => ErrorCode::ParamError,
        }
    }
}

impl TryFrom<vsapi::VisaResponse> for VisaResponse {
    type Error = VsapiTypeError;

    fn try_from(thrift_visa_response: vsapi::VisaResponse) -> Result<Self, Self::Error> {
        match thrift_visa_response.status {
            Some(code) => match code {
                vsapi::StatusCode::SUCCESS => {
                    if let Some(thrift_visa_hop) = thrift_visa_response.visa {
                        let visa = Visa::try_from(thrift_visa_hop)?;
                        Ok(Self::Allow(visa))
                    } else {
                        Err(VsapiTypeError::DeserializationError(
                            "No VisaHop in VisaResponse",
                        ))
                    }
                }
                vsapi::StatusCode::FAIL => Ok(Self::Deny(Denied::new(
                    DenyCode::Fail,
                    thrift_visa_response.reason,
                ))),
                _ => {
                    return Err(VsapiTypeError::DeserializationError("Unknown status code"));
                }
            },
            None => Err(VsapiTypeError::DeserializationError(
                "No code, required in Thrift visa",
            )),
        }
    }
}

impl Denied {
    pub fn new(code: DenyCode, reason: Option<String>) -> Self {
        Self { code, reason }
    }
}

impl VisaResponseError {
    pub fn new(code: ErrorCode, message: String, retry_in: u32) -> Self {
        Self {
            code,
            message,
            retry_in,
        }
    }
}

// TODO figure out which of these need to stay once we switch to capnp
#[derive(Debug, Clone)]
pub struct Visa {
    pub issuer_id: u64, // i32 in thrift, u64 in capnp
    pub config: i64,
    pub expires: SystemTime,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dock_pep: DockPep,
    pub session_key: KeySet,
    pub cons: Option<Constraints>,
}

#[derive(Debug, Clone)]
pub enum DockPep {
    TCP(TcpUdpPep),
    UDP(TcpUdpPep),
    ICMP(IcmpPep),
}

#[derive(Debug, Clone)]
pub struct TcpUdpPep {
    pub source_port: u16,
    pub dest_port: u16,
    pub endpoint: EndpointT,
}

#[derive(Debug, Clone)]
pub enum EndpointT {
    Any,
    Server,
    Client,
}

#[derive(Debug, Clone)]
pub struct IcmpPep {
    /// the allowed ICMP type and code (in lower 16 bits)
    pub icmp_type: u8,
    pub icmp_code: u8,
}

#[derive(Default, Debug, Clone)]
pub struct KeySet {
    pub format: KeyFormat,
    /// session key encrypted for ingress node to read
    pub ingress_key: Vec<u8>,
    /// session key encrypted for egress node to read
    pub egress_key: Vec<u8>,
}

#[derive(Default, Debug, Clone)]
pub enum KeyFormat {
    #[default]
    ZprKF01,
}

impl KeySet {
    pub fn new(ingress: &[u8], egress: &[u8]) -> Self {
        KeySet {
            ingress_key: ingress.to_vec(),
            egress_key: egress.to_vec(),
            format: KeyFormat::default(),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Constraints {
    /// not set or none means no bandwidth constraint
    pub bw: bool,
    pub bw_limit_bps: i64,
    /// empty/None means no data cap
    pub data_cap_id: String,
    pub data_cap_bytes: i64,
    /// tether address of service actor
    pub data_cap_affinity_addr: Vec<u8>,
}

#[derive(Copy, Clone, Debug)]
pub struct VsapiFiveTuple {
    pub src_address: IpAddr,
    pub dst_address: IpAddr,
    pub l3_type: L3Type,
    pub l4_protocol: VsapiIpProtocol,
    pub src_port: u16,
    pub dst_port: u16,
}

impl VsapiFiveTuple {
    pub fn new(
        l3_type: L3Type,
        src_address: IpAddr,
        dst_address: IpAddr,
        l4_protocol: VsapiIpProtocol,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            src_address,
            dst_address,
            l3_type,
            l4_protocol,
            src_port,
            dst_port,
        }
    }
}

pub type VsapiIpProtocol = u8;

pub mod vsapi_ip_number {
    use super::VsapiIpProtocol;

    pub const HOPOPT: VsapiIpProtocol = 0;
    pub const ICMP: VsapiIpProtocol = 1;
    pub const IPINIP: VsapiIpProtocol = 4;
    pub const TCP: VsapiIpProtocol = 6;
    pub const UDP: VsapiIpProtocol = 17;
    pub const IPV6_ROUTE: VsapiIpProtocol = 43;
    pub const IPV6_FRAG: VsapiIpProtocol = 44;
    pub const AH: VsapiIpProtocol = 51;
    pub const IPV6_ICMP: VsapiIpProtocol = 58;
    pub const IPV6_OPTS: VsapiIpProtocol = 60;
}

impl Visa {
    pub fn get_five_tuple(&self) -> VsapiFiveTuple {
        let src_addr = self.src_addr;
        let dst_addr = self.dst_addr;

        let l3_protocol = if src_addr.is_ipv4() {
            L3Type::Ipv4
        } else {
            L3Type::Ipv6
        };

        let (l4_protocol, src_port, dst_port) = match &self.dock_pep {
            DockPep::ICMP(icmp_pep) => {
                if l3_protocol == L3Type::Ipv6 {
                    (
                        vsapi_ip_number::IPV6_ICMP,
                        icmp_pep.icmp_type as u16,
                        icmp_pep.icmp_code as u16,
                    )
                } else {
                    (
                        vsapi_ip_number::ICMP,
                        icmp_pep.icmp_type as u16,
                        icmp_pep.icmp_code as u16,
                    )
                }
            }
            DockPep::UDP(tcp_udp_pep) => (
                vsapi_ip_number::UDP,
                tcp_udp_pep.source_port,
                tcp_udp_pep.dest_port,
            ),
            DockPep::TCP(tcp_udp_pep) => (
                vsapi_ip_number::TCP,
                tcp_udp_pep.source_port,
                tcp_udp_pep.dest_port,
            ),
        };

        return VsapiFiveTuple {
            src_address: src_addr,
            dst_address: dst_addr,
            l3_type: l3_protocol,
            l4_protocol,
            src_port,
            dst_port,
        };
    }

    /// Get the expiration in milliseconds since UNIX epoch (which is how visa service formats it).
    pub fn get_expiration_timestamp(&self) -> u64 {
        match self.expires.duration_since(UNIX_EPOCH) {
            Ok(dur) => dur.as_millis() as u64,
            Err(_) => 0,
        }
    }
}

/// Convert a visa expiration timestamp (milliseconds since UNIX epoch) to SystemTime.
pub fn visa_expiration_timestamp_to_system_time(timestamp: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(timestamp)
}

impl TryFrom<v1::visa::Reader<'_>> for Visa {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::visa::Reader) -> Result<Self, Self::Error> {
        let issuer_id = reader.get_issuer_id();
        let config = 0i64;
        let expires = visa_expiration_timestamp_to_system_time(reader.get_expiration());
        let src_addr = match reader.get_source_addr()?.which()? {
            v1::ip_addr::Which::V4(data) => IpAddr::from(<[u8; 4]>::try_from(data?)?),
            v1::ip_addr::Which::V6(data) => IpAddr::from(<[u8; 16]>::try_from(data?)?),
        };
        let dst_addr = match reader.get_dest_addr()?.which()? {
            v1::ip_addr::Which::V4(data) => {
                IpAddr::from(<[u8; 4]>::try_from(data.unwrap()).unwrap())
            }
            v1::ip_addr::Which::V6(data) => {
                IpAddr::from(<[u8; 16]>::try_from(data.unwrap()).unwrap())
            }
        };

        let dock_pep = DockPep::try_from(reader.get_dock_pep()?)?;
        let session_key = KeySet::try_from(reader.get_session_key()?)?;

        // TODO: constraints not yet implemented.
        let cons = None;

        Ok(Self {
            issuer_id,
            config,
            expires,
            src_addr,
            dst_addr,
            dock_pep,
            session_key,
            cons,
        })
    }
}

impl TryFrom<vsapi::VisaHop> for Visa {
    type Error = VsapiTypeError;

    fn try_from(hop: vsapi::VisaHop) -> Result<Self, Self::Error> {
        match hop.visa {
            Some(visa) => Visa::try_from(visa),
            None => Err(VsapiTypeError::DeserializationError("No visa")),
        }
    }
}

// Could also implement a TryFrom instead of picking arbitarty values
impl TryFrom<vsapi::Visa> for Visa {
    type Error = VsapiTypeError;

    fn try_from(thrift_visa: vsapi::Visa) -> Result<Self, Self::Error> {
        let issuer_id = match thrift_visa.issuer_id {
            Some(val) => val as u64,
            None => {
                return Err(VsapiTypeError::DeserializationError("No issuer id"));
            }
        };
        let config = match thrift_visa.configuration {
            Some(val) => val,
            None => 0,
        };
        let expires = match thrift_visa.expires {
            Some(val) => visa_expiration_timestamp_to_system_time(val as u64),
            None => {
                return Err(VsapiTypeError::DeserializationError("No expiration"));
            }
        };
        let src_addr = match thrift_visa.source_contact {
            Some(val) => ip_addr_from_vec(val)?,
            None => return Err(VsapiTypeError::DeserializationError("No src address")),
        };
        let dst_addr = match thrift_visa.dest_contact {
            Some(val) => ip_addr_from_vec(val)?,
            None => return Err(VsapiTypeError::DeserializationError("No dst address")),
        };
        let dock_pep = match thrift_visa.dock_pep {
            Some(val) => match val {
                vsapi::PEPIndex::UDP => {
                    let tcp_udp_pep = match thrift_visa.tcpudp_pep_args {
                        Some(val) => TcpUdpPep::from(val),
                        None => {
                            return Err(VsapiTypeError::DeserializationError(
                                "No TCP/UDP PEP Args",
                            ));
                        }
                    };
                    DockPep::UDP(tcp_udp_pep)
                }
                vsapi::PEPIndex::TCP => {
                    let tcp_udp_pep = match thrift_visa.tcpudp_pep_args {
                        Some(val) => TcpUdpPep::from(val),
                        None => {
                            return Err(VsapiTypeError::DeserializationError(
                                "No TCP/UDP PEP Args",
                            ));
                        }
                    };
                    DockPep::TCP(tcp_udp_pep)
                }
                vsapi::PEPIndex::ICMP => {
                    let icmp_pep = match thrift_visa.icmp_pep_args {
                        Some(val) => IcmpPep::from(val),
                        None => {
                            return Err(VsapiTypeError::DeserializationError("No ICMP PEP Args"));
                        }
                    };
                    DockPep::ICMP(icmp_pep)
                }
                _ => return Err(VsapiTypeError::DeserializationError("Unknown Dock Pep")),
            },
            None => return Err(VsapiTypeError::DeserializationError("No Dock Pep")),
        };

        let session_key = match thrift_visa.session_key {
            Some(val) => KeySet::try_from(val)?,
            None => KeySet::default(),
        };
        let cons = match thrift_visa.cons {
            Some(val) => Some(Constraints::from(val)),
            None => None,
        };

        Ok(Self {
            issuer_id,
            config,
            expires,
            src_addr,
            dst_addr,
            dock_pep,
            session_key,
            cons,
        })
    }
}

pub fn ip_addr_from_vec(v: Vec<u8>) -> Result<IpAddr, VsapiTypeError> {
    match v.len() {
        4 => Ok(IpAddr::from(
            <[u8; 4]>::try_from(v.as_slice()).expect("Bad IP length"),
        )),
        16 => Ok(IpAddr::from(
            <[u8; 16]>::try_from(v.as_slice()).expect("Bad IP length"),
        )),
        _ => Err(VsapiTypeError::DeserializationError(
            "Bad IP Address format",
        )),
    }
}

impl TryFrom<v1::dock_pep::Reader<'_>> for DockPep {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::dock_pep::Reader) -> Result<Self, Self::Error> {
        match reader.which()? {
            v1::dock_pep::Which::Tcp(tcp_udp_pep_result) => {
                let tcp_udp_pep_reader = tcp_udp_pep_result?;
                let source_port = tcp_udp_pep_reader.get_source_port();
                let dest_port = tcp_udp_pep_reader.get_dest_port();
                let enpoint = match tcp_udp_pep_reader.get_enpoint()? {
                    v1::EndpointT::Any => EndpointT::Any,
                    v1::EndpointT::Server => EndpointT::Server,
                    v1::EndpointT::Client => EndpointT::Client,
                };
                let tcp_udp_pep = TcpUdpPep::new(source_port, dest_port, enpoint);
                Ok(DockPep::TCP(tcp_udp_pep))
            }
            v1::dock_pep::Which::Udp(tcp_udp_pep_result) => {
                let tcp_udp_pep_reader = tcp_udp_pep_result?;
                let source_port = tcp_udp_pep_reader.get_source_port();
                let dest_port = tcp_udp_pep_reader.get_dest_port();
                let enpoint = match tcp_udp_pep_reader.get_enpoint()? {
                    v1::EndpointT::Any => EndpointT::Any,
                    v1::EndpointT::Server => EndpointT::Server,
                    v1::EndpointT::Client => EndpointT::Client,
                };
                let tcp_udp_pep = TcpUdpPep::new(source_port, dest_port, enpoint);
                Ok(DockPep::UDP(tcp_udp_pep))
            }
            v1::dock_pep::Which::Icmp(icmp_pep_result) => {
                let icmp_pep_reader = icmp_pep_result?;
                let type_code = icmp_pep_reader.get_icmp_type_code();
                let icmp_pep = IcmpPep::new(type_code as u8, 0);
                Ok(DockPep::ICMP(icmp_pep))
            }
        }
    }
}

impl TcpUdpPep {
    pub fn new(source_port: u16, dest_port: u16, endpoint: EndpointT) -> Self {
        Self {
            source_port,
            dest_port,
            endpoint,
        }
    }
}

impl From<vsapi::PEPArgsTCPUDP> for TcpUdpPep {
    fn from(thrift_tcp_udp_pep: vsapi::PEPArgsTCPUDP) -> Self {
        let source_port = match thrift_tcp_udp_pep.source_port {
            Some(val) => val as u16,
            None => 0,
        };
        let dest_port = match thrift_tcp_udp_pep.dest_port {
            Some(val) => val as u16,
            None => 0,
        };

        Self {
            source_port,
            dest_port,
            endpoint: match thrift_tcp_udp_pep.server {
                Some(true) => EndpointT::Server,
                Some(false) => EndpointT::Client,
                None => EndpointT::Any,
            },
        }
    }
}

impl IcmpPep {
    pub fn new(icmp_type: u8, icmp_code: u8) -> Self {
        Self {
            icmp_type,
            icmp_code,
        }
    }
}

impl From<vsapi::PEPArgsICMP> for IcmpPep {
    fn from(thrift_icmp_pep: vsapi::PEPArgsICMP) -> Self {
        let icmp_type_code = match thrift_icmp_pep.icmp_type_code {
            Some(val) => val as u16,
            None => 0,
        };

        Self {
            icmp_type: icmp_type_code as u8,
            icmp_code: 0,
        }
    }
}

impl TryFrom<v1::key_set::Reader<'_>> for KeySet {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::key_set::Reader) -> Result<Self, Self::Error> {
        let format = match reader.get_format()? {
            v1::KeyFormat::ZprKF01 => KeyFormat::ZprKF01,
        };
        let ingress_key = reader.get_ingress_key()?.to_vec();
        let egress_key = reader.get_egress_key()?.to_vec();

        Ok(Self {
            format,
            ingress_key,
            egress_key,
        })
    }
}

impl TryFrom<vsapi::KeySet> for KeySet {
    type Error = VsapiTypeError;

    fn try_from(thrift_key_set: vsapi::KeySet) -> Result<Self, Self::Error> {
        let format = match thrift_key_set.format {
            Some(_) => KeyFormat::ZprKF01,
            None => return Err(VsapiTypeError::DeserializationError("No format")),
        };
        let ingress_key = match thrift_key_set.ingress_key {
            Some(val) => val,
            None => Vec::new(),
        };
        let egress_key = match thrift_key_set.egress_key {
            Some(val) => val,
            None => Vec::new(),
        };

        Ok(Self {
            format,
            ingress_key,
            egress_key,
        })
    }
}

impl From<vsapi::Constraints> for Constraints {
    fn from(thrift_cons: vsapi::Constraints) -> Self {
        let bw = match thrift_cons.bw {
            Some(val) => val,
            None => false,
        };
        let bw_limit_bps = match thrift_cons.bw_limit_bps {
            Some(val) => val,
            None => 0,
        };
        let data_cap_id = match thrift_cons.data_cap_id {
            Some(val) => val,
            None => String::new(),
        };
        let data_cap_bytes = match thrift_cons.data_cap_bytes {
            Some(val) => val,
            None => 0,
        };
        let data_cap_affinity_addr = match thrift_cons.data_cap_affinity_addr {
            Some(val) => val,
            None => Vec::new(),
        };

        Self {
            bw,
            bw_limit_bps,
            data_cap_id,
            data_cap_bytes,
            data_cap_affinity_addr,
        }
    }
}

pub enum VisaOp {
    Grant(Visa),
    RevokeVisaId(u64),
}

impl TryFrom<vsapi::VisaRevocation> for VisaOp {
    type Error = VsapiTypeError;

    fn try_from(revoke: vsapi::VisaRevocation) -> Result<Self, Self::Error> {
        match revoke.issuer_id {
            Some(id) => Ok(Self::RevokeVisaId(id as u64)),
            None => Err(VsapiTypeError::DeserializationError("No issuer id")),
        }
    }
}

#[derive(Debug)]
pub struct ConnectRequest {
    pub blobs: Vec<AuthBlob>,
    pub claims: Vec<Claim>,
    pub substrate_addr: IpAddr,
    pub dock_interface: u8,
}

#[derive(Debug)]
pub struct Claim {
    pub key: String,
    pub value: String,
}

impl Claim {
    pub fn new(key: String, value: String) -> Self {
        Self { key, value }
    }
}

#[derive(Debug)]
pub enum AuthBlob {
    SS(ZprSelfSignedBlob),
    AC(AuthCodeBlob),
}

#[derive(Debug, Default)]
pub struct ZprSelfSignedBlob {
    pub alg: ChallengeAlg,
    pub challenge: Vec<u8>,
    pub cn: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct AuthCodeBlob {
    pub asa_addr: IpAddr,
    pub code: String,
    pub pkce: String,
    pub client_id: String,
}

#[derive(Debug, Default)]
pub enum ChallengeAlg {
    #[default]
    RsaSha256Pkcs1v15,
}

impl TryFrom<vsapi::ConnectRequest> for ConnectRequest {
    type Error = VsapiTypeError;

    fn try_from(thrift_req: vsapi::ConnectRequest) -> Result<Self, Self::Error> {
        let substrate_addr = match thrift_req.dock_addr {
            Some(val) => ip_addr_from_vec(val)?,
            None => return Err(VsapiTypeError::DeserializationError("No dock address")),
        };
        let claims = match thrift_req.claims {
            Some(claims) => {
                let mut v = Vec::new();
                for (key, val) in claims.iter() {
                    v.push(Claim::new(key.clone(), val.clone()));
                }
                v
            }
            None => return Err(VsapiTypeError::DeserializationError("No claims")),
        };
        let blobs = match thrift_req.challenge_responses {
            Some(cr) => {
                let mut b = Vec::new();
                for r in cr {
                    let mut ss = ZprSelfSignedBlob::default();
                    ss.challenge = r;
                    b.push(AuthBlob::SS(ss))
                }
                b
            }
            None => {
                return Err(VsapiTypeError::DeserializationError(
                    "No challenge responses",
                ));
            }
        };
        Ok(Self {
            blobs,
            claims,
            substrate_addr,
            dock_interface: 0,
        })
    }
}

impl TryFrom<ConnectRequest> for vsapi::ConnectRequest {
    type Error = VsapiTypeError;

    fn try_from(req: ConnectRequest) -> Result<Self, Self::Error> {
        let mut claims = BTreeMap::new();
        for claim in req.claims {
            claims.insert(claim.key, claim.value);
        }

        let mut challenge_responses = Vec::new();
        for blob in req.blobs {
            match blob {
                AuthBlob::SS(ss) => challenge_responses.push(ss.challenge),
                AuthBlob::AC(_) => {
                    return Err(VsapiTypeError::DeserializationError("Incorrect blob type"));
                }
            }
        }

        let dock_addr = match req.substrate_addr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        Ok(Self {
            connection_id: Some(0),
            dock_addr: Some(dock_addr),
            claims: Some(claims),
            challenge: None,
            challenge_responses: Some(challenge_responses),
        })
    }
}

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

impl TryFrom<vsapi::ServicesList> for AuthServicesList {
    type Error = VsapiTypeError;

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

/// A parsed [vsapi::ServiceDescriptor] that we use to keep ASA records.
#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    pub service_id: String,
    pub service_uri: String,
    pub zpr_address: IpAddr,
}

impl TryFrom<vsapi::ServiceDescriptor> for ServiceDescriptor {
    type Error = VsapiTypeError;

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

#[derive(Debug)]
pub struct Connection {
    pub zpr_addr: IpAddr,
    pub auth_expires: u64,
}

impl TryFrom<vsapi::ConnectResponse> for Connection {
    type Error = VsapiTypeError;

    fn try_from(resp: vsapi::ConnectResponse) -> Result<Self, Self::Error> {
        match resp.status {
            Some(vsapi::StatusCode::FAIL) => Err(VsapiTypeError::CodedError(ErrorCode::Fail)),
            Some(vsapi::StatusCode::SUCCESS) => match resp.actor {
                Some(actor) => {
                    if actor.zpr_addr.is_some() && actor.auth_expires.is_some() {
                        return Ok(Self {
                            zpr_addr: ip_addr_from_vec(actor.zpr_addr.unwrap())?,
                            auth_expires: actor.auth_expires.unwrap() as u64,
                        });
                    } else {
                        return Err(VsapiTypeError::DeserializationError(
                            "Required fields not set",
                        ));
                    }
                }
                None => return Err(VsapiTypeError::DeserializationError("No actor")),
            },
            _ => Err(VsapiTypeError::DeserializationError(
                "No matching status code",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

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
