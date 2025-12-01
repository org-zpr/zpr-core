//! Our internal visa type
//!
//! Currently based on a mix of the thrift and capnp protocols, will likely evolve as we move
//! away from thrift exclusively to capnp.

use super::L3Type;
use crate::vsapi::v1;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use vsapi;

#[derive(Debug, Error)]
pub enum VisaError {
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
}

impl TryFrom<v1::visa_response::Reader<'_>> for VisaResponse {
    type Error = VisaError;

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
                Err(VisaError::CodedError(code))
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
    type Error = VisaError;

    fn try_from(thrift_visa_response: vsapi::VisaResponse) -> Result<Self, Self::Error> {
        match thrift_visa_response.status {
            Some(code) => match code {
                vsapi::StatusCode::SUCCESS => {
                    if let Some(thrift_visa_hop) = thrift_visa_response.visa {
                        let visa = Visa::try_from(thrift_visa_hop)?;
                        Ok(Self::Allow(visa))
                    } else {
                        Err(VisaError::DeserializationError(
                            "No VisaHop in VisaResponse",
                        ))
                    }
                }
                vsapi::StatusCode::FAIL => Ok(Self::Deny(Denied::new(
                    DenyCode::Fail,
                    thrift_visa_response.reason,
                ))),
                _ => {
                    return Err(VisaError::DeserializationError("Unknown status code"));
                }
            },
            None => Err(VisaError::DeserializationError(
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
    pub cons: Constraints,
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
    pub endpoint: Option<EndpointT>,
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

#[derive(Copy, Clone)]
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
}

impl TryFrom<v1::visa::Reader<'_>> for Visa {
    type Error = VisaError;

    fn try_from(reader: v1::visa::Reader) -> Result<Self, Self::Error> {
        let issuer_id = reader.get_issuer_id();
        let config = 0i64;
        let expires = UNIX_EPOCH + Duration::from_millis(reader.get_expiration());
        let src_addr = match reader.get_source_addr()?.which()? {
            v1::ip_addr::Which::V4(data) => {
                IpAddr::from(<[u8; 4]>::try_from(data?)?)
            }
            v1::ip_addr::Which::V6(data) => {
                IpAddr::from(<[u8; 16]>::try_from(data?)?)
            }
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
        let cons = Constraints::default();

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
    type Error = VisaError;

    fn try_from(hop: vsapi::VisaHop) -> Result<Self, Self::Error> {
        match hop.visa {
            Some(visa) => Visa::try_from(visa),
            None => Err(VisaError::DeserializationError("No visa")),
        }
    }
}

// Could also implement a TryFrom instead of picking arbitarty values
impl TryFrom<vsapi::Visa> for Visa {
    type Error = VisaError;

    fn try_from(thrift_visa: vsapi::Visa) -> Result<Self, Self::Error> {
        let issuer_id = match thrift_visa.issuer_id {
            Some(val) => val as u64,
            None => {
                return Err(VisaError::DeserializationError("No issuer id"));
            }
        };
        let config = match thrift_visa.configuration {
            Some(val) => val,
            None => 0,
        };
        let expires = match thrift_visa.expires {
            Some(val) => {
                let dur = Duration::from_millis(val as u64);
                UNIX_EPOCH + dur
            }
            None => {
                return Err(VisaError::DeserializationError("No expiration"));
            }
        };
        let src_addr = match thrift_visa.source_contact {
            Some(val) => match ip_addr_from_vec(val) {
                Ok(addr) => addr,
                Err(_) => {
                    return Err(VisaError::DeserializationError("Bad format in src address"));
                }
            },
            None => return Err(VisaError::DeserializationError("No src address")),
        };
        let dst_addr = match thrift_visa.dest_contact {
            Some(val) => match ip_addr_from_vec(val) {
                Ok(addr) => addr,
                Err(_) => {
                    return Err(VisaError::DeserializationError("Bad format in dst address"));
                }
            },
            None => return Err(VisaError::DeserializationError("No dst address")),
        };
        let dock_pep = match thrift_visa.dock_pep {
            Some(val) => match val {
                vsapi::PEPIndex::UDP => {
                    let tcp_udp_pep = match thrift_visa.tcpudp_pep_args {
                        Some(val) => TcpUdpPep::from(val),
                        None => {
                            return Err(VisaError::DeserializationError("No TCP/UDP PEP Args"));
                        }
                    };
                    DockPep::UDP(tcp_udp_pep)
                }
                vsapi::PEPIndex::TCP => {
                    let tcp_udp_pep = match thrift_visa.tcpudp_pep_args {
                        Some(val) => TcpUdpPep::from(val),
                        None => {
                            return Err(VisaError::DeserializationError("No TCP/UDP PEP Args"));
                        }
                    };
                    DockPep::TCP(tcp_udp_pep)
                }
                vsapi::PEPIndex::ICMP => {
                    let icmp_pep = match thrift_visa.icmp_pep_args {
                        Some(val) => IcmpPep::from(val),
                        None => {
                            return Err(VisaError::DeserializationError("No ICMP PEP Args"));
                        }
                    };
                    DockPep::ICMP(icmp_pep)
                }
                _ => return Err(VisaError::DeserializationError("Unknown Dock Pep")),
            },
            None => return Err(VisaError::DeserializationError("No Dock Pep")),
        };

        let session_key = match thrift_visa.session_key {
            Some(val) => KeySet::try_from(val)?,
            None => KeySet::default(),
        };
        let cons = match thrift_visa.cons {
            Some(val) => Constraints::from(val),
            None => Constraints::default(),
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

pub fn ip_addr_from_vec(v: Vec<u8>) -> Result<IpAddr, Vec<u8>> {
    match v.len() {
        4 => Ok(IpAddr::from(
            <[u8; 4]>::try_from(v.as_slice()).expect("Bad IP length"),
        )),
        16 => Ok(IpAddr::from(
            <[u8; 16]>::try_from(v.as_slice()).expect("Bad IP length"),
        )),
        _ => Err(v),
    }
}

impl TryFrom<v1::dock_pep::Reader<'_>> for DockPep {
    type Error = VisaError;

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
    pub fn new(src: u16, dst: u16, endpt: EndpointT) -> Self {
        Self {
            source_port: src,
            dest_port: dst,
            endpoint: Some(endpt),
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
            endpoint: None,
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
    type Error = VisaError;

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
    type Error = VisaError;

    fn try_from(thrift_key_set: vsapi::KeySet) -> Result<Self, Self::Error> {
        let format = match thrift_key_set.format {
            Some(_) => KeyFormat::ZprKF01,
            None => return Err(VisaError::DeserializationError("No format")),
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
