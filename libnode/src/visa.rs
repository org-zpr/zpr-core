use crate::net_defs::{IpAddress, IpProtocol, ip_number};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vsapi;

pub enum VisaResponse {
    Allow(Visa),
    Deny(Denied),
    Error(Error),
}

pub struct Denied {
    pub code: DenyCode,
    pub reason: String,
}

// Will be more useful once we transition to capnp, right now we only use Fail
pub enum DenyCode {
    Fail,
    NoReason,
    NoMatch,
    Denied,
    SourceNotFound,
    DestNotFound,
    SourceAuthEreror,
    QuotaExceeded,
}

pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    pub retry_in: u32,
}

pub enum ErrorCode {
    Internal,
    AuthRequired,
    InvalidOperation,
    OutOfSync,
    NotFound,
    InvalidSignature,
    QuotaExceeded,
    TemporatilyUnavailable,
    AuthError,
    UnknownStatusCode,
}

impl From<vsapi::VisaResponse> for VisaResponse {
    fn from(thrift_visa_response: vsapi::VisaResponse) -> Self {
        match thrift_visa_response.status {
            Some(code) => match code {
                vsapi::StatusCode::SUCCESS => {
                    Self::Allow(Visa::from(thrift_visa_response.visa.unwrap().visa.unwrap()))
                }
                vsapi::StatusCode::FAIL => match thrift_visa_response.reason {
                    Some(reason) => Self::Deny(Denied::new(DenyCode::Fail, reason)),
                    None => Self::Deny(Denied::new(DenyCode::Fail, String::new())),
                },
                val => Self::Error(Error::new(
                    ErrorCode::UnknownStatusCode,
                    format!("Status code: {val:?}"),
                    0,
                )),
            },
            None => Self::Error(Error::new(
                ErrorCode::UnknownStatusCode,
                "No status code".to_string(),
                0,
            )),
        }
    }
}

impl Denied {
    pub fn new(code: DenyCode, reason: String) -> Self {
        Self { code, reason }
    }
}

impl Error {
    pub fn new(code: ErrorCode, message: String, retry_in: u32) -> Self {
        Self {
            code,
            message,
            retry_in,
        }
    }
}

// TODO figure out which of these need to stay once we switch to capnp
pub struct Visa {
    pub issuer_id: u64, // i32 in thrift, u64 in capnp
    pub config: i64,
    pub expires: SystemTime,
    // pub source: Vec<u8>,
    pub dest: IpAddress,
    pub src_addr: IpAddress,
    pub dst_addr: IpAddress,
    pub dock_pep: IpProtocol,
    pub tcp_udp_pep: Option<TcpUdpPep>,
    pub icmp_pep: Option<IcmpPep>,
    pub session_key: KeySet,
    pub cons: Constraints,
    // pub sig: Signature, // not in capnp
}

pub struct TcpUdpPep {
    // pub source_contact_addr: Vec<u8>,
    // pub dest_contact_addr: Vec<u8>,
    pub source_port: u16,
    pub dest_port: u16,
    // /// If this visa is for dock on server side.
    // pub server: bool,
    // /// list of allowed ICMP types
    // pub icmp_allowed: Vec<i32>,
    // pub endpoint: EndpointT, // not in thrift
}

pub struct IcmpPep {
    // pub source_contact_addr: Vec<u8>,
    // pub dest_contact_addr: Vec<u8>,
    // /// the allowed ICMP type and code (in lower 16 bits)
    pub icmp_type_code: u16,
    // /// use 0xFF for none
    // pub icmp_antecedent: i32,
    // /// timeout for state in milliseconds
    // pub state_timeout_ms: i32,
    // /// If we allow only one reply to a request
    // pub one_shot: bool,
}

#[derive(Default)]
pub struct KeySet {
    pub format: i32,
    /// session key encrypted for ingress node to read
    pub ingress_key: Vec<u8>,
    /// session key encrypted for egress node to read
    pub egress_key: Vec<u8>,
}

#[derive(Default)]
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

pub struct Signature {
    pub ty: i32,
    pub signature: Vec<u8>,
}

pub enum EndpointT {
    Any,
    Server,
    Client,
}

// Could also implement a TryFrom instead of picking arbitarty values
impl From<vsapi::Visa> for Visa {
    fn from(thrift_visa: vsapi::Visa) -> Self {
        let issuer_id = match thrift_visa.issuer_id {
            Some(val) => val as u64,
            None => 0,
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
            None => SystemTime::now(),
        };
        let dest = match thrift_visa.dest {
            Some(val) => match IpAddress::try_from(val) {
                Ok(addr) => addr,
                Err(_) => IpAddress::UNSPECIFIED,
            },
            None => IpAddress::UNSPECIFIED,
        };
        let src_addr = match thrift_visa.source_contact {
            Some(val) => match IpAddress::try_from(val) {
                Ok(addr) => addr,
                Err(_) => IpAddress::UNSPECIFIED,
            },
            None => IpAddress::UNSPECIFIED,
        };
        let dst_addr = match thrift_visa.dest_contact {
            Some(val) => match IpAddress::try_from(val) {
                Ok(addr) => addr,
                Err(_) => IpAddress::UNSPECIFIED,
            },
            None => IpAddress::UNSPECIFIED,
        };
        let dock_pep = match thrift_visa.dock_pep {
            Some(val) => {
                match val {
                    vsapi::PEPIndex::UDP => ip_number::UDP,
                    vsapi::PEPIndex::TCP => ip_number::TCP,
                    vsapi::PEPIndex::ICMP => ip_number::ICMP,
                    _ => ip_number::UDP, // Not sure what default here should be, perhaps we want to make a UNSET ip number
                }
            }
            None => ip_number::UDP, // Not sure what default here should be
        };
        let tcp_udp_pep = match thrift_visa.tcpudp_pep_args {
            Some(val) => Some(TcpUdpPep::from(val)),
            None => None,
        };
        let icmp_pep = match thrift_visa.icmp_pep_args {
            Some(val) => Some(IcmpPep::from(val)),
            None => None,
        };
        let session_key = match thrift_visa.session_key {
            Some(val) => KeySet::from(val),
            None => KeySet::default(),
        };
        let cons = match thrift_visa.cons {
            Some(val) => Constraints::from(val),
            None => Constraints::default(),
        };
        Self {
            issuer_id,
            config,
            expires,
            dest,
            src_addr,
            dst_addr,
            dock_pep,
            tcp_udp_pep,
            icmp_pep,
            session_key,
            cons,
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
        }
    }
}

impl From<vsapi::PEPArgsICMP> for IcmpPep {
    fn from(thrift_icmp_pep: vsapi::PEPArgsICMP) -> Self {
        let icmp_type_code = match thrift_icmp_pep.icmp_type_code {
            Some(val) => val as u16,
            None => 0,
        };

        Self { icmp_type_code }
    }
}

impl From<vsapi::KeySet> for KeySet {
    fn from(thrift_key_set: vsapi::KeySet) -> Self {
        let format = match thrift_key_set.format {
            Some(val) => val,
            None => 0,
        };
        let ingress_key = match thrift_key_set.ingress_key {
            Some(val) => val,
            None => Vec::new(),
        };
        let egress_key = match thrift_key_set.egress_key {
            Some(val) => val,
            None => Vec::new(),
        };

        Self {
            format,
            ingress_key,
            egress_key,
        }
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
