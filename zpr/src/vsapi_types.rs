//! Our internal visa type
//!
//! Currently based on a mix of the thrift and capnp protocols, will likely evolve as we move
//! away from thrift exclusively to capnp.

use super::L3Type;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use vsapi;

#[derive(Debug, Error)]
pub enum VisaError {
    #[error("Problem parsing visa with issuer id {0}: {1}")]
    VisaParseError(u64, &'static str),
    #[error("{0}")]
    VisaHopError(&'static str),
    #[error("Keyset Parse Error")]
    KeySetParseError,
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
    SourceAuthEreror,
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
    TemporatilyUnavailable,
    AuthError,
    UnknownStatusCode,
    VisaStructureError(VisaError),
}

impl From<vsapi::VisaResponse> for VisaResponse {
    fn from(thrift_visa_response: vsapi::VisaResponse) -> Self {
        match thrift_visa_response.status {
            Some(code) => match code {
                vsapi::StatusCode::SUCCESS => {
                    match Visa::try_from(thrift_visa_response.visa.unwrap().visa.unwrap()) {
                        Ok(v) => Self::Allow(v),
                        Err(e) => Self::VSApiError(VisaResponseError::new(
                            ErrorCode::VisaStructureError(e),
                            "No status code".to_string(),
                            0,
                        )),
                    }
                }
                vsapi::StatusCode::FAIL => {
                    Self::Deny(Denied::new(DenyCode::Fail, thrift_visa_response.reason))
                }
                val => Self::VSApiError(VisaResponseError::new(
                    ErrorCode::UnknownStatusCode,
                    format!("Status code: {val:?}"),
                    0,
                )),
            },
            None => Self::VSApiError(VisaResponseError::new(
                ErrorCode::UnknownStatusCode,
                "No status code".to_string(),
                0,
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
    pub dock_pep: VsapiIpProtocol,
    pub tcp_udp_pep: Option<TcpUdpPep>,
    pub icmp_pep: Option<IcmpPep>,
    pub session_key: KeySet,
    pub cons: Constraints,
}

#[derive(Debug, Clone)]
pub struct TcpUdpPep {
    pub source_port: u16,
    pub dest_port: u16,
}

#[derive(Debug, Clone)]
pub struct IcmpPep {
    /// the allowed ICMP type and code (in lower 16 bits)
    pub icmp_type_code: u16,
    /// use 0xFF for none
    pub icmp_antecedent: u16,
}

#[derive(Default, Debug, Clone)]
pub struct KeySet {
    pub format: i32,
    /// session key encrypted for ingress node to read
    pub ingress_key: Vec<u8>,
    /// session key encrypted for egress node to read
    pub egress_key: Vec<u8>,
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

        let mut l4_protocol = self.dock_pep;
        if l4_protocol == vsapi_ip_number::ICMP && l3_protocol == L3Type::Ipv6 {
            l4_protocol = vsapi_ip_number::IPV6_ICMP;
        }

        let (src_port, dst_port) = match self.dock_pep {
            pep if pep == vsapi_ip_number::TCP || pep == vsapi_ip_number::UDP => {
                if let Some(pargs) = &self.tcp_udp_pep {
                    (pargs.source_port, pargs.dest_port)
                } else {
                    (0, 0)
                }
            }
            pep if pep == vsapi_ip_number::ICMP => {
                if let Some(pargs) = &self.icmp_pep {
                    (pargs.icmp_type_code, pargs.icmp_antecedent)
                } else {
                    (0, 0)
                }
            }
            _ => (0, 0),
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

impl TryFrom<vsapi::VisaHop> for Visa {
    type Error = VisaError;

    fn try_from(hop: vsapi::VisaHop) -> Result<Self, Self::Error> {
        match hop.visa {
            Some(visa) => Visa::try_from(visa),
            None => Err(VisaError::VisaHopError("No visa")),
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
                return Err(VisaError::VisaParseError(0, "No issuer id"));
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
                return Err(VisaError::VisaParseError(issuer_id, "No expiration"));
            }
        };
        let src_addr = match thrift_visa.source_contact {
            Some(val) => match ip_addr_from_vec(val) {
                Ok(addr) => addr,
                Err(_) => {
                    return Err(VisaError::VisaParseError(
                        issuer_id,
                        "Bad format in src address",
                    ));
                }
            },
            None => return Err(VisaError::VisaParseError(issuer_id, "No src address")),
        };
        let dst_addr = match thrift_visa.dest_contact {
            Some(val) => match ip_addr_from_vec(val) {
                Ok(addr) => addr,
                Err(_) => {
                    return Err(VisaError::VisaParseError(
                        issuer_id,
                        "Bad format in dst address",
                    ));
                }
            },
            None => return Err(VisaError::VisaParseError(issuer_id, "No dst address")),
        };
        let dock_pep = match thrift_visa.dock_pep {
            Some(val) => match val {
                vsapi::PEPIndex::UDP => vsapi_ip_number::UDP,
                vsapi::PEPIndex::TCP => vsapi_ip_number::TCP,
                vsapi::PEPIndex::ICMP => vsapi_ip_number::ICMP,
                _ => return Err(VisaError::VisaParseError(issuer_id, "Unknown PEP")),
            },
            None => vsapi_ip_number::UDP, // Not sure what default here should be
        };
        let mut tcp_udp_pep = None;
        if dock_pep == vsapi_ip_number::UDP || dock_pep == vsapi_ip_number::TCP {
            tcp_udp_pep = match thrift_visa.tcpudp_pep_args {
                Some(val) => Some(TcpUdpPep::from(val)),
                None => return Err(VisaError::VisaParseError(issuer_id, "No TCP/UDP PEP Args")),
            };
        }

        let mut icmp_pep = None;
        if dock_pep == vsapi_ip_number::ICMP {
            icmp_pep = match thrift_visa.icmp_pep_args {
                Some(val) => Some(IcmpPep::from(val)),
                None => return Err(VisaError::VisaParseError(issuer_id, "No ICMP PEP Args")),
            };
        }

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
            tcp_udp_pep,
            icmp_pep,
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
        let icmp_antecedent = match thrift_icmp_pep.icmp_antecedent {
            Some(val) => val as u16,
            None => 0,
        };

        Self {
            icmp_type_code,
            icmp_antecedent,
        }
    }
}

impl TryFrom<vsapi::KeySet> for KeySet {
    type Error = VisaError;

    fn try_from(thrift_key_set: vsapi::KeySet) -> Result<Self, Self::Error> {
        let format = match thrift_key_set.format {
            Some(val) => val,
            None => return Err(VisaError::KeySetParseError),
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

// #[cfg(test)]
// mod tests {
//     use super::*;

// }
