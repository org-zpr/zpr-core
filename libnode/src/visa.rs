use crate::net_defs::{IpAddress, IpProtocol, ip_number};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
// use vsapi;

// TODO figure out which of these need to stay once we switch to
pub struct Visa {
    pub issuer_id: u64, // i32 in thrift, u64 in capnp
    pub config: i64,
    pub expires: SystemTime,
    // pub source: Vec<u8>,
    // pub dst: Vec<u8>,
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

impl Visa {
    pub fn new_from_thrift(thrift_visa: vsapi::Visa) -> Self {
        let issuer_id  = match thrift_visa.issuer_id {
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
            },
            None => SystemTime::now(),
        };
        let src_addr = match thrift_visa.source_contact {
            Some(val) => {
                match IpAddress::try_from(val) {
                    Ok(addr) => addr,
                    Err(_) => IpAddress::UNSPECIFIED,
                }
            },
            None => IpAddress::UNSPECIFIED,
        };
        let dst_addr = match thrift_visa.dest_contact {
            Some(val) => {
                match IpAddress::try_from(val) {
                    Ok(addr) => addr,
                    Err(_) => IpAddress::UNSPECIFIED,
                }
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
            },
            None => ip_number::UDP, // Not sure what default here should be
        };
        let tcp_udp_pep = match thrift_visa.tcpudp_pep_args {
            Some(val) => Some(TcpUdpPep::new_from_thrift(val)),
            None => None,
        };
        let icmp_pep = match thrift_visa.icmp_pep_args {
            Some(val) => Some(IcmpPep::new_from_thrift(val)),
            None => None,
        };
        let session_key = match thrift_visa.session_key {
            Some(val) => KeySet::new_from_thrift(val),
            None => KeySet::default(),
        };
        let cons = match thrift_visa.cons {
            Some(val) => Constraints::new_from_thrift(val),
            None => Constraints::default(),
        };
        Self {
            issuer_id,
            config,
            expires,
            src_addr,
            dst_addr,
            dock_pep,
            tcp_udp_pep,
            icmp_pep,
            session_key,
            cons
        }
    }
}

impl TcpUdpPep {
    pub fn new_from_thrift(thrift_tcp_udp_pep: vsapi::PEPArgsTCPUDP) -> Self {
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

impl IcmpPep {
    pub fn new_from_thrift(thrift_icmp_pep: vsapi::PEPArgsICMP) -> Self {
        let icmp_type_code = match thrift_icmp_pep.icmp_type_code {
            Some(val) => val as u16,
            None => 0,
        };

        Self {
            icmp_type_code,
        }
    }
}

impl KeySet {
    pub fn new_from_thrift(thrift_key_set: vsapi::KeySet) -> Self {
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

impl Constraints {
    pub fn new_from_thrift(thrift_cons: vsapi::Constraints) -> Self {
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
