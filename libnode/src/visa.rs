use std::time::SystemTime;
use crate::net_defs::IpProtocol;
// use vsapi;

// TODO figure out which of these need to stay once we switch to
pub struct Visa {
    pub issuer_id: u64, // i32 in thrift, u64 in capnp
    pub config: i64,
    pub expires: SystemTime,
    // pub source: Vec<u8>,
    // pub dst: Vec<u8>,
    pub src_addr: Vec<u8>,
    pub dst_addr: Vec<u8>,
    pub doc_pep: IpProtocol,
    pub tcp_udp_pep: Option<TcpUdpPep>,
    pub icmp_pep: Option<IcmpPep>,
    pub session_key: KeySet,
    pub cons: Constraints,
    // pub sig: Signature,
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
    pub endpoint: EndpointT, // not in thrift
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

pub struct KeySet {
  pub format: i32,
  /// session key encrypted for ingress node to read
  pub ingress_key: Vec<u8>,
  /// session key encrypted for egress node to read
  pub egress_key: Vec<u8>,
}

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
    pub r#type: i32,
    pub signature: Vec<u8>,
}

pub enum EndpointT {
    Any,
    Server,
    Client,
}

