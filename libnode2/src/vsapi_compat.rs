//! Old VSAPI imitation types to enable us to compile old ph with new libnode.
//!
//! TODO: This all needs to go away eventually.

use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PolicyInfo {}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VisaHop {
    pub issuer_id: Option<i32>,
    pub visa: Option<Visa>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VisaRevocation {
    pub issuer_id: Option<i32>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServicesList {
    pub services: Option<Vec<ServiceDescriptor>>,
    pub expiration: Option<u64>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServiceDescriptor {
    pub uri: Option<String>,
    pub service_id: Option<String>,
    pub address: Option<Vec<u8>>,
    pub type_: ServiceType,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ServiceType {
    ACTOR_AUTHENTICATION,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Visa {
    pub issuer_id: Option<i32>,
    pub configuration: Option<i64>,
    pub expires: Option<i64>,
    pub source: Option<Vec<u8>>,
    pub dest: Option<Vec<u8>>,
    pub source_contact: Option<Vec<u8>>,
    pub dest_contact: Option<Vec<u8>>,
    pub dock_pep: Option<PEPIndex>,
    pub tcpudp_pep_args: Option<PEPArgsTCPUDP>,
    pub icmp_pep_args: Option<PEPArgsICMP>,
    pub session_key: Option<KeySet>,
    pub cons: Option<Constraints>,
    pub sig: Option<Signature>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Signature {}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Constraints {}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeySet {}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PEPArgsTCPUDP {
    pub source_contact_addr: Option<Vec<u8>>,
    pub dest_contact_addr: Option<Vec<u8>>,
    pub source_port: Option<i32>,
    pub dest_port: Option<i32>,
    pub server: Option<bool>,
    pub icmp_allowed: Option<Vec<i32>>,
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PEPArgsICMP {
    pub source_contact_addr: Option<Vec<u8>>,
    pub dest_contact_addr: Option<Vec<u8>>,
    pub icmp_type_code: Option<i32>,
    pub icmp_antecedent: Option<i32>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StatusCode {
    SUCCESS = 0,
    FAIL = 1,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectRequest {
    pub connection_id: Option<i32>,
    pub dock_addr: Option<Vec<u8>>,
    pub claims: Option<BTreeMap<String, String>>,
    pub challenge: Option<Vec<u8>>,
    pub challenge_responses: Option<Vec<Vec<u8>>>,
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VisaResponse {
    pub status: Option<StatusCode>,
    pub visa: Option<VisaHop>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectResponse {
    /// copied from request
    pub connection_id: Option<i32>,
    /// SUCCESS if connect request granted
    pub status: Option<StatusCode>,
    pub actor: Option<Actor>,
    /// Optional message in case of non SUCCESS
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Actor {
    pub actor_type: Option<ActorType>,
    pub attrs: Option<BTreeMap<String, String>>,
    /// unix time stamp seconds
    pub auth_expires: Option<i64>,
    /// assigned ZPR address
    pub zpr_addr: Option<Vec<u8>>,
    pub tether_addr: Option<Vec<u8>>,
    /// unique in this ZPRnet
    pub ident: Option<String>,
    pub provides: Option<Vec<String>>,
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ActorType {
    ADAPTER = 0,
    NODE = 1,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServicesResponse {
    pub services: Option<ServicesList>,
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PEPIndex(pub i32);

impl PEPIndex {
    pub const UDP: PEPIndex = PEPIndex(1);
    pub const TCP: PEPIndex = PEPIndex(2);
    pub const ICMP: PEPIndex = PEPIndex(3);
    pub const ENUM_VALUES: &'static [Self] = &[Self::UDP, Self::TCP, Self::ICMP];
}

impl From<i32> for PEPIndex {
    fn from(i: i32) -> Self {
        match i {
            1 => PEPIndex::UDP,
            2 => PEPIndex::TCP,
            3 => PEPIndex::ICMP,
            _ => PEPIndex(i),
        }
    }
}

impl From<&i32> for PEPIndex {
    fn from(i: &i32) -> Self {
        PEPIndex::from(*i)
    }
}

impl From<PEPIndex> for i32 {
    fn from(e: PEPIndex) -> i32 {
        e.0
    }
}

impl From<&PEPIndex> for i32 {
    fn from(e: &PEPIndex) -> i32 {
        e.0
    }
}
