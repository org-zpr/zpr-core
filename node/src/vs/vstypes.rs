use std::collections::BTreeMap;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PolicyInfo {
    pub policy_id: u64,
    pub configuration_id: u64,
    pub node_config: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub struct Visa {
    pub hop_count: u32,
    pub issuer_id: u32,
    pub visa_pb: Vec<u8>, // TODO: Visas are still in serialized protocol buffer format
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Revocation {
    pub issuer_id: u32,
    pub configuration_id: u64,
}
