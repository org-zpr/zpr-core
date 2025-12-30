use crate::policy::v1;
use crate::policy_types::writer::{WriteTo, write_attributes};

use crate::policy_types::attribute::Attribute;

pub struct JoinPolicy {
    pub conditions: Vec<Attribute>,
    pub flags: PFlags,
    pub provides: Option<Vec<Service>>,
}

/// Service is part of a join policy.
pub struct Service {
    pub id: String,
    pub endpoints: Vec<Scope>,
    pub kind: ServiceType,
}

/// This struct mirrors what is in the capnp schema.
/// Used in comm policies and join policies.
pub struct Scope {
    pub protocol: u8,
    pub flag: Option<ScopeFlag>,
    pub port: Option<u16>,
    pub port_range: Option<(u16, u16)>,
}

/// This scope flag mirrors what is in the capnp schema.
#[derive(PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum ScopeFlag {
    UdpOneWay,
    IcmpRequestReply,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub enum ServiceType {
    #[default]
    Undefined,
    Trusted(String), // Takes the API name
    Authentication,
    Visa,
    Regular,
    BuiltIn, // eg, node access to VS, or VS access to VSS
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Copy)]
pub struct PFlags {
    pub node: bool,
    pub vs: bool,
    pub vs_dock: bool,
}

impl PFlags {
    /// Create the set of flags for a node.
    pub fn node(is_vs_dock: bool) -> PFlags {
        PFlags {
            node: true,
            vs: false,
            vs_dock: is_vs_dock,
        }
    }

    /// Create the set of flags for a visa service.
    pub fn vs() -> PFlags {
        PFlags {
            node: false,
            vs: true,
            vs_dock: false,
        }
    }

    pub fn or(&mut self, other: Self) {
        self.node |= other.node;
        self.vs |= other.vs;
        self.vs_dock |= other.vs_dock;
    }

    /// Returns number of "set" flags.
    pub fn count(&self) -> usize {
        let mut count = 0;
        if self.node {
            count += 1;
        }
        if self.vs {
            count += 1;
        }
        if self.vs_dock {
            count += 1;
        }
        count
    }
}

impl WriteTo<v1::j_policy::Builder<'_>> for JoinPolicy {
    fn write_to(&self, bldr: &mut v1::j_policy::Builder) {
        let mut matches_bldr = bldr.reborrow().init_match(self.conditions.len() as u32);
        write_attributes(&self.conditions, &mut matches_bldr);

        if let Some(provides) = &self.provides {
            let mut provides_bldr = bldr.reborrow().init_provides(provides.len() as u32);
            write_services(provides, &mut provides_bldr);
        }

        if self.flags.count() > 0 {
            let mut flags_bldr = bldr.reborrow().init_flags(self.flags.count() as u32);
            let mut idx = 0;
            if self.flags.node {
                flags_bldr.set(idx, v1::JoinFlag::Node);
                idx += 1;
            }
            if self.flags.vs {
                flags_bldr.set(idx, v1::JoinFlag::Vs);
                idx += 1;
            }
            if self.flags.vs_dock {
                flags_bldr.set(idx, v1::JoinFlag::Vsdock);
            }
        }
    }
}

/// Write a services list into capn proto List.
fn write_services(
    services: &[Service],
    builder: &mut capnp::struct_list::Builder<'_, v1::service::Owned>,
) {
    for (i, service) in services.iter().enumerate() {
        let mut s = builder.reborrow().get(i as u32);
        s.set_id(&service.id);
        let mut endpoints = s.reborrow().init_endpoints(service.endpoints.len() as u32);
        for (j, endpoint) in service.endpoints.iter().enumerate() {
            let mut scope_bldr = endpoints.reborrow().get(j as u32);
            scope_bldr.set_protocol(endpoint.protocol as u8);
            if let Some(flowtype) = &endpoint.flag {
                match flowtype {
                    ScopeFlag::IcmpRequestReply => {
                        scope_bldr.set_flag(v1::ScopeFlag::IcmpRequestRepl);
                    }
                    ScopeFlag::UdpOneWay => {
                        scope_bldr.set_flag(v1::ScopeFlag::UdpOneWay);
                    }
                }
            }
            if let Some(port) = endpoint.port {
                let mut portnum_bldr = scope_bldr.reborrow().init_port();
                portnum_bldr.set_port_num(port);
            }
            if let Some(port_range) = endpoint.port_range {
                let mut port_range_bldr = scope_bldr.reborrow().init_port_range();
                port_range_bldr.set_low(port_range.0);
                port_range_bldr.set_high(port_range.1);
            }
        }
        let mut kind_bldr = s.init_kind();
        match &service.kind {
            ServiceType::Authentication => kind_bldr.set_auth(()),
            ServiceType::Regular => kind_bldr.set_regular(()),
            ServiceType::BuiltIn => kind_bldr.set_builtin(()),
            ServiceType::Visa => kind_bldr.set_visa(()),
            ServiceType::Trusted(name) => kind_bldr.set_trusted(name),
            ServiceType::Undefined => {
                panic!("service with undefined type/kind"); // programming error
            }
        }
    }
}
