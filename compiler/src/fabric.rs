//! fabric.rs - A ZPR network fabric.  To create one, use [crate::weaver::weave].
//! This datastructre is designed to be easily massaged into the binary format
//! needed by the prototype visa service.

use core::fmt;
use std::net::Ipv6Addr;
use std::path::PathBuf;

use crate::config::{Config, Node, Protocol};
use crate::errors::CompilationError;
use crate::fabric_util::{squash_attributes, vec_to_attributes};
use crate::lex::Token;
use crate::protocols::IanaProtocol;
use crate::ptypes::Attribute;
use crate::zpl;

/// A service oriented view of the network.
#[derive(Debug, Clone, Default)]
pub struct Fabric {
    pub revision: String,
    pub metadata: String,
    pub services: Vec<FabricService>,
    pub nodes: Vec<FabricNode>,
    pub default_auth_cert: PathBuf, // CA cert for default/builtin trusted auth
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FabricService {
    pub config_id: String, // Service name as specified in configuration and ZPL.
    pub fabric_id: String, // Service name assigned in the fabric
    pub protocol: Protocol,
    pub provider_attrs: Vec<Attribute>, // Set of provider attributes required to offer the service
    pub client_policies: Vec<ClientPolicy>, // List of consumer policies
    pub service_type: ServiceType,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum ServiceType {
    Undefined,
    Trusted,
    Visa,
    Regular,
    BuiltIn, // eg, noode access to VS, or VS access to VSS
}

impl Default for ServiceType {
    fn default() -> Self {
        ServiceType::Undefined
    }
}

#[derive(Debug, Clone)]
pub struct FabricNode {
    pub config_node: Node,
    pub provider_attrs: Vec<Attribute>, // parsed out of config::Node.provider
}

#[derive(Debug, Clone, Default)]
pub struct ClientPolicy {
    pub access_only: bool, // If true, this policy is only for access, not for setting up a connection
    pub condition: Vec<Attribute>, // List of attributes that must be met for the policy to apply
                           // TODO: withouts, constraints, etc.
                           //       Actually, withouts are just attributes, eg (role, ne, marketing)
}

/// Debugging output
impl fmt::Display for Fabric {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "revision: {}\n", self.revision)?;
        write!(f, "metadata: {}\n", self.metadata)?;
        write!(
            f,
            "default auth cert: {}\n",
            self.default_auth_cert.display()
        )?;
        write!(
            f,
            "{} services - {} nodes\n",
            self.services.len(),
            self.nodes.len()
        )?;
        for s in &self.services {
            write!(
                f,
                "  service: {}  (type={:?})\n",
                s.fabric_id, s.service_type
            )?;
            write!(f, "    provider attrs:\n")?;
            for a in &s.provider_attrs {
                write!(f, "      {}\n", a)?;
            }
            write!(f, "    client policies:\n")?;
            if s.client_policies.is_empty() {
                write!(f, "      (none)\n")?;
            }
            for (i, cp) in s.client_policies.iter().enumerate() {
                write!(
                    f,
                    "      {})  {}\n",
                    i + 1,
                    cp.condition
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
                )?;
            }
        }
        for n in &self.nodes {
            write!(f, "  node: {}\n", n.config_node.id)?;
            write!(f, "    provider attrs:\n")?;
            for a in &n.provider_attrs {
                write!(f, "      {}\n", a)?;
            }
        }
        write!(f, "\n")
    }
}

impl Fabric {
    /// Add the service and the attributes that are required to provide it.
    /// There may be many services with the same `id`, but they must then have
    /// different attribute lists.
    ///
    /// Returns the fabric ID assigned to the service.
    pub fn add_service(
        &mut self,
        id: &str,
        protocol: &Protocol,
        attrs: &[Attribute],
        stype: ServiceType,
    ) -> Result<String, CompilationError> {
        assert!(stype != ServiceType::Undefined); // programming error
        if stype == ServiceType::BuiltIn {
            panic!("not allowed to explicity add a BUILTIN service: {}", id);
        }
        if stype == ServiceType::Regular && id.starts_with("/zpr") {
            return Err(CompilationError::ConfigError(format!(
                "service {} cannot start with reserved prefix '/zpr'",
                id
            )));
        }
        let mut svc_instance = 0;
        for s in &self.services {
            if s.config_id == id {
                if s.matches_attributes(attrs) {
                    // Sanity check:
                    if s.service_type != stype {
                        return Err(CompilationError::ConfigError(format!(
                            "service {} has conflicting types: {:?} and {:?}",
                            id, s.service_type, stype
                        )));
                    }
                    return Ok(s.fabric_id.clone()); // already have this service
                }
                svc_instance += 1;
            }
        }
        let fabric_id = if svc_instance > 0 {
            format!("{}#{}", id, svc_instance)
        } else {
            id.to_string()
        };
        let fs = FabricService {
            config_id: id.to_string(),
            fabric_id: fabric_id.clone(),
            protocol: protocol.clone(),
            provider_attrs: attrs.to_vec(),
            client_policies: Vec::new(),
            service_type: stype,
        };
        self.services.push(fs);
        Ok(fabric_id)
    }

    pub fn add_builtin_service(
        &mut self,
        id: &str,
        protocol: &Protocol,
        attrs: &[Attribute],
    ) -> Result<String, CompilationError> {
        let mut svc_instance = 0;
        for s in &self.services {
            if s.config_id == id {
                if s.matches_attributes(attrs) {
                    // Sanity check:
                    if s.service_type != ServiceType::BuiltIn {
                        return Err(CompilationError::ConfigError(format!(
                            "service {} has conflicting types: {:?} and BuiltIn",
                            id, s.service_type
                        )));
                    }
                    return Ok(s.fabric_id.clone()); // already have this service
                }
                svc_instance += 1;
            }
        }
        let fabric_id = if svc_instance > 0 {
            format!("{}#{}", id, svc_instance)
        } else {
            id.to_string()
        };
        let fs = FabricService {
            config_id: id.to_string(),
            fabric_id: fabric_id.clone(),
            protocol: protocol.clone(),
            provider_attrs: attrs.to_vec(),
            client_policies: Vec::new(),
            service_type: ServiceType::BuiltIn,
        };
        self.services.push(fs);
        Ok(fabric_id)
    }

    pub fn get_visa_service(&self) -> Option<&FabricService> {
        self.services
            .iter()
            .find(|s| s.service_type == ServiceType::Visa)
    }

    /// Return TRUE if the service with given fabric_id is in our fabric.
    pub fn has_service(&self, fabric_id: &str) -> bool {
        self.services.iter().any(|s| s.fabric_id == fabric_id)
    }

    /// Add a node to the fabric.  Must add visa service before calling this.
    ///
    /// This also adds visa service access to the nodes visa support service.
    pub fn add_node(&mut self, node: &Node, config: &Config) -> Result<(), CompilationError> {
        let mut node_attrs = vec_to_attributes(&node.provider)?;
        if !node.zpr_address.is_empty() {
            // First check the resolver table:
            let node_addr = config.resolve(&node.zpr_address);
            if node_addr.is_none() {
                // Attempt to directly parse it
                let naddr: Ipv6Addr = match node.zpr_address.parse() {
                    // TODO: Should be parsed to an IpAddr in config.rs
                    Ok(a) => a,
                    Err(e) => {
                        return Err(CompilationError::ConfigError(format!(
                            "invalid zpr address: {}: {}",
                            node.zpr_address, e
                        )))
                    }
                };
                node_attrs.push(Attribute::attr(zpl::ZPR_ADDR_ATTR, &format!("{}", naddr)));
            } else {
                node_attrs.push(Attribute::attr(
                    zpl::ZPR_ADDR_ATTR,
                    &format!("{}", node_addr.unwrap()),
                ));
            }
        }

        // Note that we do not have line/col info from the config file.
        let attr_map = squash_attributes(&node_attrs, &Token::default())?;
        let provider_attrs = attr_map.into_values().collect::<Vec<Attribute>>();

        let fabn = FabricNode {
            config_node: node.clone(),
            provider_attrs: provider_attrs.clone(),
        };
        self.nodes.push(fabn);

        // Now create the visa support service for this node and an access rule.
        let vs = self
            .get_visa_service()
            .expect("visa service must be added before add_node is called");
        let vs_provider_attrs = vs.provider_attrs.clone();
        let svc_name = format!("/zpr/{}/vss", node.id);

        // There cannot be a service with this id already.
        if self.has_service(&svc_name) {
            return Err(CompilationError::ConfigError(format!(
                "unabled to configure node VSS because service {} already exists in fabric",
                &svc_name
            )));
        }

        let vss_prot = Protocol {
            id: "zpr_vsup".to_string(),
            protocol: IanaProtocol::TCP,
            port: Some(format!("{}", zpl::VISA_SUPPORT_SEVICE_PORT)),
            icmp: None,
        };
        let vss_id = self.add_builtin_service(&svc_name, &vss_prot, &provider_attrs)?;
        self.add_condition_to_service(&vss_id, &vs_provider_attrs, false)?;
        Ok(())
    }

    /// Add a condition (aka policy aka rule) to an existing service specified by the
    /// fabric service ID.
    pub fn add_condition_to_service(
        &mut self,
        service_id: &str,
        attrs: &[Attribute],
        access_only: bool,
    ) -> Result<(), CompilationError> {
        let svc = self.services.iter_mut().find(|s| s.fabric_id == service_id);
        if svc.is_none() {
            // programming error
            panic!(
                "call add_condition_to_service but service {} not found",
                service_id
            );
        }
        let svc = svc.unwrap();
        svc.client_policies.push(ClientPolicy {
            condition: attrs.to_vec(),
            access_only,
        });
        Ok(())
    }

    /// Add a condition (aka plicy aka rule) to all services -- EXCEPT nodes, trusted services, and visa services.
    pub fn add_condition_to_all_services(
        &mut self,
        attrs: &[Attribute],
    ) -> Result<(), CompilationError> {
        for svc in &mut self.services {
            if svc.service_type == ServiceType::Regular {
                svc.client_policies.push(ClientPolicy {
                    access_only: false, // TODO: this is a guess
                    condition: attrs.to_vec(),
                });
            }
        }
        Ok(())
    }
}

impl FabricService {
    /// True if this services attributes overlap with `other_attrs` exactly.
    pub fn matches_attributes(&self, other_attrs: &[Attribute]) -> bool {
        if other_attrs.len() != self.provider_attrs.len() {
            return false;
        }
        for oa in other_attrs {
            if !self.provider_attrs.contains(oa) {
                return false;
            }
        }
        true
    }
}
