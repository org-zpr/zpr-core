//! weaver.rs - weave a network fabric from a policy and configuration.
//! This datastructre is designed to be easily massaged into the binary format
//! needed by the prototype visa service.

use core::fmt;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::path::PathBuf;

use ring::digest::Digest;

use crate::compilation::Compilation;
use crate::config::{Config, Node, Protocol, Service, TrustedService};
use crate::crypto::{digest_as_hex, sha256_of_bytes};
use crate::errors::CompilationError;
use crate::lex::Token;
use crate::protocols::IanaProtocol;
use crate::ptypes::{Attribute, Class, Policy};
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
    BuiltIn, // eg, noode access to VS, o VS access to VSS
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

pub fn weave(
    _comp: &Compilation,
    config: &Config,
    policy: &Policy,
) -> Result<Fabric, CompilationError> {
    let mut weaver = Weaver::new();

    weaver.compute_revision(policy.digest, &config.digest)?;

    // Create a class index which maps class name -> class struct.
    let defaults = Class::defaults();
    let mut class_idx = HashMap::new();
    // Add default classes:
    for defclass in &defaults {
        class_idx.insert(defclass.name.clone(), defclass);
    }
    for cl in &policy.defines {
        class_idx.insert(cl.name.clone(), cl);
    }

    // Create a service index maps service ID -> service struct.
    let mut service_idx = HashMap::new();
    for svc in &config.services {
        service_idx.insert(svc.id.clone(), svc);
    }

    // We do not yet support non-default trusted services though we will parse them and
    // we do grab their attributes so that we can parse ZPL that uses them.
    //
    // But since we don't put this into the binary policy yet, the resulting policy
    // will not be readable by visa service.
    for ts in &config.trusted_services {
        if ts.id != zpl::DEFAULT_TRUSTED_SERVICE_ID {
            println!(
                "warning: trusted_service '{}': non-default trusted services not supported",
                ts.id
            );
        }
    }

    weaver.init_services(&class_idx, &service_idx, policy, config)?;
    weaver.init_nodes(config)?;
    weaver.add_client_policies(&class_idx, policy, config)?;
    weaver.add_default_auth(config)?;

    Ok(weaver.fabric)
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
        let svc_name = format!("/zpr/{}/vss", node.id);

        // There cannot be a service with this id already.
        if self.has_service(&svc_name) {
            return Err(CompilationError::ConfigError(format!(
                "unabled to configure node VSS because service {} already exists in fabric",
                &svc_name
            )));
        }

        let access_policy = ClientPolicy {
            access_only: false,
            condition: vs.provider_attrs.clone(), // The VSS is accessed by the visa service
        };
        let vss_svc = FabricService {
            config_id: svc_name.clone(),
            fabric_id: svc_name.clone(),
            protocol: Protocol {
                id: "zpr_vsup".to_string(),
                protocol: IanaProtocol::TCP,
                port: Some(format!("{}", zpl::VISA_SUPPORT_SEVICE_PORT)),
                icmp: None,
            },
            provider_attrs: provider_attrs, // The VSS is provided by the node
            client_policies: vec![access_policy],
            service_type: ServiceType::BuiltIn,
        };
        self.services.push(vss_svc);
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

struct Weaver {
    fabric: Fabric,

    // Map the allow clause ID to the fabric service ID.
    allowid_to_fab_svc: HashMap<usize, String>,
}

//impl<'a> Weaver<'a> {
impl Weaver {
    fn new() -> Self {
        Self {
            fabric: Fabric::default(),
            allowid_to_fab_svc: HashMap::new(),
        }
    }

    fn compute_revision(
        &mut self,
        policy_digest: Option<Digest>,
        config_digest: &Digest,
    ) -> Result<(), CompilationError> {
        let mut revhash = Vec::new();

        match policy_digest {
            Some(d) => revhash.extend_from_slice(d.as_ref()),
            None => panic!("error - call to new Binp but ZPL digest is not set"), // programming error
        }
        revhash.extend_from_slice(config_digest.as_ref());
        let policy_revision_dig = sha256_of_bytes(&revhash);
        self.fabric.revision = digest_as_hex(&policy_revision_dig);
        Ok(())
    }

    /// Figure out the set of services in the fabric.  There may be a bunch of services in
    /// the configuration but we only want the ones that are refefenced in the ZPL.
    fn init_services(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        service_idx: &HashMap<String, &Service>,
        policy: &Policy,
        config: &Config,
    ) -> Result<(), CompilationError> {
        for ac in &policy.allows {
            if ac.service.class == zpl::DEF_CLASS_SERVICE_NAME {
                // ZPL that applies to ALL services does not generate additional
                // connect rules.  But it will create access rules.
                continue;
            }

            let mut attrs = Vec::new();

            let svc_class_attrs = attrs_for_class(&class_idx, &ac.service.class);
            attrs.extend_from_slice(&svc_class_attrs);
            attrs.extend_from_slice(&ac.service.with);

            // Otherwise the service class either match an ID in the configuration or must have a
            // parent that does.  We take the first parent that matches a configuration as
            // the service configuration to use.
            //

            let matched_service_name =
                find_defined_service(&ac.service.class, service_idx, class_idx);
            if matched_service_name.is_none() {
                return Err(CompilationError::ConfigError(format!(
                    "no service for {} found in configuration",
                    ac.service.class
                )));
            }
            let matched_service_name = matched_service_name.unwrap();
            let matched_service = service_idx.get(&matched_service_name);

            // The service may have provider attributes that we need.
            let svc = matched_service.unwrap();
            match svc.provider {
                Some(ref p) => {
                    let attr_v = vec_to_attributes(p)?;
                    attrs.extend_from_slice(&attr_v);
                }
                None => {
                    // no provider attributes
                }
            }

            let prot = match config.protocols.get(&svc.protocol_id) {
                Some(p) => p,
                None => {
                    return Err(CompilationError::ConfigError(format!(
                        "protocol {} for {} not found in configuration",
                        svc.protocol_id, svc.id
                    )))
                }
            };

            let attr_map = squash_attributes(&attrs, &ac.service.class_tok)?;

            let resolved_attrs = self.resolve_attributes(
                attr_map
                    .into_values()
                    .collect::<Vec<Attribute>>()
                    .as_slice(),
                config,
            )?;

            let fabric_svc_id =
                self.fabric
                    .add_service(&svc.id, prot, &resolved_attrs, ServiceType::Regular)?;
            self.allowid_to_fab_svc.insert(ac.id, fabric_svc_id);
        }

        // Visa service
        let vs_protocol = Protocol {
            id: "zpr_vsvc".to_string(),
            protocol: IanaProtocol::TCP,
            port: Some(format!("{}", zpl::VISA_SERVICE_PORT)),
            icmp: None,
        };
        let mut vs_attrs = Vec::new();
        vs_attrs.push(Attribute::attr(zpl::ADAPTER_CN_ATTR, zpl::VISA_SERVICE_CN));
        let fab_svc_id = self.fabric.add_service(
            zpl::VS_SERVICE_NAME,
            &vs_protocol,
            &vs_attrs,
            ServiceType::Visa,
        )?;

        // Visa service has policy that allows nodes to access it.  We use a role attribute so
        // we don't care about individual node names.
        let vs_access_attrs = vec![Attribute::attr(zpl::KATTR_ROLE, "node")];
        self.fabric
            .add_condition_to_service(&fab_svc_id, &vs_access_attrs, true)?;

        // TODO: We need to add access to the visa service by the administrator.
        //       The admin attrs is not yet supported in policy.

        // TODO: When we get around to trusted services, we need to add builtin rules
        //       that grant VS access to the trusted services.

        Ok(())
    }

    // Every attribute needs to come from a trusted service. Since right now (TODO) the
    // only service is the default one, the only attribute we accept is "cn" or the full
    // expansion of that "zpr.adapter.cn".
    //
    fn resolve_attributes(
        &self,
        attrs: &[Attribute],
        config: &Config,
    ) -> Result<Vec<Attribute>, CompilationError> {
        // TODO: The trusted service support is no yet real, this is a hack to permit compilation of
        //       ZPL files that use more than just the "cn" (default) attribute.

        let mut resolved_attrs = Vec::new();
        for a in attrs {
            if a.name == zpl::ADAPTER_CN_ATTR {
                resolved_attrs.push(a.clone());
            }
            if a.name == zpl::DEFAULT_ATTR {
                resolved_attrs.push(a.set_name(zpl::ADAPTER_CN_ATTR));
            } else {
                let new_name = config.resolve_attribute(a)?;
                resolved_attrs.push(a.set_name(&new_name));
            }
        }
        Ok(resolved_attrs)
    }

    /// Must init_services before init_nodes.
    fn init_nodes(&mut self, config: &Config) -> Result<(), CompilationError> {
        if config.nodes.is_empty() {
            return Err(CompilationError::ConfigError(
                "no nodes defined in configuration".to_string(),
            ));
        }
        if config.nodes.len() > 1 {
            return Err(CompilationError::ConfigError(
                "multiple nodes defined in configuration".to_string(),
            ));
        }
        let node_id = &config.visa_service.dock_node_id;
        let my_node = config.nodes.get(node_id).ok_or_else(|| {
            CompilationError::ConfigError(format!(
                "visa service docking node {} not found in configuration",
                node_id
            ))
        })?;
        if config.nodes.len() > 1 {
            return Err(CompilationError::ConfigError(
                "only one node is supported".to_string(),
            ));
        }

        self.fabric.add_node(&my_node, config)
    }

    /// Process the ZPL policy into conditions for accessing fabric services.
    /// Must be done after initializing the services.
    fn add_client_policies(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &Config,
    ) -> Result<(), CompilationError> {
        // Every allow is an access condition (aka rule, aka policy).
        // We need the attributes from the user and endpoints clauses.
        for ac in &policy.allows {
            // Here we collect all attributes -- some will have no values.
            let mut attrs = Vec::new();

            // Grab all the endpint attributes
            let ep_class_attrs = attrs_for_class(&class_idx, &ac.endpoint.class);
            attrs.extend_from_slice(&ep_class_attrs);
            attrs.extend_from_slice(
                &ac.endpoint
                    .with
                    .iter()
                    .filter(|a| !a.optional)
                    .cloned()
                    .collect::<Vec<Attribute>>(),
            );

            // Grab all the user attributes
            let user_class_attrs = attrs_for_class(&class_idx, &ac.user.class);
            attrs.extend_from_slice(&user_class_attrs);
            attrs.extend_from_slice(
                &ac.user
                    .with
                    .iter()
                    .filter(|a| !a.optional)
                    .cloned()
                    .collect::<Vec<Attribute>>(),
            );

            // Now we consolidate the attributes into a map, preferring attributes that have a value.
            let attr_map = squash_attributes(&attrs, &ac.endpoint.class_tok)?;

            let required_attrs = self
                .resolve_attributes(&attr_map.into_values().collect::<Vec<Attribute>>(), config)?;

            // Now figure out what service we are talking about.
            // The service may be:
            // a) a service that is defined in configuration, eg "SomeDatabase"
            // b) a service that is defined in ZPL as a child of a service defined in configuration.
            // c) the base service, eg, "service" - "allow red users to access services" -- in which case this condition applied to
            //    all services.

            if ac.service.class == zpl::DEF_CLASS_SERVICE_NAME {
                // Add to all services (not nodes or trusted services or visa service)
                self.fabric.add_condition_to_all_services(&required_attrs)?;
            } else {
                let svc_id = match self.allowid_to_fab_svc.get(&ac.id) {
                    Some(s) => s,
                    None => {
                        // programming error
                        panic!(
                            "error - allow clause id {} not found in map, allow = {}",
                            ac.id, ac
                        );
                    }
                };
                self.fabric
                    .add_condition_to_service(svc_id, &required_attrs, false)?;
            }
        }
        Ok(())
    }

    /// For now we only accept the DEFAULT (builtin) trusted service.
    fn add_default_auth(&mut self, config: &Config) -> Result<(), CompilationError> {
        let mut def_ts: Option<&TrustedService> = None;

        for ts in &config.trusted_services {
            if ts.id != zpl::DEFAULT_TRUSTED_SERVICE_ID {
                continue;
            }
            if def_ts.is_some() {
                return Err(CompilationError::ConfigError(
                    "only one default trusted service is supported".to_string(),
                ));
            }
            def_ts = Some(ts);
        }
        if def_ts.is_none() {
            return Err(CompilationError::ConfigError(
                "no default trusted service found in configuration".to_string(),
            ));
        }
        let def_ts = def_ts.unwrap();

        // The only thing we care about is cert path.
        if def_ts.cert_path.is_none() {
            return Err(CompilationError::ConfigError(
                "default trusted service must have a cert path".to_string(),
            ));
        }
        self.fabric.default_auth_cert = def_ts.cert_path.clone().unwrap();
        Ok(())
    }
}

/// Convert the list of (key, value) pairs into a list of attributes.
///
/// Note this only supports KEY:VALUE attributes, not TAG attributes.
///
/// TODO: This should be done in config parsing.
fn vec_to_attributes(v: &[(String, String)]) -> Result<Vec<Attribute>, CompilationError> {
    let mut attrs = Vec::new();
    for (k, v) in v {
        attrs.push(Attribute::attr(k, v));
    }
    Ok(attrs)
}

// Given a list of attributes that apply, return just the set of unique
// attributes and the ones with values should take precedence over ones without.
fn squash_attributes(
    attrs: &[Attribute],
    tok: &Token,
) -> Result<HashMap<String, Attribute>, CompilationError> {
    let mut attr_map: HashMap<String, Attribute> = HashMap::new();
    for a in attrs {
        if attr_map.contains_key(&a.name) {
            // Map already has this attribute in it. If the map one has a value
            // and this one doesn't, keep the map one. If they both have values and they are different
            // that is an error.

            let map_attr = attr_map.get(&a.name).unwrap();
            if map_attr.value.is_none() && a.value.is_some() {
                attr_map.insert(a.name.clone(), a.clone()); // overwrite old non-valued attribute
            } else if map_attr.value.is_some() && a.value.is_none() {
                // do nothing
            } else if map_attr.value.is_some() && a.value.is_some() {
                if map_attr.value != a.value {
                    return Err(CompilationError::AttributeValueConflict(
                        a.name.clone(),
                        tok.line,
                        tok.col,
                    ));
                }
            }
        } else {
            attr_map.insert(a.name.clone(), a.clone());
        }
    }
    Ok(attr_map)
}

/// Get all the WITH attributes on the named class, including any attributes on
/// the parent classes.  We ignore optional attributes.
fn attrs_for_class(class_idx: &HashMap<String, &Class>, class_name: &str) -> Vec<Attribute> {
    let mut attrs = Vec::new();
    let mut cl = class_idx.get(class_name).unwrap();

    // If my parent name is not my name... grab all my attributes.
    while cl.parent != cl.name {
        for a in &cl.with_attrs {
            if a.optional {
                continue;
            }
            attrs.push(a.clone());
        }
        // Then move up to the parent class.
        cl = class_idx
            .get(&cl.parent)
            .expect(format!("error parent class {} of {} not found", cl.parent, cl.name).as_str());
    }
    // WHEN parent name is my name, take my attributes
    for a in &cl.with_attrs {
        if a.optional {
            continue;
        }
        attrs.push(a.clone());
    }
    attrs
}

/// Returns first service starting with `class_name` and searching ancestors that is
/// defined in our service index (ie, is in configuration).
fn find_defined_service(
    class_name: &str,
    service_idx: &HashMap<String, &Service>,
    class_idx: &HashMap<String, &Class>,
) -> Option<String> {
    let mut cur_svc_class = class_name;
    let mut matched_service = service_idx.get(cur_svc_class);
    while matched_service.is_none() {
        let cl = class_idx.get(cur_svc_class).unwrap();
        if cl.parent == cl.name {
            // we are at top of hierarchy
            break;
        }
        cur_svc_class = &cl.parent;
        matched_service = service_idx.get(cur_svc_class);
    }
    match matched_service {
        Some(s) => Some(s.id.clone()),
        None => None,
    }
}
