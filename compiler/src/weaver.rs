//! weaver.rs - Poetically named module that can "weave" a "fabric" from a ZPL policy and configuration.

use std::collections::HashMap;

use base64::prelude::*;

use crate::compilation::Compilation;
use crate::config_api::{ConfigApi, ConfigItem};
use crate::context::CompilationCtx;
use crate::crypto::{digest_as_hex, sha256_of_bytes};
use crate::errors::CompilationError;
use crate::fabric::{Fabric, ServiceType};
use crate::fabric_util::{squash_attributes, vec_to_attributes};
use crate::protocols::{IanaProtocol, Protocol};
use crate::ptypes::{Attribute, Class, ClassFlavor, FPos, Policy};
use crate::zpl;

pub struct Weaver {
    fabric: Fabric,

    // Map the allow clause ID to the fabric service ID.
    allowid_to_fab_svc: HashMap<usize, String>,
}

/// Weave produces the fabric from the ZPL and Configuration data structures,
pub fn weave(
    _comp: &Compilation,
    config: &ConfigApi,
    policy: &Policy,
    ctx: &CompilationCtx,
) -> Result<Fabric, CompilationError> {
    let mut weaver = Weaver::new();

    let pdig = policy
        .digest
        .expect("policy digest must be set prior to calling weave");

    // Use config verison as its digest. Version is hex encoded hash.
    let cdig = match config.must_get("zpr/version") {
        ConfigItem::StrVal(ver) => {
            let mut d = [0u8; 32];
            hex::decode_to_slice(ver, &mut d).expect("version must be a 32 byte hex string");
            d
        }
        _ => {
            return Err(CompilationError::ConfigError(
                "no version in configuration".to_string(),
            ))
        }
    };

    weaver.compute_revision(pdig.as_ref(), &cdig)?;

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

    // We do not yet support non-default trusted services though we will parse them and
    // we do grab their attributes so that we can parse ZPL that uses them.
    //
    // But since we don't put this into the binary policy yet, the resulting policy
    // will not be readable by visa service.
    for ts_id in &config.must_get_keys("/trusted_services") {
        if ts_id != zpl::DEFAULT_TRUSTED_SERVICE_ID {
            ctx.warn(&format!(
                "trusted_service '{}': non-default trusted services not supported",
                ts_id
            ))?;
        }
    }

    weaver.init_services(&class_idx, policy, config, ctx)?;
    weaver.init_nodes(config)?;
    weaver.add_client_policies(&class_idx, policy, config)?;
    weaver.add_default_auth(config, ctx)?;

    Ok(weaver.fabric)
}

impl Weaver {
    fn new() -> Self {
        Self {
            fabric: Fabric::default(),
            allowid_to_fab_svc: HashMap::new(),
        }
    }

    fn compute_revision(
        &mut self,
        policy_digest: &[u8],
        config_digest: &[u8],
    ) -> Result<(), CompilationError> {
        let mut revhash = Vec::new();
        revhash.extend_from_slice(policy_digest);
        revhash.extend_from_slice(config_digest);
        let policy_revision_dig = sha256_of_bytes(&revhash);
        self.fabric.revision = digest_as_hex(&policy_revision_dig);
        Ok(())
    }

    /// Figure out the set of services in the fabric.  There may be a bunch of services in
    /// the configuration but we only want the ones that are refefenced in the ZPL.
    fn init_services(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        self.defines_to_services(class_idx, policy, config)?;
        self.allow_clauses_to_services(class_idx, policy, config)?;
        self.visa_services_to_services(config, ctx)?;

        Ok(())
    }

    /// Set up the visa service(s) in the fabric.
    /// Most visa service related functionality is built in. However user can set
    /// the attributes of the administrator who is able to access the visa service
    /// admin HTTPS API.
    fn visa_services_to_services(
        &mut self,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        let vs_protocol = Protocol {
            protocol: IanaProtocol::TCP,
            port: Some(zpl::VISA_SERVICE_PORT.to_string()),
            icmp: None,
        };

        // The provider of the visa service is a hardcoded CN value.
        let mut vs_attrs = Vec::new();
        vs_attrs.push(Attribute::attr(zpl::ADAPTER_CN_ATTR, zpl::VISA_SERVICE_CN));
        let fab_svc_id = self.fabric.add_service(
            zpl::VS_SERVICE_NAME,
            &vs_protocol,
            &vs_attrs,
            ServiceType::Visa,
        )?;

        // Visa service has policy that allows nodes to access it.  We use a node role attribute so
        // we don't care about individual node names.
        let vs_access_attrs = vec![Attribute::attr(zpl::KATTR_ROLE, "node")];
        self.fabric
            .add_condition_to_service(&fab_svc_id, &vs_access_attrs, true)?;

        // Now add a service for the admin HTTPS API.
        let admin_api_protocol = Protocol {
            protocol: IanaProtocol::TCP,
            port: Some(zpl::VISA_SERVICE_ADMIN_PORT.to_string()),
            icmp: None,
        };

        // This AMIN service is provided by the visa service too.
        let fab_admin_svc_id = self.fabric.add_builtin_service(
            &format!("{}/admin", zpl::VS_SERVICE_NAME),
            &admin_api_protocol,
            &vs_attrs,
        )?;

        let admin_access_attrs = match config.get("zpr/visa_services/default/admin_attrs") {
            Some(ConfigItem::AttrList(alist)) => vec_to_attributes(&alist)?,
            _ => {
                vec![]
            }
        };
        if admin_access_attrs.is_empty() {
            // TODO: is this an error?
            ctx.warn("no admin attributes set for visa service admin access")?;
        } else {
            self.fabric
                .add_condition_to_service(&fab_admin_svc_id, &admin_access_attrs, false)?;
            // also allow admin to connect
        }

        // TODO: When we get around to trusted services, we need to add builtin rules
        //       that grant VS access to the trusted services.
        Ok(())
    }

    /// Make sure that any service defines are reflected in policy so that proper service
    /// attributes get set up at connect time.
    fn defines_to_services(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        let mut svc_id = usize::MAX;
        for define in &policy.defines {
            if define.flavor != ClassFlavor::Service {
                continue;
            }
            // An actor can connect and offer the service if it is able to satisfy the
            // set of attributes attached to it through the define or configuration.
            //
            // TODO: If there are no allow rules that permit access to the service then
            // maybe we don't even allow it to connect?

            let mut attrs = Vec::new();
            let svc_class_attrs = attrs_for_class(&class_idx, &define.name);
            attrs.extend_from_slice(&svc_class_attrs);

            self.add_service(class_idx, define, &attrs, svc_id, config)?;
            svc_id -= 1;
        }
        Ok(())
    }

    fn add_service(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        sclass: &Class,
        initial_attrs: &[Attribute],
        svc_id: usize,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        let service_name = &sclass.name;

        let mut attrs = Vec::new();
        attrs.extend_from_slice(initial_attrs);

        // Service class either match an ID in the configuration or must have a
        // parent that does.  We take the first parent that matches a configuration as
        // the service configuration to use.
        //

        let matched_service_name = find_defined_service(service_name, config, class_idx);
        if matched_service_name.is_none() {
            return Err(CompilationError::ConfigError(format!(
                "no service for {} found in configuration",
                service_name
            )));
        }
        let matched_service_name = matched_service_name.unwrap();

        // The service may have provider attributes that we need.
        match config.get(&format!("/services/{}/provider", matched_service_name)) {
            Some(citem) => match citem {
                ConfigItem::AttrList(alist) => {
                    attrs.extend_from_slice(&vec_to_attributes(&alist)?);
                }
                _ => {
                    panic!("error: provider must be an attribute list");
                }
            },
            None => {
                // no provider attributes
            }
        };

        // service must have a protocol
        let prot = match config.get(&format!("/services/{}/protocol", matched_service_name)) {
            Some(citem) => match &citem {
                ConfigItem::Protocol(_, _, _) => Protocol::from(citem),
                _ => {
                    panic!("error: protocol must be a protocol enum");
                }
            },
            None => {
                return Err(CompilationError::ConfigError(format!(
                    "protocol for {} not found in configuration",
                    matched_service_name,
                )))
            }
        };

        let attr_map = squash_attributes(&attrs, &sclass.pos)?;

        let resolved_attrs = self.resolve_attributes(
            attr_map
                .into_values()
                .collect::<Vec<Attribute>>()
                .as_slice(),
            config,
        )?;

        if resolved_attrs.is_empty() {
            return Err(CompilationError::ConfigError(format!(
                "service with no attributes {}",
                matched_service_name
            )));
        }

        let fabric_svc_id = self.fabric.add_service(
            &matched_service_name,
            &prot,
            &resolved_attrs,
            ServiceType::Regular,
        )?;
        self.allowid_to_fab_svc.insert(svc_id, fabric_svc_id);

        Ok(())
    }

    fn allow_clauses_to_services(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
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

            let svc_class = class_idx
                .get(&ac.service.class)
                .expect("service class not found in class index");

            self.add_service(class_idx, svc_class, &attrs, ac.id, config)?;
        }
        Ok(())
    }

    // Every attribute needs to come from a trusted service. Since right now (TODO) the
    // only service is the default one, the only attribute we accept is "cn" or the full
    // expansion of that "zpr.adapter.cn".
    //
    fn resolve_attributes(
        &self,
        attrs: &[Attribute],
        config: &ConfigApi,
    ) -> Result<Vec<Attribute>, CompilationError> {
        // TODO: The trusted service support is no yet real, this is a hack to permit compilation of
        //       ZPL files that use more than just the "cn" (default) attribute.

        let trusted_service_names = config.must_get_keys("/trusted_services");

        let mut resolved_attrs = Vec::new();
        for a in attrs {
            if a.name == zpl::ADAPTER_CN_ATTR {
                if a.tag {
                    return Err(CompilationError::ConfigError(format!(
                        "{} attribute used as a tag, but is a tuple attriubte",
                        a.name
                    )));
                }
                resolved_attrs.push(a.clone());
            }
            if a.name == zpl::DEFAULT_ATTR {
                if a.tag {
                    return Err(CompilationError::ConfigError(format!(
                        "{} attribute used as a tag, but is a tuple attribute",
                        a.name
                    )));
                }
                resolved_attrs.push(a.set_name(zpl::ADAPTER_CN_ATTR));
            } else {
                // TODO: This should be cached
                // TODO: Not sure we are handling the case where ZPL is using prefixes correctly here.
                let mut matched = false;
                for ts_name in &trusted_service_names {
                    let ts_prefix = config
                        .must_get(&format!("/trusted_services/{}/prefix", ts_name))
                        .to_string();
                    let already_prefixed = a.name.starts_with(&format!("{ts_prefix}."));

                    let search_name = if already_prefixed {
                        a.name[ts_prefix.len() + 1..].to_string()
                    } else {
                        a.name.clone()
                    };
                    let ts_attrs: Vec<String>;
                    if a.tag {
                        ts_attrs =
                            config.must_get_keys(&format!("/trusted_services/{}/tags", ts_name));
                    } else {
                        ts_attrs = config
                            .must_get_keys(&format!("/trusted_services/{}/attributes", ts_name));
                    }
                    if ts_attrs.contains(&search_name) {
                        if matched {
                            return Err(CompilationError::ConfigError(format!(
                                "attribute {} found in multiple trusted services",
                                a.name
                            )));
                        }
                        let mut new_attr = a.clone();
                        new_attr.name = format!("{ts_prefix}.{search_name}");
                        resolved_attrs.push(new_attr);
                        matched = true;
                    }

                    let ts_id_attrs = config
                        .must_get_keys(&format!("/trusted_services/{}/id_attributes", ts_name));
                    if ts_id_attrs.contains(&search_name) {
                        if matched {
                            return Err(CompilationError::ConfigError(format!(
                                "attribute {} found in multiple trusted services",
                                a.name
                            )));
                        }
                        // TODO: We need attr type info from config
                        let mut new_attr = a.clone();
                        new_attr.name = format!("{ts_prefix}.{search_name}");
                        resolved_attrs.push(new_attr);
                        matched = true;
                    }

                    if already_prefixed && !matched {
                        return Err(CompilationError::ConfigError(format!(
                            "attribute {} not found in trusted service {}",
                            a.name, ts_name
                        )));
                    }
                }
                if !matched {
                    return Err(CompilationError::ConfigError(format!(
                        "attribute {} not found in any trusted service",
                        a.name
                    )));
                }
            }
        }
        Ok(resolved_attrs)
    }

    /// Must init_services before init_nodes.
    fn init_nodes(&mut self, config: &ConfigApi) -> Result<(), CompilationError> {
        let node_keys = match config.get("zpr/nodes") {
            Some(ConfigItem::KeySet(node_ids)) => node_ids,
            _ => {
                return Err(CompilationError::ConfigError(
                    "no nodes defined in configuration".to_string(),
                ))
            }
        };

        if node_keys.len() > 1 {
            return Err(CompilationError::ConfigError(
                "multiple nodes defined in configuration".to_string(),
            ));
        }
        let vs_dock_node = match config.get("zpr/visa_services/default/dock_node_id") {
            Some(ConfigItem::StrVal(node_id)) => node_id,
            _ => {
                return Err(CompilationError::ConfigError(
                    "visa service docking node not defined for default VS in configuration"
                        .to_string(),
                ))
            }
        };
        if vs_dock_node != node_keys[0] {
            return Err(CompilationError::ConfigError(format!(
                "visa service docking node must be the only node in configuration: '{}' != '{}'",
                vs_dock_node, node_keys[0]
            )));
        }
        self.fabric.add_node(&vs_dock_node, config)
    }

    /// Process the ZPL policy into conditions for accessing fabric services.
    /// Must be done after initializing the services.
    fn add_client_policies(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        // Every allow is an access condition (aka rule, aka policy).
        // We need the attributes from the user and device clauses.
        for ac in &policy.allows {
            // Here we collect all attributes -- some will have no values.
            let mut attrs = Vec::new();

            // Grab all the endpint attributes
            let ep_class_attrs = attrs_for_class(&class_idx, &ac.device.class);
            attrs.extend_from_slice(&ep_class_attrs);
            attrs.extend_from_slice(
                &ac.device
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
            let fp = FPos::from(&ac.device.class_tok);
            let attr_map = squash_attributes(&attrs, &fp)?;

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
    /// And the only thing we care about is the certificate.
    fn add_default_auth(
        &mut self,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        if config
            .get(&format!(
                "/trusted_services/{}",
                zpl::DEFAULT_TRUSTED_SERVICE_ID
            ))
            .is_none()
        {
            return Err(CompilationError::ConfigError(
                "no trusted default service found in configuration".to_string(),
            ));
        }

        let cert_data = match config.get(&format!(
            "/trusted_services/{}/certificate",
            zpl::DEFAULT_TRUSTED_SERVICE_ID
        )) {
            Some(ConfigItem::BytesB64(b64data)) => match BASE64_STANDARD.decode(b64data) {
                Ok(cert_data) => cert_data,
                Err(e) => {
                    return Err(CompilationError::ConfigError(format!(
                        "error decoding certificate data: {}",
                        e
                    )));
                }
            },
            _ => {
                // TODO: This should probably be an error, but helps for testing.
                ctx.warn("no certificate for default trusted service")?;
                vec![]
            }
        };

        self.fabric.default_auth_cert_asn = cert_data;
        Ok(())
    }
}

/// Returns first service starting with `class_name` and searching ancestors that is
/// defined in our service index (ie, is in configuration).
fn find_defined_service(
    class_name: &str,
    config: &ConfigApi,
    class_idx: &HashMap<String, &Class>,
) -> Option<String> {
    let mut cur_svc_class = class_name;
    let mut matched_service = config.get(&format!("/services/{}", cur_svc_class));

    while matched_service.is_none() {
        let cl = class_idx.get(cur_svc_class).unwrap();
        if cl.parent == cl.name {
            // we are at top of hierarchy
            break;
        }
        cur_svc_class = &cl.parent;
        matched_service = config.get(&format!("/services/{}", cur_svc_class));
    }
    match matched_service {
        Some(s) => Some(s.to_string()),
        None => None,
    }
}

/// Get all the WITH attributes on the named class, including any attributes on
/// the parent classes.  We ignore optional attributes.
fn attrs_for_class(class_idx: &HashMap<String, &Class>, class_name: &str) -> Vec<Attribute> {
    let mut attrs = Vec::new();
    let mut cl = class_idx
        .get(class_name)
        .expect(&format!("class {} not found in class index", class_name));

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

#[cfg(test)]
mod test {
    use super::*;

    use crate::context::CompilationCtx;
    use crate::lex::Token;
    use crate::ptypes::{AllowClause, ClassFlavor, Clause, FPos};
    use std::env;

    #[test]
    fn test_init_services_minimal() {
        let cfg = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["foo", "fee"]]

        [visa_service]
        dock_node = "n0"
        "#;

        let mut w = Weaver::new();
        let class_idx = HashMap::new();
        let policy = Policy::default();
        let config =
            ConfigApi::new_from_toml_content(&cfg, &env::temp_dir(), &CompilationCtx::default())
                .expect("failed to parse config");

        let res = w.init_services(&class_idx, &policy, &config, &CompilationCtx::default());
        assert!(res.is_ok());

        // Should create two services: visa-service and visa-service-admin
        assert_eq!(w.fabric.services.len(), 2);

        let vs = w
            .fabric
            .services
            .iter()
            .find(|s| s.fabric_id == zpl::VS_SERVICE_NAME);
        assert!(vs.is_some());

        let vs = w
            .fabric
            .services
            .iter()
            .find(|s| s.fabric_id == format!("{}/admin", zpl::VS_SERVICE_NAME));
        assert!(vs.is_some());
    }

    #[test]
    fn test_init_services_must_be_in_zpl() {
        let cfg = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["foo", "fee"]]

        [visa_service]
        dock_node = "n0"

        [protocols.fee]
        protocol = "iana.TCP"
        port = 80

        [services.foo]
        protocol = "fee"
        provider = [["cn", "fee"]]

        [services.bar]
        protocol = "boo"
        "#;

        let mut class_idx = HashMap::new();
        let mut policy = Policy::default();
        let ctx = CompilationCtx::default();
        let config = ConfigApi::new_from_toml_content(&cfg, &env::temp_dir(), &ctx)
            .expect("failed to parse config");

        {
            let mut w = Weaver::new();
            let res = w.init_services(&class_idx, &policy, &config, &ctx);
            assert!(res.is_ok(), "init_services failed: {}", res.unwrap_err());

            // Should create two services: visa-service and visa-service-admin.
            // Does not create services just because they are in the config.
            assert_eq!(w.fabric.services.len(), 2);
            let vs = w
                .fabric
                .services
                .iter()
                .find(|s| s.fabric_id == zpl::VS_SERVICE_NAME);
            assert!(vs.is_some());
            let vs = w
                .fabric
                .services
                .iter()
                .find(|s| s.fabric_id == format!("{}/admin", zpl::VS_SERVICE_NAME));
            assert!(vs.is_some());
        }

        // But will create services if they are in the ZPL.

        // We are only calling init_services which does not create policies anyway.
        // Will only notice that the 'foo' service is referenced.
        let a_foo = AllowClause {
            id: 1,
            device: Clause::new("device", Token::default()),
            user: Clause::new("user", Token::default()),
            service: Clause::new("foo", Token::default()),
        };
        policy.allows.push(a_foo);

        // Class named "foo" must have been parsed.
        let defaults = Class::defaults();
        for def_cl in &defaults {
            class_idx.insert(def_cl.name.clone(), def_cl);
        }
        let foo_cls = Class {
            flavor: ClassFlavor::Service,
            parent: zpl::DEF_CLASS_SERVICE_NAME.to_string(),
            name: "foo".to_string(),
            aka: "foos".to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
        };
        class_idx.insert("foo".to_string(), &foo_cls);

        // Service named "foo" must exist too.
        /*
        let foo_svc = Service {
            id: "foo".to_string(),
            protocol_id: "fee".to_string(),
            provider: None,
        };
        service_idx.insert("foo".to_string(), &foo_svc);
        */

        {
            let mut w = Weaver::new();
            let res = w.init_services(&class_idx, &policy, &config, &ctx);
            println!("{:?}", res);
            assert!(res.is_ok(), "init_services failed: {}", res.unwrap_err());
            assert_eq!(w.fabric.services.len(), 3);
            let vs = w.fabric.services.iter().find(|s| s.fabric_id == "foo");
            assert!(vs.is_some());
        }
    }
}
