//! config_api.rs is a prototype configuration API. Although only used locally
//! in this "compiler", this may be a way to build out an api "service" which
//! would be used by the compiler as well as the visa service.

use core::fmt;
use std::path::{Path, PathBuf};

use base64::prelude::*;

use crate::config::{self, Config};
use crate::context::CompilationCtx;
use crate::crypto::{digest_as_hex, load_asn1data_from_pem};
use crate::errors::CompilationError;
use crate::protocols::{IanaProtocol, IcmpFlowType, Protocol};

/// ConfigApi wraps a pseudo RESTFUL api around the config data.
/// Access is visa the [ConfigApi::get] method.
///
/// This is a testbed for the "can we implement configuration as
/// a service" research.
pub struct ConfigApi {
    config: Config,
    base_path: PathBuf,
    verbose: bool,
}

/// [ConfigItem::Protocol] has this prt-arg thing as one of its fields.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Clone)]
pub enum PortArgT {
    /// a single TCP/UDP port
    Port(u16),

    /// A range of TCP/UDP ports (lo, high) inclusive
    PortRange(u16, u16),

    /// A list of TCP/UDP ports
    PortList(Vec<u16>),

    /// List of permissible ICMP codes
    ICMPOneShot(Vec<u8>),

    /// Pair of ICMP codes (request, reply)
    ICMPReqRep(u8, u8),
}

/// The config API return values.
#[derive(Debug, PartialEq, Clone)]
pub enum ConfigItem {
    /// Generic string value
    StrVal(String),

    /// Base64 encoded byte buffer
    BytesB64(String),

    /// A set of key values (eg, a set of node IDs)
    KeySet(Vec<String>),

    /// A set of attributes as key value pairs
    AttrList(Vec<(String, String)>),

    /// A network address (host, port). Host may be a hostname or an IP address.
    NetAddr(String, u16),

    /// A protocol definition. This is a tuple of (name, protocol, ports-or-type-codes)
    Protocol(String, IanaProtocol, PortArgT),
}

impl fmt::Display for ConfigItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigItem::StrVal(s) => write!(f, "{}", s),
            ConfigItem::BytesB64(s) => write!(f, "{}", s),
            ConfigItem::KeySet(keys) => {
                let mut first = true;
                write!(f, "[")?;
                for key in keys {
                    if first {
                        first = false;
                    } else {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", key)?;
                }
                write!(f, "]")
            }
            ConfigItem::AttrList(attrs) => {
                let mut first = true;
                write!(f, "[")?;
                for (k, v) in attrs {
                    if first {
                        first = false;
                    } else {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", k, v)?;
                }
                write!(f, "]")
            }
            ConfigItem::NetAddr(host, port) => write!(f, "{}:{}", host, port),
            ConfigItem::Protocol(name, prot, ports) => {
                write!(f, "{}: {} ", name, prot)?;
                match ports {
                    PortArgT::Port(p) => write!(f, "{}", p),
                    PortArgT::PortRange(p1, p2) => write!(f, "{}-{}", p1, p2),
                    PortArgT::PortList(pl) => {
                        let mut first = true;
                        write!(f, "[")?;
                        for p in pl {
                            if first {
                                first = false;
                            } else {
                                write!(f, ", ")?;
                            }
                            write!(f, "{}", p)?;
                        }
                        write!(f, "]")
                    }
                    PortArgT::ICMPOneShot(codes) => {
                        let mut first = true;
                        write!(f, "[")?;
                        for c in codes {
                            if first {
                                first = false;
                            } else {
                                write!(f, ", ")?;
                            }
                            write!(f, "{}", c)?;
                        }
                        write!(f, "]")
                    }
                    PortArgT::ICMPReqRep(req, rep) => write!(f, "{}-{}", req, rep),
                }
            }
        }
    }
}

impl From<ConfigItem> for Protocol {
    fn from(item: ConfigItem) -> Self {
        match item {
            ConfigItem::Protocol(_name, prot, port_t) => {
                let mut p = Protocol {
                    protocol: prot,
                    port: None,
                    icmp: None,
                };
                match port_t {
                    PortArgT::Port(pnum) => {
                        p.port = Some(pnum.to_string());
                    }
                    PortArgT::PortRange(low, hi) => {
                        p.port = Some(format!("{}-{}", low, hi));
                    }
                    PortArgT::PortList(plist) => {
                        p.port = Some(
                            plist
                                .iter()
                                .map(|n| n.to_string())
                                .collect::<Vec<String>>()
                                .join(","),
                        );
                    }
                    PortArgT::ICMPOneShot(codes) => {
                        p.icmp = Some(IcmpFlowType::OneShot(codes));
                    }
                    PortArgT::ICMPReqRep(req, resp) => {
                        p.icmp = Some(IcmpFlowType::RequestResponse(req, resp));
                    }
                }
                p
            }
            _ => panic!("ConfigItem is not a protocol"),
        }
    }
}

impl From<&ConfigItem> for Protocol {
    fn from(item: &ConfigItem) -> Self {
        match item {
            ConfigItem::Protocol(_name, prot, port_t) => {
                let mut p = Protocol {
                    protocol: prot.clone(),
                    port: None,
                    icmp: None,
                };
                match port_t {
                    PortArgT::Port(pnum) => {
                        p.port = Some(pnum.to_string());
                    }
                    PortArgT::PortRange(low, hi) => {
                        p.port = Some(format!("{}-{}", low, hi));
                    }
                    PortArgT::PortList(plist) => {
                        p.port = Some(
                            plist
                                .iter()
                                .map(|n| n.to_string())
                                .collect::<Vec<String>>()
                                .join(","),
                        );
                    }
                    PortArgT::ICMPOneShot(codes) => {
                        p.icmp = Some(IcmpFlowType::OneShot(codes.clone()));
                    }
                    PortArgT::ICMPReqRep(req, resp) => {
                        p.icmp = Some(IcmpFlowType::RequestResponse(*req, *resp));
                    }
                }
                p
            }
            _ => panic!("ConfigItem is not a protocol"),
        }
    }
}

impl ConfigApi {
    /// Create the api from the TOML configuration file.
    pub fn new_from_toml_file(
        fname: &Path,
        ctx: &CompilationCtx,
    ) -> Result<ConfigApi, CompilationError> {
        let config = config::load_config(fname, ctx)?;
        let api = ConfigApi {
            config,
            base_path: fname.to_path_buf().parent().unwrap().to_path_buf(),
            verbose: ctx.verbose,
        };
        Ok(api)
    }

    /// Create the api from the TOML content. `base_path` is used for resolving
    /// relative filenames in the config.
    #[allow(dead_code)]
    pub fn new_from_toml_content(
        content: &str,
        base_path: &Path,
        ctx: &CompilationCtx,
    ) -> Result<ConfigApi, CompilationError> {
        let config = config::parse_config(content, ctx)?;
        let api = ConfigApi {
            config,
            base_path: PathBuf::from(base_path),
            verbose: ctx.verbose,
        };
        Ok(api)
    }

    // A key can start with a namespace or it uses the default namespace and
    // starts with "/".
    //
    // Anywhere in config where an address is used the author can use a value
    // from resolver.host table.  Values coming out of this API are already run
    // through the resolver.host table.
    //
    // Within a namespace there are some known keys.
    //
    // I think the idea is we could load additional config and place it in a namespace.
    // But with just one file, it's hard to understand how namespace works. So maybe
    // ignore it for now?
    //
    // - /trusted_services -> returns list of IDs of the trusted services (KeySet)
    // - /trusted_services/<foo> -> returns (type ?)
    // - /trusted_services/<foo>/api -> the api value
    // - /trusted_services/<foo>/certificate -> returns certificate (if any)
    // - /trusted_services/<foo>/provider -> k/v tuples
    // - /trusted_services/<foo>/attributes -> list of attribute names (probably also need type)
    // - /trusted_services/<foo>/tags -> list of attribute names (probably also need type)
    // - /trusted_services/<foo>/id_attributes -> list of attribute names (probably also need type)
    //
    // (PREFIX - let's make prefix same as service ID.)
    //
    // Caller will want to get the service that provides attr FOO.
    // So caller can just load them all up and create an index.
    //
    // - /services -> returns list of service names (KeySet)
    // - /services/<foo> -> returns ?
    // - /services/<foo>/provider -> returns list of k/v tuples
    // - /services/<foo>/protocol -> returns protocol id?  What if service has it's own port? Return a protocol-type
    //
    // - /protocols/<foo> -> returns a protocol type?
    //                       Not sure we need this.  When we process the config, we attach protcols to services
    //
    // Within the "global" zpr namespace is:
    //
    // - zpr/resolver/<foo> -> returns mapping (if any) for hostname "foo"
    //
    // - zpr/nodes -> returns list of node IDs (KeySet)
    // - zpr/nodes/<id> -> returns (?)
    // - zpr/nodes/<id>/zpr_addr -> returns zpr address (string?) - pre resolving (ie, so might be a domain name that needs resolving)
    // - zpr/nodes/<id>/provider -> returns list of k/v tuples
    //
    // - zpr/visa_services -> returns list of visa service IDs (KeySet)
    // - zpr/visa_services/<id> -> returns (?)
    // - zpr/visa_services/<id>/admin_attrs -> returns (list of attr k/v tuples)
    // - zpr/visa_services/<id>/dock_node_id -> returns (docking node id)
    //
    pub fn get(&self, key: &str) -> Option<ConfigItem> {
        if key.is_empty() {
            if self.verbose {
                println!("zplc> FAIL {key}")
            };
            return None;
        }
        let res = if key.starts_with("/") {
            let path: Vec<&str> = key.split("/").collect();
            if path.len() < 2 {
                return None;
            }
            self.get_ns("", path[1..].to_vec())
        } else {
            let mut key_path = key.split("/");
            let ns = key_path.next().unwrap();
            let rest = key_path.collect::<Vec<&str>>();
            self.get_ns(ns, rest)
        };
        if self.verbose {
            if res.is_some() {
                println!("zplc>  OK  {key}");
            } else {
                println!("zplc> FAIL {key}");
            }
        }
        res
    }

    /// This version of [ConfigItem::get] will panic if the key is not found.
    pub fn must_get(&self, key: &str) -> ConfigItem {
        self.get(key)
            .expect(format!("key not found: {}", key).as_str())
    }

    pub fn must_get_keys(&self, key: &str) -> Vec<String> {
        match self.must_get(key) {
            ConfigItem::KeySet(keys) => keys,
            _ => panic!("not a KeySet"),
        }
    }

    fn get_ns(&self, ns: &str, key_path: Vec<&str>) -> Option<ConfigItem> {
        if ns == "zpr" {
            return self.get_zpr(key_path);
        }
        if !ns.is_empty() {
            panic!("non-default namespace not yet supported in config")
        }
        if key_path.is_empty() {
            return None;
        }
        let key = key_path[0];
        match key {
            "trusted_services" => {
                if key_path.len() == 1 {
                    // trusted_services -> list of trusted service IDs
                    return Some(ConfigItem::KeySet(
                        self.config
                            .trusted_services
                            .iter()
                            .map(|ts| ts.id.clone())
                            .collect(),
                    ));
                }
                self.get_trusted_service(key_path[1..].to_vec())
            }
            "services" => {
                if key_path.len() == 1 {
                    // services -> list of service IDs
                    return Some(ConfigItem::KeySet(
                        self.config.services.iter().map(|s| s.id.clone()).collect(),
                    ));
                }
                self.get_service(key_path[1..].to_vec())
            }
            _ => panic!("unknown key: {}", key),
        }
    }

    fn get_zpr(&self, key_path: Vec<&str>) -> Option<ConfigItem> {
        if key_path.is_empty() {
            return None;
        }
        let key = key_path[0];
        match key {
            "version" => {
                return Some(ConfigItem::StrVal(digest_as_hex(&self.config.digest)));
            }
            "resolver" => {
                if key_path.len() == 1 {
                    return None;
                }
                self.resolve_hostname(key_path[1])
            }
            "nodes" => self.get_zpr_nodes(key_path),
            "visa_services" => {
                if key_path.len() == 1 {
                    // visa_services -> list of visa service IDs
                    // We only support one visa service at the moment.
                    return Some(ConfigItem::KeySet(vec!["default".to_string()]));
                }
                self.get_zpr_visa_service(key_path[1..].to_vec())
            }
            _ => panic!("unknown key: {}", key),
        }
    }

    /// `key_path` here is everything after services/ -- and it contains at least
    /// one element (the service ID).
    fn get_service(&self, key_path: Vec<&str>) -> Option<ConfigItem> {
        let svc = self.config.services.iter().find(|s| s.id == key_path[0])?;
        if key_path.len() == 1 {
            // services/<id> -> <id>
            return Some(ConfigItem::StrVal(svc.id.clone()));
        }
        let key = key_path[1];
        match key {
            "provider" => {
                // TODO: Why is provider an option?
                let Some(provider) = svc.provider.as_ref() else {
                    return None;
                };
                Some(ConfigItem::AttrList(provider.clone()))
            }
            "protocol" => {
                let Some(prot) = self.config.protocols.get(&svc.protocol_id) else {
                    panic!(
                        "protocol {} for service {} not found",
                        svc.protocol_id, svc.id
                    );
                };
                match prot.protocol {
                    IanaProtocol::TCP | IanaProtocol::UDP => {
                        // TODO: The config should parse out the port. For now we only accept single port number.
                        let Some(pstr) = prot.port.as_ref() else {
                            panic!(
                                "port not set for service {}, protocol {}",
                                svc.id, svc.protocol_id
                            );
                        };
                        // TODO: This error should be caught in config parser
                        let portnum = pstr.parse::<u16>().expect(
                            format!("failed to parse port number for serrvice {}", svc.id).as_str(),
                        );
                        Some(ConfigItem::Protocol(
                            svc.id.clone(),
                            prot.protocol,
                            PortArgT::Port(portnum),
                        ))
                    }
                    IanaProtocol::ICMP | IanaProtocol::ICMPv6 => {
                        let Some(flowtype) = prot.icmp.as_ref() else {
                            panic!(
                                "flowtype not set for service {}, protocol {}",
                                svc.id, svc.protocol_id
                            );
                        };
                        match flowtype {
                            IcmpFlowType::RequestResponse(req, rep) => Some(ConfigItem::Protocol(
                                svc.id.clone(),
                                prot.protocol,
                                PortArgT::ICMPReqRep(*req, *rep),
                            )),
                            IcmpFlowType::OneShot(codes) => Some(ConfigItem::Protocol(
                                svc.id.clone(),
                                prot.protocol,
                                PortArgT::ICMPOneShot(codes.clone()),
                            )),
                        }
                    }
                }
            }
            _ => panic!("unknown key {}", key),
        }
    }

    /// `key_path` here is everything after trusted_services/ -- and it contains at least
    /// one element (the trusted service ID).
    fn get_trusted_service(&self, key_path: Vec<&str>) -> Option<ConfigItem> {
        let svc = self
            .config
            .trusted_services
            .iter()
            .find(|ts| ts.id == key_path[0])?;
        if key_path.len() == 1 {
            // trusted_services/<id> -> <id>
            return Some(ConfigItem::StrVal(svc.id.clone()));
        }
        let key = key_path[1];
        match key {
            "api" => Some(ConfigItem::StrVal(svc.api.clone())),
            "certificate" => {
                let Some(cert_path) = svc.cert_path.as_ref() else {
                    return None;
                };
                if cert_path.as_os_str().is_empty() {
                    // No cert path. Possibly this is an error to be detected in config parser?
                    return None;
                }
                // TODO: pretty sure that the path in the config is not set up relative to source path.
                // TODO: This may be a case where we need to return an error?
                let cert_path = self.abs_path(Path::new(cert_path));
                let cert_data = match load_asn1data_from_pem(&cert_path) {
                    Ok(data) => data,
                    Err(e) => {
                        panic!(
                            "failed to load certificate data from '{}': {}",
                            cert_path.display(),
                            e
                        );
                    }
                };
                Some(ConfigItem::BytesB64(BASE64_STANDARD.encode(&cert_data)))
            }
            "prefix" => Some(ConfigItem::StrVal(svc.prefix.clone())),
            "provider" => panic!("trusted_service.Provider not yet implemented"),
            // TODO: Just like when parsing config, we need a notation to express the attribute properties.
            // Eg, multi-value or tag, required or optional.
            // For now we assume all attributes are tuple-type.
            "attributes" => Some(ConfigItem::KeySet(
                svc.returns_attrs
                    .iter()
                    .filter(|a| !a.tag)
                    .map(|a| a.name.clone())
                    .collect(),
            )),
            "tags" => Some(ConfigItem::KeySet(
                svc.returns_attrs
                    .iter()
                    .filter(|a| a.tag)
                    .map(|a| a.name.clone())
                    .collect(),
            )),
            "id_attributes" => Some(ConfigItem::KeySet(
                svc.identity_attrs.iter().map(|a| a.name.clone()).collect(),
            )),
            _ => panic!("unknown key {}", key),
        }
    }

    /// Given a path, return the possibly adjusted absolute path.
    /// If the passed path `p` is not absolute it is assumed to be relative to the base path.
    ///
    // TODO: This should happen in config - weaver doesn't need to do path stuff.
    fn abs_path(&self, p: &Path) -> PathBuf {
        if p.is_absolute() {
            return p.to_path_buf();
        }
        self.base_path.join(p)
    }

    /// `key_path` here is everything after "zpr/visa_services"
    fn get_zpr_visa_service(&self, key_path: Vec<&str>) -> Option<ConfigItem> {
        if key_path.len() == 1 {
            // visa_services/<id> -> <id>
            if key_path[0] == "default" {
                return Some(ConfigItem::StrVal("default".to_string()));
            }
            return None; // unknown visa service
        }
        let key = key_path[1];
        match key {
            "admin_attrs" => Some(ConfigItem::AttrList(
                self.config.visa_service.admin_attrs.clone(),
            )),
            "dock_node_id" => Some(ConfigItem::StrVal(
                self.config.visa_service.dock_node_id.clone(),
            )),
            _ => panic!("unknown key {}", key),
        }
    }

    /// Returns hostname or IP or None
    fn resolve_hostname(&self, hostname: &str) -> Option<ConfigItem> {
        let mapping = self.config.resolve(hostname)?;
        Some(ConfigItem::StrVal(mapping.to_string()))
    }

    fn get_zpr_nodes(&self, key_path: Vec<&str>) -> Option<ConfigItem> {
        if key_path.len() == 1 {
            // nodes -> list of node IDs
            return Some(ConfigItem::KeySet(
                self.config.nodes.keys().cloned().collect(),
            ));
        }
        let node_id = key_path[1];
        let node = self.config.nodes.get(node_id)?;
        if key_path.len() == 2 {
            // nodes/<id> -> <id>
            return Some(ConfigItem::StrVal(node.id.clone()));
        }
        let key = key_path[2];
        match key {
            "key" => Some(ConfigItem::StrVal(node.key.clone())),
            "provider" => Some(ConfigItem::AttrList(node.provider.clone())),
            "zpr_addr" => self
                .resolve_hostname(&node.zpr_address)
                .or_else(|| Some(ConfigItem::StrVal(node.zpr_address.clone()))),
            "interfaces" => {
                if key_path.len() == 3 {
                    // nodes/<id>/interfaces -> list of interface names
                    return Some(ConfigItem::KeySet(
                        node.interfaces
                            .iter()
                            .map(|iface| iface.name.clone())
                            .collect(),
                    ));
                }
                let ifname = key_path[3];
                // The only attribute on an interface is the netaddr, so we return that here ignoring
                // any further key path.
                let iface = node.interfaces.iter().find(|iface| iface.name == ifname)?;
                // The hostname value may be a mapping.
                let hostname = match self.config.resolve(&iface.host) {
                    Some(mapping) => mapping.to_string(),
                    None => iface.host.clone(),
                };
                return Some(ConfigItem::NetAddr(hostname, iface.port));
            }
            _ => panic!("unknown key: {}", key),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_some_keys() {
        let cfg = r#"
        [resolver]
        order = [ "hosts", "dns" ]

        [resolver.hosts]
        "node.zpr" = "fd5a:5052:90de::1"

        [nodes.n0]
        key = "none"
        zpr_address = "node.zpr"
        interfaces = [ "in1", "in2" ]
        in1.netaddr = "127.0.0.1:5000"
        in2.netaddr = "foo.bah:5000"
        provider = [["foo", "fee"]]

        [visa_service]
        dock_node = "n0"

        [protocols.bar]
        protocol = "iana.TCP"
        port = 21

        [services.foo]
        protocol = "bar"
        "#;
        let ctx = CompilationCtx::default();
        let api = ConfigApi::new_from_toml_content(cfg, &Path::new(""), &ctx).unwrap();

        let ver = api.get("zpr/version").unwrap();
        assert_eq!(ver.to_string().len(), 64);

        let nkeys = api.get("zpr/nodes").unwrap();
        assert_eq!(nkeys.to_string(), "[n0]");
        let nkeys = match nkeys {
            ConfigItem::KeySet(keys) => keys,
            _ => panic!("expected a KeySet"),
        };
        assert_eq!(nkeys.len(), 1);
        assert_eq!(nkeys[0], "n0");

        assert_eq!(
            api.get("zpr/nodes/n0/key").unwrap(),
            ConfigItem::StrVal("none".to_string())
        );

        // Note returns the node address post running through the resolver.
        assert_eq!(
            api.get("zpr/nodes/n0/zpr_addr").unwrap(),
            ConfigItem::StrVal("fd5a:5052:90de::1".to_string())
        );
        assert_eq!(
            api.get("zpr/nodes/n0/interfaces").unwrap().to_string(),
            "[in1, in2]"
        );
        {
            let (poe_host, poe_port) = match api.get("zpr/nodes/n0/interfaces/in1/netaddr").unwrap()
            {
                ConfigItem::NetAddr(host, port) => (host, port),
                _ => panic!("expected a NetAddr"),
            };
            assert_eq!(poe_host, "127.0.0.1");
            assert_eq!(poe_port, 5000);
        }
        {
            let (poe_host, poe_port) = match api.get("zpr/nodes/n0/interfaces/in2/netaddr").unwrap()
            {
                ConfigItem::NetAddr(host, port) => (host, port),
                _ => panic!("expected a NetAddr"),
            };
            assert_eq!(poe_host, "foo.bah");
            assert_eq!(poe_port, 5000);
        }
        assert!(api.get("/services/foo").is_some());

        assert_eq!(
            api.get("zpr/visa_services").unwrap().to_string(),
            "[default]"
        );
    }
}
