//! config_api.rs is a prototype configuration API. Although only used locally
//! in this "compiler", this may be a way to build out an api "service" which
//! would be used by the compiler as well as the visa service.

use crate::crypto::digest_as_hex;
use crate::config::Config;


pub struct ConfigApi {
    config: Config,
}

pub enum ConfigItem {
    StrVal(String),
    BytesAsHex(String),
    KeySet(Vec<String>),
    AttrList(Vec<(String, String)>), // vec of tuples
}

impl ConfigApi {
    // TODO: This should be "new from file" -- hide the config thing.
    pub fn new_from_config(config: Config) -> ConfigApi {
        ConfigApi {
            config,
        }
    }

    pub fn get_version(&self) -> String {
        String::new()
    }

    // A key can start with a namespace or it uses the default namespace and
    // starts with "/".
    //
    // Versioning.
    //    We can come up with a version as a hash of our source file.
    //
    //    Since this little api just reads a file, the version is constant.
    //    So I think we ignore it here.
    //
    //    What if version is in the key path?
    //       /versions -> returns ordered list of versions (most recent first)
    //
    //    Then prefix all calls with a version, eg:
    //       /<version>/trusted_services -> 
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
    // - /trusted_services/<foo>/provides -> list of attribute names (probably also need type)
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
            return None;
        }
        if key.starts_with("/") {
            self.get_ns("", vec![key])
        } else {
            let mut key_path = key.split("/");
            let ns = key_path.next().unwrap();
            let rest = key_path.collect::<Vec<&str>>();
            self.get_ns(ns, rest)
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
            "trusted_services" => None,
            "services" => None,
            "protocols" => None,
            _ => None,
        }
    }

    fn get_zpr(&self, key_path: Vec<&str>) -> Option<ConfigItem> {
        if key_path.is_empty() {
            return None;
        }
        let key = key_path[0];
        match key {
            "version" => {
                return Some(ConfigItem::BytesAsHex(digest_as_hex(&self.config.digest)));
            }
            "resolver" => None,
            "nodes" => None,
            "visa_services" => None,
            _ => None,
        }
    }

}

