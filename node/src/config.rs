// config.rs - Config file format for the node

use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Configuration {
    #[serde(skip)]
    base_path: String,

    #[serde(skip)]
    node_addr: Option<IpAddr>,

    creds: Creds,

    claims: toml::Table,
}

#[derive(Debug, Clone, Deserialize)]
struct Creds {
    certificate: String, // this nodes signed certificate file
    private_key: String, // this nodes private key file
}

impl Configuration {
    pub fn get_cert_path(&self) -> String {
        let base = Path::new(&self.base_path);
        let cert_pb = base.join(&self.creds.certificate);
        return cert_pb.to_str().unwrap().to_string();
    }

    pub fn get_key_path(&self) -> String {
        let base = Path::new(&self.base_path);
        let cert_pb = base.join(&self.creds.private_key);
        return cert_pb.to_str().unwrap().to_string();
    }

    // Gets a copy of the claims
    pub fn get_claims(&self) -> HashMap<String, String> {
        let mut hmap: HashMap<String, String> = HashMap::new();
        for (k, v) in self.claims.iter() {
            hmap.insert(k.to_string(), v.to_string());
        }
        hmap
    }

    pub fn get_claim(&self, key: &str) -> Option<String> {
        match self.claims.get(key) {
            Some(v) => v.as_str().map(|s| s.to_string()), // Double decode since v.as_str() from Table includes quotes.
            None => None,
        }
    }

    pub fn get_node_addr(&self) -> IpAddr {
        if let Some(a) = &self.node_addr {
            *a // somehow this de-ref returns a copy of the addr ???? XXX
        } else {
            panic!("node address not set in Configuration"); // This fair since the address is required in load_configuration
        }
    }
}

pub fn load_configuration(path: &str) -> Result<Configuration, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut toml_text = String::new();
    let len = reader.read_to_string(&mut toml_text)?;
    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("empty config file: {}", path),
        ));
    }
    let mut c: Configuration = match toml::from_str(&toml_text) {
        Ok(c) => c,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to parse config file: {}: {}", path, e),
            ))
        }
    };

    c.base_path = match std::path::Path::new(path).parent().unwrap().to_str() {
        Some(p) => p.to_string(),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to get parent path of config file: {}", path),
            ))
        }
    };

    // The node address is one of the required claims.
    let node_addr: IpAddr = match c.get_claim("zpr.addr") {
        Some(s) => match s.parse() {
            Ok(a) => a,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to parse zpr.addr claim: {}", e),
                ));
            }
        },
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "zpr.addr claim not found in config",
            ));
        }
    };

    c.node_addr = Some(node_addr);

    Ok(c)
}
