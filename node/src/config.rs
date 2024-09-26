// config.rs - Config file format for the node

use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use base64::prelude::*;

#[derive(Debug, Clone, Deserialize)]
pub struct Configuration {
    #[serde(skip)]
    base_path: PathBuf,

    #[serde(skip)]
    node_addr: Option<IpAddr>,

    creds: Creds,

    dock: Dock,

    claims: toml::Table,
}

#[derive(Debug, Clone, Deserialize)]
struct Creds {
    ca_certificate: String,  // path to the CA certificate
    rsa_certificate: String, // path to the RSA certificate
    rsa_private_key: String, // path to the RSA private key
}

#[derive(Debug, Clone, Deserialize)]
struct Dock {
    enabled: bool,
    listen_address: String,    // dock listen address, "host:port"
    noise_certificate: String, // this nodes signed (noise) certificate file
    noise_private_key: String, // base64 noise private key for this node

    #[serde(skip)]
    noise_private_key_bin: [u8; 32], // decoded noise private key
}

impl Configuration {
    pub fn get_ca_cert_path(&self) -> PathBuf {
        let base = Path::new(&self.base_path);
        base.join(&self.creds.ca_certificate)
    }

    pub fn get_noise_cert_path(&self) -> PathBuf {
        let base = Path::new(&self.base_path);
        base.join(&self.dock.noise_certificate)
    }

    pub fn get_noise_private_key(&self) -> &[u8; 32] {
        &self.dock.noise_private_key_bin
    }

    pub fn get_rsa_cert_path(&self) -> PathBuf {
        let base = Path::new(&self.base_path);
        base.join(&self.creds.rsa_certificate)
    }

    pub fn get_rsa_private_key_path(&self) -> PathBuf {
        let base = Path::new(&self.base_path);
        base.join(&self.creds.rsa_private_key)
    }

    // Gets a copy of the claims
    pub fn get_claims(&self) -> BTreeMap<String, String> {
        let mut hmap: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in self.claims.iter() {
            let vstr = v.as_str().map(String::from).unwrap_or_default();
            hmap.insert(k.clone(), vstr);
        }
        hmap
    }

    pub fn get_claim(&self, key: &str) -> Option<String> {
        self.claims.get(key)?.as_str().map(String::from) // Double decode since v.as_str() from Table includes quotes.
    }

    pub fn get_node_addr(&self) -> IpAddr {
        self.node_addr
            .expect("node address not set in Configuration") // This fair panic since the address is required in load_configuration
    }

    pub fn is_dock_enabled(&self) -> bool {
        self.dock.enabled
    }

    pub fn get_dock_listen_addr(&self) -> &str {
        &self.dock.listen_address
    }
}

pub fn load_configuration(path: &Path) -> Result<Configuration, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut toml_text = String::new();
    let len = file.read_to_string(&mut toml_text)?;
    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("empty config file: {}", path.to_string_lossy()),
        ));
    }
    let mut c: Configuration = match toml::from_str(&toml_text) {
        Ok(c) => c,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "failed to parse config file: {}: {}",
                    path.to_string_lossy(),
                    e
                ),
            ))
        }
    };

    c.base_path = match std::path::Path::new(path).parent() {
        Some(p) => PathBuf::from(p),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "failed to get parent path of config file: {}",
                    path.to_string_lossy()
                ),
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
    c.dock.noise_private_key_bin = match BASE64_STANDARD.decode(c.dock.noise_private_key.as_bytes())
    {
        Ok(v) => match v.try_into() {
            Ok(a) => a,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "noise private key length incorrect",
                ));
            }
        },
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to decode noise private key from base64: {}", e),
            ));
        }
    };

    Ok(c)
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempFile {
        path: String,
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    impl TempFile {
        fn new_toml(contents: &str) -> TempFile {
            let mut rng = rand::thread_rng();
            let tstamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let dir = env::temp_dir();
            let num: u32 = rng.gen();
            let path = dir.join(format!("org_zpr_cd_test_{}_{}.toml", num, tstamp));
            fs::write(&path, contents).expect("Unable to write file");
            TempFile {
                path: path.to_str().unwrap().to_string(),
            }
        }

        fn get_path(&self) -> &Path {
            return Path::new(&self.path);
        }
    }

    #[test]
    fn test_get_claims() {
        let toml_txt = r#"
            [creds]
            ca_certificate = "foo-ca-cert.pem"
            rsa_certificate = "foo-cert.pem"
            rsa_private_key = "rsa-key.pem"

            [dock]
            enabled = false
            listen_address = "0.0.0.0:5000"
            noise_private_key = "AB2eP6zV7ve0A4eQgNVNXlAM2q0rYerCPXFMl+/ntUw="
            noise_certificate = "noise-cert.pem"

            [claims]
            "zpr.addr" = "fc00:3001::1"
            "x509.cn" = "node.zpr"
        "#;

        let tmpfile = TempFile::new_toml(&toml_txt);
        let c = load_configuration(tmpfile.get_path());
        if let Err(e) = c {
            panic!("failed to load configuration: {}", e);
        }
        let c = c.unwrap();
        let claims = c.get_claims();
        assert_eq!(claims.len(), 2);

        assert_eq!(c.get_claim("zpr.addr").unwrap(), "fc00:3001::1");
        assert_eq!(c.get_claim("x509.cn").unwrap(), "node.zpr");

        assert_eq!(c.get_claim("not_there"), None);

        assert_eq!(claims.get("zpr.addr").unwrap(), "fc00:3001::1");
        assert_eq!(claims.get("x509.cn").unwrap(), "node.zpr");
    }
}
