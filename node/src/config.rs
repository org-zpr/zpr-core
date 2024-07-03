// config.rs - Config file format for the node

use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;



#[derive(Debug, Clone, Deserialize)]
pub struct Configuration {
    #[serde(skip)]
    base_path: String,    

    creds: Creds,    

    claims: toml::Table,
}

#[derive(Debug, Clone, Deserialize)]
struct Creds {
    certificate: String,  // this nodes signed certificate file
    private_key: String,  // this nodes private key file
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
        return hmap;
    }

    pub fn get_claim(&self, key: &str) -> Option<String> {
        match self.claims.get(key) {
            Some(v) => match v.as_str() {
                Some(s) => Some(s.to_string()), // Double decode since v.as_str() includes quotes.
                None => None,
            },
            None => None,
        }
    }
}


pub fn load_configuration(path: &str) -> Result<Configuration, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut toml_text = String::new();
    let len = reader.read_to_string(&mut toml_text)?;
    if len == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("empty config file: {}", path)));
    }
    let mut c: Configuration = match toml::from_str(&toml_text) {
        Ok(c) => c,
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to parse config file: {}: {}", path, e))),
    };

    c.base_path = match std::path::Path::new(path).parent().unwrap().to_str() {
        Some(p) => p.to_string(),
        None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to get parent path of config file: {}", path))),
    };
    Ok(c)
}