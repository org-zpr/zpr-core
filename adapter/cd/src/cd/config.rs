use ph::km_noise::derive_public_key;
use serde::Deserialize;

use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::X509;

use base64::prelude::*;

use std::fs;
use std::fmt;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read};
use std::path::PathBuf;


// "Config" is configuration details for the CD binary.
pub struct Config {
    pub socket_path: PathBuf,
}

// "Configuration" is the ZPR connection configuration file.
// There is one of these for each ZPR network the adapter can conenct to.
#[derive(Debug, Clone, Deserialize)]
struct Configuration {
    profile: Profile,
    dock: Dock,
    adapter: Adapter,
}

#[derive(Debug, Clone, Deserialize)]
struct Profile {
    name: String,
    root_ca: String, // path to PEM file
}

#[derive(Debug, Clone, Deserialize)]
struct Dock {
    host_or_ip: String,
    port: u16,
    noise_public_key: String, // base64 encoded public key
}

#[derive(Debug, Clone, Deserialize)]
struct Adapter {
    noise_certificate: String, // path to PEM file
    noise_private_key: String, // base64 encoded private key
}


/// The bits of the configuration that relate to the cryptography
/// used in setting up the security assocaition.
#[derive(Clone, Debug)]
pub struct CryptoConfig {
    pub remote_noise_public_key: [u8; 32],
    pub local_noise_keypair: NoiseKeypair,
    pub local_certificate: X509,
    pub root_ca: X509,
}


#[derive(Clone, Debug)]
pub struct NoiseKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl fmt::Display for NoiseKeypair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NoiseKeypair ( private: {}, public: {} )", BASE64_STANDARD.encode(&self.private), BASE64_STANDARD.encode(&self.public))
    }
}

impl NoiseKeypair {
    pub fn new(private: [u8; 32]) -> NoiseKeypair {
        NoiseKeypair {
            private,
            public: derive_public_key(&private),
        }
    }
}

impl Into<snow::Keypair> for NoiseKeypair {
    fn into(self) -> snow::Keypair {
        snow::Keypair {
            private: self.private.to_vec(),
            public: self.public.to_vec(),
        }
    }
}


/// The ConfigRecord is a parsed and loaded configuration file.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConfigRecord {
    name: String,
    source: String, // path name of Configuration that loaded this
    host_or_ip: String,
    port: u16,
    adapter_noise_keypair: NoiseKeypair,
    certificate: X509,
    root_ca: X509,
    dock_noise_public_key: [u8; 32],
}

fn load_cert(path: &str) -> Result<X509, std::io::Error> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            return Err(Error::new(
                e.kind(),
                format!("Error opening certificate file {}: {}", path, e),
            ))
        }
    };
    let mut pem_data = String::new();
    file.read_to_string(&mut pem_data)?;
    let cert = X509::from_pem(pem_data.as_bytes())?;
    Ok(cert)
}

#[allow(dead_code)]
fn load_key(path: &str) -> Result<Rsa<Private>, std::io::Error> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            return Err(Error::new(
                e.kind(),
                format!("Error opening private key file {}: {}", path, e),
            ))
        }
    };
    let mut pem_data = String::new();
    file.read_to_string(&mut pem_data)?;
    let key = Rsa::private_key_from_pem(pem_data.as_bytes())?;
    Ok(key)
}

// Read and parse the configuration, read in all the keys (etc), create and return the ConfigRecord.
pub fn load_configuration(path: &str) -> Result<ConfigRecord, std::io::Error> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut toml_text = String::new();
    let len = reader.read_to_string(&mut toml_text)?;
    if len == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Empty configuration file: {}", path),
        ));
    }

    // Load the config file, only use this struct to populate our ConfigRecord.
    let c: Configuration = match toml::from_str(&toml_text) {
        Ok(c) => c,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Error parsing configuration file {}: {}", path, e),
            ))
        }
    };

    let base_path = std::path::Path::new(path).parent().unwrap();

    let root_ca = load_cert(base_path.join(&c.profile.root_ca).to_str().unwrap())?;
    let cert = load_cert(base_path.join(&c.adapter.noise_certificate).to_str().unwrap())?;

    let private_key: [u8; 32] = match BASE64_STANDARD.decode(c.adapter.noise_private_key.as_bytes()) {
        Ok(pk) => match pk.try_into() {
            Ok(pk) => pk,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("noise private key length incorrect"),
                ))
            }
        },
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Error decoding noise private key: {}", e),
            ))
        }
    };

    let adapter_keypar = NoiseKeypair::new(private_key);

    let noise_pk: [u8; 32] = match BASE64_STANDARD.decode(c.dock.noise_public_key.as_bytes()) {
        Ok(pk) => match pk.try_into() {
            Ok(pk) => pk,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("noise public key length incorrect"),
                ))
            }
        },
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Error decoding noise public key: {}", e),
            ))
        }
    };

    let conf_rec = ConfigRecord {
        name: c.profile.name,
        source: path.to_string(),
        host_or_ip: c.dock.host_or_ip,
        port: c.dock.port,
        adapter_noise_keypair: adapter_keypar,
        certificate: cert,
        root_ca,
        dock_noise_public_key: noise_pk,
    };

    Ok(conf_rec)
}

impl ConfigRecord {
    pub fn get_cn(&self) -> String {
        let subject = self.certificate.subject_name();
        let cn = subject
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .unwrap();
        return cn.data().as_utf8().unwrap().to_string();
    }

    pub fn get_name(&self) -> &str {
        self.name.as_str()
    }

    pub fn get_dock_host(&self) -> &str {
        self.host_or_ip.as_str()
    }

    pub fn get_dock_port(&self) -> u16 {
        self.port
    }

    pub fn get_path(&self) -> &str {
        self.source.as_str()
    }

    pub fn has_same_source_as(&self, other: &ConfigRecord) -> bool {
        self.source == other.source
    }

    pub fn get_dock_noise_public_key(&self) -> &[u8; 32] {
        &self.dock_noise_public_key
    }

    pub fn get_certificate(&self) -> &X509 {
        &self.certificate
    }

    pub fn get_root_ca(&self) -> &X509 {
        &self.root_ca
    }

    pub fn get_crypto_particulars(&self) -> CryptoConfig {
        CryptoConfig {
            remote_noise_public_key: self.dock_noise_public_key,
            local_noise_keypair: self.adapter_noise_keypair.clone(),
            local_certificate: self.certificate.clone(),
            root_ca: self.root_ca.clone(),
        }
    }

}
