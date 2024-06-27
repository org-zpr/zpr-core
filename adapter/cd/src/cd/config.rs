use serde::Deserialize;

use openssl::rsa::Rsa;
use openssl::x509::X509;
use openssl::pkey::Private;

use std::fs;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read};




// "Config" is configuration details for the CD binary.
pub struct Config {
    pub socket_path: String,
}


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
}

#[derive(Debug, Clone, Deserialize)]
struct Adapter {
    certificate: String, // path to PEM file
    private_key: String, // path to PEM file
}


#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConfigRecord {
    name: String,
    source: String, // path name of Configuration that loaded this
    host_or_ip: String,
    port: u16,
    private_key: Rsa<Private>,
    certificate: X509,
    root_ca: X509,
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
    let cert = load_cert(base_path.join(&c.adapter.certificate).to_str().unwrap())?;
    let private_key = load_key(base_path.join(&c.adapter.private_key).to_str().unwrap())?;

    let conf_rec = ConfigRecord{
        name: c.profile.name,
        source: path.to_string(),
        host_or_ip: c.dock.host_or_ip,
        port: c.dock.port,
        private_key,
        certificate: cert,
        root_ca,
    };

    Ok(conf_rec)
}

impl ConfigRecord {

    pub fn get_cn(&self) -> String {
        let subject = self.certificate.subject_name();
        let cn = subject.entries_by_nid(openssl::nid::Nid::COMMONNAME).next().unwrap();
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
}
