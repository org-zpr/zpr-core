use std::path::{PathBuf, Path};

use thiserror::Error;
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use toml::Table;

use crate::token::claims_for;

const KEY_SIZE: u32 = 2048;


#[derive(Debug, Error)]
pub enum FsDbError {
    #[error("I/O Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("OpenSSL Error: {0}")]
    OpenSSLError(#[from] openssl::error::ErrorStack),

    #[error("UTF8 Error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("TOML Deserialization Error: {0}")]
    TomlDeError(#[from] toml::de::Error),

    #[error("TOML Serialization Error: {0}")]
    TomlSerError(#[from] toml::ser::Error),

    #[error("Metadata Error: {0}")]
    MetadataError(String)
}


#[derive(Debug, Clone, Default)]
pub struct FsDb {
    root: PathBuf,
}


#[derive(Debug, Deserialize, Serialize)]
struct Metadata {
    /// Attributes to return with the authentication token.
    /// - key = value, where value is a string is an ordinary single values attribute.
    /// - key = [value1, value2, ...] where value is a list of values is used for multi-value attributes.
    /// - key = "" (empty string) is a tag, "key".
    attributes: Table,
}

impl FsDb {
    pub fn new(root: &Path) -> Result<Self, FsDbError> {
        if !root.exists() {
            std::fs::create_dir_all(&root)?;
        }
        Ok(FsDb { root: root.to_path_buf() })
    }

    pub fn print(&self, pat: &Option<String>, attrs: bool, tokens: bool) -> Result<(), FsDbError> {
        let entries = std::fs::read_dir(&self.root)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let cn = path.file_name().unwrap().to_str().unwrap();
                if cn.len() < 3 || !cn.starts_with("cn.") {
                    continue; // Skip non-actor directories
                }
                if pat.is_none() || cn.contains(pat.as_ref().unwrap()) {
                    println!("{}", &cn[3..]); // Skip the "cn." prefix
                    if attrs {
                        let attributes = self.get_attributes(&cn[3..])?;
                        for tuple in &attributes {
                            if tuple.1.is_empty() {
                                println!("   #{}", tuple.0);
                            } else {
                                println!("   {}:{}", tuple.0, tuple.1);
                            }
                        }
                    }
                    if tokens {
                        let tokens = self.list_tokens(&cn[3..])?;
                        for tuple in &tokens {
                            println!("   token.{}:", tuple.0);
                            match claims_for(&tuple.1) {
                                Ok(claims) => {
                                    for (k, v) in claims.iter() {
                                        println!("      {}: {}", k, v);
                                    }
                                }
                                Err(e) => {
                                    println!("      Error parsing token: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn actor_exists(&self, cn: &str) -> bool {
        let cn = clean_cn(cn);
        let actor_path = self.root.join(format!("cn.{cn}"));
        actor_path.exists()
    }

    pub fn create_actor(&self, cn: &str) -> Result<String, FsDbError> {
        let cn = clean_cn(cn);
        let actor_path = self.root.join(format!("cn.{cn}"));
        if actor_path.exists() {
            return Err(FsDbError::IoError(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("actor {} already exists", cn),
            )));
        }
        std::fs::create_dir_all(&actor_path)?;
        self.create_keypair(&actor_path)?;
        Ok(cn)
    }

    pub fn delete_actor(&self, cn: &str) -> Result<String, FsDbError> {
        let cn = clean_cn(cn);
        let actor_path = self.root.join(format!("cn.{cn}"));
        if !actor_path.exists() {
            return Err(FsDbError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("actor {} not found", cn),
            )));
        }
        std::fs::remove_dir_all(&actor_path)?;
        Ok(cn)
    }

    /// Returns the public key in PEM format.
    pub fn get_pub_key(&self, cn: &str) -> Result<String, FsDbError> {
        let cn = clean_cn(cn);
        let actor_path = self.root.join(format!("cn.{cn}"));
        let public_key_path = actor_path.join("public.pem");
        if !public_key_path.exists() {
            return Err(FsDbError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("public key for {} not found", cn),
            )));
        }
        let public_key_data = std::fs::read(public_key_path)?;
        let public_key = String::from_utf8(public_key_data)?;
        Ok(public_key)
    }

    /// Add a token to the actors directory. Note this is MUT to avoid adding these
    /// in multiple threads at the same time (since we count the number of tokens
    /// already in the directory to come up with the file name).
    pub fn add_token(&mut self , cn: &str, token: &str) -> Result<(), FsDbError> {
        let cn = clean_cn(cn);
        let actor_path = self.root.join(format!("cn.{cn}"));
        if !actor_path.exists() {
            return Err(FsDbError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("actor {} not found", cn),
            )));
        }

        // Count the files that start with "token."
        let token_count = std::fs::read_dir(&actor_path)?
            .into_iter()
            .filter(|entry| {
                let de = entry.as_ref().unwrap();
                let path = de.path();
                path.is_file() && path.file_name().unwrap().to_str().unwrap().starts_with("token.")
            })
            .count();

        let token_path = actor_path.join(format!("token.{token_count}"));
        std::fs::write(token_path, token)?;
        Ok(())
    }


    /// The result list is of (token_id, encoded_toke) pairs.
    pub fn list_tokens(&self, cn: &str) -> Result<Vec<(String, String)>, FsDbError> {
        let cn = clean_cn(cn);
        let actor_path = self.root.join(format!("cn.{cn}"));
        if !actor_path.exists() {
            return Err(FsDbError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("actor {} not found", cn),
            )));
        }
        let mut tokens = Vec::new();
        for entry in std::fs::read_dir(&actor_path)? {
            let entry = entry?;
            let path = &entry.path();
            if path.is_file() {
                let fname = path.file_name().unwrap().to_str().unwrap();
                if fname.starts_with("token.") {
                    // Read the token data
                    let token_data = std::fs::read(path)?;
                    let token = String::from_utf8(token_data)?;
                    let token_id = fname[6..].to_string();
                    tokens.push((token_id, token));
                }
            }
        }
        Ok(tokens)
    }

    /// Add attributes to a record.
    /// - A single value attribute is of the form "key:value".
    /// - A multi-value attribute is of the form "key:value1,value2,..." You can set a multi-values attribute to just a
    ///   single value by adding a trailing comma.  Eg, "key:value1,".
    /// - A tag is of the form "key" (no colon, no value).
    pub fn add_attributes(&self, cn: &str, attrs: &[String]) -> Result<String, FsDbError> {
        let cn = clean_cn(cn);
        let actor_path = self.root.join(format!("cn.{cn}"));
        if !actor_path.exists() {
            return Err(FsDbError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("actor {} not found", cn),
            )));
        }
        let md_path = actor_path.join("metadata.toml");

        let mut metadata = if md_path.exists() {
            let toml_data = std::fs::read_to_string(&md_path)?;
            toml::from_str(&toml_data)?
        } else {
            Metadata { attributes: Table::new() }
        };

        for attr in attrs {
            let attr = attr.trim();
            let parts: Vec<&str> = attr.split(':').collect();
            let key = parts[0].to_string();
            let value = if parts.len() > 1 {
                parts[1].split(',').map(|s| s.to_string()).collect::<Vec<_>>()
            } else {
                vec![]
            };
            if value.is_empty() {
                // Tag
                metadata.attributes.insert(key.clone(), toml::Value::String(String::new()));
            } else if value.len() > 1 {
                // Multivalue -- skip empty values
                metadata.attributes.insert(key.clone(),
                    toml::Value::Array(value.into_iter()
                        .filter(|s| !s.is_empty())
                        .map(toml::Value::String).collect()));
            } else {
                // Single value
                metadata.attributes.insert(key.clone(), toml::Value::String(value[0].clone()));
            }
        }

        // Now write the metadata back to the file.
        let toml_data = toml::to_string(&metadata)?;
        std::fs::write(&md_path, toml_data)?;
        Ok(cn)
    }


    // Note that this does loose the type information about multi-value attributes.
    // The attribute types are always (KEY, VALUE) and if there are multiple values
    // the VALUE is a comma separated list of values.  Tags have blank value.
    //
    // TODO: Could use a real ZprAttribute type.
    pub fn get_attributes(&self, cn: &str) -> Result<Vec<(String, String)>, FsDbError> {
        let cn = clean_cn(cn);
        let actor_path = self.root.join(format!("cn.{cn}"));
        if !actor_path.exists() {
            return Err(FsDbError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("actor {} not found", cn),
            )));
        }
        let md_path = actor_path.join("metadata.toml");
        let mut attrs = Vec::new();
        if !md_path.exists() {
            // No attributes
            return Ok(attrs);
        }
        let toml_data = std::fs::read_to_string(&md_path)?;
        let metadata: Metadata = toml::from_str(&toml_data)?;
        for (key, value) in metadata.attributes.iter() {
            match value {
                toml::Value::String(s) => {
                    attrs.push((key.clone(), s.clone()));
                }
                toml::Value::Array(arr) => {
                    let values: Vec<String> = arr.iter()
                        .filter_map(|v| if let toml::Value::String(s) = v { Some(s.clone()) } else { None })
                        .collect();
                    attrs.push((key.clone(), values.join(",")));
                }
                _ => return Err(FsDbError::MetadataError(format!("malformed attribute: {}: {:?}", key, value)))
            }
        }
        Ok(attrs)
    }



    fn create_keypair(&self, dir: &Path) -> Result<(), FsDbError> {
        println!("creating new SSL keypair...");
        let rsa = Rsa::generate(KEY_SIZE)?;
        let private_key_data = rsa.private_key_to_pem()?;
        let public_key_data = rsa.public_key_to_pem()?;
        std::fs::write(dir.join("private.pem"), private_key_data)?;
        std::fs::write(dir.join("public.pem"), public_key_data)?;
        Ok(())
    }
}


/// Since we use CN as part of a file name, we restrict it pretty substantially here
/// to only certain characters.
fn clean_cn(cn: &str) -> String {
    let mut cn = cn.to_string();
    cn.retain(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    cn = cn.replace("..", "_");
    cn
}


