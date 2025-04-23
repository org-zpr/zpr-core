//! Collection of PKI related utility functions.

use std::path::Path;
use std::fs;

use openssl::pkey::PKey;
use openssl::x509::X509;
use thiserror::Error;
use tracing::error;

use crate::logging::targets::KEY_MGMT;  // TODO: eliminate logging from this module



const PEM_BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END_CERTIFICATE: &str = "-----END CERTIFICATE-----";

/// The size in bytes of a noise key.
pub const NOISE_KEY_LEN: usize = 32;



#[derive(Debug, Error)]
pub enum ParseError {
    #[error("PEM certificate not found in text data")]
    PEMCertNotFound,

    #[error("PEM format error")]
    PEMFormatError,

    #[error("Key Error")]
    KeyError,

    #[error("I/O error {0}")]
    IOError(#[from] std::io::Error),
}




/// Look for first instance of "-----BEGIN CERTIFICATE-----" and return that up to and
/// including the "-----END CERTIFICATE-----" line.
///
/// - `textdata` is the textual representation of a certificate that must include the PEM
///    encoded certificate in it somewhere.  Typically, a certificate file has the PEM data
///    at the end.
///
/// Returns a copy of the PEM data from the intput without trying to parse it.
fn extract_cert_pem_data(textdata: &str) -> Result<String, ParseError> {
    let mut pemdata = String::new();
    let mut reading = false;
    for line in textdata.lines() {
        if reading {
            pemdata.push_str(line);
            pemdata.push_str("\n");
            if line.starts_with(PEM_END_CERTIFICATE) {
                return Ok(pemdata);
            }
        } else if line.starts_with(PEM_BEGIN_CERTIFICATE) {
            reading = true;
            pemdata.push_str(line);
            pemdata.push_str("\n");
        }
    }
    if !reading {
        Err(ParseError::PEMCertNotFound)
    } else {
        Err(ParseError::PEMFormatError)
    }
}


/// Load a certificate from a file.
pub fn load_cert(path: &Path) -> Result<X509, ParseError> {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return Err(ParseError::IOError(e)),
    };
    let cert_pem_data = extract_cert_pem_data(&contents)?;
    match X509::from_pem(cert_pem_data.as_bytes()) {
        Ok(cert) => Ok(cert),
        Err(e) => {
            error!(target: KEY_MGMT, "error constructing cert from PEM data: {e}");
            Err(ParseError::PEMFormatError)
        }
    }
}


/// Load a private X22519 key from a PEM file
pub fn load_noise_private_key(path: &Path) -> Result<[u8; NOISE_KEY_LEN], ParseError> {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return Err(ParseError::IOError(e)),
    };

    let pk = match PKey::private_key_from_pem(&contents.as_bytes()) {
        Ok(k) => k,
        Err(e) => {
            error!(target: KEY_MGMT, "error reading key from PEM data: {e}");
            return Err(ParseError::PEMFormatError);
        }
    };

    match pk.raw_private_key() {
        Ok(k) => {
            let mut key = [0u8; NOISE_KEY_LEN];
            key.copy_from_slice(&k);
            Ok(key)
        }
        Err(e) => {
            error!(target: KEY_MGMT, "error extracting raw key: {e}");
            Err(ParseError::KeyError)
        }
    }
}


/// Load a public X22519 key from a PEM file
pub fn load_noise_public_key(path: &Path) -> Result<[u8; NOISE_KEY_LEN], ParseError> {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return Err(ParseError::IOError(e)),
    };

    let pk = match PKey::public_key_from_pem(&contents.as_bytes()) {
        Ok(k) => k,
        Err(e) => {
            error!(target: KEY_MGMT, "error reading key from PEM data: {e}");
            return Err(ParseError::PEMFormatError);
        }
    };

    match pk.raw_public_key() {
        Ok(k) => {
            if k.len() != NOISE_KEY_LEN {
                error!(
                    target: KEY_MGMT,
                    "public key in cert is incorrect length (got {} bytes, expected {NOISE_KEY_LEN})",
                    k.len(),
                );
                return Err(ParseError::KeyError);
            }
            let key = <[u8; NOISE_KEY_LEN]>::try_from(k).unwrap();
            Ok(key)
        }
        Err(e) => {
            error!(target: KEY_MGMT, "error extracting raw key: {e}");
            Err(ParseError::KeyError)
        }
    }
}
