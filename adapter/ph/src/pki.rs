//! Collection of PKI related utility functions.

use std::fs;
use std::path::Path;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Name, extension::KeyUsage};

use thiserror::Error;
use tracing::error;

use crate::km_noise::NoiseKeypair;
use crate::logging::targets::KEY_MGMT; // TODO: eliminate logging from this module

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

/// Get the CN value as a string out of the certificate. If not found or any
/// other issue, returns None.
pub fn get_cn_from_cert(cert: &X509) -> Option<String> {
    let entry_ref_opt = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next();
    if let Some(entry_ref) = entry_ref_opt {
        let sslstr_res = entry_ref.data().as_utf8();
        if let Ok(sslstr) = sslstr_res {
            return Some(sslstr.to_string());
        }
    }
    None
}

pub fn generate_self_signed_noise_cert(
    cn: &str,
    keypair: &NoiseKeypair,
) -> Result<X509, Box<dyn std::error::Error>> {
    if cn.is_empty() {
        return Err("CN (common name) must be non-empty".into());
    }
    // Generate a new RSA private key
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    // Create an X509 certificate builder
    let mut builder = X509::builder()?;

    // Set the version of the certificate (V3)
    builder.set_version(2)?;

    // Set the serial number
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, true)?;
    let serial_asn1 = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial_asn1)?;

    // Set the issuer name (for a self-signed cert, this is also the subject)
    let mut name = X509Name::builder()?;
    name.append_entry_by_text("CN", cn)?; // Common Name (e.g., domain name or IP)
    let name = name.build();
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?; // Self-signed

    // Set the validity period
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?; // Valid for 1 year
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    let x_key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()?;
    builder.append_extension(x_key_usage)?;

    // Set the public key
    let ssl_pubkey = PKey::public_key_from_raw_bytes(&keypair.public, Id::X25519)?;
    builder.set_pubkey(&ssl_pubkey)?;

    // Sign the certificate with the private key
    builder.sign(&pkey, MessageDigest::sha256())?;

    // Build the certificate
    let cert = builder.build();

    Ok(cert)
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_extract_cert_pem_data() {
        let cert_pem_data = r#"-----BEGIN CERTIFICATE-----
MIIDWzCCAUOgAwIBAgIURkj38EC8A6U5BF8Ue/ZWxz/+SLcwDQYJKoZIhvcNAQEL
BQAwYjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1BMQ8wDQYDVQQHDAZCb3N0b24x
CzAJBgNVBAoMAkFJMQwwCgYDVQQLDANaUFIxGjAYBgNVBAMMEWF1dGhvcml0eS56
cHIub3JnMB4XDTI1MDQyMjE5NDI1MFoXDTI2MDQyMjE5NDI1MFowFjEUMBIGA1UE
AwwLYmFzLnpwci5vcmcwKjAFBgMrZW4DIQBNXMASeEGW3ctMJtw7R90cdlLCf0Gk
hO9Wp+gJcQvCAqNPME0wCwYDVR0PBAQDAgMIMB0GA1UdDgQWBBTGlOk8ool6B5Hc
yWQ2ccZZO9fHijAfBgNVHSMEGDAWgBTXkyt7dSNy0AvuM57CcuqTVg0EQjANBgkq
hkiG9w0BAQsFAAOCAgEAFf2OnYsNdvjIty6csAUXLmY7pXMyucWTn5x6l0IVU+BO
2DFVUorEFE9Wfa6e/SuVnBnNe1jHcFN4RuA/Y/UVR1RHOePY1IT7ktRfje1BBFlI
D6H1LhxtdkKUhdOP1xqyNIpi6x7sH8MKnbJSa8rig8usO15rDSHqkyR8RgViGTcT
q+MMVLJXTy7qlAvIA21CQ9/P7c/VIw1BGSYsdaDSOhm4accX7ehnV9YOCiDYyTjY
x8Eps7wj7u7vGPDZCc2N+SroYa1TpJ9Gffmx1lh3t6/HCDMuSymHbJhbN8X39jcD
2KKeyVJpTl/EfQTOzA4ztOF1HiXzSyL/+F8BtnKPKsXK35b2s5O0NYDxtDHwHVHG
t3npCLN1jWCzTA4ggkLB0hcpG5BvBEsSH7hjlidBCmeNlwY4vQmaDDVJQgCI3ivx
DbQFb9lVBYEg73MARYcCfkL3oHaZKecNUi2iWl32aQH3IBqp3UciR0Lrt1zFVyAw
aL0HpHww+ZyAYtgo5+0wskLyO9U+hKPXhpQifjm51YI5ISLcdlXch1pR6pE/EQxJ
BriqxhRYR33Xnlb86e5JeKlXNCZFk4vybD5mozh03mu6AvO3XLd8hrmOT1gQfZTq
n5ystfC9RDOzkrR8ICLvoWBQ52ctmNH3oWs1p1DT3uL6k3QMnNlejIkUqAY51aI=
-----END CERTIFICATE-----
"#;

        let cert = X509::from_pem(cert_pem_data.as_bytes()).unwrap();
        let cns = get_cn_from_cert(&cert);
        assert!(cns.is_some());
        let cns = cns.unwrap();
        assert_eq!(cns, "bas.zpr.org".to_string());
    }

    #[test]
    fn test_that_self_signed_cert_encodes_cn() {
        let keypair = NoiseKeypair::generate();
        let self_signed_cert = generate_self_signed_noise_cert("foo.zpr", &keypair).unwrap();
        let cn = get_cn_from_cert(&self_signed_cert).unwrap();
        assert_eq!(cn, "foo.zpr".to_string());
    }
}
