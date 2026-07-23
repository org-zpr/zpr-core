//! Collection of PKI related utility functions.
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use ed25519_dalek::{Signature as EdSignature, SigningKey as EdSigningKey};
use rand::{TryRngCore, rngs::OsRng};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use tracing::error;
use x509_cert::{
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    certificate::TbsCertificate,
    der::{
        Decode, Encode,
        asn1::{BitString, OctetStringRef},
        oid::ObjectIdentifier,
    },
    ext::{
        Extension,
        pkix::{KeyUsage, KeyUsages},
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef},
    time::Validity,
};

use pkcs8::PrivateKeyInfoRef;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{OID_PKCS1_SHA256WITHRSA, OID_SIG_ED25519};
use x509_parser::prelude::FromDer;

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

    #[error("Certificate decode error")]
    DecodeError,

    #[error("Key Error")]
    KeyError,

    #[error("I/O error {0}")]
    IOError(#[from] std::io::Error),
}

///Public key extracted from a certificate.
pub struct PubKey {
    key: Vec<u8>,
}

impl PubKey {
    pub fn raw_public_key(&self) -> Result<Vec<u8>, ParseError> {
        Ok(self.key.clone())
    }
}

// An X.509 certificate, stored as its DER encoding.
#[derive(Clone, PartialEq, Eq)]
pub struct Cert {
    der: Vec<u8>,
}

impl std::fmt::Debug for Cert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cert")
            .field("cn", &self.common_name())
            .finish()
    }
}

impl Cert {
    /// Construct from DER bytes
    pub fn from_der(der: &[u8]) -> Result<Cert, ParseError> {
        X509Certificate::from_der(der).map_err(|e| {
            error!(target: KEY_MGMT, "error parsing DER certificate: {e}");
            ParseError::DecodeError
        })?;
        Ok(Cert { der: der.to_vec() })
    }

    /// Construct from PEM bytes
    pub fn from_pem(pem: &[u8]) -> Result<Cert, ParseError> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem).map_err(|e| {
            error!(target: KEY_MGMT, "error parsing PEM certificate: {e}");
            ParseError::PEMFormatError
        })?;
        Cert::from_der(&pem.contents)
    }

    /// The DER encoding of the certificate.
    pub fn to_der(&self) -> Result<Vec<u8>, ParseError> {
        Ok(self.der.clone())
    }

    /// The PEM encoding of the certificate. (Used in tests)
    #[allow(dead_code)]
    pub fn to_pem(&self) -> Result<Vec<u8>, ParseError> {
        let b64 = BASE64_STANDARD.encode(&self.der);
        let mut out = String::with_capacity(b64.len() + 64);
        out.push_str(PEM_BEGIN_CERTIFICATE);
        out.push('\n');
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str(PEM_END_CERTIFICATE);
        out.push('\n');
        Ok(out.into_bytes())
    }

    /// The certificate subject's Common Name
    pub fn common_name(&self) -> Option<String> {
        let (_, cert) = X509Certificate::from_der(&self.der).ok()?;
        cert.subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .map(|s| s.to_string())
    }

    /// The DER encoding of the subject distinguished name
    pub fn subject_der(&self) -> Vec<u8> {
        match X509Certificate::from_der(&self.der) {
            Ok((_, cert)) => cert.subject().as_raw().to_vec(),
            Err(e) => {
                error!(target: KEY_MGMT, "error extracting subject DN: {e}");
                Vec::new()
            }
        }
    }

    /// Extract the certificate's public key.
    pub fn public_key(&self) -> Result<PubKey, ParseError> {
        let (_, cert) = X509Certificate::from_der(&self.der).map_err(|e| {
            error!(target: KEY_MGMT, "error parsing certificate: {e}");
            ParseError::DecodeError
        })?;
        let key = cert.public_key().subject_public_key.data.to_vec();
        Ok(PubKey { key })
    }

    /// Verify this certificate's signature against the presumed issuer's
    /// public key
    pub fn verify(&self, key: &PubKey) -> Result<bool, ParseError> {
        let (_, cert) = X509Certificate::from_der(&self.der).map_err(|e| {
            error!(target: KEY_MGMT, "error parsing certificate for verify: {e}");
            ParseError::DecodeError
        })?;

        let tbs = cert.tbs_certificate.as_ref();
        let sig = cert.signature_value.data.as_ref();
        let alg = &cert.signature_algorithm.algorithm;

        if *alg == OID_PKCS1_SHA256WITHRSA {
            let vk =
                UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, key.key.as_slice());
            Ok(vk.verify(tbs, sig).is_ok())
        } else if *alg == OID_SIG_ED25519 {
            let vk = UnparsedPublicKey::new(&signature::ED25519, key.key.as_slice());
            Ok(vk.verify(tbs, sig).is_ok())
        } else {
            error!(target: KEY_MGMT, "unsupported certificate signature algorithm: {alg}");
            Err(ParseError::KeyError)
        }
    }
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
pub fn load_cert(path: &Path) -> Result<Cert, ParseError> {
    let contents = fs::read_to_string(path)?;
    let cert_pem_data = extract_cert_pem_data(&contents)?;
    Cert::from_pem(cert_pem_data.as_bytes())
}

/// Load a private X22519 key from a PEM file
pub fn load_noise_private_key(path: &Path) -> Result<[u8; NOISE_KEY_LEN], ParseError> {
    let contents = fs::read_to_string(path)?;
    let block = pem::parse(contents.as_bytes()).map_err(|e| {
        error!(target: KEY_MGMT, "error reading key from PEM data: {e}");
        ParseError::PEMFormatError
    })?;
    let pki = PrivateKeyInfoRef::try_from(block.contents()).map_err(|e| {
        error!(target: KEY_MGMT, "error parsing PKCS#8 private key: {e}");
        ParseError::KeyError
    })?;
    let inner = <&OctetStringRef>::from_der(pki.private_key.as_bytes()).map_err(|e| {
        error!(target: KEY_MGMT, "error decoding CurvePrivateKey: {e}");
        ParseError::KeyError
    })?;
    let raw = inner.as_bytes();
    if raw.len() != NOISE_KEY_LEN {
        error!(
            target: KEY_MGMT,
            "private key has wrong length (got {}, expected {NOISE_KEY_LEN})",
            raw.len(),
        );
        return Err(ParseError::KeyError);
    }
    Ok(<[u8; NOISE_KEY_LEN]>::try_from(raw).unwrap())
}

/// Load a public X22519 key from a PEM file
pub fn load_noise_public_key(path: &Path) -> Result<[u8; NOISE_KEY_LEN], ParseError> {
    let contents = fs::read_to_string(path)?;
    let block = pem::parse(contents.as_bytes()).map_err(|e| {
        error!(target: KEY_MGMT, "error reading key from PEM data: {e}");
        ParseError::PEMFormatError
    })?;
    let spki = SubjectPublicKeyInfoOwned::from_der(block.contents()).map_err(|e| {
        error!(target: KEY_MGMT, "error parsing SubjectPublicKeyInfo: {e}");
        ParseError::KeyError
    })?;
    let raw = spki.subject_public_key.raw_bytes();
    if raw.len() != NOISE_KEY_LEN {
        error!(
            target: KEY_MGMT,
            "public key in cert is incorrect length (got {} bytes, expected {NOISE_KEY_LEN})",
            raw.len(),
        );
        return Err(ParseError::KeyError);
    }
    Ok(<[u8; NOISE_KEY_LEN]>::try_from(raw).unwrap())
}

/// Get the CN value as a string out of the certificate. If not found or any
/// other issue, returns None.
pub fn get_cn_from_cert(cert: &Cert) -> Option<String> {
    cert.common_name()
}

const ID_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

struct NoiseCertProfile {
    name: Name,
}

impl BuilderProfile for NoiseCertProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.name.clone()
    }
    fn get_subject(&self) -> Name {
        self.name.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}

pub fn generate_self_signed_noise_cert(
    cn: &str,
    keypair: &NoiseKeypair,
) -> Result<Cert, Box<dyn std::error::Error>> {
    if cn.is_empty() {
        return Err("CN (common name) must be non-empty".into());
    }

    let name = Name::from_str(&format!("CN={cn}"))?;

    let mut serial_bytes = [0u8; 16];
    OsRng.try_fill_bytes(&mut serial_bytes)?;
    serial_bytes[0] &= 0x7f;
    let serial = SerialNumber::new(&serial_bytes)?;

    let validity = Validity::from_now(Duration::from_hours(365 * 24))?;

    let spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ID_X25519,
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(&keypair.public)?,
    };

    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed)?;

    let signer = EdSigningKey::from_bytes(&seed);

    let mut builder = CertificateBuilder::new(NoiseCertProfile { name }, serial, validity, spki)?;

    let key_usage = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment);
    builder.add_extension((false, &key_usage))?;

    let cert = builder.build::<_, EdSignature>(&signer)?;
    let der = cert.to_der()?;

    Ok(Cert { der })
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

        let cert = Cert::from_pem(cert_pem_data.as_bytes()).unwrap();
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
