//! Collection of PKI related utility functions.
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use ed25519_dalek::{Signature as EdSignature, SigningKey as EdSigningKey};
use rand::{TryRngCore, rngs::OsRng};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use tracing::error;
use x509_cert::{
    Certificate,
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    certificate::TbsCertificate,
    der::{
        Decode, Encode, EncodePem,
        asn1::{BitString, OctetStringRef},
        oid::ObjectIdentifier,
        pem::{self, LineEnding},
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

use libnode::pki::first_pem_block;
use pkcs8::PrivateKeyInfoRef;

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

/// Construct from DER bytes
pub fn from_der(der: &[u8]) -> Result<Certificate, ParseError> {
    Certificate::from_der(der).map_err(|e| {
        error!(target: KEY_MGMT, "error parsing DER certificate: {e}");
        ParseError::DecodeError
    })
}

/// Construct from PEM bytes
pub fn from_pem(pem_data: &[u8]) -> Result<Certificate, ParseError> {
    let text = std::str::from_utf8(pem_data).map_err(|e| {
        error!(target: KEY_MGMT, "certificate PEM data is not valid UTF-8: {e}");
        ParseError::PEMFormatError
    })?;
    let block = first_pem_block(text).ok_or_else(|| {
        error!(target: KEY_MGMT, "no PEM block found in certificate data");
        ParseError::PEMCertNotFound
    })?;
    let (_, der) = pem::decode_vec(block.as_bytes()).map_err(|e| {
        error!(target: KEY_MGMT, "error parsing PEM certificate: {e}");
        ParseError::PEMFormatError
    })?;
    from_der(&der)
}

/// The DER encoding of the certificate.
pub fn to_der(cert: &Certificate) -> Result<Vec<u8>, ParseError> {
    cert.to_der().map_err(|e| {
        error!(target: KEY_MGMT, "error encoding certificate: {e}");
        ParseError::DecodeError
    })
}

/// The PEM encoding of the certificate. (Used in tests)
#[allow(dead_code)]
pub fn to_pem(cert: &Certificate) -> Result<String, ParseError> {
    EncodePem::to_pem(cert, LineEnding::LF).map_err(|e| {
        error!(target: KEY_MGMT, "error encoding certificate as PEM: {e}");
        ParseError::DecodeError
    })
}

/// The certificate subject's Common Name
pub fn common_name(cert: &Certificate) -> Option<String> {
    cert.tbs_certificate()
        .subject()
        .common_name()
        .ok()?
        .map(|cn| cn.value().to_string())
}

/// The certificate subject's full distinguished name
pub fn subject_name(cert: &Certificate) -> &Name {
    cert.tbs_certificate().subject()
}

/// The DER encoding of the subject distinguished name
pub fn subject_der(cert: &Certificate) -> Vec<u8> {
    match cert.tbs_certificate().subject().to_der() {
        Ok(der) => der,
        Err(e) => {
            error!(target: KEY_MGMT, "error encoding subject DN: {e}");
            Vec::new()
        }
    }
}

/// Extract the certificate's public key.
pub fn public_key(cert: &Certificate) -> &SubjectPublicKeyInfoOwned {
    cert.tbs_certificate().subject_public_key_info()
}

/// Verify a certificate's signature against the presumed issuer's
/// public key
pub fn verify(cert: &Certificate, key: &SubjectPublicKeyInfoOwned) -> Result<bool, ParseError> {
    let tbs = cert.tbs_certificate().to_der().map_err(|e| {
        error!(target: KEY_MGMT, "error re-encoding TBS certificate: {e}");
        ParseError::DecodeError
    })?;
    let sig = cert.signature().raw_bytes();
    let alg = &cert.signature_algorithm().oid;
    let raw_key = key.subject_public_key.raw_bytes();

    if *alg == OID_SHA256_WITH_RSA {
        let vk = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, raw_key);
        Ok(vk.verify(&tbs, sig).is_ok())
    } else if *alg == OID_ED25519 {
        let vk = UnparsedPublicKey::new(&signature::ED25519, raw_key);
        Ok(vk.verify(&tbs, sig).is_ok())
    } else {
        error!(target: KEY_MGMT, "unsupported certificate signature algorithm: {alg}");
        Err(ParseError::KeyError)
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
pub fn load_cert(path: &Path) -> Result<Certificate, ParseError> {
    let contents = fs::read_to_string(path)?;
    let cert_pem_data = extract_cert_pem_data(&contents)?;
    from_pem(cert_pem_data.as_bytes())
}

/// Load a private X22519 key from a PEM file
pub fn load_noise_private_key(path: &Path) -> Result<[u8; NOISE_KEY_LEN], ParseError> {
    let contents = fs::read_to_string(path)?;
    let block = first_pem_block(&contents).ok_or_else(|| {
        error!(target: KEY_MGMT, "no PEM block found in key file");
        ParseError::PEMFormatError
    })?;
    let (_, der) = pem::decode_vec(block.as_bytes()).map_err(|e| {
        error!(target: KEY_MGMT, "error reading key from PEM data: {e}");
        ParseError::PEMFormatError
    })?;
    let pki = PrivateKeyInfoRef::try_from(der.as_slice()).map_err(|e| {
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
    let block = first_pem_block(&contents).ok_or_else(|| {
        error!(target: KEY_MGMT, "no PEM block found in key file");
        ParseError::PEMFormatError
    })?;
    let (_, der) = pem::decode_vec(block.as_bytes()).map_err(|e| {
        error!(target: KEY_MGMT, "error reading key from PEM data: {e}");
        ParseError::PEMFormatError
    })?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&der).map_err(|e| {
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
pub fn get_cn_from_cert(cert: &Certificate) -> Option<String> {
    common_name(cert)
}

const ID_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

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
) -> Result<Certificate, Box<dyn std::error::Error>> {
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

    Ok(cert)
}

#[cfg(test)]
mod test {

    use super::*;

    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
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

    #[test]
    fn test_extract_cert_pem_data() {
        let cert = from_pem(TEST_CERT_PEM.as_bytes()).unwrap();
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

    const TEST_X25519_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEINjp9Br1Ykn9R6D2sCUkOUMJKSEZXMX5JPR65vb6+yl6\n-----END PRIVATE KEY-----\n";
    const TEST_X25519_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEAFlTnsuk9He+ISGuIRgE37erOxcR3HhV3fFJt4NSyUH4=\n-----END PUBLIC KEY-----\n";

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn test_load_noise_keys_roundtrip() {
        use crate::km_noise::derive_public_key;

        let priv_path = write_temp("zpr_test_noise_priv.pem", TEST_X25519_PRIV_PEM);
        let pub_path = write_temp("zpr_test_noise_pub.pem", TEST_X25519_PUB_PEM);

        let priv_key = load_noise_private_key(&priv_path).unwrap();
        let pub_key = load_noise_public_key(&pub_path).unwrap();

        std::fs::remove_file(&priv_path).ok();
        std::fs::remove_file(&pub_path).ok();

        assert_eq!(priv_key.len(), NOISE_KEY_LEN);
        assert_eq!(pub_key.len(), NOISE_KEY_LEN);
        assert_eq!(derive_public_key(&priv_key), pub_key);
    }

    #[test]
    fn test_verify_ed25519_signature() {
        const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).unwrap();
        let signer = EdSigningKey::from_bytes(&seed);
        let verifying = signer.verifying_key();

        let name = Name::from_str("CN=ed25519.test").unwrap();
        let mut serial_bytes = [0u8; 16];
        OsRng.try_fill_bytes(&mut serial_bytes).unwrap();
        serial_bytes[0] &= 0x7f;
        let serial = SerialNumber::new(&serial_bytes).unwrap();
        let validity = Validity::from_now(Duration::from_hours(24)).unwrap();
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ID_ED25519,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(verifying.as_bytes()).unwrap(),
        };
        let builder =
            CertificateBuilder::new(NoiseCertProfile { name }, serial, validity, spki).unwrap();
        let cert = builder.build::<_, EdSignature>(&signer).unwrap();

        // The correct Ed25519 key verifies the signature.
        assert!(verify(&cert, public_key(&cert)).unwrap());
        // A tampered key does not.
        let mut tampered = public_key(&cert).clone();
        let mut raw_tampered = tampered.subject_public_key.raw_bytes().to_vec();
        raw_tampered[0] ^= 0xff;
        tampered.subject_public_key = BitString::from_bytes(&raw_tampered).unwrap();
        assert!(!verify(&cert, &tampered).unwrap());
    }
}
