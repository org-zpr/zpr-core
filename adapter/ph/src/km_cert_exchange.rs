//! Key Management Certificate Exchange
//!
//!
//! This lays out a sequence of two messages and three operations. There
//! are two roles:
//!
//! - _Initiator_ - the party that starts the exchange.
//! - _Responder_ - the party that responds to the initiator.
//!
//! The _initiator_ has access to the signed certificate of the _responder_
//! and so can verify that signatures created by the _responder_ are correct.
//!
//! The _responder_ has no information about the _initiator_ except that
//! it will expect the _initiators_ certificate to be signed by a
//! certificate authority known to the _responder_.  The certificate for
//! the certificate authority is accessible to the _responder_ in some
//! out of band fashion.
//!
//!  1. Initiator creates a message.  This includes the initiator's
//!     signed certificate.  The message is signed with the initiator's
//!     private RSA key.
//!
//!  2. Responder processes the initial message, checking that the
//!     certificate furnished is signed by the proper authority and
//!     that the message signature is valid.  If all goes well the
//!     responder creates a response for the initiator which includes
//!     the _fingerprint_ of the responders signed certificate. The
//!     response is signed with the responders private key.
//!
//!  3. Initiator processes the response message, checking that the
//!     signature is valid and that the key fingerprint matches the
//!     known fingerprint of the responders certificate.
//!
//!
//! In a node-adapter scenario, the initiator is an adapter and the responder
//! is a node.
//!
//! In a node-node scenario either side could be an initiator and/or a
//! responder.
//!

use bytes::{BufMut, Bytes, BytesMut};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;
use std::fs;
use std::io::prelude::*;
use std::path::Path;
use tracing::error;
use zerocopy::byteorder::network_endian::*;
use zerocopy::{AsBytes, FromBytes, FromZeroes, Unaligned};

const CERT_FINGERPRINT_LEN: usize = 20; // sha-1
const RSA_SIGNATURE_LEN: usize = 256; // assumes/requires 2048bit keys

const MSG_BUF_SIZE: usize = 4096;

const PEM_BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END_CERTIFICATE: &str = "-----END CERTIFICATE-----";

#[derive(Debug)]
pub enum CertExchangeError {
    CertificateError,
    InvalidPayloadError,
    ShortPayloadError,
    CertificateVerificationError,
    SignatureVerificationError,
    CertificateFingerprintError,
    NonceMismatchError,
    DecompressionError,
    RoleError,
}

#[derive(Debug)]
pub enum ParseError {
    PEMCertNotFound,
    PEMFormatError,
    IOError(std::io::Error),
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
struct CertHelloHdr {
    pub nonce: U64,
    pub cert_len: U16,
    // Followed by the cert bytes (DER, then compressed)
    // Followed by the SHA256 RSA signature (256 bytes)
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
struct CertResponseHdr {
    pub nonce: U64,
    pub cert_fingerprint: [u8; 20], // SHA-1 certificate fingerprint
                                    // Followed by the SHA256 RSA signature (256 bytes)
}

#[derive(Debug, PartialEq)]
enum Role {
    Initiator,
    Responder,
}

/// The Certificate Exchange object holds state for the exchange process. This is not
/// thread safe.
pub struct KmCertExchange {
    role: Role,
    local_cert: X509,
    local_fingerprint: [u8; CERT_FINGERPRINT_LEN],
    local_private_key: Rsa<Private>,
    remote_cert: Option<X509>, // only needed for initiator
    last_sent_nonce: u64,
    authority_cert: Option<X509>, // only needed for responder
}

impl KmCertExchange {
    /// Create Exchange object for initiator.
    ///
    /// - `cert` - the certificate of the initiator.
    /// - `private_key` - the private key of the initiator.
    /// - `responder_cert` - the signed certificate of the responder.
    pub fn new_initiator(cert: X509, private_key: Rsa<Private>, responder_cert: X509) -> Self {
        let fp = get_cert_fingerprint(&cert);
        KmCertExchange {
            role: Role::Initiator,
            local_cert: cert,
            local_fingerprint: fp,
            local_private_key: private_key,
            remote_cert: Some(responder_cert),
            last_sent_nonce: 0,
            authority_cert: None,
        }
    }

    /// Create Exchange object for responder.
    ///
    /// - `cert` - the certificate of the responder.
    /// - `private_key` - the private key of the responder.
    /// - `authority_cert` - the certificate of the authority that is expected to have signed an initiator's certificate.
    pub fn new_responder(cert: X509, private_key: Rsa<Private>, authority_cert: X509) -> Self {
        let fp = get_cert_fingerprint(&cert);
        KmCertExchange {
            role: Role::Responder,
            local_cert: cert,
            local_fingerprint: fp,
            local_private_key: private_key,
            remote_cert: None,
            last_sent_nonce: 0,
            authority_cert: Some(authority_cert),
        }
    }

    /// Like [KmCertExchange::new_initiator] but takes the paths to the various PEM files.
    pub fn new_initiator_from_paths(
        cert_file: &Path,
        private_key_file: &Path,
        responder_cert_file: &Path,
    ) -> Result<Self, ParseError> {
        let cert = load_cert(cert_file)?;
        let private_key = load_private_key(private_key_file)?;
        let responder_public_key = load_cert(responder_cert_file)?;
        Ok(KmCertExchange::new_initiator(
            cert,
            private_key,
            responder_public_key,
        ))
    }

    /// Like [KmCertExchange::new_initiator] but takes the PEM data in string form.
    pub fn new_initiator_from_pem(
        cert_pem: &str,
        private_key_pem: &str,
        responder_cert_pem: &str,
    ) -> Result<Self, ParseError> {
        let cert = match X509::from_pem(cert_pem.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                error!("error constructing cert from PEM data: {}", e);
                return Err(ParseError::PEMFormatError);
            }
        };
        let private_key = match Rsa::private_key_from_pem(private_key_pem.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                error!("error constructing private key from PEM data: {}", e);
                return Err(ParseError::PEMFormatError);
            }
        };
        let responder_cert = match X509::from_pem(responder_cert_pem.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                error!("error constructing responder cert from PEM data: {}", e);
                return Err(ParseError::PEMFormatError);
            }
        };
        Ok(KmCertExchange::new_initiator(
            cert,
            private_key,
            responder_cert,
        ))
    }

    /// Like [KmCertExchange::new_responder] but takes the paths to the various PEM files.
    pub fn new_responder_from_paths(
        cert_file: &Path,
        private_key_file: &Path,
        authority_cert_file: &Path,
    ) -> Result<Self, ParseError> {
        let cert = load_cert(cert_file)?;
        let private_key = load_private_key(private_key_file)?;
        let authority_cert = load_cert(authority_cert_file)?;
        Ok(KmCertExchange::new_responder(
            cert,
            private_key,
            authority_cert,
        ))
    }

    /// Like [KmCertExchange::new_responder] but takes the paths to the various PEM files.
    pub fn new_responder_from_pem(
        cert_pem: &str,
        private_key_pem: &str,
        authority_cert_pem: &str,
    ) -> Result<Self, ParseError> {
        let cert = match X509::from_pem(cert_pem.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                error!("error constructing cert from PEM data: {}", e);
                return Err(ParseError::PEMFormatError);
            }
        };
        let private_key = match Rsa::private_key_from_pem(private_key_pem.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                error!("error constructing private key from PEM data: {}", e);
                return Err(ParseError::PEMFormatError);
            }
        };
        let authority_cert = match X509::from_pem(authority_cert_pem.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                error!("error constructing cert from PEM data: {}", e);
                return Err(ParseError::PEMFormatError);
            }
        };

        Ok(KmCertExchange::new_responder(
            cert,
            private_key,
            authority_cert,
        ))
    }

    /// Step 1 - Initiator creates a message for the responder.
    ///
    /// ## Errors
    /// [CertExchangeError::RoleError] - if the role is not `Initiator`.
    pub fn create_initiator_payload(&mut self) -> Result<Bytes, CertExchangeError> {
        if self.role != Role::Initiator {
            return Err(CertExchangeError::RoleError);
        }
        let mut rbuf = [0; 8];
        rand_bytes(&mut rbuf).unwrap();

        let cert_der = self.local_cert.to_der().unwrap();

        let mut comp = ZlibEncoder::new(Vec::new(), Compression::best());
        comp.write_all(&cert_der).unwrap();
        let compressed = comp.finish().unwrap();

        let sz = compressed.len() as u16;

        let msg = CertHelloHdr {
            nonce: U64::from_bytes(rbuf),
            cert_len: sz.into(),
        };
        self.last_sent_nonce = msg.nonce.into(); // keep track for checking later.

        let pkey = PKey::from_rsa(self.local_private_key.clone()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();

        let mut buf = BytesMut::with_capacity(MSG_BUF_SIZE);
        buf.extend_from_slice(msg.as_bytes());
        signer.update(msg.as_bytes()).unwrap();

        buf.extend_from_slice(&compressed);
        signer.update(&compressed).unwrap();

        let sig = signer.sign_to_vec().unwrap();
        assert!(sig.len() == RSA_SIGNATURE_LEN);

        buf.put(&sig[..]);

        Ok(buf.freeze())
    }

    /// Step 2 - The responder accepts the initiator messages, checks it, and returns a message of its own.
    ///
    /// On the responder side, this is the final step. If this does not return error you get
    /// the initiator's certificate and a response payload as return value.
    ///
    /// ## Errors
    /// - [CertExchangeError::RoleError] - if the role is not `Responder`.
    /// - [CertExchangeError::ShortPayloadError] - if the payload is too short.
    /// - [CertExchangeError::InvalidPayloadError] - if the payload is malformed and cannot be parsed.
    /// - [CertExchangeError::DecompressionError] - if the certificate cannot be decompressed.
    /// - [CertExchangeError::CertificateError] - if the certificate cannot be constructed from the DER data or
    ///   if we cannot extract the public key from the certificate.
    /// - [CertExchangeError::SignatureVerificationError] - if the signature on the message is not valid.
    /// - [CertExchangeError::CertificateVerificationError] - if the certificate failes authority verification.
    ///
    pub fn process_initiator_payload(
        &self,
        payload: &[u8],
    ) -> Result<(X509, Bytes), CertExchangeError> {
        if self.role != Role::Responder {
            return Err(CertExchangeError::RoleError);
        }

        // Payload should be at minimum: CertHelloHdr + signature
        if payload.len() < std::mem::size_of::<CertHelloHdr>() + RSA_SIGNATURE_LEN {
            return Err(CertExchangeError::ShortPayloadError);
        }
        let hello = match CertHelloHdr::ref_from_prefix(&payload) {
            Some(k) => k,
            None => {
                return Err(CertExchangeError::InvalidPayloadError);
            }
        };

        // Now we have the cert length, so check again.
        let cert_len: usize = hello.cert_len.into();
        if payload.len() < std::mem::size_of::<CertHelloHdr>() + cert_len + RSA_SIGNATURE_LEN {
            return Err(CertExchangeError::ShortPayloadError);
        }

        // Decompress the certificate
        let cert_offset = std::mem::size_of::<CertHelloHdr>();
        let mut decomp = ZlibDecoder::new(&payload[cert_offset..cert_offset + cert_len]);
        let mut cert_der = Vec::new();
        match decomp.read_to_end(&mut cert_der) {
            Ok(_) => (),
            Err(e) => {
                error!("error decompressing cert: {}", e);
                return Err(CertExchangeError::DecompressionError);
            }
        };

        // Re-create the certificate
        let initiator_cert = match X509::from_der(&cert_der) {
            Ok(c) => c,
            Err(e) => {
                error!("error constructing cert from DER data: {}", e);
                return Err(CertExchangeError::CertificateError);
            }
        };

        // TODO: Now check that the cert is signed by our authority.
        {
            let authority_pkey = self.authority_cert.as_ref().unwrap().public_key().unwrap();
            match initiator_cert.verify(&authority_pkey) {
                Ok(_) => (),
                Err(e) => {
                    error!("error verifying cert: {}", e);
                    return Err(CertExchangeError::CertificateVerificationError);
                }
            }
        }

        // Extract the public key from the cert and check the message signature.
        let initiator_public_key = match initiator_cert.public_key() {
            Ok(p) => p,
            Err(e) => {
                error!("error extracting public key from cert: {}", e);
                return Err(CertExchangeError::CertificateError);
            }
        };
        {
            let signature = &payload[cert_offset + cert_len..]; // presumably there is nothing else on end of payload
            let mut verifier =
                Verifier::new(MessageDigest::sha256(), &initiator_public_key).unwrap();
            verifier.update(&payload[..cert_offset + cert_len]).unwrap();
            if !verifier.verify(signature).unwrap() {
                return Err(CertExchangeError::SignatureVerificationError);
            }
        }

        let mut resp = CertResponseHdr {
            nonce: hello.nonce,
            cert_fingerprint: [0; CERT_FINGERPRINT_LEN],
        };
        resp.cert_fingerprint
            .copy_from_slice(&self.local_fingerprint);

        let mut buf = BytesMut::with_capacity(MSG_BUF_SIZE);
        buf.extend_from_slice(resp.as_bytes());

        let my_pkey = PKey::from_rsa(self.local_private_key.clone()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &my_pkey).unwrap();
        signer.update(&buf[0..buf.len()]).unwrap();
        let sig = signer.sign_to_vec().unwrap();
        assert!(sig.len() == RSA_SIGNATURE_LEN); // sanity check
        buf.put(&sig[..]);

        Ok((initiator_cert, buf.freeze()))
    }

    /// Step 3 - (final step) The initiator processes the responders response.
    ///
    /// This involves the checking the message nonce, and then the signature on the
    /// message to ensure it matches with the known public key of the responder.
    ///
    /// ## Errors
    ///
    /// - [CertExchangeError::RoleError] - if the role is not `Initiator`.
    /// - [CertExchangeError::ShortPayloadError] - if the payload is too short.
    /// - [CertExchangeError::InvalidPayloadError] - if the payload is malformed and cannot be parsed.
    /// - [CertExchangeError::NonceMismatchError] - if the nonce in the response does not match the nonce in the request.
    /// - [CertExchangeError::CertificateFingerprintError] - if the fingerprint in the response does not match the
    ///   known fingerprint of the responder.
    /// - [CertExchangeError::SignatureVerificationError] - if the signature on the message is not valid.
    ///
    pub fn process_responder_payload(&self, payload: &[u8]) -> Result<(), CertExchangeError> {
        if self.role != Role::Initiator {
            return Err(CertExchangeError::RoleError);
        }

        // Payload should be exactly the CertResponseHdr + signature
        if payload.len() != std::mem::size_of::<CertResponseHdr>() + RSA_SIGNATURE_LEN {
            return Err(CertExchangeError::ShortPayloadError);
        }

        let response = match CertResponseHdr::ref_from_prefix(&payload) {
            Some(r) => r,
            None => {
                return Err(CertExchangeError::InvalidPayloadError);
            }
        };

        // First check nonce!
        let nonce_received: u64 = response.nonce.into();
        if nonce_received != self.last_sent_nonce {
            return Err(CertExchangeError::NonceMismatchError);
        }

        // Then check the fingerprint. Should match the remote certificate we in our
        // constructor.
        let computed_fingerprint = get_cert_fingerprint(self.remote_cert.as_ref().unwrap());
        if computed_fingerprint != response.cert_fingerprint {
            return Err(CertExchangeError::CertificateFingerprintError);
        }

        // Finally the signature -- should be signed by remote private key
        let signature = &payload[std::mem::size_of::<CertResponseHdr>()..];
        let remote_pubkey = self.remote_cert.as_ref().unwrap().public_key().unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &remote_pubkey).unwrap();
        verifier
            .update(&payload[..std::mem::size_of::<CertResponseHdr>()])
            .unwrap();
        if !verifier.verify(signature).unwrap() {
            return Err(CertExchangeError::SignatureVerificationError);
        }

        Ok(())
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
fn load_cert(path: &Path) -> Result<X509, ParseError> {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return Err(ParseError::IOError(e)),
    };
    let cert_pem_data = extract_cert_pem_data(&contents)?;
    match X509::from_pem(cert_pem_data.as_bytes()) {
        Ok(cert) => Ok(cert),
        Err(e) => {
            error!("error constructing cert from PEM data: {}", e);
            Err(ParseError::PEMFormatError)
        }
    }
}

/// Load private key from a PEM file.
fn load_private_key(pemfile_path: &Path) -> Result<Rsa<Private>, ParseError> {
    let pemdata = fs::read(pemfile_path).map_err(ParseError::IOError)?;
    match Rsa::private_key_from_pem(&pemdata) {
        Ok(key) => Ok(key),
        Err(e) => {
            error!("error constructing private key from PEM data: {}", e);
            Err(ParseError::PEMFormatError)
        }
    }
}

/// Helper to get a certificate fingerprint.
fn get_cert_fingerprint(cert: &X509) -> [u8; CERT_FINGERPRINT_LEN] {
    let digest = cert.digest(MessageDigest::sha1()).unwrap();
    if digest.len() != CERT_FINGERPRINT_LEN {
        panic!("unexpected digest length, got {}", digest.len());
    }
    let fp: [u8; CERT_FINGERPRINT_LEN] = digest.as_ref().try_into().unwrap();
    fp
}

#[cfg(test)]
mod test {
    use libc::BUFSIZ;

    use super::*;

    // certificate-authority certificate
    const CA_CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIIDijCCAnICCQDvR2uxX2eKJTANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAktZMQ4wDAYDVQQHDAVWaWxsZTEQMA4GA1UECgwHc3VyZW5l
dDEWMBQGA1UECwwNYXV0aG9yaXphdGlvbjEXMBUGA1UEAwwOYXV0aDAuaW50ZXJu
YWwxFzAVBgkqhkiG9w0BCQEWCGF1dGhAZm9vMB4XDTIwMDIyODE5MjMyN1oXDTI1
MDIyNjE5MjMyN1owgYYxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJLWTEOMAwGA1UE
BwwFVmlsbGUxEDAOBgNVBAoMB3N1cmVuZXQxFjAUBgNVBAsMDWF1dGhvcml6YXRp
b24xFzAVBgNVBAMMDmF1dGgwLmludGVybmFsMRcwFQYJKoZIhvcNAQkBFghhdXRo
QGZvbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMCxt6RgI11Q3aZa
DTUp6Q+5uMB+fqhhuaPoeqEZYujgLbeJrldMQ2aIHlqntC1y4tPSCCYriVRS5j6V
cqgtu3saFsA/8MwAvaeY5LmD8wE7fl4b/MGst86FVyD3TLlTt5FDIkhJK+jpgKf1
4NjGDBYSiYVuZ54Kxg8HQXPGXx5txjTxmcBY44b5g5ARxOVu/u/ut0ZeS3z2Uf7K
q4cZ2/C+xxpYo+NMgg3sfuUDfMDAhLymfmWGa5SEj8XCUoYZv3bJLUDjMLtB06yo
alxQowZovSpUdJOjb0e+B8FvaziwRVohQ4Y1hEpx9X/idvwgHxzGzR9mSax+iz+p
OUbw3TMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAChfVONalJLlRCgbqC9gxjhYq
3fA3E4r9yVVlWQmkx8XTK4Z2NWqSdE5PmaYQdvdnzMAsxGHjxgaN/KH/wctEL+qK
2C7bnaevDBrHTtrVM6UUZfec5eerf7UA1MDKq0BqsaUamhzqxygh9Ei2mrG36+LK
my2Mk/tFcvSOS8tB8Q+gAGDKX/4DshR3aEkIDzqpdmwK8ffxD9sJp8HewjNtO3Pv
nsdyXmJ65z95DU5GIsshL7og94933hCN/b86R9Zq6/RAoAM/87TJFnxCywG39Zr5
GRAzgLWJLdkNEos8XB42MCS7tn/jefKDGquuI625jeARa2eCoJT9yk95pQbuAQ==
-----END CERTIFICATE-----
    "#;

    // This is an "adapter" certificate.  Is signed by CA cert above.
    const ADAPTER_CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIIEWzCCA0OgAwIBAgIJAMSVUe6Pd/Z7MA0GCSqGSIb3DQEBBQUAMIGGMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCS1kxDjAMBgNVBAcMBVZpbGxlMRAwDgYDVQQKDAdz
dXJlbmV0MRYwFAYDVQQLDA1hdXRob3JpemF0aW9uMRcwFQYDVQQDDA5hdXRoMC5p
bnRlcm5hbDEXMBUGCSqGSIb3DQEJARYIYXV0aEBmb28wHhcNMjQwNjE4MTQzMjI4
WhcNMjUwNjE4MTQzMjI4WjBLMQswCQYDVQQGEwJVUzELMAkGA1UECAwCS1kxCzAJ
BgNVBAoMAllZMQswCQYDVQQLDAJaWjEVMBMGA1UEAwwMdGVzdG5vZGUuenByMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk0x4ui48znwmmnbeVrRMXeiz
DdR2EKbZwsoW/sfePCTa50UJHgA3vPPTGhJTTfjJrVyp2nazpaBuy66h85PQWS2x
FqstxHVTj0+CF4t+YKUyHFZiF2rLWQonO5R43v489NF9JHKH2SgxKMjTsPpJY8sd
yFgUTbiD6G8T/j/ZIojBIkQG2wWNpdjqUDnzeaU32MGHV8iigUrpc3xDqw+RWhKP
kPjoyInoA4tNNrfHrddu61w3FPx6KTN1L8UV9K+BlNW/s3buluYMSi2vW24fjdTn
F3ev2+w+QUcvWP94/pFRiLEDAO+LO3hxFC16qNU33LMvAo8BdJvPG3GbN2+fIwID
AQABo4IBBDCCAQAwgaUGA1UdIwSBnTCBmqGBjKSBiTCBhjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAktZMQ4wDAYDVQQHDAVWaWxsZTEQMA4GA1UECgwHc3VyZW5ldDEW
MBQGA1UECwwNYXV0aG9yaXphdGlvbjEXMBUGA1UEAwwOYXV0aDAuaW50ZXJuYWwx
FzAVBgkqhkiG9w0BCQEWCGF1dGhAZm9vggkA70drsV9niiUwCQYDVR0TBAIwADAL
BgNVHQ8EBAMCBPAwHwYDVR0RBBgwFoIUYXV0aDAuc3BhY2VsYXNlci5uZXQwHQYD
VR0OBBYEFFdtDdU6IP12wNv4YUdyZejdx8EaMA0GCSqGSIb3DQEBBQUAA4IBAQBp
gM2xMYgo6ntaPTV7xhLmAbwlhoKBt3I+i6KQUU9Ec/3AEiiZsyQxcPHAtmeU4han
5JpOK3hUYVH/SaSj2BHqkXH0yfFyIkAf0V1UsfWwcD8OEZffb5yP02RzIWCqdBN7
pdx9gtGwy4l779FNvHGQ8AI4y+cpxwiXyBiXdB3Mv1wG5gUNe4pGk7JWA5lb9XQ9
sOwVMjkwcUsqGr489gqYRWl1mAMz1D2T+U91HavGybvUBlgb/3+dgjksa/ZWTUhD
2CRFn7sqmwcPHLoGV/+yCjjuheyx+z7LrPqyqPfWwrr68udK4Yqz8iiqwMC1b8m0
1Hm6nwN1sHYkYgYgk/Ey
-----END CERTIFICATE-----
    "#;

    // This private key goes with above certificate.
    const ADAPTER_KEY_DATA: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCTTHi6LjzOfCaa
dt5WtExd6LMN1HYQptnCyhb+x948JNrnRQkeADe889MaElNN+MmtXKnadrOloG7L
rqHzk9BZLbEWqy3EdVOPT4IXi35gpTIcVmIXastZCic7lHje/jz00X0kcofZKDEo
yNOw+kljyx3IWBRNuIPobxP+P9kiiMEiRAbbBY2l2OpQOfN5pTfYwYdXyKKBSulz
fEOrD5FaEo+Q+OjIiegDi002t8et127rXDcU/HopM3UvxRX0r4GU1b+zdu6W5gxK
La9bbh+N1OcXd6/b7D5BRy9Y/3j+kVGIsQMA74s7eHEULXqo1Tfcsy8CjwF0m88b
cZs3b58jAgMBAAECggEAQYQ8FqPGTBmQmhfRIUOkzAhazAX6VcHBDhERVVXVFW9X
JpLgUUXLhPH2rZwFDaNhIQkcS52MnljTrykHw+21OFVIdUrCWqXM+utkc9CJ77bK
qSwLCVtpAzuu46NQd+8hcctUHEgNAJwN8ZQSBJ/u0MJhhuEWdtNhaJsvi2Ee1WrN
ZvUkpn6SpCHVvEtZjJZL0elQrgk7EMzWSWz/1a8ORzbmBDw5X/0dV/VKCfx1kJ+w
9fmIhfGU3lFT8rOpqcx3MlB+PzRVV4P3hUBirovxBu2TEqp01hvPnb5m6ZGE0U/p
B4LBke3S23iSkYwPaHwcbLVLhF2pruYmXS1hvCZxEQKBgQC3gBWKZZeV8uT0vKN+
FScBk5WLYSq63dUSonszWr0AxN03WsoHjkr4AqB+wtMPI2L7Kpy8whwtTXehqNpT
W+Zz12eVQI2fuGTYZg7zjxN0+H2nRxTOWyVcpW4h1tavzzXAzTDo1jc8DYvMhgXp
IIOMYDbOCQPCnopdE0Xd2QF7NQKBgQDNftHfeNOINkt3RTTI5NY9pTibl/alzqJf
aW8BXEsnKM8BB6ux/sTNE4ejaK7a4xvKhgss+Z0FkM11Ycoa2D5/X9CyXT/cOmhF
E2vt6yyQUSscMQMAaUmma8Gvu5dDF3a7/5liphjafPyFRa275JIxdbDgaCvV62kH
EjPLMjOj9wKBgQCHhe9iwVlNA5EZN2DAM7sVLPybbe3zCPbexmWbLf683KhMw57G
Kc8wkDAcrqLWYVovCe+scOgChV4/ZMeqHQt8rq/vyTdPqQ3BzM5qD1ddYlDbBGJX
bXWQkRVfpJ32RmD6vhDLRbqRfaesK6ed38eIG18emAXQ7Opfh2ZoTGcNqQKBgDKN
/53lwMyi5t/506mUuqxByHJm6VQTSNkGPDvuc8K3hG2xcGkCz3HQWy81YscQ1lZ1
sawn4Jxs6k71dt4x0vZNIS+wRzSr3dkYlRXcJIOApIVz/VQNkwPxQJ42HVlxHVHU
6OxfBoBB/XHgGYS/D8RBOvmKRzaCir0lmj5kJFYzAoGBAKEEaHn0LvmDpHYSUOA4
FgJnFmtHTHcYFaFus/oqwEtylftAsM5h8o5ww2OCJDa2FSxzaayV1wpm2r1HwvDn
p/oYQcQrtBHsdvdZ/8IRR7/9HJNanbhTuKdkdmVjt4rPoUDc2zqzEZUEG33E2Glh
+VS382WYhn8T/WeSmWHmF69D
-----END PRIVATE KEY-----
    "#;

    // From `openssl x509 -in node-cert.pem -noout -fingerprint`
    const NODE_CERT_FINGERPRINT: &str =
        "5F:35:D5:7F:E8:6B:74:F4:A4:AB:30:84:4B:BF:C1:B9:0A:B3:80:6F";

    // This is a "node" certificate.  Signed by CA cert above.
    const NODE_CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIIEWDCCA0CgAwIBAgIJAMSVUe6Pd/Z8MA0GCSqGSIb3DQEBBQUAMIGGMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCS1kxDjAMBgNVBAcMBVZpbGxlMRAwDgYDVQQKDAdz
dXJlbmV0MRYwFAYDVQQLDA1hdXRob3JpemF0aW9uMRcwFQYDVQQDDA5hdXRoMC5p
bnRlcm5hbDEXMBUGCSqGSIb3DQEJARYIYXV0aEBmb28wHhcNMjQwNzAzMTczOTAz
WhcNMjUwNzAzMTczOTAzWjBIMQswCQYDVQQGEwJVUzELMAkGA1UECAwCS1kxDTAL
BgNVBAoMBE9yZ3kxDDAKBgNVBAsMA0ZvbzEPMA0GA1UEAwwGbjAuenByMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomv2Rwx/y32QnSp8hjj2+vA+6uUR
Xwz+h8SRw5xk0TQRL218xQSrnG8O5iWr/Ho2rSWo9TmltluocR2InAcb5FGga6FA
eAkydtSy1xgw/cjCzuvMUjp4V+BMThgOGKx5Ot6sN4CgaHfRmtjwgxTjN5UDTj1W
q/znOHdlp3bw1/tIXlXqI29ivZslUOBMMId++ZmINL0BBuf89e/c0LYFLUmk5s8z
PcwkR6+x2Lfl9amAUV8mALWDUp4va4ugZr8kUrJ01qJ7tTIqMvrlbdY3FW4Ffd0W
wEQT6RK6+Y6XmEDV7gGLGNX+I1gGXMmqd+hmUIEjlvmRMP2cclD1NM8b6wIDAQAB
o4IBBDCCAQAwgaUGA1UdIwSBnTCBmqGBjKSBiTCBhjELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgMAktZMQ4wDAYDVQQHDAVWaWxsZTEQMA4GA1UECgwHc3VyZW5ldDEWMBQG
A1UECwwNYXV0aG9yaXphdGlvbjEXMBUGA1UEAwwOYXV0aDAuaW50ZXJuYWwxFzAV
BgkqhkiG9w0BCQEWCGF1dGhAZm9vggkA70drsV9niiUwCQYDVR0TBAIwADALBgNV
HQ8EBAMCBPAwHwYDVR0RBBgwFoIUYXV0aDAuc3BhY2VsYXNlci5uZXQwHQYDVR0O
BBYEFFhizDyJTn/rxHETEzHcD2srbsujMA0GCSqGSIb3DQEBBQUAA4IBAQBMGqBL
cyMwr1bmZ/TVCTM/Luy7U/bjiwtKdMrKiWD0b/v5bDxteoYIAguE9uRGAd8lArgT
NduEztPUS/Mjk4EGtDHMxSuGpR61tiVFMLHcVHaB+LDtCVJWPjCMddqA4ONgTs6r
LRfqzWIIRjAQkaq3rJdg1WcnEj11dqJDSFsl5GTxb2J8slDLEj4EoLhqv3g4R1js
P9GXz78ju2R2fulR541sGICHEz/0f1pIqkRWCpe8NUs53jDdt7+aHuyu4uLSXxDC
4Rk0p1rz70WCVSCqkuESCLtP6ADLUZUJXIqimvYpbLOadNKf2RNesQGPy7Dsqkoe
k829PTfmNDSvEBdR
-----END CERTIFICATE-----
"#;

    // This is a "node" private key.
    const NODE_KEY_DATA: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCia/ZHDH/LfZCd
KnyGOPb68D7q5RFfDP6HxJHDnGTRNBEvbXzFBKucbw7mJav8ejatJaj1OaW2W6hx
HYicBxvkUaBroUB4CTJ21LLXGDD9yMLO68xSOnhX4ExOGA4YrHk63qw3gKBod9Ga
2PCDFOM3lQNOPVar/Oc4d2WndvDX+0heVeojb2K9myVQ4Ewwh375mYg0vQEG5/z1
79zQtgUtSaTmzzM9zCRHr7HYt+X1qYBRXyYAtYNSni9ri6BmvyRSsnTWonu1Mioy
+uVt1jcVbgV93RbARBPpErr5jpeYQNXuAYsY1f4jWAZcyap36GZQgSOW+ZEw/Zxy
UPU0zxvrAgMBAAECggEACr5XcQWrolsw6KR5zisQczLXBpSWXJIwd+yRs72xkYD/
LgLxANs5OsTB2IlfYfj3iuZ10Zq5kmFnt+u7MI7r0mNv2A63g/kfxGp3VfD8tJzF
/gfs4PeLJEzq3zOKIymtby5xd85jTeW3EKYO6qzEBtYtfMxj4kZ9SOfk6nncnnye
otb9b93CKgiMJq6UVTrFUw1ro/XtlIBaEakrZU8ynkq+MYrMmOlLCBZ1OJNTbqic
4uvATCTREpPCTm/jZrY55EYDHz3GgPB48Hv9t9HEXQ8YSIDjzcDfb3Usfsxd3B3M
tvpPU10SSgcbf3S+D8rdXjL1qW99E8Gi6uBcIa65CQKBgQDEPDIyZ+qLv2oIByUf
LyuZuzmzqy4t0ji8Cf8nf96Ba19uLp38ERrnsLlRQyspk1TEJhuuEAQSwYzOU50C
OBqRfY2rKuxYCIv5f3gsQgW7YV789Qy+/Zd3SSxsH5fAEGq9rcHr3GHSqSbiAwmK
GxEhofTguL76BJA88Cm2S90/DwKBgQDT43IvNSi2pL3jhPp7JTLhD61yEks8Lcd9
vynAVKU0azO1I0IJqS9hPWhGTZbkiriufvb6/Nn/RwYbVsEYvkjiwzJn68qWUMMi
S2b0tYAKY3tRjJVFPQ2+resnOkowBjuAMxP2iZ07pv2dnVp2qxeRoC2qIWx2B5gl
yDv5KhcVZQKBgCRqj14vTqV0djbbLJZm6I504jZndABo3MJ4kHNCFYaq6GDIIeVf
P0Dz2NAtyNrETpy//a8FpdvdM0Yu2hpJUxTg2eOD6axEmcVJVIHSFsI5RalnyF/B
K9SlLas7CaxI36Ynkq80jKrNXTvgGGsarskxBwKVBkvbgPDuGK+N0JcdAoGAJeRe
3yJajY8Yhj+Zq7wTRTxQgD3VRoXJTyuIg+SfRqiFLreHb8LZvkIFC82EVoqYTFxY
PrpJIeXJqcnx7kLZNfRCZ2M7b3Yx70gcuVZb93+i5gqGB0PL2XWwv+skqUH0EhEQ
WN5zR9+tKyqgqugd5uUGRY6EnvbstpUAZKaqSiECgYAoJ1QSOuVBlZGnKeiIdqJA
tKepsc6CJ3SObunNy+1ZdJScCUNg8gfMf360A24x8Tk71gTXJEPeD1hmHCd2ofTB
M8SDDxMCXVvLGHAUMwayzyW55OQKcheCIhfStx5fraKSc+FxvfyTxexH/1X7mrjO
DeCZBXjYdUB7u/8lFF40mw==
-----END PRIVATE KEY-----
"#;

    // This is the public key extracted from the NODE_CERT_DATA.
    // Eg, `openssl x509 -pubkey -noout -in node-cert.pem > node.pub`
    const NODE_PUBLIC_KEY_DATA: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomv2Rwx/y32QnSp8hjj2
+vA+6uURXwz+h8SRw5xk0TQRL218xQSrnG8O5iWr/Ho2rSWo9TmltluocR2InAcb
5FGga6FAeAkydtSy1xgw/cjCzuvMUjp4V+BMThgOGKx5Ot6sN4CgaHfRmtjwgxTj
N5UDTj1Wq/znOHdlp3bw1/tIXlXqI29ivZslUOBMMId++ZmINL0BBuf89e/c0LYF
LUmk5s8zPcwkR6+x2Lfl9amAUV8mALWDUp4va4ugZr8kUrJ01qJ7tTIqMvrlbdY3
FW4Ffd0WwEQT6RK6+Y6XmEDV7gGLGNX+I1gGXMmqd+hmUIEjlvmRMP2cclD1NM8b
6wIDAQAB
-----END PUBLIC KEY-----
"#;

    #[test]
    fn test_km_cert_fingerprint_same_as_openssl() {
        let cert = X509::from_pem(NODE_CERT_DATA.as_bytes()).unwrap();
        let fp = get_cert_fingerprint(&cert);
        let mut fpstr = String::new();
        for b in fp.iter() {
            fpstr.push_str(&format!("{:02X}:", b));
        }
        fpstr.pop();
        assert_eq!(NODE_CERT_FINGERPRINT, fpstr);
    }

    #[test]
    fn test_km_cert_payload_create_and_process() {
        // Pretend to be an adapter, and create a payload for a node.
        let mut adapter_exchanger = KmCertExchange::new_initiator_from_pem(
            ADAPTER_CERT_DATA,
            ADAPTER_KEY_DATA,
            NODE_CERT_DATA,
        )
        .unwrap();
        let i_payload = match adapter_exchanger.create_initiator_payload() {
            Ok(p) => p,
            Err(e) => {
                panic!("Error creating payload: {:?}", e)
            }
        };
        assert_eq!(i_payload.len(), 1171);

        // Now a node will accept the payload and check the clients cert and signature.
        // Returning its key fingerprint and a signature.
        let node_exchanger =
            KmCertExchange::new_responder_from_pem(NODE_CERT_DATA, NODE_KEY_DATA, CA_CERT_DATA)
                .unwrap();
        let (i_cert, r_payload) = match node_exchanger.process_initiator_payload(&i_payload) {
            Ok(tuple) => (tuple.0, tuple.1),
            Err(e) => {
                panic!("Error processing initiator payload: {:?}", e)
            }
        };
        assert_eq!(r_payload.len(), 284);

        // Node emits the initiator cert on success:
        let adapter_cert = X509::from_pem(ADAPTER_CERT_DATA.as_bytes()).unwrap();
        assert_eq!(adapter_cert, i_cert);

        // Finally, the initiator can check the response from responder.
        match adapter_exchanger.process_responder_payload(&r_payload) {
            Ok(_) => {}
            Err(e) => {
                panic!("Error processing responder payload: {:?}", e)
            }
        }
    }

    #[test]
    fn test_km_cert_bad_initiator_signature() {
        let mut adapter_exchanger = KmCertExchange::new_initiator_from_pem(
            ADAPTER_CERT_DATA,
            ADAPTER_KEY_DATA,
            NODE_CERT_DATA,
        )
        .unwrap();
        let i_payload = match adapter_exchanger.create_initiator_payload() {
            Ok(p) => p,
            Err(e) => {
                panic!("Error creating payload: {:?}", e)
            }
        };
        assert_eq!(i_payload.len(), 1171);

        // Mess with the sigature by altering a byte
        let plen = i_payload.len();
        let mut bad_payload = [0u8; MSG_BUF_SIZE];
        bad_payload[0..plen].copy_from_slice(&i_payload);
        bad_payload[plen - 7] ^= 0x7f;

        let node_exchanger =
            KmCertExchange::new_responder_from_pem(NODE_CERT_DATA, NODE_KEY_DATA, CA_CERT_DATA)
                .unwrap();
        match node_exchanger.process_initiator_payload(&bad_payload) {
            Ok(_) => {
                panic!("should have failed to process")
            }
            Err(CertExchangeError::SignatureVerificationError) => {} // ok
            Err(e) => {
                panic!("unexpected error processing bad signature payload: {:?}", e)
            }
        };
    }
}
