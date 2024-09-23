//! Key Management Certificate Exchange
//!
//!
//!
//! Each party in the exchange has a signed certificate that includes their
//! public key. In this case that is a NOISE key. The certificate is signed
//! by a certificate authority and each party also has the authority
//! certificate.
//!
//! The messages sent are exceedingly simple: each just sends its signed
//! certificate to the other.
//!
//! Upon receiving a message, the recipient checks the signature on the
//! certfiicate and then checks that the public key in the certificate
//! is the one expected (extrated from the current SA).
//!
//!
//!

use openssl::x509::X509;
use std::fs;
use std::path::Path;
use tracing::error;
use zerocopy::byteorder::network_endian::*;
use zerocopy::{AsBytes, FromBytes, FromZeroes, Unaligned};

const PEM_BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END_CERTIFICATE: &str = "-----END CERTIFICATE-----";

#[derive(Debug)]
pub enum CertExchangeError {
    CertificateError,
    CertificateFormatError,
    KeyError,
    CertificateParseError,
    InvalidPayloadError,
    ShortPayloadError,
    BufferSizeError,
    CertificateVerificationError,
    KeyMismatchError,
}

#[derive(Debug)]
pub enum ParseError {
    PEMCertNotFound,
    PEMFormatError,
    IOError(std::io::Error),
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
struct CertExchgHdr {
    pub cert_len: U16,
    // Followed by the cert bytes (DER)
}

/// The Certificate Exchange object holds the local certificate (which includes the noise public key)
/// and the certificate for our trusted signing authority.
pub struct KmCertExchange {
    local_cert: X509,
    authority_cert: X509,
}

impl KmCertExchange {
    /// - `cert` - the certificate of the initiator.
    /// - `authority_cert` - the certificate of the authority that is expected to have signed the responders certificate.
    pub fn new(cert: X509, authority_cert: X509) -> Self {
        KmCertExchange {
            local_cert: cert,
            authority_cert,
        }
    }

    /// Like [KmCertExchange::new] but takes the paths to the various PEM files.
    pub fn new_from_paths(
        cert_file: &Path,
        authority_cert_file: &Path,
    ) -> Result<Self, ParseError> {
        let cert = load_cert(cert_file)?;
        let authority_cert = load_cert(authority_cert_file)?;
        Ok(KmCertExchange::new(cert, authority_cert))
    }

    /// Like [KmCertExchange::new] but takes the contents of the various PEM files.
    pub fn new_from_pem(cert_pem: &str, authority_cert_pem: &str) -> Result<Self, ParseError> {
        let cert = match X509::from_pem(cert_pem.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                error!("error constructing cert from PEM data: {}", e);
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
        Ok(KmCertExchange::new(cert, authority_cert))
    }

    /// Write a cert exhange payload into the supplied buffer.
    ///
    /// ## Errors
    /// - [CertExchangeError::BufferSizeError] - the buffer is too short to hold the payload.
    /// - [CertExchangeError::CertificateFormatError] - the certificate is too large to be encoded in the payload.
    pub fn write_payload(&self, buf: &mut impl bytes::BufMut) -> Result<(), CertExchangeError> {
        let cert_der = self.local_cert.to_der().unwrap();
        if cert_der.len() > u16::MAX as usize {
            return Err(CertExchangeError::CertificateFormatError);
        }
        let sz = cert_der.len() as u16;

        if buf.remaining_mut() < std::mem::size_of::<CertExchgHdr>() + cert_der.len() {
            return Err(CertExchangeError::BufferSizeError);
        }

        let msg = CertExchgHdr {
            cert_len: sz.into(),
        };
        buf.put(msg.as_bytes());
        buf.put(cert_der.as_slice());
        Ok(())
    }

    /// Process a payload from a peer.
    ///
    /// ## Errors
    /// - [CertExchangeError::ShortPayloadError] - the payload is too short to be valid.
    /// - [CertExchangeError::InvalidPayloadError] - unable to parse our header from the payload.
    /// - [CertExchangeError::CertificateParseError] - unable to parse the DER encoded certificate from the payload.
    /// - [CertExchangeError::CertificateVerificationError] - the certificate failed signature verification (not signed by expected authority).
    /// - [CertExchangeError::KeyMismatchError] - the public key in the certificate does not match the `expected_peer_key`.
    /// - [CertExchangeError::CertificateFormatError] - unable to get a public key from the certificate.
    /// - [CertExchangeError::KeyError] - OpenSSL unable to get the raw public key form.
    pub fn process_payload(
        &self,
        payload: &[u8],
        expected_peer_public_key: &[u8],
    ) -> Result<X509, CertExchangeError> {
        // Payload should be at minimum: CertExchgHdr
        if payload.len() < std::mem::size_of::<CertExchgHdr>() {
            return Err(CertExchangeError::ShortPayloadError);
        }
        let msg = match CertExchgHdr::ref_from_prefix(&payload) {
            Some(k) => k,
            None => {
                return Err(CertExchangeError::InvalidPayloadError);
            }
        };

        // Now we have the cert length, so check again.
        let cert_len: usize = msg.cert_len.into();
        if payload.len() < std::mem::size_of::<CertExchgHdr>() + cert_len {
            return Err(CertExchangeError::ShortPayloadError);
        }

        let cert_offset = std::mem::size_of::<CertExchgHdr>();
        let initiator_cert = match X509::from_der(&payload[cert_offset..]) {
            Ok(c) => c,
            Err(e) => {
                error!("error constructing cert from DER data: {}", e);
                return Err(CertExchangeError::CertificateParseError);
            }
        };

        // TODO: Now check that the cert is signed by our authority.
        {
            let authority_pkey = self.authority_cert.public_key().unwrap(); // TODO: check this unwrap in ctor
            match initiator_cert.verify(&authority_pkey) {
                Ok(_) => (),
                Err(e) => {
                    error!("cert verification failed: {}", e);
                    return Err(CertExchangeError::CertificateVerificationError);
                }
            }
        }

        // Extract the public key from the cert and check it against expected
        let initiator_public_key = match initiator_cert.public_key() {
            Ok(p) => p,
            Err(e) => {
                error!("error extracting public key from cert: {}", e);
                return Err(CertExchangeError::CertificateFormatError);
            }
        };

        match initiator_public_key.raw_public_key() {
            Ok(p) => {
                if p != *expected_peer_public_key {
                    return Err(CertExchangeError::KeyMismatchError);
                }
            }
            Err(e) => {
                error!("unable to get raw public key: {}", e);
                return Err(CertExchangeError::KeyError);
            }
        }

        return Ok(initiator_cert);
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::km_noise::{derive_public_key, NOISE_KEY_LEN};
    use base64::prelude::*;
    use bytes::BytesMut;

    const MSG_BUF_SIZE: usize = 4096;

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

    // adapter private key
    const ADAPTER_NOISE_KEY: &str = "ICP2umiV9w/+UdjlaChamy62cBN8BuvVDTbSoeLDQlY=";

    // signed cert with adapter noise public key inside
    const ADAPTER_CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUWkavw7sjL6ozyx+qGjrbT1wBz40wDQYJKoZIhvcNAQEL
BQAwgYYxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJLWTEOMAwGA1UEBwwFVmlsbGUx
EDAOBgNVBAoMB3N1cmVuZXQxFjAUBgNVBAsMDWF1dGhvcml6YXRpb24xFzAVBgNV
BAMMDmF1dGgwLmludGVybmFsMRcwFQYJKoZIhvcNAQkBFghhdXRoQGZvbzAeFw0y
NDA5MjAxNDU0MTdaFw0yNTA3MTcxNDU0MTdaMBYxFDASBgNVBAMMC2FkYXRwZXIu
Zm9vMCowBQYDK2VuAyEAqKvsuYwjYHnc0quenQkf1yT+4v9yvNh3YDNiDpvZkQ+j
gdcwgdQwCwYDVR0PBAQDAgMIMB0GA1UdDgQWBBQfedYns4Xqx51VngzPQn7d+abZ
pDCBpQYDVR0jBIGdMIGaoYGMpIGJMIGGMQswCQYDVQQGEwJVUzELMAkGA1UECAwC
S1kxDjAMBgNVBAcMBVZpbGxlMRAwDgYDVQQKDAdzdXJlbmV0MRYwFAYDVQQLDA1h
dXRob3JpemF0aW9uMRcwFQYDVQQDDA5hdXRoMC5pbnRlcm5hbDEXMBUGCSqGSIb3
DQEJARYIYXV0aEBmb2+CCQDvR2uxX2eKJTANBgkqhkiG9w0BAQsFAAOCAQEAtQCp
8F03nB5xje/yGbt8OKAfrTv4pXJgYr6OYhD/kkc9Q5KtwdXxXwUGrZ4gA/Uhg6Cw
im7y1N6UHjIv+ZTRjGOLlI6hvOz6rsCquq0CMWzOMgphf8WCxwvFlLlP4nD8Z7Rb
qX06qsVy5ZihoOY3jWIFd8o8NS/n/vcVcCWdQ0A5y2Qab4vS9DpanvzkHHLByt/i
hLUjYXBhQlHoxCoJBrWZFdxzebl6LIBoGlhBLjv/8JXIkj0vxS9r16RV1/cafgkr
YdmdJcbVt762z8y6FONk3Ig7z4xWg1VKWixh2CLXtqzZbyD7vBbpe+Mr5MiFyGhk
MrOCC7A2J3IpFxNcjg==
-----END CERTIFICATE-----
"#;

    // node private key
    #[allow(dead_code)]
    const NODE_NOISE_KEY: &str = "QMBJE5qUTPv9klauHFNY/XNjWLJ+oWkzGRmDKmnKYkg=";

    // signed cert with node noise public key inside
    const NODE_CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIUVWbapktKdShwnGJPQ95JufVu/CIwDQYJKoZIhvcNAQEL
BQAwgYYxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJLWTEOMAwGA1UEBwwFVmlsbGUx
EDAOBgNVBAoMB3N1cmVuZXQxFjAUBgNVBAsMDWF1dGhvcml6YXRpb24xFzAVBgNV
BAMMDmF1dGgwLmludGVybmFsMRcwFQYJKoZIhvcNAQkBFghhdXRoQGZvbzAeFw0y
NDA5MjAxNDU3MTVaFw0yNTA3MTcxNDU3MTVaMBMxETAPBgNVBAMMCG5vZGUuZm9v
MCowBQYDK2VuAyEAaWeYgl7LDyt9fUr6JcM0/8oUIDzosI1rJqx3Ni9eNmyjgdcw
gdQwCwYDVR0PBAQDAgMIMB0GA1UdDgQWBBSGKEJ+62uAKTbov8lkdwKJ5lVaIzCB
pQYDVR0jBIGdMIGaoYGMpIGJMIGGMQswCQYDVQQGEwJVUzELMAkGA1UECAwCS1kx
DjAMBgNVBAcMBVZpbGxlMRAwDgYDVQQKDAdzdXJlbmV0MRYwFAYDVQQLDA1hdXRo
b3JpemF0aW9uMRcwFQYDVQQDDA5hdXRoMC5pbnRlcm5hbDEXMBUGCSqGSIb3DQEJ
ARYIYXV0aEBmb2+CCQDvR2uxX2eKJTANBgkqhkiG9w0BAQsFAAOCAQEAk4+AO6tL
fiQPiZVF8PUE1vV2SJP8Rtz2Wij2ak5mdfofejsWrYMkdyp9/hXaFC0N/GEMJbW7
v+8qTNsYiMRXehLYDGQfWkPV7qUMAJ5/eU/Wk0oxu1Buv2NLXoDUERMTfMcntSFz
8PKizVLuFYrT7JEtrl7CYwZqarW22mlkIafTmxrLW2qnwO3gPWB3SYtbpZV5LaUs
z0FTkzHeWMtDPgUMU6sgXUEHZNyAxOLJgdGg3olYhF0uQNT5LdegfQafANYEQpnu
/l2BW2DoIhyiVwKfGPYNJ8X94ZkShzlftXD4raIL0/ZNRALVbqj6j8PWxuCDLbRN
JjLI9OaLcE83mA==
-----END CERTIFICATE-----
"#;

    #[test]
    fn test_km_cert_payload_create_and_process() {
        let adapter_exchanger =
            KmCertExchange::new_from_pem(ADAPTER_CERT_DATA, CA_CERT_DATA).unwrap();

        let mut buffer = BytesMut::with_capacity(MSG_BUF_SIZE);
        //let mut buffer = [0u8; MSG_BUF_SIZE];
        match adapter_exchanger.write_payload(&mut buffer) {
            Ok(()) => (),
            Err(e) => {
                panic!("Error creating payload: {:?}", e)
            }
        };
        assert_eq!(buffer.len(), 783);

        // Now a node will accept the payload and check the clients cert and signature.
        // Returning its key fingerprint and a signature.
        let node_exchanger = KmCertExchange::new_from_pem(NODE_CERT_DATA, CA_CERT_DATA).unwrap();

        let public_key: Vec<u8>;
        {
            let ak_private: [u8; NOISE_KEY_LEN] = match BASE64_STANDARD.decode(ADAPTER_NOISE_KEY) {
                Ok(d) => d.try_into().unwrap(),
                Err(e) => {
                    panic!("error decoding base64: {:?}", e);
                }
            };
            let ak_public = derive_public_key(&ak_private);
            public_key = ak_public.to_vec();
        }

        let i_cert = match node_exchanger.process_payload(&buffer[..buffer.len()], &public_key) {
            Ok(c) => c,
            Err(e) => {
                panic!("Error processing payload: {:?}", e)
            }
        };

        // Node emits the initiator cert on success:
        let adapter_cert = X509::from_pem(ADAPTER_CERT_DATA.as_bytes()).unwrap();
        assert_eq!(adapter_cert, i_cert);
    }

    #[test]
    fn test_km_cert_key_not_match() {
        let adapter_exchanger =
            KmCertExchange::new_from_pem(ADAPTER_CERT_DATA, CA_CERT_DATA).unwrap();
        let mut buffer = BytesMut::with_capacity(MSG_BUF_SIZE);
        match adapter_exchanger.write_payload(&mut buffer) {
            Ok(()) => (),
            Err(e) => {
                panic!("Error creating payload: {:?}", e)
            }
        };

        let node_exchanger = KmCertExchange::new_from_pem(NODE_CERT_DATA, CA_CERT_DATA).unwrap();

        let public_key: Vec<u8> = vec![7; NOISE_KEY_LEN];
        match node_exchanger.process_payload(&buffer[..buffer.len()], &public_key) {
            Ok(_) => panic!("Should not have succeeded"),
            Err(CertExchangeError::KeyMismatchError) => {
                // Expected
            }
            Err(e) => panic!("unexpected error: {:?}", e),
        };
    }
}
