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
use std::path::Path;
use tracing::error;
use zerocopy::byteorder::network_endian::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::logging::targets::KEY_MGMT;
use crate::pki::{load_cert, ParseError};

#[derive(Debug)]
pub enum CertExchangeError {
    CertificateFormatError,
    KeyError,
    CertificateParseError,
    InvalidPayloadError,
    ShortPayloadError,
    BufferSizeError,
    CertificateVerificationError,
    KeyMismatchError,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
struct CertExchgHdr {
    pub cert_len: U16,
    // Followed by the cert bytes (DER)
}

/// The Certificate Exchange object holds the local certificate (which includes the noise public key)
/// and the certificate for our trusted signing authority.
#[derive(Clone)]
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
    #[allow(dead_code)]
    pub fn new_from_pem(cert_pem: &str, authority_cert_pem: &str) -> Result<Self, ParseError> {
        let cert = match X509::from_pem(cert_pem.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                error!(target: KEY_MGMT, "error constructing cert from PEM data: {e}");
                return Err(ParseError::PEMFormatError);
            }
        };
        let authority_cert = match X509::from_pem(authority_cert_pem.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                error!(target: KEY_MGMT, "error constructing cert from PEM data: {e}");
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
            Ok((k, _)) => k,
            Err(_) => {
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
                error!(target: KEY_MGMT, "error constructing cert from DER data: {e}");
                return Err(CertExchangeError::CertificateParseError);
            }
        };

        // TODO: Now check that the cert is signed by our authority.
        {
            let authority_pkey = self.authority_cert.public_key().unwrap(); // TODO: check this unwrap in ctor
            match initiator_cert.verify(&authority_pkey) {
                Ok(_) => (),
                Err(e) => {
                    error!(target: KEY_MGMT, "cert verification failed: {e}");
                    return Err(CertExchangeError::CertificateVerificationError);
                }
            }
        }

        // Extract the public key from the cert and check it against expected
        let initiator_public_key = match initiator_cert.public_key() {
            Ok(p) => p,
            Err(e) => {
                error!(target: KEY_MGMT, "error extracting public key from cert: {e}");
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
                error!(target: KEY_MGMT, "unable to get raw public key: {e}");
                return Err(CertExchangeError::KeyError);
            }
        }

        return Ok(initiator_cert);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::km_noise::derive_public_key;
    use crate::km_testdata::test::*;
    use crate::pki::NOISE_KEY_LEN;
    use base64::prelude::*;
    use bytes::BytesMut;

    const MSG_BUF_SIZE: usize = 4096;

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
