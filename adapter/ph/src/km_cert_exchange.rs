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

use tracing::{error, warn};
use x509_cert::Certificate;
use zerocopy::byteorder::network_endian::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::km::PeerCertificate;
use crate::logging::targets::KEY_MGMT;
use crate::pki::{self, ParseError};

#[derive(Debug)]
pub enum CertExchangeError {
    CertificateFormatError,
    CertificateParseError,
    InvalidPayloadError,
    ShortPayloadError,
    BufferSizeError,
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
    local_cert: Certificate,
    authority_cert: Option<Certificate>,
}

impl KmCertExchange {
    /// - `cert` - the certificate of the initiator.
    /// - `authority_cert` - the certificate of the authority that is expected to have signed the responders certificate.
    pub fn new(cert: Certificate, authority_cert: Option<Certificate>) -> Self {
        KmCertExchange {
            local_cert: cert,
            authority_cert,
        }
    }

    /// Like [KmCertExchange::new] but takes the contents of the various PEM files.
    #[allow(dead_code)]
    pub fn new_from_pem(cert_pem: &str, authority_cert_pem: &str) -> Result<Self, ParseError> {
        let cert = pki::from_pem(cert_pem.as_bytes())?;
        let authority_cert = pki::from_pem(authority_cert_pem.as_bytes())?;
        Ok(KmCertExchange::new(cert, Some(authority_cert)))
    }

    /// Write a cert exhange payload into the supplied buffer.
    ///
    /// ## Errors
    /// - [CertExchangeError::BufferSizeError] - the buffer is too short to hold the payload.
    /// - [CertExchangeError::CertificateFormatError] - the certificate is too large to be encoded in the payload.
    pub fn write_payload(&self, buf: &mut impl bytes::BufMut) -> Result<(), CertExchangeError> {
        let cert_der =
            pki::to_der(&self.local_cert).map_err(|_| CertExchangeError::CertificateFormatError)?;
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
        buf.put_slice(&cert_der);
        Ok(())
    }

    /// Process a payload from a peer.
    /// Returns the presented certificate. If we were able to verify the signature against the
    /// `authority_cert` passed in the constructor, then the returned enum will be [PeerCertificate::Verified],
    /// otherwise it will be [PeerCertificate::Unverified].
    ///
    /// ## Errors
    /// - [CertExchangeError::ShortPayloadError] - the payload is too short to be valid.
    /// - [CertExchangeError::InvalidPayloadError] - unable to parse our header from the payload.
    /// - [CertExchangeError::CertificateParseError] - unable to parse the DER encoded certificate from the payload.
    /// - [CertExchangeError::KeyMismatchError] - the public key in the certificate does not match the `expected_peer_key`.
    /// - [CertExchangeError::CertificateFormatError] - unable to get a public key from the certificate.
    pub fn process_payload(
        &self,
        payload: &[u8],
        expected_peer_public_key: &[u8],
    ) -> Result<PeerCertificate, CertExchangeError> {
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
        let initiator_cert = match pki::from_der(&payload[cert_offset..cert_offset + cert_len]) {
            Ok(c) => c,
            Err(e) => {
                error!(target: KEY_MGMT, "error constructing cert from DER data: {e}");
                return Err(CertExchangeError::CertificateParseError);
            }
        };

        let is_verified = if let Some(authority_cert) = &self.authority_cert {
            match pki::verify(&initiator_cert, pki::public_key(authority_cert)) {
                Ok(true) => true,
                Ok(false) => {
                    warn!(target: KEY_MGMT, "cert failed signature verification");
                    false
                }
                Err(e) => {
                    warn!(target: KEY_MGMT, "cert not verifiable against authority (unverified): {e}");
                    false
                }
            }
        } else {
            false
        };

        if pki::public_key(&initiator_cert)
            .subject_public_key
            .raw_bytes()
            != expected_peer_public_key
        {
            return Err(CertExchangeError::KeyMismatchError);
        }
        let peer_result = if is_verified {
            PeerCertificate::Verified(initiator_cert)
        } else {
            PeerCertificate::Unverified(initiator_cert)
        };
        return Ok(peer_result);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::km_noise::{NoiseKeypair, derive_public_key};
    use crate::km_testdata::test::*;
    use crate::pki::{NOISE_KEY_LEN, generate_self_signed_noise_cert};
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
        let adapter_cert = pki::from_pem(ADAPTER_CERT_DATA.as_bytes()).unwrap();
        assert_eq!(PeerCertificate::Verified(adapter_cert), i_cert);
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

    #[test]
    fn test_km_cert_with_self_signed() {
        let keypair = NoiseKeypair::generate();

        let self_signed_cert = generate_self_signed_noise_cert("foo.zpl", &keypair).unwrap();
        let self_signed_cert_pem_str = pki::to_pem(&self_signed_cert).unwrap();

        let adapter_exchanger =
            KmCertExchange::new_from_pem(&self_signed_cert_pem_str, CA_CERT_DATA).unwrap();

        let mut buffer = BytesMut::with_capacity(MSG_BUF_SIZE);
        //let mut buffer = [0u8; MSG_BUF_SIZE];
        match adapter_exchanger.write_payload(&mut buffer) {
            Ok(()) => (),
            Err(e) => {
                panic!("Error creating payload: {:?}", e)
            }
        };
        assert!(buffer.len() > 100);

        // Now a node will accept the payload and check the clients cert and signature.
        // Returning its key fingerprint and a signature.
        let node_exchanger = KmCertExchange::new_from_pem(NODE_CERT_DATA, CA_CERT_DATA).unwrap();

        let i_cert = match node_exchanger.process_payload(&buffer[..buffer.len()], &keypair.public)
        {
            Ok(c) => c,
            Err(e) => {
                panic!("Error processing payload: {:?}", e)
            }
        };

        // Node emits the initiator cert on success:
        assert_eq!(PeerCertificate::Unverified(self_signed_cert), i_cert);
    }
}
