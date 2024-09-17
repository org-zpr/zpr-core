
///! Key Management Certificate Exchange
///
///
///! This is structured so that it could be broken out into an interface if we need
///! to.  The general idea is that this is how the payloads are created and processed
///! during key exchange.  Our noise handshake as just two messages, so this assumes
///! two messages.
///!
///! Message 1 is from initiator to responder which includes:
///! - The initiator's certificate
///! - A timestamp (unix epoch millis)
///! - A signature over the above using the initiator's private key
///!
///! Message 2 is a reply from responder to initiator which includes:
///! - The fingerprint of the responders certificate.  We assume that the responders
///!   certificate is known to the initiator and can be retrieved out of band.
///! - The initiator timestamp (copies from initator payload)
///! - A signature over the above using the responder's private key
///!



use bytes::{Bytes, BytesMut, BufMut};
use zerocopy::{AsBytes, FromBytes, FromZeroes, Unaligned};
use zerocopy::byteorder::network_endian::*;
use std::time::{SystemTime, UNIX_EPOCH};


#[derive(Debug)]
pub enum CertExchangeError {
    CertificateError,
    InvalidPayloadError,
    ShortPayloadError,
    SignatureError,
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
struct CertHelloHdr {
    pub timestamp: U64,
    pub cert_len: U16,
    // Followed by the cert bytes (PEM, compressed?)
    // Followed by the PKCS1_1.5_SHA256_signature (32 bytes)
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
struct CertResponseHdr {
    pub timestamp: U64,
    pub cert_fingerprint: [u8; 20], // SHA-1 certificate fingerprint
    // Followed by the PKCS1_1.5_SHA256_signature (32 bytes)
}


pub struct KmCertExchange;

impl KmCertExchange {

    pub fn new () -> Self {
        KmCertExchange {
            // load keys and certs here.
            // ...
        }
    }

    pub fn create_initiator_payload(&self) -> Result<Bytes, CertExchangeError>{

        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

        let msg = CertHelloHdr {
            timestamp: ts.into(),
            cert_len: U16::new(0),
        };

        // write message into a buffer
        let mut buf = BytesMut::with_capacity(1024);
        buf.extend_from_slice(msg.as_bytes());

        // write the cert --- probably compressed ? TODO
        let cert = &[0, 1, 2, 3, 4];
        buf.extend_from_slice(cert);


        // compute and append signature
        // compute signature from buf[0] to end of cert.
        let sig = b"fake-signaure";
        buf.put(&sig[..]);


        Ok(buf.freeze())
    }

    pub fn process_initiator_payload(&self, payload: &[u8]) -> Result<Bytes, CertExchangeError> {
        if payload.len() < std::mem::size_of::<CertHelloHdr>() {
            return Err(CertExchangeError::ShortPayloadError);
        }
        let hello = match CertHelloHdr::ref_from_prefix(&payload) {
            Some(k) => k,
            None => {
                return Err(CertExchangeError::InvalidPayloadError);
            }
        };

        // TODO: We could check the timestamp.

        // TODO: Parse the cert, and check it is signed by our authority.

        // TODO: Check the signature using public key in cert.

        // Then, if everything is ok...

        let resp = CertResponseHdr {
            timestamp: hello.timestamp,
            cert_fingerprint: [0; 20], // TODO
        };

        let mut buf = BytesMut::with_capacity(1024);
        buf.extend_from_slice(resp.as_bytes());


        // compute and append signature.
        let sig = b"fake-signature";
        buf.put(&sig[..]);

        Ok(buf.freeze())
    }

}





#[cfg(test)]
mod test {
    use super::*;


    #[test]
    fn test_km_cert_payload_create_and_process() {
        let exchange = KmCertExchange::new();
        let payload = match exchange.create_initiator_payload() {
            Ok(p) => p,
            Err(e) => { panic!("Error creating payload: {:?}", e) },
        };
        assert_eq!(payload.len(), 28);

        let resp = match exchange.process_initiator_payload(&payload) {
            Ok(p) => p,
            Err(e) => { panic!("Error handling payload: {:?}", e) },
        };
        assert_eq!(resp.len(), 42);
    }
}