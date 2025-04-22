//! This module implements the bootstrap authentication scheme which is used
//! when we need to join a ZPRnet but there are no authentication services
//! attached yet.  The canonical use for this is to attach the first authentication
//! service.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Padding;
use openssl::sign::Signer;

use base64::prelude::*;
use thiserror::Error;

use zerocopy::byteorder::network_endian::*; // XXX
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned}; // XXX

use serde::{Deserialize, Serialize};

// XXX This struct from zdp is pending in another PR
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[allow(dead_code)]
#[repr(packed)]
pub struct ZdpInitAuthenticationPayload {
    pub flags: u8,
    pub nonce: [u8; 8],
    pub ctime: U64,
    pub hmac: [u8; 32],
}

/// "self signed" blob type
const BLOB_TYPE_SS: &str = "SS";

// Note that this passed around as JSON text encoded in base64.
#[derive(Serialize, Deserialize, Debug)]
pub struct ZdpSelfSignedBlob {
    pub blob_type: String, // "SS"
    pub ts: u64,
    pub cn: String,
    pub challenge: String, // byte buffer, base64 encoded
    pub sig: String,       // byte buffer, base64 encoded
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("OpenSSL Error: {0}")]
    OpenSSLError(String),

    #[error("I/O Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Serialization Error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct RsaBootstrapAuth {
    pkey: PKey<Private>,
    cn: String,
}

/// Implementes BootstrapAuth using our RSA signature scheme.
impl RsaBootstrapAuth {
    /// Create a new RsaBootstrapAuth object.
    /// The cn is the common name of the actor.
    /// The rsa_keyfile is the path to the PEM file containing the RSA private key.
    /// The visa service (policy) must be configured with the corresponding public key.
    pub fn new(cn: &str, rsa_keyfile: &Path) -> Result<Self, BootstrapError> {
        let pemdata = std::fs::read(rsa_keyfile)?;
        let pkey = PKey::private_key_from_pem(&pemdata)
            .map_err(|e| BootstrapError::OpenSSLError(format!("Failed to load RSA key: {}", e)))?;
        Ok(RsaBootstrapAuth {
            pkey,
            cn: cn.to_string(),
        })
    }

    /// The returned string is a "SelfSignedBlob" object serialized to JSON and then base64 encoded.
    ///
    /// The signature here is created by signing:
    ///  - the current timestamp (in seconds since the epoch)
    ///  - the common name (cn) of the actor
    ///  - the challenge from the ZDP server, which is the (nonce, ctime, hmac) all concatentated
    ///    together in a byte buffer.
    pub fn authenticate(
        &self,
        payload: &ZdpInitAuthenticationPayload,
    ) -> Result<String, BootstrapError> {
        // TODO: This could be an impl function in zdp
        let mut challenge = [0u8; 48];
        challenge[0..8].copy_from_slice(&payload.nonce);
        challenge[8..16].copy_from_slice(&payload.ctime.to_bytes());
        challenge[16..48].copy_from_slice(&payload.hmac);

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;

        let mut signer = Signer::new(MessageDigest::sha256(), &self.pkey)
            .map_err(|e| BootstrapError::OpenSSLError(format!("Failed to create signer: {}", e)))?;

        // Presumably this is PKCS1 v1.5 padding
        signer
            .set_rsa_padding(Padding::PKCS1)
            .map_err(|e| BootstrapError::OpenSSLError(format!("Failed to set padding: {}", e)))?;

        let ts_bytes = ts.to_be_bytes();
        signer
            .update(&ts_bytes)
            .map_err(|e| BootstrapError::OpenSSLError(format!("Failed to update signer: {}", e)))?;

        let cn_bytes = self.cn.clone().into_bytes();
        signer
            .update(&cn_bytes)
            .map_err(|e| BootstrapError::OpenSSLError(format!("Failed to update signer: {}", e)))?;

        signer
            .update(&challenge)
            .map_err(|e| BootstrapError::OpenSSLError(format!("Failed to update signer: {}", e)))?;

        let signature = signer
            .sign_to_vec()
            .map_err(|e| BootstrapError::OpenSSLError(format!("Failed to sign: {}", e)))?;

        let sig_str = BASE64_STANDARD.encode(&signature);

        let blob = ZdpSelfSignedBlob {
            blob_type: BLOB_TYPE_SS.to_string(),
            ts,
            cn: self.cn.clone(),
            challenge: BASE64_STANDARD.encode(&challenge),
            sig: sig_str,
        };

        let json_txt = serde_json::to_string(&blob)?;
        let blob_str = BASE64_STANDARD.encode(&json_txt);
        Ok(blob_str)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use openssl::sign::Verifier;
    use std::path::PathBuf;

    #[test]
    fn test_rsa_bootstrap_auth() {
        let mut keypath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        keypath.push("tests");
        keypath.push("data");
        keypath.push("rsa-key.pem");

        let cn = "test.cn.zpr";
        let bs = RsaBootstrapAuth::new(cn, &keypath).unwrap();

        let ctime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;

        let payload = ZdpInitAuthenticationPayload {
            flags: 0,
            nonce: [42u8; 8],
            ctime: ctime.into(),
            hmac: [24u8; 32],
        };

        let blob = bs.authenticate(&payload).unwrap();
        assert!(!blob.is_empty());

        let blob_json = BASE64_STANDARD.decode(&blob).unwrap();
        let blob = serde_json::from_slice::<ZdpSelfSignedBlob>(&blob_json).unwrap();

        assert_eq!(blob.blob_type, BLOB_TYPE_SS);
        assert!(blob.ts > 0);
        assert!(blob.ts >= ctime);
        assert_eq!(blob.cn, cn);

        let challenge_buffer = BASE64_STANDARD.decode(&blob.challenge).unwrap();
        assert_eq!(challenge_buffer.len(), 48);
        {
            // Challenge buffer layout:
            // [ 0..8 ] nonce
            // [ 8..16] ctime
            // [16..48] hmac
            for i in 0..8 {
                assert_eq!(challenge_buffer[i], payload.nonce[i]);
                assert_eq!(challenge_buffer[i + 8], payload.ctime.to_bytes()[i]);
            }
            for i in 0..32 {
                assert_eq!(challenge_buffer[i + 16], payload.hmac[i]);
            }
        }

        let sig_data = BASE64_STANDARD.decode(&blob.sig).unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &bs.pkey).unwrap();
        verifier.set_rsa_padding(Padding::PKCS1).unwrap();
        {
            let ts_bytes = blob.ts.to_be_bytes();
            verifier.update(&ts_bytes).unwrap();

            let cn_bytes = blob.cn.clone().into_bytes();
            verifier.update(&cn_bytes).unwrap();

            verifier.update(&challenge_buffer).unwrap();
        }
        assert!(verifier.verify(&sig_data).unwrap());
    }
}
