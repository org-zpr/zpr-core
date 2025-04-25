//! This module implements the bootstrap authentication scheme which is used
//! when we need to join a ZPRnet but there are no authentication services
//! attached yet.  Also includes other "auth" related functionality.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use zerocopy::byteorder::network_endian::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::rsa::Padding;
use openssl::sign::Signer;

use base64::prelude::*;
use thiserror::Error;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// When a node signs a challenge for an adapter it uses this sort of key.
pub const AUTH_KEY_SIZE_BYTES: usize = 32; // blake3 256bit key

/// "self signed" blob type
pub const BLOB_TYPE_SS: &str = "SS";

/// Auth Code blob type
pub const BLOB_TYPE_AC: &str = "AC";

/// When checking a challenge returned to a node by an adapter, it may
/// be no older than this.
pub const MAX_BLOB_AGE_SECONDS: u64 = 120; // 2 minutes

/// This is the data payload in a [zdp::PacketType::InitAuthenticationRequest] packet.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Debug)]
#[repr(packed)]
pub struct ZdpInitAuthenticationPayload {
    /// 8 bytes random data
    pub nonce: [u8; 8],

    /// Unix time seconds, big endian
    pub ctime: U64,

    /// blake3 hmac over nonce and ctime
    pub hmac: [u8; 32],
}

/// The "self signed" authentication BLOB which originates on an adatper and is
/// passed to a node via a [zdp::PacketType::AcquireZprAddressRequest]
/// message.
///
/// Note that this passed around as JSON text encoded in base64.
#[derive(Serialize, Deserialize, Debug)]
pub struct ZdpSelfSignedBlob {
    pub blob_type: String, // "SS"
    pub ts: u64,
    pub cn: String,
    pub challenge: String, // byte buffer, base64 encoded
    pub sig: String,       // byte buffer, base64 encoded
}

/// The "Auth Code" authentication BLOB which originates on an adatper and is
/// passed to a node via a [zdp::PacketType::AcquireZprAddressRequest]
/// message.
///
/// Note that this passed around as JSON text encoded in base64.
#[derive(Serialize, Deserialize, Debug)]
pub struct ZdpAuthCodeBlob {
    pub blob_type: String, // "AC"
    pub code: String,
    pub pkce: String,
    pub client_id: String,
    pub asa: String,
}

/// Enum used to return different blob types based on their blob_type field.
#[allow(dead_code)]
#[derive(Debug)]
pub enum DecodedBlob {
    SelfSigned(ZdpSelfSignedBlob),
    AuthCode(ZdpAuthCodeBlob),
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("OpenSSL Error: {0}")]
    OpenSSLError(String),

    #[error("I/O Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Serialization Error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Format error: {0}")]
    FormatError(String),

    #[error("Invalid Base64: {0}")]
    DecodeError(#[from] base64::DecodeError),

    #[error("Invalid HMAC")]
    InvalidHmac,

    #[error("Challenge Too Old")]
    ChallengeTooOld,
}

#[derive(Debug)]
pub struct RsaBootstrapAuth {
    pkey: PKey<Private>,
    cn: String,
}

impl ZdpAuthCodeBlob {
    /// Placeholder function that returns a fake AuthCode blob.
    /// Returns base64 encoded JSON serialized [ZdpAuthCodeBlob].
    pub fn new_fake() -> Self {
        ZdpAuthCodeBlob {
            blob_type: BLOB_TYPE_AC.to_string(),
            code: "fake_auth_code".to_string(),
            pkce: "fake_pkce".to_string(),
            client_id: "fake_clientid".to_string(),
            asa: "fake_asa".to_string(),
        }
    }

    /// Gets the "encoded" form of the blob: base64 encoded JSON.
    pub fn encode(&self) -> String {
        let json_txt = serde_json::to_string(self).unwrap();
        BASE64_STANDARD.encode(&json_txt)
    }
}

impl ZdpSelfSignedBlob {
    /// The `challenge` field in the blob is a base64 encoded [zdp::ZdpInitAuthenticationPayload].
    /// This extracts that data and checks it.
    pub fn verify_blob_challenge(&self, key: &[u8; AUTH_KEY_SIZE_BYTES]) -> Result<(), AuthError> {
        let payload_bytes = BASE64_STANDARD.decode(self.challenge.clone())?;
        if payload_bytes.len() != size_of::<ZdpInitAuthenticationPayload>() {
            return Err(AuthError::FormatError(format!(
                "challenge size is incorrect"
            )));
        }
        let zpayload = match ZdpInitAuthenticationPayload::read_from_bytes(&payload_bytes) {
            Ok(zpayload) => zpayload,
            Err(e) => {
                return Err(AuthError::FormatError(format!(
                    "failed to deserialize ZdpInitAuthenticationPayload: {e}"
                )));
            }
        };

        let hash_ok = {
            let mut hasher = blake3::Hasher::new_keyed(&key);
            hasher.update(&zpayload.nonce);
            hasher.update(&zpayload.ctime.to_bytes());
            let computed_hmac = hasher.finalize();
            let presented_hmac = blake3::Hash::from_bytes(zpayload.hmac);
            computed_hmac == presented_hmac
        };

        if !hash_ok {
            return Err(AuthError::InvalidHmac);
        }

        // Now can check age of blob.
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;

        if now > zpayload.ctime.get() + MAX_BLOB_AGE_SECONDS {
            return Err(AuthError::ChallengeTooOld);
        }

        Ok(())
    }
}

impl ZdpInitAuthenticationPayload {
    pub fn new(key: &[u8; AUTH_KEY_SIZE_BYTES]) -> Self {
        let ctime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;
        let be_time = ctime.to_be_bytes();
        let mut nonce = [0u8; 8];
        rand_bytes(&mut nonce).expect("failed to generate random bytes for nonce");
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(&nonce);
        hasher.update(&be_time);
        let hmac = hasher.finalize();
        ZdpInitAuthenticationPayload {
            nonce,
            ctime: ctime.into(),
            hmac: hmac.into(),
        }
    }

    pub fn new_empty() -> Self {
        ZdpInitAuthenticationPayload {
            nonce: [0u8; 8],
            ctime: 0.into(),
            hmac: [0u8; 32],
        }
    }
}

pub fn decode_blob(blob_str: &str) -> Result<DecodedBlob, AuthError> {
    let json_txt = BASE64_STANDARD.decode(blob_str)?;

    let jobj: Value = serde_json::from_slice(&json_txt)?;
    let blob_type = jobj.get("blob_type").ok_or_else(|| {
        AuthError::FormatError(format!("missing blob_type field in blob: {}", blob_str))
    })?;

    match blob_type.as_str() {
        Some(BLOB_TYPE_SS) => {
            let ss_blob = serde_json::from_slice::<ZdpSelfSignedBlob>(&json_txt)?;
            Ok(DecodedBlob::SelfSigned(ss_blob))
        }
        Some(BLOB_TYPE_AC) => {
            let ac_blob = serde_json::from_slice::<ZdpAuthCodeBlob>(&json_txt)?;
            Ok(DecodedBlob::AuthCode(ac_blob))
        }
        _ => Err(AuthError::FormatError(format!(
            "unknown blob_type: {:?}",
            blob_type
        ))),
    }
}

/// Implementes BootstrapAuth using our RSA signature scheme.
impl RsaBootstrapAuth {
    /// Create a new RsaBootstrapAuth object.
    /// The `cn` is the common name of the actor.
    /// The `rsa_keyfile` is the path to the PEM file containing the RSA private key.
    /// The visa service (policy) must be configured with the corresponding public key.
    pub fn new(cn: &str, rsa_keyfile: &Path) -> Result<Self, AuthError> {
        let pemdata = std::fs::read(rsa_keyfile)?;
        let pkey = PKey::private_key_from_pem(&pemdata)
            .map_err(|e| AuthError::OpenSSLError(format!("Failed to load RSA key: {}", e)))?;
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
    ) -> Result<String, AuthError> {
        // TODO: Check the payload.flags?
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
            .map_err(|e| AuthError::OpenSSLError(format!("Failed to create signer: {}", e)))?;

        // Presumably this is PKCS1 v1.5 padding
        signer
            .set_rsa_padding(Padding::PKCS1)
            .map_err(|e| AuthError::OpenSSLError(format!("Failed to set padding: {}", e)))?;

        let ts_bytes = ts.to_be_bytes();
        signer
            .update(&ts_bytes)
            .map_err(|e| AuthError::OpenSSLError(format!("Failed to update signer: {}", e)))?;

        let cn_bytes = self.cn.clone().into_bytes();
        signer
            .update(&cn_bytes)
            .map_err(|e| AuthError::OpenSSLError(format!("Failed to update signer: {}", e)))?;

        signer
            .update(&challenge)
            .map_err(|e| AuthError::OpenSSLError(format!("Failed to update signer: {}", e)))?;

        let signature = signer
            .sign_to_vec()
            .map_err(|e| AuthError::OpenSSLError(format!("Failed to sign: {}", e)))?;

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
