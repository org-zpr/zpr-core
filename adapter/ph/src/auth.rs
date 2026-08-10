//! This module implements the bootstrap authentication scheme which is used
//! when we need to join a ZPRnet but there are no authentication services
//! attached yet.  Also includes other "auth" related functionality.

use aws_lc_rs::signature::RsaKeyPair;
use libnode::rsa_sign::{load_rsa_key, sign_rsa_key};

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use zerocopy::byteorder::network_endian::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use rand::{TryRngCore, rngs::OsRng};
use reqwest::StatusCode;
use reqwest::header;
use reqwest::redirect::Policy;
use reqwest::tls::Certificate;

use base64::prelude::*;
use thiserror::Error;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pki::{Cert, get_cn_from_cert};

/// When a node signs a challenge for an adapter it uses this sort of key.
pub const AUTH_KEY_SIZE_BYTES: usize = 32; // blake3 256bit key

/// "self signed" blob type
pub const BLOB_TYPE_SS: &str = "SS";

/// Auth Code blob type
pub const BLOB_TYPE_AC: &str = "AC";

/// When checking a challenge returned to a node by an adapter, it may
/// be no older than this.
pub const MAX_BLOB_AGE_SECONDS: u64 = 120; // 2 minutes

// TODO: Not sure how we get these out or if we need them.
pub const HARD_CODED_BAS_TLS_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIFmzCCA4OgAwIBAgIUJSg4OHOfPqY+lD7ymZy6akX/ZZ8wDQYJKoZIhvcNAQEL
BQAwXTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAktZMRMwEQYDVQQHDApMb3Vpc3Zp
bGxlMQswCQYDVQQKDAJBSTEMMAoGA1UECwwDWlBSMREwDwYDVQQDDAhhdXRoLnpw
cjAeFw0yNTA0MTYxOTQ4MjRaFw0yNjA0MTYxOTQ4MjRaMF0xCzAJBgNVBAYTAlVT
MQswCQYDVQQIDAJLWTETMBEGA1UEBwwKTG91aXN2aWxsZTELMAkGA1UECgwCQUkx
DDAKBgNVBAsMA1pQUjERMA8GA1UEAwwIYXV0aC56cHIwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDl6DwVoQJsWAOTK4JWZYp3YL7b647ypIadVioKaGAk
1Fk4FwogcZG/tBqsxCCW+pv7FXfjbwp6ChrxUGaTZUGzF5ft5L7q4oqSKOHvL1i9
DiyU3xwk/biMiPTyuB8YYIiwQDiHAtYncJVMGMJPefDTl8OPNsjGQyJI+xuoBP/n
PhbNIgn6E8YxrNl0/u+xWHjM6iOe5bZhXH1nkJQ+hviTxAtRDfayGM0nXrkEzdkC
Aav95Kgp91cIa2lgoPpHm+HwQANp8jEPvsTVFMbwlPuFx9nopyXLzAdkgv9Z3+S3
W9ISFWdaAQ4TJDrWfAQyPgPy8UPLOzoK/TC9qbRx2QLQaY3v6+hurnWUm0cHAZ5n
zs8KflWXfRR+DA3Vc4aDF5vhT0IBDxs5rGu3/gtlJKwfwzMGDtprtuAXpXyZ48yM
f17WymXsamWDIN58cHjPWgLYoUsr87HtRFGVmlqvCBzaQf4zGCOoW5LWSlkzD2da
6ak3xBbogGExSk7RAhi9XLCl0LKfjTRsEGuAKpbGvt4h8i2Bq5YLmrzrqzI5XDYt
u3W1hWwSwwAzK6SHvYLyOMTI75UMy9Zsh4VoUJUNkYm4XgO0WFaA9bs5Cq73d1zY
i70s8jccheYhoAVXOWLDBQxCu2beHR7tkNXwyZ/RBhL/4/tyc+FKzF6C9sE9f6hv
EQIDAQABo1MwUTAdBgNVHQ4EFgQU+bscgkfPxWQLdX4AypBqXnzmvxwwHwYDVR0j
BBgwFoAU+bscgkfPxWQLdX4AypBqXnzmvxwwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEASZvKIbzeXKd1WuMmZT7kCywYqmWfgo7O51VNWni3FLdQ
5De44BGIOVUFn+0vC0xQQbQ4iM9yTMb27AQJGm9Aor92w9G7LvR6Mp5py16eJb+F
MSMZwN7PqK/QdnbIwiUGplDkKndd1dA/ZcHg5oJdE1areX0Zw8ZZ5yZoO12xnhc4
AK2Mop897EGSYHyrxidYbocPj5Bn7m3mVC7U2quh1HwnZzbWfpx9g8Ry4T8kUco3
dwZa2RHWhy2yrky2t3pg5tqaw79f/pXoTkcxvRSwZU3EcY23rq5OYQc7SLBIMm/a
n8ZSJIduRRTLNE7T6Y7o43jDU8u+tcfB5ZE9ytuJA/NgtIYeEiNHMRepYNI2pffj
MGELMS4xR3NIEyA6ZGVRBnI4dDr/3AmliOKKSt77iueSYCaPDBaxbbwcvEBBJtB0
TPzKFsY5IH5ve5pZu7IhHIbE/yrAicbNtfX487WQTZfY+Qo8bf+XbdQIcRzkD+Q4
VAvgJld9s5RI6x8CocU/PQvtQcWPFj//SbnnaMv2TTMLYgP+XWFwD1K1WQFpx2PK
YM6AGtFc6p9klbags4r80QK+yEwYiBaNjDKmiNfQ1J38HCmd9lnMbzt9p7T838fP
FiCJxns37RAqhGyryo9L0cryIEPwerjtNoLxmg94rfdovRmY+pm+HokRbD4Vycw=
-----END CERTIFICATE-----
"#;

/// This is the data payload in a [zdp::PacketType::InitAuthenticationRequest] packet.
#[derive(Clone, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Default)]
#[repr(packed)]
pub struct ZdpInitAuthenticationPayload {
    /// 8 bytes random data
    pub nonce: [u8; 8],

    /// Unix time seconds, big endian
    pub ctime: U64,

    /// blake3 hmac over nonce and ctime
    pub hmac: [u8; 32],
}

// Implement our own Debug to format the buffers in human friendly way.
impl std::fmt::Debug for ZdpInitAuthenticationPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let nonce_str = self
            .nonce
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");
        let hmac_str = self
            .hmac
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");
        write!(
            f,
            "ZdpInitAuthenticationPayload {{ nonce: [{}], ctime: {}, hmac: [{}] }}",
            nonce_str,
            self.ctime.get(),
            hmac_str,
        )
    }
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
#[derive(Serialize, Deserialize, Debug, Clone)]
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
pub enum AuthBlob {
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

    #[error("Authentication Error: {0}")]
    AuthError(String),
}

#[derive(Debug, Clone)]
pub struct RsaBootstrapAuth {
    pkey: Arc<RsaKeyPair>,
    cn: String,
}

/// OAuthRsa holds small amount of state needed to talk to a
/// zpr-oauthrsa authentication service.
#[derive(Debug, Clone)]
pub struct OAuthRsa {
    client_id: String,
    private_key: Arc<RsaKeyPair>,
}

impl ZdpAuthCodeBlob {
    /// Gets the "encoded" form of the blob: base64 encoded JSON.
    pub fn encode(&self) -> String {
        let json_txt = serde_json::to_string(self).unwrap();
        BASE64_STANDARD.encode(&json_txt)
    }
}

impl ZdpSelfSignedBlob {
    /// Gets the "encoded" form of the blob: base64 encoded JSON.
    pub fn encode(&self) -> String {
        let json_txt = serde_json::to_string(self).unwrap();
        BASE64_STANDARD.encode(&json_txt)
    }

    /// The `challenge` field in the blob is a base64 encoded [zdp::ZdpInitAuthenticationPayload].
    /// This extracts that data and checks that:
    ///   - The CN in the provided `peer_cert` matches the CN in the blob.
    ///   - The HMAC in the blob is valid for the provided `key`.
    ///   - The blob is not older than `MAX_BLOB_AGE_SECONDS`.
    pub fn verify_blob_challenge(
        &self,
        peer_cert: &Cert,
        key: &[u8; AUTH_KEY_SIZE_BYTES],
    ) -> Result<(), AuthError> {
        if let Some(link_cn) = get_cn_from_cert(peer_cert) {
            if link_cn != self.cn {
                return Err(AuthError::FormatError(format!(
                    "CN mismatch: expected {link_cn} found {}",
                    self.cn
                )));
            }
        } else {
            return Err(AuthError::FormatError("no CN in peer cert".to_string()));
        }

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
        OsRng
            .try_fill_bytes(&mut nonce)
            .expect("failed to generate random bytes for nonce");
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
}

/// Decode a blob string into a [AuthBlob] object.
/// The blob string is base64 encoded JSON which contains a "blob_type" field.
pub fn decode_blob(blob_str: &str) -> Result<AuthBlob, AuthError> {
    let json_txt = BASE64_STANDARD.decode(blob_str)?;

    let jobj: Value = serde_json::from_slice(&json_txt)?;
    let blob_type = jobj.get("blob_type").ok_or_else(|| {
        AuthError::FormatError(format!("missing blob_type field in blob: {}", blob_str))
    })?;

    match blob_type.as_str() {
        Some(BLOB_TYPE_SS) => {
            let ss_blob = serde_json::from_slice::<ZdpSelfSignedBlob>(&json_txt)?;
            Ok(AuthBlob::SelfSigned(ss_blob))
        }
        Some(BLOB_TYPE_AC) => {
            let ac_blob = serde_json::from_slice::<ZdpAuthCodeBlob>(&json_txt)?;
            Ok(AuthBlob::AuthCode(ac_blob))
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
        let pkey = load_rsa_key(&pemdata)
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

        let mut data = Vec::new();
        data.extend_from_slice(&ts.to_be_bytes());
        data.extend_from_slice(self.cn.as_bytes());
        data.extend_from_slice(&challenge);

        let signature = sign_rsa_key(&self.pkey, &data);

        let sig_str = BASE64_STANDARD.encode(&signature);

        let blob = ZdpSelfSignedBlob {
            blob_type: BLOB_TYPE_SS.to_string(),
            ts,
            cn: self.cn.clone(),
            challenge: BASE64_STANDARD.encode(&challenge),
            sig: sig_str,
        };
        Ok(blob.encode())
    }

    #[cfg(test)]
    pub fn cn(&self) -> &str {
        &self.cn
    }
}

/// Response json object to initial auth request from an actor
/// from a zpr-oauthrsa authentication service.
#[derive(Deserialize, Debug)]
struct PreauthResp {
    nonce: String,
}

/// Request json object from an actor to a zpr-oauthrsa authentication service.
/// Includes the nonce from preauth step and the payload which is the RSA
/// signature of the nonce.  The `client_id` must match one known to the
/// authentication service (for now we are using CNs here).
#[derive(Serialize, Debug)]
struct AuthReq {
    client_id: String,
    nonce: String,
    payload: String,
}

/// Implements the ZPR oauthrsa protocol.
///
/// Works like this:
/// - Adapter sends a GET request to /preauthorize with form encoded params in query string
///   of (response_type, client_id, scope, state).
/// - Service returns json object with a "nonce" field, a base64 encoded byte buffer.
/// - Adapter sends a POST to /authorize with a json object having fields: (client_id, nonce, payload).
///   `nonce` is copied from the service response.  `payload` is the base64 encoded signature of
///   the nonce using the adapters private RSA key.  The `client_id` (in the case of BAS) is
///   the CN of the adapter.
/// - The service response with an auth-code which will be part of a redirect `location` header.
///   The format is `https://auth.zpr?code=<CODE>`).
///
/// Once we have an auth-code back from the authentication service we can construct the
/// auth-code blob as:
/// - blob_type: "AC"
/// - code: "<CODE>" (the auth-code)
/// - pkce: empty for now
/// - client_id: the CN of the adapter
/// - asa: The ZPR address of the authentication service
///
/// The blob should be passed to the Node which will forward it to the visa service.
impl OAuthRsa {
    /// Create a new OAuthRsa object.
    /// - `client_id` is the adapter CN
    /// - `private_key` is the RSA private key used to sign the nonce
    pub fn new(client_id: &str, private_key: Arc<RsaKeyPair>) -> Self {
        OAuthRsa {
            client_id: client_id.to_string(),
            private_key,
        }
    }

    /// Performs the two calls to the authentication service and the signing of the nonce.
    /// On success returns the auth-code blob.
    /// - `service_addr` is the address of the authentication service
    /// - `tls_cert` is the TLS certificate used by the authentication service
    pub async fn authenticate(
        &self,
        service_addr: SocketAddr,
        tls_cert: Cert,
    ) -> Result<ZdpAuthCodeBlob, AuthError> {
        let der = tls_cert.to_der();
        let tls_cert = Certificate::from_der(der).unwrap();

        let nonce_buf = self.preauthorize(service_addr, &tls_cert).await?;

        let signature = sign_rsa_key(&self.private_key, &nonce_buf);

        let auth_code = self
            .authorize(service_addr, &tls_cert, &nonce_buf, &signature)
            .await?;

        Ok(ZdpAuthCodeBlob {
            blob_type: BLOB_TYPE_AC.to_string(),
            code: auth_code,
            pkce: String::new(),
            client_id: self.client_id.clone(),
            asa: service_addr.to_string(),
        })
    }

    /// Call preauthorize function on authentication service.
    /// Returns the nonce.
    async fn preauthorize(
        &self,
        service_addr: SocketAddr,
        tls_cert: &Certificate,
    ) -> Result<Vec<u8>, AuthError> {
        // See https://github.com/org-zpr/zpr-core/issues/861
        let cb = reqwest::ClientBuilder::new()
            .add_root_certificate(tls_cert.clone())
            .danger_accept_invalid_certs(true) // TODO: Figure this TLS stuff out and get rid of this
            .timeout(std::time::Duration::from_secs(10));
        let client = cb.build().unwrap();

        let resp = client
            .get(format!("https://{}/preauthorize", service_addr))
            .query(&[("response_type", "code"), ("client_id", &self.client_id)])
            .send()
            .await
            .map_err(|e| AuthError::AuthError(format!("failed to send request: {}", e)))?;

        let pa_resp: PreauthResp = resp
            .json()
            .await
            .map_err(|e| AuthError::AuthError(format!("failed to parse response: {}", e)))?;

        Ok(BASE64_STANDARD.decode(pa_resp.nonce.as_bytes())?)
    }

    /// Call the authorize function on the authentication service.
    /// Returns the auth-code.
    async fn authorize(
        &self,
        service_addr: SocketAddr,
        tls_cert: &Certificate,
        nonce: &[u8],
        payload: &[u8],
    ) -> Result<String, AuthError> {
        let authreq = AuthReq {
            client_id: self.client_id.clone(),
            nonce: BASE64_STANDARD.encode(nonce),
            payload: BASE64_STANDARD.encode(payload),
        };

        // Note client set to NOT follow redirects since that is how we get our response.
        let cb = reqwest::ClientBuilder::new()
            .add_root_certificate(tls_cert.clone())
            .danger_accept_invalid_certs(true) // TODO: Figure this TLS stuff out and get rid of this
            .redirect(Policy::none())
            .timeout(std::time::Duration::from_secs(10));
        let client = cb.build().unwrap();

        let resp = client
            .post(format!("https://{}/authorize", service_addr))
            .json(&authreq)
            .send()
            .await
            .map_err(|e| AuthError::AuthError(format!("failed to send POST request: {}", e)))?;

        // Expect status code FOUND
        if resp.status() != StatusCode::FOUND {
            return Err(AuthError::AuthError(format!(
                "failed to authorize: {}",
                resp.status()
            )));
        }

        // Now extract the auth-code from the location header.
        if let Some(loc) = resp.headers().get(header::LOCATION) {
            if let Ok(loc_str) = loc.to_str() {
                if loc_str.contains("error") {
                    // TODO: We could parse this URL and get error & error_description
                    return Err(AuthError::AuthError(format!(
                        "failed to authorize: {}",
                        loc_str
                    )));
                }
                if let Some(code) = loc_str.split("code=").nth(1) {
                    return Ok(code.to_string());
                } else {
                    return Err(AuthError::AuthError(format!(
                        "failed to find code in location header: {}",
                        loc_str
                    )));
                }
            } else {
                return Err(AuthError::AuthError(format!(
                    "failed to parse location header: {}",
                    loc.to_str().unwrap_or("invalid utf8")
                )));
            }
        } else {
            return Err(AuthError::AuthError(
                "failed to find location header in response".to_string(),
            ));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
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

        let mut data = Vec::new();
        data.extend_from_slice(&blob.ts.to_be_bytes());
        data.extend_from_slice(blob.cn.as_bytes());
        data.extend_from_slice(&challenge_buffer);

        let public_key =
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, bs.pkey.public_key().as_ref());
        public_key
            .verify(&data, &sig_data)
            .expect("signature verification failed");
    }
}
