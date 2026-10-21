//! This module implements the bootstrap authentication scheme which is used
//! when we need to join a ZPRnet but there are no authentication services
//! attached yet.  Also includes other "auth" related functionality.

use aws_lc_rs::signature::RsaKeyPair;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use zerocopy::byteorder::network_endian::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use reqwest::StatusCode;
use reqwest::header;
use reqwest::redirect::Policy;
use reqwest::tls::Certificate;

use base64::prelude::*;
use thiserror::Error;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_cert::Certificate as X509Certificate;
use zpr_utils::rsa_sign::{load_rsa_key, sign_rsa_key};

use crate::pki;

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

    #[error("authentication rejected: {0}")]
    Rejected(String),

    #[error("authentication service request failed: {0}")]
    Service(#[from] reqwest::Error),
}

fn check_auth_status(status: StatusCode) -> Result<(), AuthError> {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        Err(AuthError::Rejected(format!("HTTP {status}")))
    } else if status.is_client_error() || status.is_server_error() {
        Err(AuthError::AuthError(format!(
            "authentication service HTTP {status}"
        )))
    } else {
        Ok(())
    }
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
    ///   - Actor identity is independent of the link certificate. The visa
    ///     service authenticates the blob CN through its RSA signature.
    ///   - The HMAC in the blob is valid for the provided `key`.
    ///   - The blob is not older than `MAX_BLOB_AGE_SECONDS`.
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
        aws_lc_rs::rand::fill(&mut nonce).expect("failed to generate random bytes for nonce");
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
        AuthError::FormatError("authentication evidence has no blob_type field".into())
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
        _ => Err(AuthError::FormatError(
            "unsupported authentication evidence type".into(),
        )),
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
        let pkey = Arc::new(
            load_rsa_key(&pemdata)
                .map_err(|e| AuthError::OpenSSLError(format!("Failed to load RSA key: {}", e)))?,
        );
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
        tls_cert: X509Certificate,
        source_addr: std::net::IpAddr,
    ) -> Result<ZdpAuthCodeBlob, AuthError> {
        let der = pki::to_der(&tls_cert)
            .map_err(|e| AuthError::FormatError(format!("cannot encode TLS certificate: {e}")))?;
        let tls_cert = Certificate::from_der(&der).unwrap();

        let nonce_buf = self
            .preauthorize(service_addr, &tls_cert, source_addr)
            .await?;

        let signature = sign_rsa_key(&self.private_key, &nonce_buf);

        let auth_code = self
            .authorize(service_addr, &tls_cert, &nonce_buf, &signature, source_addr)
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
        source_addr: std::net::IpAddr,
    ) -> Result<Vec<u8>, AuthError> {
        // See https://github.com/org-zpr/zpr-core/issues/861
        let cb = reqwest::ClientBuilder::new()
            .local_address(source_addr)
            .add_root_certificate(tls_cert.clone())
            .danger_accept_invalid_certs(true) // TODO: Figure this TLS stuff out and get rid of this
            .timeout(std::time::Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .get(format!("https://{}/preauthorize", service_addr))
            .query(&[("response_type", "code"), ("client_id", &self.client_id)])
            .send()
            .await?;
        check_auth_status(resp.status())?;

        let pa_resp: PreauthResp = resp.json().await?;

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
        source_addr: std::net::IpAddr,
    ) -> Result<String, AuthError> {
        let authreq = AuthReq {
            client_id: self.client_id.clone(),
            nonce: BASE64_STANDARD.encode(nonce),
            payload: BASE64_STANDARD.encode(payload),
        };

        // Note client set to NOT follow redirects since that is how we get our response.
        let cb = reqwest::ClientBuilder::new()
            .local_address(source_addr)
            .add_root_certificate(tls_cert.clone())
            .danger_accept_invalid_certs(true) // TODO: Figure this TLS stuff out and get rid of this
            .redirect(Policy::none())
            .timeout(std::time::Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .post(format!("https://{}/authorize", service_addr))
            .json(&authreq)
            .send()
            .await?;
        check_auth_status(resp.status())?;

        // Expect status code FOUND
        if resp.status() != StatusCode::FOUND {
            return Err(AuthError::AuthError(format!(
                "failed to authorize: {}",
                resp.status()
            )));
        }

        let location = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AuthError::FormatError("missing or invalid OAuth Location".into()))?;
        parse_auth_redirect(location)
    }
}

fn parse_auth_redirect(location: &str) -> Result<String, AuthError> {
    let url = reqwest::Url::parse(location)
        .map_err(|_| AuthError::FormatError("invalid OAuth redirect URL".into()))?;
    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
    if let Some(error) = params.get("error") {
        return Err(match error.as_ref() {
            "access_denied" | "invalid_client" | "unauthorized_client" | "invalid_grant" => {
                AuthError::Rejected("OAuth credentials or access denied".into())
            }
            _ => AuthError::AuthError("OAuth service could not authorize request".into()),
        });
    }
    params
        .get("code")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| AuthError::FormatError("OAuth redirect has no authorization code".into()))
}

#[cfg(test)]
mod test {
    use super::*;
    use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use std::path::PathBuf;

    #[test]
    fn evidence_errors_do_not_disclose_authorization_codes() {
        let blob = BASE64_STANDARD.encode(br#"{"code":"private-authorization-code"}"#);
        let error = decode_blob(&blob).unwrap_err().to_string();
        assert!(!error.contains(&blob));
        assert!(!error.contains("private-authorization-code"));
    }

    #[test]
    fn expired_bootstrap_challenge_is_rejected() {
        let key = [42; 32];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut challenge = ZdpInitAuthenticationPayload {
            nonce: [1; 8],
            ctime: (now - MAX_BLOB_AGE_SECONDS - 1).into(),
            hmac: [0; 32],
        };
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(&challenge.nonce);
        hasher.update(&challenge.ctime.to_bytes());
        challenge.hmac = hasher.finalize().into();
        let blob = ZdpSelfSignedBlob {
            blob_type: BLOB_TYPE_SS.into(),
            ts: now,
            cn: "actor.identity".into(),
            challenge: BASE64_STANDARD.encode(challenge.as_bytes()),
            sig: String::new(),
        };
        assert!(matches!(
            blob.verify_blob_challenge(&key),
            Err(AuthError::ChallengeTooOld)
        ));
    }

    #[test]
    fn authentication_status_classification() {
        for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
            assert!(matches!(
                check_auth_status(status),
                Err(AuthError::Rejected(_))
            ));
        }
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(matches!(
                check_auth_status(status),
                Err(AuthError::AuthError(_))
            ));
        }
        assert!(check_auth_status(StatusCode::FOUND).is_ok());
    }

    #[test]
    fn oauth_redirect_classification_and_decoding() {
        assert_eq!(
            parse_auth_redirect("https://auth.zpr/?state=abc&code=a%2Bb%2Fc%3D").unwrap(),
            "a+b/c="
        );
        for error in [
            "access_denied",
            "invalid_client",
            "unauthorized_client",
            "invalid_grant",
        ] {
            assert!(matches!(
                parse_auth_redirect(&format!("https://auth.zpr/?error={error}")),
                Err(AuthError::Rejected(_))
            ));
        }
        assert!(matches!(
            parse_auth_redirect("https://auth.zpr/?error=temporarily_unavailable"),
            Err(AuthError::AuthError(_))
        ));
        for invalid in [
            "not a url",
            "https://auth.zpr/?code=",
            "https://auth.zpr/?state=x",
        ] {
            assert!(matches!(
                parse_auth_redirect(invalid),
                Err(AuthError::FormatError(_))
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn external_https_authentication_uses_the_authentication_source() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

        let keypath = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/rsa-key.pem");
        let bootstrap = RsaBootstrapAuth::new("actor.identity", &keypath).unwrap();
        let public_key = bootstrap.pkey.public_key().as_ref().to_vec();
        let auth = OAuthRsa::new("actor.identity", bootstrap.pkey);
        let cert_pem = include_bytes!("../../../integration-test/pregen/zpr-rsa-cert.pem");
        let key_pem = include_bytes!("../../../integration-test/pregen/zpr-rsa-key.pem");
        let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from_pem_slice(cert_pem).unwrap()],
            PrivateKeyDer::from_pem_slice(key_pem).unwrap(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service = listener.local_addr().unwrap();
        let source: std::net::IpAddr = "127.0.0.2".parse().unwrap();
        let server = async {
            for preauthorize in [true, false] {
                let (stream, peer) = listener.accept().await.unwrap();
                assert_eq!(peer.ip(), source);
                let mut stream = acceptor.accept(stream).await.unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    assert!(headers.len() < 8192);
                    headers.push(stream.read_u8().await.unwrap());
                }
                let headers = String::from_utf8(headers).unwrap();
                let content_len = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|value| value.parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; content_len];
                stream.read_exact(&mut body).await.unwrap();
                if preauthorize {
                    assert!(headers.starts_with("GET /preauthorize?"));
                    assert!(headers.contains("client_id=actor.identity"));
                    let body = r#"{"nonce":"AQID"}"#;
                    stream.write_all(format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ).as_bytes()).await.unwrap();
                } else {
                    assert!(headers.starts_with("POST /authorize "));
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["client_id"], "actor.identity");
                    assert_eq!(body["nonce"], "AQID");
                    let signature = BASE64_STANDARD
                        .decode(body["payload"].as_str().unwrap())
                        .unwrap();
                    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public_key)
                        .verify(&[1, 2, 3], &signature)
                        .unwrap();
                    stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://auth.zpr/?code=auth%2Bcode\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                }
                stream.shutdown().await.unwrap();
            }
        };
        let request = async {
            auth.authenticate(service, pki::from_pem(cert_pem).unwrap(), source)
                .await
                .unwrap()
        };
        let ((), blob) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(server, request)
        })
        .await
        .unwrap();
        assert_eq!(blob.blob_type, BLOB_TYPE_AC);
        assert_eq!(blob.client_id, "actor.identity");
        assert_eq!(blob.asa, service.to_string());
        assert_eq!(blob.code, "auth+code");
        let asm = Arc::new(crate::assembly::test::create_assembly(
            crate::assembly::test::TestAssemblyBuilder::new(),
        ));
        let req = crate::visa_mgmt::build_connect_request(
            &asm,
            zpr_utils::net_defs::IpAddress::UNSPECIFIED,
            &AuthBlob::AuthCode(blob),
            None,
        )
        .unwrap();
        let [zpr::vsapi_types::AuthBlob::AC(evidence)] = req.blobs.as_slice() else {
            panic!("expected auth-code evidence for the visa service");
        };
        assert_eq!(evidence.asa_addr, service.ip());
        assert_eq!(evidence.code, "auth+code");
        assert_eq!(evidence.client_id, "actor.identity");
    }

    #[test]
    fn bootstrap_challenge_is_bound_to_link_key_not_actor_name() {
        let keypath = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/rsa-key.pem");
        let bootstrap = RsaBootstrapAuth::new("actor.not.transport.identity", &keypath).unwrap();
        let link_key = [42; 32];
        let challenge = ZdpInitAuthenticationPayload::new(&link_key);
        let AuthBlob::SelfSigned(blob) =
            decode_blob(&bootstrap.authenticate(&challenge).unwrap()).unwrap()
        else {
            panic!("expected self-signed evidence");
        };
        assert!(blob.verify_blob_challenge(&link_key).is_ok());
        assert!(blob.verify_blob_challenge(&[43; 32]).is_err());
        assert_eq!(blob.cn, "actor.not.transport.identity");
    }

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
