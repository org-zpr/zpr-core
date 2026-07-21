//! Cryptographic helpers used by lntest for key loading and self-signed blob construction.

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use rand::{TryRngCore, rngs::OsRng};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zpr::vsapi_types::{ChallengeAlg, SelfSignedBlob};

/// Build a [SelfSignedBlob] signed with the given private key.
///
/// Generates a fresh 32-byte random challenge, timestamps it, signs the
/// concatenation of `(timestamp_be || cn_bytes || challenge)` with SHA-256
/// RSA PKCS#1 v1.5, and returns the completed blob.
pub fn build_self_signed_blob(
    cn: &str,
    private_key: &PKey<Private>,
) -> Result<SelfSignedBlob, Box<dyn std::error::Error>> {
    let mut challenge = vec![0u8; 32];
    OsRng.try_fill_bytes(&mut challenge)?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut data = Vec::new();
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(cn.as_bytes());
    data.extend_from_slice(&challenge);

    let mut signer = Signer::new(MessageDigest::sha256(), private_key)?;
    signer.update(&data)?;
    let raw_signature = signer.sign_to_vec()?;

    Ok(SelfSignedBlob {
        alg: ChallengeAlg::RsaSha256Pkcs1v15,
        challenge,
        cn: cn.to_string(),
        timestamp,
        signature: raw_signature,
    })
}

/// Load an RSA private key from a PEM file.
pub fn load_private_key(keyfile: &Path) -> Result<PKey<Private>, Box<dyn std::error::Error>> {
    let key_data = fs::read(keyfile)?;
    let rsa = Rsa::private_key_from_pem(&key_data)?;
    let pkey = PKey::from_rsa(rsa)?;
    Ok(pkey)
}
