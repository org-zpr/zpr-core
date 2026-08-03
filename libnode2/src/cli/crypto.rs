//! Cryptographic helpers used by lntest for key loading and self-signed blob construction.

use crate::rsa_sign::{load_rsa_key, sign_rsa_key};
use aws_lc_rs::signature::RsaKeyPair;
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
    private_key: &RsaKeyPair,
) -> Result<SelfSignedBlob, Box<dyn std::error::Error>> {
    let mut challenge = vec![0u8; 32];
    aws_lc_rs::rand::fill(&mut challenge)?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut data = Vec::new();
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(cn.as_bytes());
    data.extend_from_slice(&challenge);

    let raw_signature = sign_rsa_key(private_key, &data);

    Ok(SelfSignedBlob {
        alg: ChallengeAlg::RsaSha256Pkcs1v15,
        challenge,
        cn: cn.to_string(),
        timestamp,
        signature: raw_signature,
    })
}

/// Load an RSA private key from a PEM file.
pub fn load_private_key(
    keyfile: &Path,
) -> Result<RsaKeyPair, Box<dyn std::error::Error + Send + Sync>> {
    let key_data = fs::read(keyfile)?;
    Ok(load_rsa_key(&key_data)?)
}
