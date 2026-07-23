//! RSA signinging helpers using aws-lc-rs

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use std::sync::Arc;

//Wrapped potential errors
type BoxError = Box<dyn std::error::Error + Send + Sync>;

//Parses to create RSA key pair
pub fn load_rsa_key(pem_bytes: &[u8]) -> Result<Arc<RsaKeyPair>, BoxError> {
    let block = pem::parse(pem_bytes)?;
    let key = match block.tag() {
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(block.contents())?,
        "PRIVATE KEY" => RsaKeyPair::from_pkcs8(block.contents())?,
        other => return Err(format!("unsupported PEM tag: {other}").into()),
    };
    Ok(Arc::new(key))
}

//Signs RSA key pair padded with aws_lc_rs::rand random bytes
pub fn sign_rsa_key(key: &RsaKeyPair, msg: &[u8]) -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut signature = vec![0u8; key.public_modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut signature)
        .expect("RSA signing failed");
    signature
}
