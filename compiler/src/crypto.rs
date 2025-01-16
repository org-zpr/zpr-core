//! Various and sundry crypto utilities that the compiler needs.

use ring::digest::{self, Digest};

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::X509;

use std::path::Path;

use crate::errors::CompilationError;

/// Create SHA256 digest of given string.
pub fn sha256(data: &str) -> Digest {
    digest::digest(&digest::SHA256, data.as_bytes())
}

/// Create SHA256 digest of contents of given file.
pub fn sha256_of_file(file: &Path) -> Result<Digest, CompilationError> {
    // read file into memory
    let data = std::fs::read(file).map_err(|e| {
        CompilationError::FileError(format!("failed to read file {:?}: {}", file, e))
    })?;
    Ok(digest::digest(&digest::SHA256, &data))
}

/// Create SHA256 digest of given byte array.
pub fn sha256_of_bytes(data: &[u8]) -> Digest {
    digest::digest(&digest::SHA256, data)
}

/// Convert a `ring::digest::Digest` to a hex string.
pub fn digest_as_hex(digest: &Digest) -> String {
    let mut s = String::new();
    for b in digest.as_ref() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Load a PEM certifiate file and return the ASN.1 data in DER encoding.
/// Passed file should start with `-----BEGIN CERTIFICATE-----`.
pub fn load_asn1data_from_pem(pem_file: &Path) -> Result<Vec<u8>, CompilationError> {
    let pdata = std::fs::read(pem_file).map_err(|e| {
        CompilationError::FileError(format!(
            "failed to read certificate file {:?}: {}",
            pem_file, e
        ))
    })?;
    let cert = match X509::from_pem(&pdata) {
        Ok(c) => c,
        Err(e) => {
            return Err(CompilationError::FileError(format!(
                "error constructing cert from PEM data {}: {}",
                pem_file.display(),
                e
            )));
        }
    };
    Ok(cert.to_der().map_err(|e| {
        CompilationError::FileError(format!("error converting certificate to DER format: {}", e))
    })?)
}

/// Load a private key from a PEM file.
/// This should be an RSA private key suitable for signing (NOT just a noise key).
/// File must begin with `-----BEGIN PRIVATE KEY-----`.
#[allow(dead_code)]
pub fn load_rsa_private_key(pem_file: &Path) -> Result<Rsa<Private>, CompilationError> {
    let pdata = std::fs::read(pem_file).map_err(|e| {
        CompilationError::FileError(format!(
            "failed to read private key file {:?}: {}",
            pem_file, e
        ))
    })?;
    let key = match Rsa::private_key_from_pem(&pdata) {
        Ok(k) => k,
        Err(e) => {
            return Err(CompilationError::FileError(format!(
                "error constructing private key from PEM data {}: {}",
                pem_file.display(),
                e
            )));
        }
    };
    Ok(key)
}

/// Sign a byte array using PKCS1v15 with SHA256.
pub fn sign_pkcs1v15_sha256(key: &Rsa<Private>, data: &[u8]) -> Result<Vec<u8>, CompilationError> {
    let private_key = PKey::from_rsa(key.clone()).map_err(|e| {
        CompilationError::CryptoError(format!("error converting RSA key to PKey: {}", e))
    })?;
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key)
        .map_err(|e| CompilationError::CryptoError(format!("error creating signer: {}", e)))?;
    signer
        .update(data)
        .map_err(|e| CompilationError::CryptoError(format!("error updating signer: {}", e)))?;
    signer
        .sign_to_vec()
        .map_err(|e| CompilationError::CryptoError(format!("error signing data: {}", e)))
}
