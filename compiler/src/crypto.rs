use ring::digest::{self, Digest};
use std::path::Path;

use crate::errors::CompilationError;

pub fn sha256(data: &str) -> Digest {
    digest::digest(&digest::SHA256, data.as_bytes())
}

pub fn sha256_of_file(file: &Path) -> Result<Digest, CompilationError> {
    // read file into memory
    let data = std::fs::read(file).map_err(|e| {
        CompilationError::FileError(format!("failed to read file {:?}: {}", file, e))
    })?;
    Ok(digest::digest(&digest::SHA256, &data))
}

pub fn sha256_of_bytes(data: &[u8]) -> Digest {
    digest::digest(&digest::SHA256, data)
}

pub fn digest_as_hex(digest: &Digest) -> String {
    let mut s = String::new();
    for b in digest.as_ref() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
