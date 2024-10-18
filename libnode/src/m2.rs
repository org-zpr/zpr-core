use crate::vsapi;
use openssl::hash::{Hasher, MessageDigest};
use std::io::prelude::*;

/// Create the milestone 2 version of the auth HMAC used in the node challenge response.
///
/// The prototype version of this is HMAC(challenge + timestamp + session_id) using the RSA private key.
///
/// For milestone two we just create a SHA256 hash of (challenge + timestamp + session_id). No auth at all.
pub fn milestone2_create_hmac(chal: vsapi::Challenge, session_id: i32, timestamp: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.write_all(&chal.challenge_data.unwrap()).unwrap();
    buf.write_all(&timestamp.to_be_bytes()).unwrap();
    buf.write_all(&session_id.to_be_bytes()).unwrap();

    let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
    hasher.update(&buf).unwrap();
    let dig = hasher.finish().unwrap();
    (&dig).to_vec()
}
