//! RSA signinging helpers using aws-lc-rs

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use std::io::Cursor;
use std::sync::Arc;
use x509_parser::pem::Pem;

//Wrapped potential errors
type BoxError = Box<dyn std::error::Error + Send + Sync>;

//Parses to create RSA key pair
pub fn load_rsa_key(pem_bytes: &[u8]) -> Result<Arc<RsaKeyPair>, BoxError> {
    let (block, _) = Pem::read(Cursor::new(pem_bytes))?;
    let key = match block.label.as_str() {
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(block.contents.as_slice())?,
        "PRIVATE KEY" => RsaKeyPair::from_pkcs8(block.contents.as_slice())?,
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

#[cfg(test)]
mod test {
    use super::*;
    use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    const RSA_PKCS1_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvgrBRb2Cx4OQpNv7XYruH2x19fthTpD5qAkuZQTdnC0XnwEz
etomiRPQJzmUjPrBejRqmoE3BLlbrFbfJFyIkBliIC0ZNdsFdIwAGtD0km8biHYC
ZQMMcM+WOc0kITgeWmu3K32s1/BJKjBd6I/VchLsErHBb3Wa1hEGOezIP5pMQt1m
QrfLjKEZ5xTfW9DZF8ykCaJG4ZCqJfbmvDdU9B4Cn/apqFEjtdtAhskqcXgE9tLV
BbM4Dxv9BBE1rlZdZaJeKsaRPyz5aLr6eSCFYAdPxqjQRtWNCViX8rCQkyyv9URB
lND6sPZpMBSXx1Ja63HM+gEgCgq5XGJlV8xUcwIDAQABAoIBACQGF+LnbI3zU4zc
okZ2GnNcdPPe5fAlrR18OA4wIO4E4jBi4uZLyfg8CD4XPSCIO/q1SuvkyJAdrtH5
Wa0j2UMvfJlK0zeRP/R6wV5T87h6VUbFz+hj7ozH3NsyFsIxSBetyXf2B7ibNNNJ
fdOiyDwqeBOHHHrLWUFw0rRSPRdJDP3GlVc6+wZBO6SbwNRBaQk0pnrwhd2xONoa
g1hjHkAnZYNxOb7Tjl/ry9W1xWinpWuhr7cbSn9GTCvOGiTnypoOMlmYygAhxXIV
N+9G7IsyhjNk+cgkJX9/59nQyJOJdpw5cFGNhHErWghyRakLtX8Ao4wF1FMmZZFB
qjsh6ZECgYEA/I+xEKxI3dn5GR52tKWYV9sINzAQgYY5U6V7r/DO4Vy/Y43qNKyG
9aywJnYddEkkyV6Z35qlUrMR8m/g/v/A/rZBKWbsYHLL3p6PVXI92EVmwLwXRIR5
aHKY/fc3IFzhF1vPNvYjmQNV1oItaXTk6GkO6HXq6G/uRlf6nTrfIhkCgYEAwKEm
n7GrR+5JlYxlbUrqW3kHR9PhwB5CqG2o3qkmVNHMLLnV8p98Laz4Kp9nC/oFLBJm
GfAc97/3bJAPsmfnK0DZJpd7kmT6eF5seUSluXx89l28CKfMj6t4gBXMBdpjNWdx
cdcU878luxf7NWzBbhWz2JInUFSr5mcRDsH8NGsCgYEA5/KfTwyqrvSsjKEpq6YZ
TzZdSTHfNtUqeOOVwHOLy/T94FRJL67zE1VRQUFgs5cpLbav4meIRXcnmFufaxE/
Ea4YEgnwNHO5P+6m/HY6zhCO2ZrkU4zGY2I7l6IfAp3KK0Wp/HP5JWGmx6YuRpeQ
UtGJW3xQDMAfOIM8KoISwqECgYEAv3Kqv4bGc9wpeB+sYr5VRAp6qPG16cppd5pd
fsbgmOZWpZEhSV0m/wJtN3dr5CReZZn3rgnN0JITJ+vaHfdUctGlwMxHfY0svtsh
tjj6+On4DKfGjVewYI4MWkjPmHWfqmEgCAO7CDJPHq7L9iIb8PxS3YkM17L/kiOX
eXJk5fcCgYAFxYX+jVrP82D1Ily8rSBTnC+258HAgTEr8dMbzwZvfQ2R/qtmpmNI
OfxFtTBGAUz6ZEO1bmPvE2mqWDQ89BhktKjFEYrJLpoX+dqUiVwXN8pFsfKM3fIv
bvVvsKU1O617lDXVElw6gl5mmuzbl1NrTRCtZIUQEWvdbzXhCj2wbQ==
-----END RSA PRIVATE KEY-----
"#;

    const RSA_PKCS8_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+CsFFvYLHg5Ck
2/tdiu4fbHX1+2FOkPmoCS5lBN2cLRefATN62iaJE9AnOZSM+sF6NGqagTcEuVus
Vt8kXIiQGWIgLRk12wV0jAAa0PSSbxuIdgJlAwxwz5Y5zSQhOB5aa7crfazX8Ekq
MF3oj9VyEuwSscFvdZrWEQY57Mg/mkxC3WZCt8uMoRnnFN9b0NkXzKQJokbhkKol
9ua8N1T0HgKf9qmoUSO120CGySpxeAT20tUFszgPG/0EETWuVl1lol4qxpE/LPlo
uvp5IIVgB0/GqNBG1Y0JWJfysJCTLK/1REGU0Pqw9mkwFJfHUlrrccz6ASAKCrlc
YmVXzFRzAgMBAAECggEAJAYX4udsjfNTjNyiRnYac1x0897l8CWtHXw4DjAg7gTi
MGLi5kvJ+DwIPhc9IIg7+rVK6+TIkB2u0flZrSPZQy98mUrTN5E/9HrBXlPzuHpV
RsXP6GPujMfc2zIWwjFIF63Jd/YHuJs000l906LIPCp4E4ccestZQXDStFI9F0kM
/caVVzr7BkE7pJvA1EFpCTSmevCF3bE42hqDWGMeQCdlg3E5vtOOX+vL1bXFaKel
a6GvtxtKf0ZMK84aJOfKmg4yWZjKACHFchU370bsizKGM2T5yCQlf3/n2dDIk4l2
nDlwUY2EcStaCHJFqQu1fwCjjAXUUyZlkUGqOyHpkQKBgQD8j7EQrEjd2fkZHna0
pZhX2wg3MBCBhjlTpXuv8M7hXL9jjeo0rIb1rLAmdh10SSTJXpnfmqVSsxHyb+D+
/8D+tkEpZuxgcsveno9Vcj3YRWbAvBdEhHlocpj99zcgXOEXW8829iOZA1XWgi1p
dOToaQ7oderob+5GV/qdOt8iGQKBgQDAoSafsatH7kmVjGVtSupbeQdH0+HAHkKo
bajeqSZU0cwsudXyn3wtrPgqn2cL+gUsEmYZ8Bz3v/dskA+yZ+crQNkml3uSZPp4
Xmx5RKW5fHz2XbwIp8yPq3iAFcwF2mM1Z3Fx1xTzvyW7F/s1bMFuFbPYkidQVKvm
ZxEOwfw0awKBgQDn8p9PDKqu9KyMoSmrphlPNl1JMd821Sp445XAc4vL9P3gVEkv
rvMTVVFBQWCzlykttq/iZ4hFdyeYW59rET8RrhgSCfA0c7k/7qb8djrOEI7ZmuRT
jMZjYjuXoh8CncorRan8c/klYabHpi5Gl5BS0YlbfFAMwB84gzwqghLCoQKBgQC/
cqq/hsZz3Cl4H6xivlVECnqo8bXpyml3ml1+xuCY5lalkSFJXSb/Am03d2vkJF5l
mfeuCc3QkhMn69od91Ry0aXAzEd9jSy+2yG2OPr46fgMp8aNV7BgjgxaSM+YdZ+q
YSAIA7sIMk8ersv2Ihvw/FLdiQzXsv+SI5d5cmTl9wKBgAXFhf6NWs/zYPUiXLyt
IFOcL7bnwcCBMSvx0xvPBm99DZH+q2amY0g5/EW1MEYBTPpkQ7VuY+8TaapYNDz0
GGS0qMURiskumhf52pSJXBc3ykWx8ozd8i9u9W+wpTU7rXuUNdUSXDqCXmaa7NuX
U2tNEK1khRARa91vNeEKPbBt
-----END PRIVATE KEY-----
"#;

    fn load_sign_verify(pem: &str) {
        let key = load_rsa_key(pem.as_bytes()).expect("key should load");
        let msg = b"the quick brown fox";
        let sig = sign_rsa_key(&key, msg);
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key().as_ref());
        public.verify(msg, &sig).expect("signature should verify");
    }

    #[test]
    fn loads_pkcs1_traditional() {
        load_sign_verify(RSA_PKCS1_PEM);
    }

    #[test]
    fn loads_pkcs8() {
        load_sign_verify(RSA_PKCS8_PEM);
    }

    #[test]
    fn rejects_unsupported_tag() {
        let pem = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";
        assert!(load_rsa_key(pem.as_bytes()).is_err());
    }
}
