use std::net::IpAddr;

/// Blob passed with a ConnectRequest
#[derive(Debug)]
pub enum AuthBlob {
    SS(ZprSelfSignedBlob),
    AC(AuthCodeBlob),
}

#[derive(Debug, Default)]
pub struct ZprSelfSignedBlob {
    pub alg: ChallengeAlg,
    pub challenge: Vec<u8>,
    pub cn: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct AuthCodeBlob {
    pub asa_addr: IpAddr,
    pub code: String,
    pub pkce: String,
    pub client_id: String,
}

#[derive(Debug, Default)]
pub enum ChallengeAlg {
    #[default]
    RsaSha256Pkcs1v15,
}
