use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::vsapi_types::AuthBlob;
use crate::vsapi_types::VsapiTypeError;
use crate::vsapi_types::ZprSelfSignedBlob;
use crate::vsapi_types::util::ip::ip_addr_from_vec;

#[derive(Debug)]
pub struct ConnectRequest {
    pub blobs: Vec<AuthBlob>,
    pub claims: Vec<Claim>,
    pub substrate_addr: IpAddr,
    pub dock_interface: u8,
}

#[derive(Debug)]
pub struct Claim {
    pub key: String,
    pub value: String,
}

impl Claim {
    pub fn new(key: String, value: String) -> Self {
        Self { key, value }
    }
}

impl TryFrom<vsapi::ConnectRequest> for ConnectRequest {
    type Error = VsapiTypeError;

    fn try_from(thrift_req: vsapi::ConnectRequest) -> Result<Self, Self::Error> {
        let substrate_addr = match thrift_req.dock_addr {
            Some(val) => ip_addr_from_vec(val)?,
            None => return Err(VsapiTypeError::DeserializationError("No dock address")),
        };
        let claims = match thrift_req.claims {
            Some(claims) => {
                let mut v = Vec::new();
                for (key, val) in claims.iter() {
                    v.push(Claim::new(key.clone(), val.clone()));
                }
                v
            }
            None => return Err(VsapiTypeError::DeserializationError("No claims")),
        };
        let blobs = match thrift_req.challenge_responses {
            Some(cr) => {
                let mut b = Vec::new();
                for r in cr {
                    let mut ss = ZprSelfSignedBlob::default();
                    ss.challenge = r;
                    b.push(AuthBlob::SS(ss))
                }
                b
            }
            None => {
                return Err(VsapiTypeError::DeserializationError(
                    "No challenge responses",
                ));
            }
        };
        Ok(Self {
            blobs,
            claims,
            substrate_addr,
            dock_interface: 0,
        })
    }
}

impl TryFrom<ConnectRequest> for vsapi::ConnectRequest {
    type Error = VsapiTypeError;

    fn try_from(req: ConnectRequest) -> Result<Self, Self::Error> {
        let mut claims = BTreeMap::new();
        for claim in req.claims {
            claims.insert(claim.key, claim.value);
        }

        let mut challenge_responses = Vec::new();
        for blob in req.blobs {
            match blob {
                AuthBlob::SS(ss) => challenge_responses.push(ss.challenge),
                AuthBlob::AC(_) => {
                    return Err(VsapiTypeError::DeserializationError("Incorrect blob type"));
                }
            }
        }

        let dock_addr = match req.substrate_addr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        Ok(Self {
            connection_id: Some(0),
            dock_addr: Some(dock_addr),
            claims: Some(claims),
            challenge: None,
            challenge_responses: Some(challenge_responses),
        })
    }
}
