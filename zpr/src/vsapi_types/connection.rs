use std::net::IpAddr;

use crate::vsapi_types::ErrorCode;
use crate::vsapi_types::VsapiTypeError;
use crate::vsapi_types::util::ip::ip_addr_from_vec;

#[derive(Debug)]
pub struct Connection {
    pub zpr_addr: IpAddr,
    pub auth_expires: u64,
}

impl TryFrom<vsapi::ConnectResponse> for Connection {
    type Error = VsapiTypeError;

    fn try_from(resp: vsapi::ConnectResponse) -> Result<Self, Self::Error> {
        match resp.status {
            Some(vsapi::StatusCode::FAIL) => Err(VsapiTypeError::CodedError(ErrorCode::Fail)),
            Some(vsapi::StatusCode::SUCCESS) => match resp.actor {
                Some(actor) => {
                    if actor.zpr_addr.is_some() && actor.auth_expires.is_some() {
                        return Ok(Self {
                            zpr_addr: ip_addr_from_vec(actor.zpr_addr.unwrap())?,
                            auth_expires: actor.auth_expires.unwrap() as u64,
                        });
                    } else {
                        return Err(VsapiTypeError::DeserializationError(
                            "Required fields not set",
                        ));
                    }
                }
                None => return Err(VsapiTypeError::DeserializationError("No actor")),
            },
            _ => Err(VsapiTypeError::DeserializationError(
                "No matching status code",
            )),
        }
    }
}
