use std::net::IpAddr;

use crate::vsapi::v1;
use crate::vsapi_types::util::ip::ip_addr_from_vec;
use crate::vsapi_types::{Visa, VsapiTypeError};

#[derive(Debug)]
pub struct Connection {
    pub zpr_addr: IpAddr,
    pub auth_expires: u64,
}

#[derive(Debug)]
pub enum VisaResponse {
    Allow(Visa),
    Deny(Denied),
    VSApiError(VisaResponseError),
}

#[derive(Debug)]
pub struct Denied {
    pub code: DenyCode,
    pub reason: Option<String>,
}

// Will be more useful once we transition to capnp, right now we only use Fail
#[derive(Debug, Eq, PartialEq)]
pub enum DenyCode {
    Fail,
    NoReason,
    NoMatch,
    Denied,
    SourceNotFound,
    DestNotFound,
    SourceAuthError,
    DestAuthError,
    QuotaExceeded,
}

#[derive(Debug)]
pub struct VisaResponseError {
    pub code: ErrorCode,
    pub message: String,
    pub retry_in: u32,
}

#[derive(Debug)]
pub enum ErrorCode {
    Internal,
    AuthRequired,
    InvalidOperation,
    OutOfSync,
    NotFound,
    InvalidSignature,
    QuotaExceeded,
    TemporarilyUnavailable,
    AuthError,
    ParamError,
    UnknownStatusCode,
    Fail,
}

impl Denied {
    pub fn new(code: DenyCode, reason: Option<String>) -> Self {
        Self { code, reason }
    }
}

impl VisaResponseError {
    pub fn new(code: ErrorCode, message: String, retry_in: u32) -> Self {
        Self {
            code,
            message,
            retry_in,
        }
    }
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

impl TryFrom<v1::visa_response::Reader<'_>> for VisaResponse {
    type Error = VsapiTypeError;

    fn try_from(capnp_visa_response: v1::visa_response::Reader) -> Result<Self, Self::Error> {
        match capnp_visa_response.which()? {
            v1::visa_response::Which::Allow(v) => {
                let visa = v?;
                Ok(Self::Allow(visa.try_into()?))
            }
            v1::visa_response::Which::Deny(c) => {
                let deny_code = DenyCode::from(c?);
                Ok(Self::Deny(Denied::new(deny_code, None)))
            }
            v1::visa_response::Which::Error(e) => {
                let code = ErrorCode::from(e?.get_code()?);
                Err(VsapiTypeError::CodedError(code))
            }
        }
    }
}

impl From<v1::VisaDenyCode> for DenyCode {
    fn from(code: v1::VisaDenyCode) -> Self {
        match code {
            v1::VisaDenyCode::NoReason => DenyCode::NoReason,
            v1::VisaDenyCode::NoMatch => DenyCode::NoMatch,
            v1::VisaDenyCode::Denied => DenyCode::Denied,
            v1::VisaDenyCode::SourceNotFound => DenyCode::SourceNotFound,
            v1::VisaDenyCode::DestNotFound => DenyCode::DestNotFound,
            v1::VisaDenyCode::SourceAuthError => DenyCode::SourceAuthError,
            v1::VisaDenyCode::DestAuthError => DenyCode::DestAuthError,
            v1::VisaDenyCode::QuotaExceeded => DenyCode::QuotaExceeded,
        }
    }
}

impl From<DenyCode> for v1::VisaDenyCode {
    fn from(code: DenyCode) -> Self {
        match code {
            DenyCode::NoReason => v1::VisaDenyCode::NoReason,
            DenyCode::NoMatch => v1::VisaDenyCode::NoMatch,
            DenyCode::Denied => v1::VisaDenyCode::Denied,
            DenyCode::SourceNotFound => v1::VisaDenyCode::SourceNotFound,
            DenyCode::DestNotFound => v1::VisaDenyCode::DestNotFound,
            DenyCode::SourceAuthError => v1::VisaDenyCode::SourceAuthError,
            DenyCode::DestAuthError => v1::VisaDenyCode::DestAuthError,
            DenyCode::QuotaExceeded => v1::VisaDenyCode::QuotaExceeded,
            DenyCode::Fail => v1::VisaDenyCode::NoReason, // No direct mapping (TODO: remove Fail)
        }
    }
}

impl From<v1::ErrorCode> for ErrorCode {
    fn from(code: v1::ErrorCode) -> Self {
        match code {
            v1::ErrorCode::Internal => ErrorCode::Internal,
            v1::ErrorCode::AuthRequired => ErrorCode::AuthRequired,
            v1::ErrorCode::InvalidOperation => ErrorCode::InvalidOperation,
            v1::ErrorCode::OutOfSync => ErrorCode::OutOfSync,
            v1::ErrorCode::NotFound => ErrorCode::NotFound,
            v1::ErrorCode::InvalidSignature => ErrorCode::InvalidSignature,
            v1::ErrorCode::QuotaExceeded => ErrorCode::QuotaExceeded,
            v1::ErrorCode::TemporarilyUnavailable => ErrorCode::TemporarilyUnavailable,
            v1::ErrorCode::AuthError => ErrorCode::AuthError,
            v1::ErrorCode::ParamError => ErrorCode::ParamError,
        }
    }
}

impl TryFrom<vsapi::VisaResponse> for VisaResponse {
    type Error = VsapiTypeError;

    fn try_from(thrift_visa_response: vsapi::VisaResponse) -> Result<Self, Self::Error> {
        match thrift_visa_response.status {
            Some(code) => match code {
                vsapi::StatusCode::SUCCESS => {
                    if let Some(thrift_visa_hop) = thrift_visa_response.visa {
                        let visa = Visa::try_from(thrift_visa_hop)?;
                        Ok(Self::Allow(visa))
                    } else {
                        Err(VsapiTypeError::DeserializationError(
                            "No VisaHop in VisaResponse",
                        ))
                    }
                }
                vsapi::StatusCode::FAIL => Ok(Self::Deny(Denied::new(
                    DenyCode::Fail,
                    thrift_visa_response.reason,
                ))),
                _ => {
                    return Err(VsapiTypeError::DeserializationError("Unknown status code"));
                }
            },
            None => Err(VsapiTypeError::DeserializationError(
                "No code, required in Thrift visa",
            )),
        }
    }
}
