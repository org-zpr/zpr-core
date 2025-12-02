use thiserror::Error;
use zpr::vsapi_types::VsapiTypeError;

#[derive(Debug, Error)]
pub enum VSApiError {
    #[error("VS API connection is closed")]
    ConnClosed,

    #[error("command failed: {0}")]
    CommandFailed(String),

    #[error("VS API authentication failed: {0}")]
    AuthFailed(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("VS API error code {0}: {1} (retry in {2} seconds)")]
    CodedError(u16, String, u32),

    #[error("capn proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("capn proto not in schema: {0}")]
    CapnpNotInSchema(#[from] capnp::NotInSchema),

    #[error("string conversion error: {0}")]
    StringConversion(#[from] std::str::Utf8Error),

    #[error("serialization error: {0}")]
    DTError(#[from] DTError),

    #[error("vsapi type error: {0}")]
    ApiTypeError(#[from] VsapiTypeError),
}

#[derive(Debug, Error)]
pub enum DTError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("capn proto not in schema: {0}")]
    CapnpNotInSchema(#[from] capnp::NotInSchema),
}
