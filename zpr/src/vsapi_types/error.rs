use thiserror::Error;

/// Error type
#[derive(Debug, Error)]
pub enum VsapiTypeError {
    #[error("Serialization error {0}")]
    SerializationError(&'static str),
    #[error("Deserialization error: {0:?}")]
    DeserializationError(&'static str),
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("Cap'n Proto error: {0}")]
    NotInSchema(#[from] capnp::NotInSchema),
    #[error("Cap'n Proto error: {0}")]
    Utf8Error(#[from] core::str::Utf8Error),
    #[error("Error code: {0:?}")]
    CodedError(crate::vsapi_types::ErrorCode),
    #[error("IP address conversion error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
}
