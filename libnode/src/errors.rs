use thiserror::Error;

#[derive(Debug, Error)]
pub enum VSError {
    #[error("ClientError: {0}")]
    ClientError(#[from] VSClientError),
    #[error("IOError: {0}")]
    IOError(#[from] std::io::Error),
    #[error("CertificateError: {0}")]
    CertificateError(String),
    #[error("KeyError: {0}")]
    KeyError(String),
    #[error("EnqueueError")]
    EnqueueError,
    #[error("Disconnect")]
    Disconnect,
}

#[derive(Debug, Error)]
pub enum VSClientError {
    #[error("Thrift error: {0}")]
    Thrift(#[from] thrift::Error),
    #[error("No API key")]
    NoAPIKey,
    #[error("Unsupported traffic type")]
    UnsupportedTrafficType,
}
