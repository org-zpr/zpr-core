use std::{error, net::AddrParseError};
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
    #[error("AlreadyRunning")]
    AlreadyRunning,
}

#[derive(Debug, Error)]
pub enum VSClientError {
    #[error("RPC error: {0}")]
    RpcError(#[source] Box<dyn error::Error + Sync + Send>),
    #[error("Conn closed")]
    ConnClosed,
    #[error("No API key")]
    NoAPIKey,
    #[error("Unsupported traffic type")]
    UnsupportedTrafficType,
    #[error("Address error: {0}")]
    AddressError(String),
    #[error("IOError: {0}")]
    IOError(#[from] std::io::Error),
}

impl From<thrift::Error> for VSClientError {
    fn from(e: thrift::Error) -> Self {
        VSClientError::RpcError(Box::new(e))
    }
}

impl From<AddrParseError> for VSClientError {
    fn from(e: AddrParseError) -> Self {
        VSClientError::AddressError(format!("AddrParseError: {}", e))
    }
}