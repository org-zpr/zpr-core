use std::fmt;
use std::fmt::Formatter;

#[derive(Debug)]
pub enum VSError {
    ClientError(VSClientError),
    IOError(std::io::Error),
    CertificateError(String),
    KeyError(String),
    EnqueueError,
    Disconnect,
}

impl From<VSClientError> for VSError {
    fn from(e: VSClientError) -> Self {
        VSError::ClientError(e)
    }
}

impl From<std::io::Error> for VSError {
    fn from(e: std::io::Error) -> Self {
        VSError::IOError(e)
    }
}

impl fmt::Display for VSError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VSError::ClientError(e) => write!(f, "ClientError: {}", e),
            VSError::IOError(e) => write!(f, "IOError: {}", e),
            VSError::CertificateError(s) => write!(f, "CertificateError: {}", s),
            VSError::KeyError(s) => write!(f, "KeyError: {}", s),
            VSError::EnqueueError => write!(f, "EnqueueError"),
            VSError::Disconnect => write!(f, "Disconnect"),
        }
    }
}

#[derive(Debug)]
pub enum VSClientError {
    Thrift(thrift::Error),
    NoAPIKey,
    UnsupportedTrafficType,
}

impl fmt::Display for VSClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VSClientError::Thrift(e) => write!(f, "Thrift error: {}", e),
            VSClientError::NoAPIKey => write!(f, "No API key"),
            VSClientError::UnsupportedTrafficType => write!(f, "Unsupported traffic type"),
        }
    }
}

impl From<thrift::Error> for VSClientError {
    fn from(e: thrift::Error) -> Self {
        VSClientError::Thrift(e)
    }
}
