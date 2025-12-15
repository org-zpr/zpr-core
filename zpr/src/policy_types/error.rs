use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttributeError {
    #[error("Invalid attribute domain: {0}")]
    InvalidDomain(String),

    #[error("Invalid attribute: {0}")]
    ParseError(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

#[derive(Debug, Error)]
pub enum PolicyTypeError {
    #[error("attribute error: {0}")]
    AttributeError(#[from] AttributeError),
}
