use thiserror::Error;

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
}
