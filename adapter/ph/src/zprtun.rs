//! Common interface for the TUN devices.
//!
//! The actual TUN implementation is platform specific and can be found in `sys/<platform>/zprtun.rs`.
//! The loading code is in `sys.rs`.

/// Error type used by some ZPRTun functions across platform implementations.
#[derive(thiserror::Error, Debug)]
pub enum ZPRTunError {
    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("platform error from TUN device: {0}")]
    PlatformError(String),
}
