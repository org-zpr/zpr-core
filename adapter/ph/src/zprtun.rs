//! Common interface for the TUN devices.
//!
//! The actual TUN implementation is platform specific and can be found in `sys/<platform>/zprtun.rs`.
//!
//!
//!
use crate::sys::TunPi;

#[allow(dead_code)]
pub const DEFAULT_TUN_MTU: u16 = 1400;

/// Error type used by some ZPRTun functions across platform implementations.
#[derive(thiserror::Error, Debug)]
pub enum ZPRTunError {
    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("platform error from TUN device: {0}")]
    PlatformError(String),
}

/// TRUE if the platform TUN implementation supports per-packet packet info.
pub const TUN_HAS_PI: bool = TunPi::PI_SIZE > 0;
