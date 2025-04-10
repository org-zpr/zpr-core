use thiserror::Error;

use crate::config::PCErr;
use crate::sys;

#[derive(Debug, Error)]
pub enum LaunchErr {
    #[error("config error: {0}")]
    PCError(#[from] PCErr),

    #[error("platform error: {0}")]
    PlatformError(#[from] sys::PlatformErr),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("file error: {0}")]
    FileError(String),

    #[error("environment error: {0}")]
    EnvironmentErr(String),
}
