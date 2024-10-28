//! Platform specific implementations.
//! - ZprTun - TUN device management

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

mod platform {
    #[cfg(target_os = "linux")]
    pub use super::linux::ZprTun;

    #[cfg(target_os = "macos")]
    pub use super::macos::ZprTun;
}

/// Can be accessed in the project as `crate::sys::ZprTun`
pub use platform::ZprTun;
