#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::TunPi;
#[cfg(target_os = "linux")]
pub use self::linux::ZprTun;

#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::TunPi;
#[cfg(target_os = "macos")]
pub use self::macos::ZprTun;
