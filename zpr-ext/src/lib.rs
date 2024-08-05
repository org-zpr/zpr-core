/// Various "extensions" to external crates.
pub mod std;

#[cfg(feature = "tokio")]
pub mod tokio;

#[cfg(feature = "tokio-tun")]
pub mod tokio_tun;

#[cfg(feature = "zerocopy")]
pub mod zerocopy;
