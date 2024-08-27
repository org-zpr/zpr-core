//! Various "extensions" to external crates.
//!
//! The module structure here mirrors that of each individual crate.
//!
//! Most of the extensions are in the form of traits named as
//! `FooExt`, where `Foo` is the type or trait which is being extended.

pub mod std;

#[cfg(feature = "bytes")]
pub mod bytes;

#[cfg(feature = "tokio")]
pub mod tokio;

#[cfg(feature = "tokio-tun")]
pub mod tokio_tun;

#[cfg(feature = "zerocopy")]
pub mod zerocopy;
