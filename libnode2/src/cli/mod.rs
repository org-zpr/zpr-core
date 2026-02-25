//! CLI modules for the lntest binary.
//!
//! This module is only compiled when the `build-lnt` feature is active. It
//! groups everything needed by `src/bin/lntest.rs` into focused sub-modules
//! and re-exports the types that `main()` needs directly.

pub mod args;
pub mod cmd;
pub mod crypto;
pub mod handler;
pub mod logging;
pub mod tui;

pub use args::{Args, Config};
pub use cmd::Cmd;
pub use handler::run_handler;
pub use logging::{LogBuffer, enable_logging};
pub use tui::{App, run_tui};
