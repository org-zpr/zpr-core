//! The ZPL compiler produces ZPR policy from a ZPL source file and associated
//! configuration.
//!
//! The crate produces a binary named `zpc` which is the command line interface to
//! the compiler.
//!
//! A library is also available for direct access.  See [compilation::CompilationBuilder].

// This lib.rs is here to allow the integration tests
// to use the modules in the src directory.

mod allow;
pub mod compilation;
mod define;
pub mod errors;
mod lex;
mod parser;
mod ptypes;
mod putil;
mod zplstr;
