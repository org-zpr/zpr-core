//! The ZPL compiler produces ZPR policy from a ZPL source file and associated
//! configuration.
//!
//! The crate produces a binary named `zpc` which is the command line interface to
//! the compiler.
//!
//! A library is also available for direct access.  See [compilation::CompilationBuilder].

// This lib.rs is here to allow the integration tests
// to use the modules in the src directory.

pub mod polio {
    include!(concat!(env!("OUT_DIR"), "/polio.rs"));
}

mod allow;
pub mod compilation;
mod config;
mod config_api;
mod context;
mod crypto;
mod define;
pub mod errors;
mod fabric;
mod fabric_util;
mod lex;
mod parser;
mod policybuilder;
mod protocols;
mod ptypes;
mod putil;
mod weaver;
mod zpl;
mod zplstr;
