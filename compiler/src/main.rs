pub mod polio {
    include!(concat!(env!("OUT_DIR"), "/polio.rs"));
}

mod allow;
mod compilation;
mod config;
mod crypto;
mod define;
mod errors;
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

use clap::Parser;
use std::path::PathBuf;

use compilation::Compilation;
use crypto::load_rsa_private_key;

/// ZPL Policy Compiler
///
/// Compile a ZPL policy (plus its configuration) into a binary format for the
/// visa service.
#[derive(Debug, Parser)]
#[command(name = "zpc")]
#[command(version = "1.0", verbatim_doc_comment)]
struct Cli {
    /// Path to the ZPL file.
    #[arg(value_name = "ZPL_FILE")]
    zpl: PathBuf,

    /// Path to a priate RSA key to sign the compiled policy with.
    #[arg(short, long, value_name = "FILE")]
    key: Option<PathBuf>,

    /// Load configuration from ZPLC_FILE instead of the default.
    #[arg(short = 'c', long = "config", value_name = "ZPLC_FILE")]
    zplc: Option<PathBuf>,

    /// Write output binary to existing directory DIR instead of default.
    #[arg(short = 'd', long = "outdir", value_name = "DIR")]
    outdir: Option<PathBuf>,

    /// Sets extra verbosity.
    #[arg(short, long)]
    verbose: bool,

    /// Only perform parsing step. Does not produce a binary policy.
    #[arg(short, long)]
    parse_only: bool,
}

fn main() {
    let mut exit_code = 0;
    let cli = Cli::parse();
    let mut cb = Compilation::builder(cli.zpl).verbose(cli.verbose);
    if cli.parse_only {
        cb = cb.parse_only(true);
    }
    if let Some(cfg) = cli.zplc {
        cb = cb.config(&cfg);
    }
    if let Some(outdir) = cli.outdir {
        cb = cb.output_directory(&outdir);
    }
    if let Some(key) = cli.key {
        let key = match load_rsa_private_key(&key) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("error loading private key: {}", e);
                std::process::exit(1);
            }
        };
        cb = cb.sign_with_key(key);
    }
    let comp = cb.build();
    match comp.compile() {
        Ok(_) => println!("ℤ done!"),
        Err(e) => {
            eprintln!("error: {}", e);
            exit_code = 1;
        }
    }
    std::process::exit(exit_code);
}
