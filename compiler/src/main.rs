mod allow;
mod compilation;
mod config;
mod define;
mod errors;
mod lex;
mod parser;
mod protocols;
mod ptypes;
mod putil;
mod zplstr;

use clap::Parser;
use std::path::PathBuf;

use compilation::Compilation;

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

    /// Sets extra verbosity.
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let mut exit_code = 0;
    let cli = Cli::parse();
    let mut cb = Compilation::builder(cli.zpl).verbose(cli.verbose);
    if let Some(cfg) = cli.zplc {
        cb = cb.config(&cfg);
    }
    let comp = cb.build();
    match comp.compile() {
        Ok(_) => println!("compiled ok"),
        Err(e) => {
            eprintln!("error: {}", e);
            exit_code = 1;
        }
    }
    std::process::exit(exit_code);
}
