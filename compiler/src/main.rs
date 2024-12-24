mod compilation;
mod lex;
mod parser;
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
    let cli = Cli::parse();

    let comp = Compilation::builder(cli.zpl).verbose(cli.verbose).build();

    comp.compile();

    println!("ready");
}
