use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;

use runners::errors::LaunchErr;
use runners::runner::runner;
use runners::sys;

const DEFAULT_ADAPTER_CONFIG: &str = "adapter.toml";

/// Wrapper to help starting a ZPR adapter. Invokes the packet handler (ph) after
/// setting up required network interface.
///
/// This is an intentionally limited and simple way to launch the packet
/// handler. For more complex scenarios, consider using the `ph` binary
/// directly.
///
#[derive(Debug, Parser)]
#[command(name = "adapter")]
#[command(version = "1.0", verbatim_doc_comment)]
struct Cli {
    /// Path to the packet handler (ph) binary. Only needed if it is not on the PATH.
    ph_bin: Option<PathBuf>,

    /// Path to the adapter configuration file. By default we expect to find a file named "adapter.toml" in the current directory.
    #[arg(short = 'c', long, value_name = "FILE")]
    adapter_config: Option<PathBuf>,

    /// Turns on all debug logging (same as running ph with "--debug all")
    #[arg(short, long)]
    verbose: bool,

    /// Just print out what would be done, do not actually do it.
    #[arg(long)]
    dry_run: bool,
}

fn main() {
    let cli: Cli = Cli::parse();
    let adapter_config = match cli.adapter_config {
        Some(path) => path,
        None => PathBuf::from(DEFAULT_ADAPTER_CONFIG),
    };
    let res = runner(
        cli.ph_bin,
        &adapter_config,
        cli.dry_run,
        launch_adapter,
        cli.verbose,
    );
    if let Err(e) = res {
        eprintln!("launch error: {}", e);
        std::process::exit(1);
    }
}

fn launch_adapter(
    ph_bin: &Path,
    config_file: &Path,
    verbose: bool,
    dry_run: bool,
) -> Result<(), LaunchErr> {
    let mut cmd = Command::new(ph_bin);
    cmd.arg("adapter").arg("-c").arg(config_file);
    if verbose {
        cmd.arg("--debug").arg("all");
    }
    println!("launching adapter");
    sys::get_platform().exec(cmd, dry_run)?;
    Ok(())
}
