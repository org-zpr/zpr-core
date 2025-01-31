use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;

use runners::errors::LaunchErr;
use runners::runner::runner;
use runners::sys;

const DEFAULT_NODE_CONFIG: &str = "node.toml";

/// Wrapper to help starting a ZPR node. Invokes the packet handler (ph) after
/// setting up required network interface.
///
/// This is an intentionally limited and simple way to launch the packet
/// handler. For more complex scenarios, consider using the `ph` binary
/// directly.
///
#[derive(Debug, Parser)]
#[command(name = "node")]
#[command(version = "1.0", verbatim_doc_comment)]
struct Cli {
    /// Path to the packet handler (ph) binary. Only needed if it is not on the PATH.
    ph_bin: Option<PathBuf>,

    /// Path to the node configuration file. By default we expect to find a file named "node.toml" in the current directory.
    #[arg(short = 'c', long, value_name = "FILE")]
    node_config: Option<PathBuf>,

    /// Turns on all debug logging (same as running ph with "--debug all")
    #[arg(short, long)]
    verbose: bool,

    /// Just print out what would be done, do not actually do it.
    #[arg(long)]
    dry_run: bool,
}

fn main() {
    let cli: Cli = Cli::parse();
    let node_config = match cli.node_config {
        Some(path) => path,
        None => PathBuf::from(DEFAULT_NODE_CONFIG),
    };
    let res = runner(
        cli.ph_bin,
        &node_config,
        cli.dry_run,
        launch_node,
        cli.verbose,
    );
    if let Err(e) = res {
        eprintln!("launch error: {}", e);
        std::process::exit(1);
    }
}

fn launch_node(
    ph_bin: &Path,
    config_file: &Path,
    verbose: bool,
    dry_run: bool,
) -> Result<(), LaunchErr> {
    let mut cmd = Command::new(ph_bin);
    cmd.arg("node").arg("-c").arg(config_file);
    if verbose {
        cmd.arg("--debug").arg("all");
    }
    println!("launching node");
    sys::get_platform().exec(cmd, dry_run)?;
    Ok(())
}
