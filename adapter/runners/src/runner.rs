use std::path::{Path, PathBuf};

use crate::env::configure_env;
use crate::errors::LaunchErr;
use crate::sys;
use crate::zpr;

/// Launching function.
/// Args:
/// - ph_bin: Path to the packet handler binary.
/// - config_file: Path to the configuration file.
/// - verbose: Enable verbose output.
/// - dry_run: Do not actually launch the process, just print what would be done.
///
/// Usually does not return. If it does, it means the launch failed.
type LaunchF = fn(&Path, &Path, bool, bool) -> Result<(), LaunchErr>;

/// Launch a node or adapter. Caller provides the launching function.
pub fn runner(
    alt_ph_bin: Option<PathBuf>,
    config_file: &Path,
    dry_run: bool,
    launcher: LaunchF,
    verbose: bool,
) -> Result<(), LaunchErr> {
    if sys::get_platform().has_root_perms() == false {
        eprintln!("this program must be run as root");
        if !dry_run {
            std::process::exit(1);
        }
    }
    let ph_bin = match alt_ph_bin {
        Some(bin) => bin,
        None => PathBuf::from(zpr::PH_BIN.to_string()),
    };
    let mut exit_code = 0;
    match configure_env(config_file, dry_run) {
        Ok(_) => match launcher(&ph_bin, config_file, verbose, dry_run) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Error: {}", e);
                exit_code = 1;
            }
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            exit_code = 1;
        }
    }
    std::process::exit(exit_code);
}
