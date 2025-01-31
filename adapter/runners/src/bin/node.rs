use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use thiserror::Error;

use runners::config::{ConfigRdr, PCErr};
use runners::sys;

const DEFAULT_NODE_CONFIG: &str = "node.toml";
const NODE_ADDR_KEY: &str = "agent_addr";
const TUN_NAME_KEY: &str = "tun_if";
const CONTROL_PATH_KEY: &str = "control_path";
const IPV4_MASK: u8 = 16;
const IPV6_MASK: u8 = 32;
const TUN_MTU: usize = 1400;

#[derive(Debug, Error)]
pub enum LaunchErr {
    #[error("config error: {0}")]
    PCError(#[from] PCErr),

    #[error("platform error: {0}")]
    PlatformError(#[from] sys::PlatformErr),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

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
    ph_bin: Option<String>,

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
    let mut exit_code = 0;
    let cli = Cli::parse();
    if sys::get_platform().has_root_perms() == false {
        eprintln!("this program must be run as root");
        if !cli.dry_run {
            std::process::exit(1);
        }
    }
    let node_config = match cli.node_config {
        Some(path) => path,
        None => PathBuf::from(DEFAULT_NODE_CONFIG),
    };
    let ph_bin = match cli.ph_bin {
        Some(bin) => bin,
        None => "ph".to_string(),
    };
    match configure_env(&node_config, cli.dry_run) {
        Ok(_) => match launch_node(&ph_bin, &node_config, cli.verbose, cli.dry_run) {
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

// Setup the environment for a successful PH run, includes:
// - create the parent directories for the control socket.
// - create the TUN interface if there isn't one already.
fn configure_env(config: &Path, dry_run: bool) -> Result<(), LaunchErr> {
    let rdr = ConfigRdr::new(config)?;

    // The control_path parent directories must exist. This can be set in the
    // config, or there is a default.
    let ctrl_path = match rdr.get_config_str_value_for_section_and_key("global", CONTROL_PATH_KEY) {
        Ok(Some(path)) => PathBuf::from(path),
        Ok(None) => sys::get_data_home(),
        Err(e) => return Err(LaunchErr::PCError(e)),
    };
    if dry_run {
        println!("mkdir -p {}", ctrl_path.display());
    } else {
        fs::create_dir_all(&ctrl_path)?;
    }

    let node_addr_str = rdr.must_get_config_str_value_for_key(NODE_ADDR_KEY)?;
    let node_addr = node_addr_str.parse::<IpAddr>().or(Err(PCErr::KeyError(
        "node_addr not valid IP address".to_string(),
    )))?;

    let mask = match node_addr {
        IpAddr::V4(_ipv4) => IPV4_MASK,
        IpAddr::V6(_ipv6) => IPV6_MASK,
    };

    let tun_name = match rdr.get_config_str_value_for_key(TUN_NAME_KEY)? {
        Some(name) => name,
        None => sys::get_platform().get_tun_ifname().to_string(),
    };

    // TODO: We could check self_addr setting and make sure that we have the
    //       address there on an interface.

    // If TUN already exists we could check to see if it has correct address etc.
    // But for now just notify.
    if sys::get_platform().is_tun_exist(&tun_name) {
        println!(
            "TUN interface {} already exists, skipping TUN configuration",
            tun_name
        );
    } else {
        // Create the tun interface, assign addresses etc.
        sys::get_platform().create_tun(&tun_name, node_addr, mask, TUN_MTU, dry_run)?;
    }

    Ok(())
}

fn launch_node(
    ph_bin: &str,
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
