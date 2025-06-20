//! ZPR Packet Handler command line arg processing structs.
//!
//! The main entry point is [crate::main_argparse::argparse] which will parse the command line arguments
//! and any config file, returning a PH configuration.

use crate::auth::AuthError;
use crate::logging::targets::*;
use clap::{Args, Parser, Subcommand};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

/// Errors you may encounter when trying to parse command line or configuration
/// file.
#[derive(thiserror::Error, Debug)]
pub enum ArgsError {
    #[error("missing argument: {0}")]
    Missing(String),

    #[error("{0}")]
    IOError(#[from] std::io::Error),

    #[error("{0}")]
    ParseError(String),

    #[error("{0}")]
    PathError(String),

    #[error("bootstrap config error: {0}")]
    AuthError(#[from] AuthError),
}

/// ZPR Packet Handler
///
/// You can run the packet hander as a node or an adapter.  You can specify a configuration
/// file and you can override configuration file settings with command line arguments.
///
/// Eg, start a node:
///    sudo ./ph node -c node_config.toml
///
/// Eg, start an adapter:
///    sudo ./ph adapter -c adapter_config.toml
///
/// Eg, start an adapter and point it at a specific node:
///    sudo ./ph adapter -c adapter_config.toml --node-addr 10.1.0.8:12345
///
/// Eg, override the name of the node (which may or may not be also set in the config file):
///    sudo ./ph node -c node_config.toml
///
#[derive(Debug, Parser)]
#[command(version, verbatim_doc_comment)]
pub struct Control {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug)]
pub struct CommonArgs {
    /// Unix domain socket path for the "control" interface
    #[arg(long, value_name = "DOMAIN_SOCKET_PATH")]
    pub control_path: Option<String>,

    /// For a node this is listen substrate address for dock,
    /// for adapter it is best to leave this at its default setting (0.0.0.0:0)
    ///
    #[arg(short = 'a', long, value_name = "ADDR:PORT", value_parser = parse_socket_addr_or_scoped_ip_addr)]
    pub self_addr: Option<SocketAddr>,

    /// Certificate of the Certificate Authority
    #[arg(long, value_name = "PATH")]
    pub ca_file: Option<String>,

    /// Certificate including the noise public key, signed by the authority
    #[arg(long, value_name = "PATH")]
    pub certificate_file: Option<String>, // noise public key signed by authority

    /// Path to the noise private key file (PEM format)
    #[arg(long, short = 'k', value_name = "PATH")]
    pub private_key_file: Option<String>, // noise private key

    /// Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)
    #[arg(long, env, short = 'K', value_name = "NOISE_KEY")]
    pub noise_private_key: Option<String>, // noise private key (base64 encoded)

    /// TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)
    #[arg(long, short = 'i', value_name = "DEVICE")]
    pub tun_if: Option<String>,

    /// ZPR address (no port) of the adapter (must match your TUN address)
    #[arg(long, short = 'z')]
    pub zpr_addr: Option<Vec<IpAddr>>,

    /// Enable debug logging for specified targets
    #[arg(long, short = 'd', value_parser = clap::builder::PossibleValuesParser::new(ALL_TARGETS))]
    pub debug: Vec<String>,

    /// Disable info & warnings for specified targets
    #[arg(long, short = 'q', value_parser = clap::builder::PossibleValuesParser::new(ALL_TARGETS))]
    pub quiet: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the handler in adapter mode
    #[command()]
    Adapter {
        /// Path to adapter configuration file (any options specified on command line will override configuration file)
        #[arg(long, short = 'c', value_name = "PATH")]
        config_file: Option<PathBuf>,

        #[command(flatten)]
        common: CommonArgs,

        /// Substrate address of the node to connect to
        #[arg(long, short = 'N', value_name = "ADDR:PORT", value_parser = parse_socket_addr_or_scoped_ip_addr)]
        node_addr: Option<SocketAddr>,

        /// PEM file holding the nodes noise public key
        #[arg(long, short = 'b', value_name = "PATH")]
        node_public_key_file: Option<PathBuf>, // noise public key for node (only specified when starting an adapter)

        /// PEM file holding the boostrap RSA private key
        #[arg(long, value_name = "PATH")]
        bootstrap_key: Option<PathBuf>,
    },
    /// Start the handler in node mode
    #[command(verbatim_doc_comment)]
    Node {
        /// Path to node configuration file (any options specified on command line will override configuration file)
        #[arg(long, short = 'c', value_name = "PATH")]
        config_file: Option<PathBuf>,

        #[command(flatten)]
        common: CommonArgs,
    },
}

fn parse_socket_addr_or_scoped_ip_addr(
    s: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync + 'static>> {
    // First try to parse as a full socket address (IP + optional scope + port).
    if let Ok(sa) = SocketAddr::from_str(s) {
        return Ok(sa);
    }

    // Failing that, assume we have just IP + optional scope.  First parse the scope if any.
    let addr_str;
    let scope_id;
    match s.split_once('%') {
        Some((a, b)) => {
            addr_str = a;
            scope_id = u32::from_str(b).map_err(Box::new)?;
        }

        None => {
            addr_str = s;
            scope_id = 0;
        }
    }

    // Now parse the address.
    let addr = IpAddr::from_str(addr_str).map_err(Box::new)?;

    // Create a socket address with port 0.
    let mut sa = SocketAddr::new(addr, 0);

    // Fill in the scope ID if the address is V6.
    match &mut sa {
        SocketAddr::V4(_) => (),
        SocketAddr::V6(sa6) => sa6.set_scope_id(scope_id),
    }

    Ok(sa)
}
