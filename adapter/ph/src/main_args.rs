//! ZPR Packet Handler command line arg processing
//!

use crate::assembly::PhMode;
use clap::{Args, Parser, Subcommand};
use serde::Deserialize;
use std::env;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// This config struct is loaded up from the command line args and used by the
/// ph system to configure itself.
#[derive(Debug)]
pub struct Config {
    pub name: String,
    pub control_path: PathBuf,
    pub self_addr: SocketAddr, // should probably be left at 0.0.0.0:0
    pub ca_file: PathBuf,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub tun_if: Option<String>,
    pub debug: bool,
    pub node_addr: Option<SocketAddr>, // required for adapter
    pub agent_addr: Option<IpAddr>,    // required for adapter
    pub node_public_key_file: Option<PathBuf>, // required for adapter
}

/// Errors you may encounter when trying to parse command line or configuration
/// file.
#[derive(thiserror::Error, Debug)]
pub enum ArgsError {
    #[error("missing argument: {0}")]
    Missing(String),

    #[error("invalid argument: {0}")]
    Invalid(String),

    #[error("{0}")]
    IOError(#[from] std::io::Error),

    #[error("{0}")]
    ParseError(String),
}

// Little trait to make creating "missing argument" errors easier.
trait ArgError {
    fn arg_missing(&self) -> ArgsError;
}

// With this you can just do `"some-field-name".arg_missing()`.
impl ArgError for str {
    fn arg_missing(&self) -> ArgsError {
        ArgsError::Missing(self.to_string())
    }
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
///    sudo ./ph node -c node_config.toml --name node0
///
#[derive(Debug, Parser)]
#[command(version, verbatim_doc_comment)]
struct Control {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Debug)]
pub struct CommonArgs {
    /// An optional, identifying name for instance.  Will default to "adapter" or "node" depending on mode.
    #[arg(short = 'n', long)]
    name: Option<String>,

    /// The unix domain socket path for the "control" interface.
    #[arg(long, value_name = "DOMAIN_SOCKET_PATH")]
    control_path: Option<String>,

    /// The local substrate IPv4 or IPv6 address and port for this node or adapter. Best to leave this at
    /// `0.0.0.0:0` unless you know what you are doing.
    #[arg(short = 'a', long, value_name = "ADDR:PORT")]
    self_addr: Option<SocketAddr>,

    /// Certificate of the Certificate Authority
    #[arg(long, value_name = "PATH")]
    ca_file: Option<String>,

    /// Certificate including the noise public key, signed by the authority.
    #[arg(long, value_name = "PATH")]
    certificate_file: Option<String>, // noise public key signed by authority

    /// Path to the noise private key file (PEM format)
    #[arg(long, short = 'k', value_name = "PATH")]
    private_key_file: Option<String>, // noise private key

    /// The TUN device to use, eg "tun1".  Leave blank for automatic selection.
    #[arg(long, short = 'i', value_name = "DEVICE")]
    tun_if: Option<String>,

    /// Enable debug logging
    #[arg(long, short = 'd')]
    debug: Option<bool>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Starts the handler in adapter mode.
    #[command()]
    Adapter {
        /// Path to adapter configuration file (any options specified on command line will override configuration file)
        #[arg(long, short = 'c', value_name = "PATH")]
        config_file: Option<PathBuf>,

        #[command(flatten)]
        common: CommonArgs,

        /// The substrate address of the node.
        #[arg(long, short = 'N', value_name = "ADDR:PORT")]
        node_addr: Option<SocketAddr>,

        /// The ZPR address (no port) of the adapter. Must match your TUN address!
        #[arg(long, short = 'z')]
        agent_addr: Option<IpAddr>,

        /// PEM file holding the nodes noise public key.
        #[arg(long, short = 'b', value_name = "PATH")]
        node_public_key_file: Option<String>, // noise public key for node (only specified when starting an adapter)
    },
    /// Starts the handler in node mode.
    #[command()]
    Node {
        /// Path to node configuration file (any options specified on command line will override configuration file)
        #[arg(long, short = 'c', value_name = "PATH")]
        config_file: Option<PathBuf>,

        #[command(flatten)]
        common: CommonArgs,
    },
}

// Return the path to the data home directory. A place we can stash things like
// unix domain sockets.
fn get_data_home() -> PathBuf {
    let mut dh = match env::var("XDG_DATA_HOME") {
        Ok(val) => PathBuf::from(val),
        Err(_) => match env::var("HOME") {
            Ok(val) => {
                let mut pb = PathBuf::from(val);
                pb.push(".local/share");
                pb
            }
            Err(_) => PathBuf::from("/var/run"),
        },
    };
    dh.push("zpr");
    dh
}

impl Default for Config {
    fn default() -> Self {
        Self {
            name: "".to_string(),
            control_path: get_data_home().join("control.sock"),
            self_addr: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0),
            ca_file: PathBuf::from(""),
            certificate_file: PathBuf::from(""),
            private_key_file: PathBuf::from(""),
            tun_if: None,
            debug: false,
            node_addr: None,
            agent_addr: None,
            node_public_key_file: None,
        }
    }
}

impl Config {
    fn check_valid(&self, mode: PhMode) -> Result<(), ArgsError> {
        if self.name.is_empty() {
            // return Err(MissingArgError("name"));
            return Err("name".arg_missing());
        }
        if self.control_path.to_str().unwrap().is_empty() {
            return Err("control_path".arg_missing());
        }
        if self.ca_file.to_str().unwrap().is_empty() {
            return Err("ca_file".arg_missing());
        }
        if self.certificate_file.to_str().unwrap().is_empty() {
            return Err("certificate_file".arg_missing());
        }
        if self.private_key_file.to_str().unwrap().is_empty() {
            return Err("private_key_file".arg_missing());
        }
        match mode {
            PhMode::Adapter => {
                if self.node_addr.is_none() {
                    return Err("node_addr".arg_missing());
                }
                if self.agent_addr.is_none() {
                    return Err("agent_addr".arg_missing());
                }
                if self.node_public_key_file.is_none() {
                    return Err("node_public_key_file".arg_missing());
                }
            }
            PhMode::Node => {
                // nothing node specific to check
            }
        }
        Ok(())
    }

    // Overwrite our internal state with the values present in the global section.
    fn merge_globals(&mut self, config: &GlobalConfigSection) {
        if let Some(name) = &config.name {
            self.name = name.clone();
        }
        if let Some(control_path) = &config.control_path {
            self.control_path = control_path.clone();
        }
        if let Some(self_addr) = &config.self_addr {
            self.self_addr = *self_addr;
        }
        if let Some(ca_file) = &config.ca_file {
            self.ca_file = ca_file.clone();
        }
        if let Some(certificate_file) = &config.certificate_file {
            self.certificate_file = certificate_file.clone();
        }
        if let Some(private_key_file) = &config.private_key_file {
            self.private_key_file = private_key_file.clone();
        }
        if let Some(tun_if) = &config.tun_if {
            self.tun_if = Some(tun_if.clone());
        }
        if let Some(debug) = config.debug {
            self.debug = debug;
        }
    }

    fn merge_adapter(&mut self, config: &AdapterConfigSection) {
        if let Some(node_addr) = &config.node_addr {
            self.node_addr = Some(*node_addr);
        }
        if let Some(agent_addr) = &config.agent_addr {
            self.agent_addr = Some(*agent_addr);
        }
        if let Some(node_public_key_file) = &config.node_public_key_file {
            self.node_public_key_file = Some(node_public_key_file.clone());
        }
    }

    fn merge_common(&mut self, common: &CommonArgs) {
        if let Some(name) = &common.name {
            self.name = name.clone();
        }
        if let Some(control_path) = &common.control_path {
            self.control_path = PathBuf::from(control_path);
        }
        if let Some(self_addr) = &common.self_addr {
            self.self_addr = *self_addr;
        }
        if let Some(ca_file) = &common.ca_file {
            self.ca_file = PathBuf::from(ca_file);
        }
        if let Some(certificate_file) = &common.certificate_file {
            self.certificate_file = PathBuf::from(certificate_file);
        }
        if let Some(private_key_file) = &common.private_key_file {
            self.private_key_file = PathBuf::from(private_key_file);
        }
        if let Some(tun_if) = &common.tun_if {
            self.tun_if = Some(tun_if.clone());
        }
        if let Some(debug) = common.debug {
            self.debug = debug;
        }
    }
}

// This describes the adapter configuration file TOML format.
#[derive(Deserialize, Debug, Clone)]
struct AdapterConfig {
    global: GlobalConfigSection,
    adapter: AdapterConfigSection,
}

// This describes the node configuration file TOML format.
#[derive(Deserialize, Debug, Clone)]
struct NodeConfig {
    global: GlobalConfigSection,
}

#[derive(Deserialize, Debug, Clone)]
struct GlobalConfigSection {
    name: Option<String>,
    control_path: Option<PathBuf>,
    self_addr: Option<SocketAddr>,
    ca_file: Option<PathBuf>,
    certificate_file: Option<PathBuf>,
    private_key_file: Option<PathBuf>,
    tun_if: Option<String>,
    debug: Option<bool>,
}

#[derive(Deserialize, Debug, Clone)]
struct AdapterConfigSection {
    node_addr: Option<SocketAddr>,
    node_public_key_file: Option<PathBuf>,
    agent_addr: Option<IpAddr>,
}

fn load_config<T>(path: &Path) -> Result<T, ArgsError>
where
    T: serde::de::DeserializeOwned,
{
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut toml_text = String::new();
    let len = reader.read_to_string(&mut toml_text)?;
    if len == 0 {
        return Err(ArgsError::ParseError(format!(
            "Empty configuration file {:#?}",
            path
        )));
    }
    let ac: T = match toml::from_str(&toml_text) {
        Ok(ac) => ac,
        Err(e) => {
            return Err(ArgsError::ParseError(format!(
                "Error parsing configuration file {:#?}: {}",
                path, e
            )));
        }
    };
    Ok(ac)
}

pub fn argparse() -> std::result::Result<(PhMode, Config), ArgsError> {
    let mut config: Config;
    let ph_mode: PhMode;
    let control = Control::parse();
    match control.command {
        Command::Adapter {
            config_file,
            common,
            node_addr,
            agent_addr,
            node_public_key_file,
        } => {
            ph_mode = PhMode::Adapter;
            let config_file: Option<AdapterConfig> = match config_file {
                Some(p) => match load_config(&p) {
                    Ok(ac) => Some(ac),
                    Err(e) => {
                        return Err(e);
                    }
                },
                None => None,
            };
            config = Config::default();
            config.name = "adapter".to_string();
            // fold in anything from the config file:
            if let Some(config_file) = config_file {
                config.merge_globals(&config_file.global);
                config.merge_adapter(&config_file.adapter);
            }
            // fold in anything from the command line:
            config.merge_common(&common);
            // fold in the adapter specific command line args:
            if let Some(node_addr) = node_addr {
                config.node_addr = Some(node_addr);
            }
            if let Some(agent_addr) = agent_addr {
                config.agent_addr = Some(agent_addr);
            }
            if let Some(node_public_key_file) = node_public_key_file {
                config.node_public_key_file = Some(node_public_key_file.into());
            }
        }

        Command::Node {
            config_file,
            common,
        } => {
            ph_mode = PhMode::Node;
            let config_file: Option<NodeConfig> = match config_file {
                Some(p) => match load_config(&p) {
                    Ok(ac) => Some(ac),
                    Err(e) => {
                        return Err(e);
                    }
                },
                None => None,
            };
            config = Config::default();
            config.name = "node".to_string();
            // fold in anything from the config file:
            if let Some(config_file) = config_file {
                config.merge_globals(&config_file.global);
            }
            // fold in anything from the command line:
            config.merge_common(&common);
        }
    }
    if let Err(e) = config.check_valid(ph_mode) {
        return Err(e);
    }
    Ok((ph_mode, config))
}
