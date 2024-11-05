//! ZPR Packet Handler command line arg processing
//!
//! The main entry point is [argparse] which will parse the command line arguments
//! and any config file, returning a PH configuration.

use crate::assembly::PhMode;
use clap::{Args, Parser, Subcommand};
use serde::Deserialize;
use std::env;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// This config struct is loaded up from the command line args and used by the
/// ph system to configure itself.  Do not create this directly, use [argparse].
#[derive(Debug)]
pub struct Config {
    /// Name (for logging, etc) of the node or adapter instance.
    pub name: String,

    /// Path to the unix domain socket for the control interface.
    pub control_path: PathBuf,

    /// Source address for our UDP substrate socket. In mode cases should be `0.0.0.0:0`.
    pub self_addr: SocketAddr,

    /// Path to a PEM file containing the Certificate Authority certificate.
    pub ca_file: PathBuf,

    /// Path to a PEM file containing the signed certificate listing the noise public key.
    pub certificate_file: PathBuf,

    /// Path to a PEM file containing the noise private key.
    pub private_key_file: PathBuf,

    /// Optionally specify the name of the TUN interface to use. In most cases this
    /// should be left as None so that the kernal can pick a free one.
    pub tun_if: Option<String>,

    /// Enable debug logging.
    pub debug: bool,

    /// Required for adapter - the node dock address on substrate.
    pub node_addr: Option<SocketAddr>,

    /// Required for adapter - the adapters ZPR agent address.
    pub agent_addr: Option<IpAddr>,

    /// Required for adapter - the path to the PEM file containing the nodes (signed) noise public key.
    pub node_public_key_file: Option<PathBuf>,
}

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
    // Check that the required bits are present based on mode.
    //
    // TODO: Might be nice to check things like file existence here too.
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

// Global section is shared by nodes and adapters.
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

// Adapter only bits.
#[derive(Deserialize, Debug, Clone)]
struct AdapterConfigSection {
    node_addr: Option<SocketAddr>,
    node_public_key_file: Option<PathBuf>,
    agent_addr: Option<IpAddr>,
}

// Load a config, either adapter or node, from a TOML file.
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

/// Parse the program arguments, may also parse a configuration file if that has been
/// specified in the arguments.  If all goes well this returns a valid configuration
/// and "mode" for the program.
///
/// The configuration returned will have the correct contents for the [PhMode], but
/// additional checking is still necessary.  For example, file paths specified
/// may not actually exist.
///
/// # Arguments
///
/// `args` - Optional vector of strings representing the command line arguments.
/// If None we parse from `std::env::args_os()`.
pub fn argparse(args: Option<Vec<&str>>) -> std::result::Result<(PhMode, Config), ArgsError> {
    let mut config: Config;
    let ph_mode: PhMode;
    let control = match args {
        Some(args) => Control::parse_from(args),
        None => Control::parse(),
    };
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

#[cfg(test)]
mod test {

    use super::*;
    use rand::Rng;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempFile {
        path: String,
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    impl TempFile {
        fn new_toml(contents: &str) -> TempFile {
            let mut rng = rand::thread_rng();
            let tstamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let dir = env::temp_dir();
            let num: u32 = rng.gen();
            let path = dir.join(format!("org_zpr_ph_test_main_{}_{}.toml", num, tstamp));
            fs::write(&path, contents).expect("Unable to write file");
            TempFile {
                path: path.to_str().unwrap().to_string(),
            }
        }

        fn get_path(&self) -> &Path {
            return Path::new(&self.path);
        }
    }

    #[test]
    fn test_main_args_load_config_adapter() {
        let tomltxt = r#"
        [global]
        name = "adapter0"
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        debug = true

        [adapter]
        node_addr = "192.168.0.2:5000"
        agent_addr = "10.0.0.1"
        node_public_key_file = "tests/node_public_key.pem"
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let config: AdapterConfig = load_config(tmpfile.get_path()).unwrap();

        assert_eq!(config.global.name, Some("adapter0".to_string()));
        assert_eq!(
            config.global.control_path,
            Some(PathBuf::from("/var/run/zpr/control.sock"))
        );
        assert_eq!(
            config.global.self_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)),
                12345
            ))
        );
        assert_eq!(config.global.ca_file, Some(PathBuf::from("tests/ca.pem")));
        assert_eq!(
            config.global.certificate_file,
            Some(PathBuf::from("tests/certificate.pem"))
        );
        assert_eq!(
            config.global.private_key_file,
            Some(PathBuf::from("tests/private_key.pem"))
        );
        assert_eq!(config.global.tun_if, Some("tun23".to_string()));
        assert_eq!(config.global.debug, Some(true));

        assert_eq!(
            config.adapter.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.adapter.agent_addr,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            config.adapter.node_public_key_file,
            Some(PathBuf::from("tests/node_public_key.pem"))
        );
    }

    #[test]
    fn test_main_args_load_config_node() {
        let tomltxt = r#"
        [global]
        name = "node0"
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        debug = true
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let config: NodeConfig = load_config(tmpfile.get_path()).unwrap();

        assert_eq!(config.global.name, Some("node0".to_string()));
        assert_eq!(
            config.global.control_path,
            Some(PathBuf::from("/var/run/zpr/control.sock"))
        );
        assert_eq!(
            config.global.self_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)),
                12345
            ))
        );
        assert_eq!(config.global.ca_file, Some(PathBuf::from("tests/ca.pem")));
        assert_eq!(
            config.global.certificate_file,
            Some(PathBuf::from("tests/certificate.pem"))
        );
        assert_eq!(
            config.global.private_key_file,
            Some(PathBuf::from("tests/private_key.pem"))
        );
        assert_eq!(config.global.tun_if, Some("tun23".to_string()));
        assert_eq!(config.global.debug, Some(true));
    }

    #[test]
    fn test_main_args_argparse_adapter_config() {
        let tomltxt = r#"
        [global]
        name = "adapter0"
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        debug = true

        [adapter]
        node_addr = "192.168.0.2:5000"
        agent_addr = "10.0.0.1"
        node_public_key_file = "tests/node_public_key.pem"
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "-n",
            "a0",
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert_eq!(config.name, "a0".to_string());
        assert_eq!(
            config.control_path,
            PathBuf::from("/var/run/zpr/control.sock")
        );
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)), 12345)
        );
        assert_eq!(config.ca_file, PathBuf::from("tests/ca.pem"));
        assert_eq!(
            config.certificate_file,
            PathBuf::from("tests/certificate.pem")
        );
        assert_eq!(
            config.private_key_file,
            PathBuf::from("tests/private_key.pem")
        );
        assert_eq!(config.tun_if, Some("tun23".to_string()));
        assert_eq!(config.debug, true);

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.agent_addr,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            config.node_public_key_file,
            Some(PathBuf::from("tests/node_public_key.pem"))
        );
    }

    #[test]
    fn test_main_args_adapter_config_requires_adapter_section() {
        let tomltxt = r#"
        [global]
        name = "adapter0"
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        debug = true
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "-n",
            "a0",
        ];
        match argparse(Some(args)) {
            Err(ArgsError::ParseError(_)) => {}
            _ => panic!("Expected ParseError"),
        }
    }

    // You can leave the adapter section blank and provide the details on
    // the command line.
    #[test]
    fn test_main_args_adapter_config_blank_adapter() {
        let tomltxt = r#"
        [global]
        name = "adapter0"
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        debug = true

        [adapter]
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--node-addr",
            "192.168.0.2:5000",
            "--agent-addr",
            "10.0.0.1",
            "--node-public-key-file",
            "tests/node_public_key.pem",
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.agent_addr,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            config.node_public_key_file,
            Some(PathBuf::from("tests/node_public_key.pem"))
        );
    }

    // Leave out some stuff in the config file, but specify on command line.
    #[test]
    fn test_main_args_argparse_adapter_config_override_globs() {
        let tomltxt = r#"
        [global]
        control_path = "/var/run/zpr/control.sock"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"

        [adapter]
        node_addr = "192.168.0.2:5000"
        agent_addr = "10.0.0.1"
        node_public_key_file = "tests/node_public_key.pem"
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--self-addr",
            "192.168.0.1:12345",
            "--tun-if",
            "tun23",
            "-d",
            "true",
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert_eq!(config.name, "adapter".to_string());
        assert_eq!(
            config.control_path,
            PathBuf::from("/var/run/zpr/control.sock")
        );
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)), 12345)
        );
        assert_eq!(config.ca_file, PathBuf::from("tests/ca.pem"));
        assert_eq!(
            config.certificate_file,
            PathBuf::from("tests/certificate.pem")
        );
        assert_eq!(
            config.private_key_file,
            PathBuf::from("tests/private_key.pem")
        );
        assert_eq!(config.tun_if, Some("tun23".to_string()));
        assert_eq!(config.debug, true);

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.agent_addr,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            config.node_public_key_file,
            Some(PathBuf::from("tests/node_public_key.pem"))
        );
    }

    #[test]
    fn test_main_args_argparse_adapter_config_minimal() {
        let tomltxt = r#"
        [global]
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"

        [adapter]
        node_addr = "192.168.0.2:5000"
        agent_addr = "10.0.0.1"
        node_public_key_file = "tests/node_public_key.pem"
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert_eq!(config.name, "adapter".to_string());
        assert!(!config.control_path.to_string_lossy().is_empty());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
        );
        assert_eq!(config.ca_file, PathBuf::from("tests/ca.pem"));
        assert_eq!(
            config.certificate_file,
            PathBuf::from("tests/certificate.pem")
        );
        assert_eq!(
            config.private_key_file,
            PathBuf::from("tests/private_key.pem")
        );
        assert!(config.tun_if.is_none());
        assert_eq!(config.debug, false);

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.agent_addr,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            config.node_public_key_file,
            Some(PathBuf::from("tests/node_public_key.pem"))
        );
    }

    #[test]
    fn test_main_args_argparse_node_config_minimal() {
        let tomltxt = r#"
        [global]
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "node", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Node);

        assert_eq!(config.name, "node".to_string());
        assert!(!config.control_path.to_string_lossy().is_empty());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
        );
        assert_eq!(config.ca_file, PathBuf::from("tests/ca.pem"));
        assert_eq!(
            config.certificate_file,
            PathBuf::from("tests/certificate.pem")
        );
        assert_eq!(
            config.private_key_file,
            PathBuf::from("tests/private_key.pem")
        );
        assert!(config.tun_if.is_none());
        assert_eq!(config.debug, false);
    }

    #[test]
    fn test_main_args_argparse_node_config_no_toml() {
        let args = vec![
            "ph",
            "node",
            "--ca-file",
            "tests/ca.pem",
            "--certificate-file",
            "tests/certificate.pem",
            "--private-key-file",
            "tests/private_key.pem",
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Node);

        assert_eq!(config.name, "node".to_string());
        assert!(!config.control_path.to_string_lossy().is_empty());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
        );
        assert_eq!(config.ca_file, PathBuf::from("tests/ca.pem"));
        assert_eq!(
            config.certificate_file,
            PathBuf::from("tests/certificate.pem")
        );
        assert_eq!(
            config.private_key_file,
            PathBuf::from("tests/private_key.pem")
        );
        assert!(config.tun_if.is_none());
        assert_eq!(config.debug, false);
    }
}
