//! Static system configuration.

use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{self, Path, PathBuf};

use base64::prelude::*;
use serde::Deserialize;

use crate::assembly::PhMode;
use crate::km_cert_exchange;
use crate::km_noise::NOISE_KEY_LEN;

use crate::main_args::{ArgsError, CommonArgs};

/// Size of a packet buffer.
pub const PACKET_BUFFER_SIZE: usize = 4096 * 3;

/// Size of headroom necessary for most messages.
pub const DEFAULT_MESSAGE_HEADROOM: usize = 256;

pub const DEFAULT_REQUEST_RETRY_COUNT: usize = 3;
pub const DEFAULT_REQUEST_RETRY_TIMER: usize = 1;

pub const ANCILLARY_BUFFER_SIZE: usize = 128;

const DEFAULT_BUFFER_COUNT: usize = 512; // should be at least 2x batch size
const DEFAULT_BATCH_SIZE: usize = 256;
const DEFAULT_DATAPATH_QUEUE_SIZE: usize = 256;
const DEFAULT_MGMT_QUEUE_SIZE: usize = 256;
const DEFAULT_SERVICE_QUEUE_SIZE: usize = 256;

#[cfg(not(target_os = "macos"))]
const DEFAULT_WORKER_CONCURRENCY: usize = 4;

#[cfg(target_os = "macos")]
const DEFAULT_WORKER_CONCURRENCY: usize = 1;

pub const DEFAULT_KEEP_ALIVE_PERIOD: std::time::Duration = std::time::Duration::from_secs(3);
pub const DEFAULT_KEEP_ALIVE_RETRIES: usize = 3;

pub const DEFAULT_LINK_RESTART_HOLDDOWN: std::time::Duration = std::time::Duration::from_secs(5);

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

/// This config struct is loaded up from the command line args and used by the
/// ph system to configure itself.  Do not create this directly,
/// use [crate::main_argparse::argparse].
#[derive(Debug)]
pub struct Config {
    /// Path to the unix domain socket for the control interface.
    pub control_path: PathBuf,

    /// Source address for our UDP substrate socket. For an adapter this should (always?) be `0.0.0.0:0`.
    /// For a node this is the nodes dock listening address.
    pub self_addr: SocketAddr,

    /// Path to a PEM file containing the Certificate Authority certificate.
    pub ca_file: PathBuf,

    /// Path to a PEM file containing the signed certificate listing the noise public key.
    pub certificate_file: PathBuf,

    /// Path to a PEM file containing the noise private key, if specified.
    /// One of either [private_key_file] or [private_key_data] must be specified.
    private_key_file: Option<PathBuf>,

    /// The noise private key data, base64 encoded. User has option to set this through an environment variable.
    /// One of either [private_key_file] or [private_key_data] must be specified.
    private_key_data: Option<String>,

    /// Optionally specify the name of the TUN interface to use. In most cases this
    /// should be left as None so that the kernal can pick a free one.
    pub tun_if: Option<String>,

    /// Enable debug logging for specified targets, or ALL
    pub debug: Vec<String>,

    /// Disable info & warnings for specified targets, or ALL
    pub quiet: Vec<String>,

    /// Required for adapter - the node dock address on substrate.
    pub node_addr: Option<SocketAddr>,

    /// Required for adapter - the adapters ZPR agent address.
    pub agent_addr: Vec<IpAddr>,

    /// Required for adapter - the path to the PEM file containing the nodes noise public key (not a certificate).
    pub node_public_key_file: Option<PathBuf>,
}

impl Config {
    pub fn get_noise_private_key_data(&self) -> Result<[u8; NOISE_KEY_LEN], ArgsError> {
        if let Some(ref b64data) = self.private_key_data {
            let key_data: [u8; NOISE_KEY_LEN] = match BASE64_STANDARD.decode(b64data) {
                Ok(data) => data
                    .try_into()
                    .map_err(|v| ArgsError::ParseError(format!("malformed noise key: {v:?}")))?,
                Err(e) => {
                    return Err(ArgsError::ParseError(format!(
                        "failed to decode base64 noise key: {e:?}"
                    )))
                }
            };
            return Ok(key_data);
        }
        if let Some(ref pkf) = self.private_key_file {
            return km_cert_exchange::load_private_key(&pkf).map_err(|e| {
                ArgsError::ParseError(format!("failed to load private key from file: {e:?}"))
            });
        }
        Err("neither private_key_file nor noise_private_key specified".arg_missing())
    }

    pub fn noise_private_key_source(&self) -> String {
        if let Some(ref b64data) = self.private_key_data {
            return format!("key://{}", b64data);
        }
        if let Some(ref pkf) = self.private_key_file {
            return format!("file://{}", pkf.display());
        }
        return "".to_string();
    }

    pub fn new_for_adapter(
        config_file: Option<AdapterConfig>,
        common: &CommonArgs,
    ) -> Result<Self, ArgsError> {
        let mut config = Config::default();
        // fold in anything from the config file:
        if let Some(config_file) = config_file {
            let base_dir = config_file.config_path.parent().unwrap();
            config.set_from_globals(&config_file.global, base_dir)?;
            config.set_from_adapter(&config_file.adapter, base_dir)?;
        }
        config.set_from_common(common)?;
        Ok(config)
    }

    pub fn new_for_node(
        config_file: Option<NodeConfig>,
        common: &CommonArgs,
    ) -> Result<Self, ArgsError> {
        let mut config = Config::default();
        // fold in anything from the config file:
        if let Some(config_file) = config_file {
            let base_dir = config_file.config_path.parent().unwrap();
            config.set_from_globals(&config_file.global, base_dir)?;
        }
        config.set_from_common(common)?;
        Ok(config)
    }

    // Check that the required bits are present based on mode.
    // Also checks that the various files exist.
    pub fn check_valid(&self, mode: PhMode) -> Result<(), ArgsError> {
        if self.control_path.to_str().unwrap().is_empty() {
            return Err("control_path".arg_missing());
        }
        // For control path, the parent dir must exist or there will be an error later.
        if let Some(parent) = self.control_path.parent() {
            match check_file_exists("control socket parent directory", parent) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        if self.ca_file.to_str().unwrap().is_empty() {
            return Err("ca_file".arg_missing());
        }
        check_file_exists("certificate authority file", &self.ca_file)?;
        if self.certificate_file.to_str().unwrap().is_empty() {
            return Err("certificate_file".arg_missing());
        }
        check_file_exists("certificate file", &self.certificate_file)?;
        if let Some(ref pkf) = self.private_key_file {
            if pkf.to_str().unwrap().is_empty() {
                return Err("private_key_file".arg_missing());
            }
            check_file_exists("private key file", &pkf)?;
        } else if let Some(ref pkd) = self.private_key_data {
            if pkd.is_empty() {
                return Err("private_key_data".arg_missing());
            }
        } else {
            return Err("private_key_file or noise_private_key".arg_missing());
        }
        if self.agent_addr.is_empty() {
            return Err("agent_addr".arg_missing());
        }
        match mode {
            PhMode::Adapter => {
                if self.node_addr.is_none() {
                    return Err("node_addr".arg_missing());
                }
                if self.node_public_key_file.is_none() {
                    return Err("node_public_key_file".arg_missing());
                } else {
                    check_file_exists(
                        "node public key file",
                        &self.node_public_key_file.as_ref().unwrap(),
                    )?;
                }
            }
            PhMode::Node => {
                // nothing node specific to check
            }
        }
        Ok(())
    }

    // Overwrite our internal state with the values present in the global section.
    fn set_from_globals(
        &mut self,
        config: &GlobalConfigSection,
        base_dir: &Path,
    ) -> Result<(), ArgsError> {
        if let Some(control_path) = &config.control_path {
            if control_path.is_relative() {
                self.control_path = base_dir.join(control_path);
            } else {
                self.control_path = control_path.clone();
            }
        }
        if let Some(self_addr) = &config.self_addr {
            self.self_addr = *self_addr;
        }
        if let Some(ca_file) = &config.ca_file {
            if ca_file.is_relative() {
                self.ca_file = base_dir.join(ca_file);
            } else {
                self.ca_file = ca_file.clone();
            }
        }
        if let Some(certificate_file) = &config.certificate_file {
            if certificate_file.is_relative() {
                self.certificate_file = base_dir.join(certificate_file);
            } else {
                self.certificate_file = certificate_file.clone();
            }
        }
        if let Some(private_key_file) = &config.private_key_file {
            if private_key_file.is_relative() {
                self.private_key_file = Some(base_dir.join(private_key_file));
            } else {
                self.private_key_file = Some(private_key_file.clone());
            }
        }
        if let Some(tun_if) = &config.tun_if {
            self.tun_if = Some(tun_if.clone());
        }
        if let Some(agent_addr) = &config.agent_addr {
            self.agent_addr.extend(&*agent_addr);
        }
        if let Some(debug) = &config.debug {
            self.debug.extend(debug.into_iter().cloned());
        }
        if let Some(quiet) = &config.quiet {
            self.quiet.extend(quiet.into_iter().cloned());
        }
        Ok(())
    }

    // Overwrite our internal state with the values present in the adapter section.
    fn set_from_adapter(
        &mut self,
        config: &AdapterConfigSection,
        base_dir: &Path,
    ) -> Result<(), ArgsError> {
        if let Some(node_addr) = &config.node_addr {
            self.node_addr = Some(*node_addr);
        }
        if let Some(node_public_key_file) = &config.node_public_key_file {
            if node_public_key_file.is_relative() {
                self.node_public_key_file = Some(base_dir.join(node_public_key_file));
            } else {
                self.node_public_key_file = Some(node_public_key_file.clone());
            }
        }
        Ok(())
    }

    // Overwrite our internal state with the values present in the CommonArgs (from command line)
    fn set_from_common(&mut self, common: &CommonArgs) -> Result<(), ArgsError> {
        if let Some(control_path) = &common.control_path {
            let cp = PathBuf::from(control_path);
            if cp.is_relative() {
                self.control_path = path::absolute(cp).or_else(|e| {
                    Err(ArgsError::PathError(format!(
                        "path error for control_path: {:?}",
                        e
                    )))
                })?;
            } else {
                self.control_path = cp;
            }
        }
        if let Some(self_addr) = &common.self_addr {
            self.self_addr = *self_addr;
        }
        if let Some(ca_file) = &common.ca_file {
            let cf = PathBuf::from(ca_file);
            if cf.is_relative() {
                self.ca_file = fs::canonicalize(cf).or_else(|e| {
                    Err(ArgsError::PathError(format!(
                        "path error for ca_file: {:?}",
                        e
                    )))
                })?;
            } else {
                self.ca_file = PathBuf::from(ca_file);
            }
        }
        if let Some(certificate_file) = &common.certificate_file {
            let cf = PathBuf::from(certificate_file);
            if cf.is_relative() {
                self.certificate_file = fs::canonicalize(cf).or_else(|e| {
                    Err(ArgsError::PathError(format!(
                        "path error for certificate_file: {:?}",
                        e
                    )))
                })?;
            } else {
                self.certificate_file = cf;
            }
        }
        if common.private_key_file.is_some() && common.noise_private_key.is_some() {
            return Err(ArgsError::ParseError(
                "private_key_file and noise_private_key cannot be used together".to_string(),
            ));
        }
        if let Some(private_key_data) = &common.noise_private_key {
            self.private_key_file = None;
            self.private_key_data = Some(private_key_data.clone());
        }
        if let Some(private_key_file) = &common.private_key_file {
            self.private_key_data = None;
            let pkf = PathBuf::from(private_key_file);
            if pkf.is_relative() {
                let pkf_resolved = fs::canonicalize(pkf).or_else(|e| {
                    Err(ArgsError::PathError(format!(
                        "path error for private_key_file: {:?}",
                        e
                    )))
                })?;
                self.private_key_file = Some(pkf_resolved);
            } else {
                self.private_key_file = Some(PathBuf::from(private_key_file));
            }
        }
        if let Some(tun_if) = &common.tun_if {
            self.tun_if = Some(tun_if.clone());
        }
        self.agent_addr.extend(&common.agent_addr);

        self.debug.extend(common.debug.iter().cloned());
        self.quiet.extend(common.quiet.iter().cloned());

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            control_path: get_data_home().join("control.sock"),
            self_addr: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0),
            ca_file: PathBuf::from(""),
            certificate_file: PathBuf::from(""),
            private_key_file: None,
            private_key_data: None,
            tun_if: None,
            debug: Vec::new(),
            quiet: Vec::new(),
            node_addr: None,
            agent_addr: Vec::new(),
            node_public_key_file: None,
        }
    }
}

// This describes the adapter configuration file TOML format.
#[derive(Deserialize, Debug, Clone)]
pub struct AdapterConfig {
    #[serde(skip)]
    pub config_path: PathBuf,

    pub global: GlobalConfigSection,
    pub adapter: AdapterConfigSection,
}

// This describes the node configuration file TOML format.
#[derive(Deserialize, Debug, Clone)]
pub struct NodeConfig {
    #[serde(skip)]
    pub config_path: PathBuf,

    pub global: GlobalConfigSection,
}

// Global section is shared by nodes and adapters.
#[derive(Deserialize, Debug, Clone)]
pub struct GlobalConfigSection {
    pub control_path: Option<PathBuf>,
    pub self_addr: Option<SocketAddr>,
    pub ca_file: Option<PathBuf>,
    pub certificate_file: Option<PathBuf>,
    pub private_key_file: Option<PathBuf>,
    pub tun_if: Option<String>,
    pub agent_addr: Option<Vec<IpAddr>>,
    pub debug: Option<Vec<String>>,
    pub quiet: Option<Vec<String>>,
}

// Adapter only bits.
#[derive(Deserialize, Debug, Clone)]
pub struct AdapterConfigSection {
    pub node_addr: Option<SocketAddr>,
    pub node_public_key_file: Option<PathBuf>,
}

/// Configuration of data path & control plane topology.
pub struct TopologyConfig {
    /// Number of packet buffers to allocate per fastpath worker.
    pub buffer_count: usize,

    pub fastpath_concurrency: usize,

    pub fastpath_batch_size: usize,
    pub capture_batch_size: usize,

    #[allow(dead_code)] // see TODO in main
    pub capture_queue_size: usize,
    pub mgmt_dispatch_queue_size: usize,
    pub adapter_manager_queue_size: usize,
    pub km_signal_queue_size: usize,
    pub km_message_queue_size: usize,
    pub km_link_queue_size: usize,

    pub vs_queue_size: usize,
    pub vss_queue_size: usize,
}

impl Default for TopologyConfig {
    fn default() -> Self {
        Self {
            buffer_count: DEFAULT_BUFFER_COUNT,

            fastpath_concurrency: DEFAULT_WORKER_CONCURRENCY,

            fastpath_batch_size: DEFAULT_BATCH_SIZE,
            capture_batch_size: DEFAULT_BATCH_SIZE,

            capture_queue_size: DEFAULT_DATAPATH_QUEUE_SIZE,
            mgmt_dispatch_queue_size: DEFAULT_MGMT_QUEUE_SIZE,
            adapter_manager_queue_size: DEFAULT_MGMT_QUEUE_SIZE,
            km_signal_queue_size: DEFAULT_MGMT_QUEUE_SIZE,
            km_message_queue_size: DEFAULT_MGMT_QUEUE_SIZE,
            km_link_queue_size: DEFAULT_MGMT_QUEUE_SIZE,

            vs_queue_size: DEFAULT_SERVICE_QUEUE_SIZE,
            vss_queue_size: DEFAULT_SERVICE_QUEUE_SIZE,
        }
    }
}

// Return the path to the data home directory. A place we can stash things like
// unix domain sockets. Default is '/var/run/zpr'.
fn get_data_home() -> PathBuf {
    let mut dh = match env::var("XDG_DATA_HOME") {
        Ok(val) => PathBuf::from(val),
        Err(_) => match env::var("HOME") {
            Ok(val) => {
                let mut pb = PathBuf::from(val);
                pb.push(".local/share");
                // Now we will only take this if user already has a .local/share dir.
                if pb.exists() {
                    pb
                } else {
                    PathBuf::from("/var/run")
                }
            }
            Err(_) => PathBuf::from("/var/run"),
        },
    };
    dh.push("zpr");
    dh
}

fn check_file_exists(desc: &str, path: &Path) -> Result<(), ArgsError> {
    match fs::exists(path) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ArgsError::PathError(format!(
            "{} not found: {:?}",
            desc, path
        ))),
        Err(e) => Err(ArgsError::PathError(format!(
            "{} path error: {:?}",
            desc, e
        ))),
    }
}
