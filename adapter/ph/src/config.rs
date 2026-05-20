//! Static system configuration.

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{self, Path, PathBuf};
use zpr::packet_info::{KM_ID_NOISE, KM_ID_NULL, KmId};

use admin_api::get_data_home;
use base64::prelude::*;
use openssl::pkey::PKey;
use serde::Deserialize;

use crate::assembly::PhMode;
use crate::auth::{OAuthRsa, RsaBootstrapAuth};
use crate::batch_io;
use crate::pki;
use crate::pki::{NOISE_KEY_LEN, load_cert, load_noise_private_key};

use crate::main_args::{ArgsError, CommonArgs};

/// Upper bound on number of active links (peers) that the PH can manage.
pub const MAX_ACTIVE_LINKS: usize = 1024;

/// Size of a packet buffer.
pub const PACKET_BUFFER_SIZE: usize = 4096 * 3;

/// Size of a "small" packet buffer, suitable for most outbound management traffic.
pub const SMALL_PACKET_BUFFER_SIZE: usize = 2048;

/// Size of a "tiny" packet buffer, suitable for packets with no bodies (e.g. acks).
/// Note, this is not large enough for `DEFAULT_MESSAGE_HEADROOM`; use
/// with `TINY_MESSAGE_HEADROOM` instead.
pub const TINY_PACKET_BUFFER_SIZE: usize = 256;

/// Size of headroom necessary for most messages.
pub const DEFAULT_MESSAGE_HEADROOM: usize = 256;

/// Size of headroom suitable for "tiny" (bodyless) messages.
pub const TINY_MESSAGE_HEADROOM: usize = 64;

pub const DEFAULT_ZDPR_RECEIVE_WINDOW_SIZE: usize = 32;

pub const DEFAULT_ZDPR_RETRY_TIMER: std::time::Duration = std::time::Duration::from_millis(600);

pub const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
pub const DEFAULT_TERMINATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Used during shutdown. We give enough time for a clean exit, but will not wait forever.
pub const DEFAULT_STATE_MACHINE_RESET_WAIT: std::time::Duration =
    std::time::Duration::from_secs(10);

pub const DEFAULT_VSS_PORT: u16 = 8183;

/// Visa service minimum visa ID value. Values below this are reserved.
/// More importantly, if code puts visas into the table with IDs below this, they will not be cleared
/// out during normal operation.
pub const MIN_VISA_ID: u64 = 1000;

/// If we loose the Cap'n Proto connection to the VS, or are unable to establish it in the first place,
/// wait this long before retry.
pub const VSCONN_RETRY_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// Slightly longer -- asking visa service to grant an address
/// means it may have to do a lot of work to verify auth.
pub const VS_GRANT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long to wait for an actor to finish out of band authentication.
pub const ACTOR_AUTHENTICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// How long to wait when we expect the VS to have to talk to external auth services.
pub const VS_AUTHENTICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub const ANCILLARY_BUFFER_SIZE: usize = 128;

const DEFAULT_BUFFER_COUNT: usize = 512; // should be at least 5x batch size; see fastpath_worker.rs for explanation
const DEFAULT_BATCH_SIZE: usize = 64;
const DEFAULT_DATAPATH_QUEUE_SIZE: usize = 256;
const DEFAULT_MGMT_QUEUE_SIZE: usize = 128; // should be at least 2x batch size to avoid oscillating behavior
const DEFAULT_SERVICE_QUEUE_SIZE: usize = 128;

#[cfg(not(target_os = "macos"))]
const DEFAULT_WORKER_CONCURRENCY: usize = 4;

#[cfg(target_os = "macos")]
const DEFAULT_WORKER_CONCURRENCY: usize = 1;

pub const DEFAULT_KEEP_ALIVE_PERIOD: std::time::Duration = std::time::Duration::from_secs(3);
pub const DEFAULT_KEEP_ALIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

pub const DEFAULT_LINK_RESTART_HOLDDOWN: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum length of payload to include in a Bind Request.
///
/// 256 octects is more than enough to capture the longest common headers
/// (e.g. QUIC, which is over 64) without bumping up against IPv4 min-max
/// length of 576.
pub const BIND_REQUEST_MAX_PAYLOAD_LENGTH: usize = 256;

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
#[derive(Debug, Clone)]
pub struct Config {
    /// Name of this node or adapter. If no signed certificate is available this is used as the CN.
    /// This has no meaning for nodes.
    pub name: String,

    /// Path to the unix domain socket for the control interface.
    pub control_path: PathBuf,

    pub capture_path: PathBuf,

    /// Source address for our UDP substrate socket. For an adapter this should (always?) be `0.0.0.0:0`.
    /// For a node this is the nodes dock listening address.
    pub self_addr: SocketAddr,

    /// Path to a PEM file containing the Certificate Authority certificate.
    /// Optional and if present is used by the link management system to verify passed noise certificates.
    pub ca_file: Option<PathBuf>,

    /// Path to a PEM file containing the signed certificate listing the noise public key.
    pub certificate_file: Option<PathBuf>,

    /// Path to a PEM file containing the noise private key, if specified.
    /// For a node, one of either `private_key_file` or `private_key_data` must be specified.
    pub private_key_file: Option<PathBuf>,

    /// The noise private key data, base64 encoded. User has option to set this through an environment variable.
    /// For a node, one of either `private_key_file` or `private_key_data` must be specified.
    pub private_key_data: Option<String>,

    /// The RSA private key used by a node to authenticate with the visa service.
    /// Required for nodes.
    pub auth_private_key: Option<PathBuf>,

    /// Optionally specify the name of the TUN interface to use. In most cases this
    /// should be left as None so that the kernal can pick a free one.
    pub tun_if: Option<String>,

    /// Enable debug logging for specified targets, or ALL
    pub logging: Vec<(String, String)>,

    /// Required for adapter - the node dock address on substrate.
    pub node_addr: Option<SocketAddr>,

    /// Required for node, optional for adapter - the ZPR address (no port) of the adapter.
    pub zpr_addr: Vec<IpAddr>,

    /// Required for adapter - the path to the PEM file containing the nodes noise public key (not a certificate).
    pub node_public_key_file: Option<PathBuf>,

    /// Ignored for node, optional for adapter - Only set if the adapter is configured for bootstrap authentication.
    pub bootstrap: Option<RsaBootstrapAuth>,

    /// If present this has key material for use during a zpr-oauthrsa authentication.
    pub rsaoauth: Option<OAuthRsa>,

    /// The batch I/O engine to use.
    pub batch_io_engine: String,

    /// Type of key manager implementation
    pub km_impl: KmId,
}

impl Config {
    /// If private noise key is specified through config or args, return it here.
    pub fn get_noise_private_key_data(&self) -> Result<Option<[u8; NOISE_KEY_LEN]>, ArgsError> {
        if let Some(ref b64data) = self.private_key_data {
            let key_data: [u8; NOISE_KEY_LEN] = match BASE64_STANDARD.decode(b64data) {
                Ok(data) => data
                    .try_into()
                    .map_err(|v| ArgsError::ParseError(format!("malformed noise key: {v:?}")))?,
                Err(e) => {
                    return Err(ArgsError::ParseError(format!(
                        "failed to decode base64 noise key: {e:?}"
                    )));
                }
            };
            return Ok(Some(key_data));
        }
        if let Some(ref pkf) = self.private_key_file {
            let pk = load_noise_private_key(&pkf).map_err(|e| {
                ArgsError::ParseError(format!("failed to load private key from file: {e:?}"))
            })?;
            return Ok(Some(pk));
        }
        Ok(None)
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

    /// Create the [Config] struct using an optional configuration file plus
    /// any passed "common" command line arguments.
    ///
    /// Note that additional, adapter specific command line arguments may get
    /// folded into the returned object later.
    pub fn new_for_adapter(
        config_file: Option<AdapterConfig>,
        common: &CommonArgs,
    ) -> Result<Self, ArgsError> {
        let mut config = Config::default();
        config.set_from_common(common)?;
        if let Some(config_file) = config_file {
            let base_dir = config_file.config_path.parent().unwrap();
            config.set_from_globals(&config_file.global, base_dir)?;
            config.set_from_adapter(&config_file.adapter, base_dir)?;
            config.set_from_authentication(&config_file.authentication, base_dir)?;
        }
        Ok(config)
    }

    pub fn new_for_node(
        config_file: Option<NodeConfig>,
        auth_private_key: Option<PathBuf>,
        common: &CommonArgs,
    ) -> Result<Self, ArgsError> {
        let mut config = Config::default();
        if let Some(pkey_file) = auth_private_key {
            if pkey_file.is_relative() {
                let pkey_file = fs::canonicalize(pkey_file).or_else(|e| {
                    Err(ArgsError::PathError(format!(
                        "path error for auth_private_key: {:?}",
                        e
                    )))
                })?;
                config.auth_private_key = Some(pkey_file);
            } else {
                config.auth_private_key = Some(pkey_file);
            }
        }
        config.set_from_common(common)?;
        if let Some(config_file) = config_file {
            let base_dir = config_file.config_path.parent().unwrap();
            config.set_from_globals(&config_file.global, base_dir)?;
            config.set_from_authentication(&config_file.authentication, base_dir)?;
        }
        Ok(config)
    }

    /// If we have a `certificate_file` use that to figure out our CN.
    /// Otherwise we return the `global.name` value.
    pub fn get_noise_cn(&self) -> Result<String, ArgsError> {
        match self.certificate_file.as_ref() {
            None => Ok(self.name.clone()),
            Some(f) => get_noise_cn(&f),
        }
    }

    // Check that the required bits are present based on mode.
    // Also checks that the various files exist.
    pub fn check_valid(&self, mode: PhMode) -> Result<(), ArgsError> {
        if self.control_path.as_os_str().is_empty() {
            return Err("control_path".arg_missing());
        }
        // For control path, the parent dir must exist or there will be an error later.
        if let Some(parent) = self.control_path.parent() {
            match check_file_exists("control socket parent directory", parent) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        if self.capture_path.as_os_str().is_empty() {
            return Err("capture_path".arg_missing());
        }
        // For capture path, the parent dir must exist or there will be an error later.
        if let Some(parent) = self.capture_path.parent() {
            match check_file_exists("capture socket parent directory", parent) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        if let Some(ca_file) = &self.ca_file {
            check_file_exists("certificate authority file", ca_file)?;
        }
        if let Some(ref cf) = self.certificate_file {
            check_file_exists("certificate file", cf)?;
        }
        if let Some(ref pkf) = self.private_key_file {
            if pkf.to_str().unwrap().is_empty() {
                return Err("private_key_file".arg_missing());
            }
            check_file_exists("private key file", &pkf)?;
        } else if let Some(ref pkd) = self.private_key_data {
            if pkd.is_empty() {
                return Err("private_key_data".arg_missing());
            }
        }
        match mode {
            PhMode::Node => {
                if self.zpr_addr.is_empty() {
                    return Err("zpr_addr".arg_missing());
                }
                if self.certificate_file.is_none() {
                    return Err("certificate_file".arg_missing());
                }
                if self.private_key_file.is_none() && self.private_key_data.is_none() {
                    return Err("private_key_file or noise_private_key".arg_missing());
                }
            }
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
                if self.private_key_file.is_none()
                    && self.private_key_data.is_none()
                    && self.name.is_empty()
                {
                    return Err(
                        "adapter name must be set to CN when not using explicit link keys"
                            .arg_missing(),
                    );
                }
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
        if let Some(capture_path) = &config.capture_path {
            if capture_path.is_relative() {
                self.capture_path = base_dir.join(capture_path);
            } else {
                self.capture_path = capture_path.clone();
            }
        }
        if let Some(self_addr) = &config.self_addr {
            self.self_addr = *self_addr;
        }
        if let Some(ca_file) = &config.ca_file {
            if ca_file.is_relative() {
                self.ca_file = Some(base_dir.join(ca_file));
            } else {
                self.ca_file = Some(ca_file.clone());
            }
        }
        if let Some(certificate_file) = &config.certificate_file {
            if certificate_file.is_relative() {
                self.certificate_file = Some(base_dir.join(certificate_file));
            } else {
                self.certificate_file = Some(certificate_file.clone());
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
        if let Some(actor_addr) = &config.zpr_addr {
            self.zpr_addr.extend(&*actor_addr);
        }
        if let Some(logging) = &config.logging {
            self.logging.extend(logging.into_iter().cloned());
        }
        if let Some(io_engine) = &config.io_engine {
            self.batch_io_engine = io_engine.clone();
        }
        Ok(())
    }

    // Overwrite our internal state with the values present in the adapter section
    // of TOML config.
    fn set_from_adapter(
        &mut self,
        config: &AdapterConfigSection,
        base_dir: &Path,
    ) -> Result<(), ArgsError> {
        if let Some(cn) = &config.name {
            self.name = cn.clone();
        }
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

        if let Some(bootstrap_key_file) = &config.bootstrap_key {
            // In order to set the bootstrap object, we need to know the CN which means we need
            // the certificate_file arg to be valid.

            let cn = self.get_noise_cn()?;

            if bootstrap_key_file.is_relative() {
                self.bootstrap = Some(RsaBootstrapAuth::new(
                    &cn,
                    &base_dir.join(bootstrap_key_file),
                )?);
            } else {
                self.bootstrap = Some(RsaBootstrapAuth::new(&cn, bootstrap_key_file)?);
            }
        }
        Ok(())
    }

    fn set_from_authentication(
        &mut self,
        config: &Option<AuthenticationConfigSection>,
        base_dir: &Path,
    ) -> Result<(), ArgsError> {
        if let Some(config) = config {
            if let Some(bas_key) = &config.bas_key {
                let keyfile = if bas_key.is_relative() {
                    base_dir.join(bas_key)
                } else {
                    bas_key.clone()
                };
                let pemdata = fs::read_to_string(&keyfile).map_err(|e| {
                    ArgsError::PathError(format!(
                        "failed to read bas_key file {}: {:?}",
                        keyfile.display(),
                        e
                    ))
                })?;
                let priv_key = PKey::private_key_from_pem(&pemdata.as_bytes()).map_err(|e| {
                    ArgsError::ParseError(format!(
                        "failed to parse bas_key file {}: {:?}",
                        keyfile.display(),
                        e
                    ))
                })?;
                self.rsaoauth = Some(OAuthRsa::new(&self.get_noise_cn()?, priv_key));
            }
            if let Some(auth_private_key) = &config.auth_private_key {
                let keyfile = if auth_private_key.is_relative() {
                    base_dir.join(auth_private_key)
                } else {
                    auth_private_key.clone()
                };
                self.auth_private_key = Some(keyfile);
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
        if let Some(capture_path) = &common.capture_path {
            let cp = PathBuf::from(capture_path);
            if cp.is_relative() {
                self.capture_path = path::absolute(cp).or_else(|e| {
                    Err(ArgsError::PathError(format!(
                        "path error for capture_path: {:?}",
                        e
                    )))
                })?;
            } else {
                self.capture_path = cp;
            }
        }
        if let Some(self_addr) = &common.self_addr {
            self.self_addr = *self_addr;
        }
        if let Some(ca_file) = &common.ca_file {
            let cf = PathBuf::from(ca_file);
            if cf.is_relative() {
                self.ca_file = Some(fs::canonicalize(cf).or_else(|e| {
                    Err(ArgsError::PathError(format!(
                        "path error for ca_file: {:?}",
                        e
                    )))
                })?);
            } else {
                self.ca_file = Some(PathBuf::from(ca_file));
            }
        }
        if let Some(certificate_file) = &common.certificate_file {
            let cf = PathBuf::from(certificate_file);
            if cf.is_relative() {
                let cfile = fs::canonicalize(cf).or_else(|e| {
                    Err(ArgsError::PathError(format!(
                        "path error for certificate_file: {:?}",
                        e
                    )))
                })?;
                self.certificate_file = Some(cfile);
            } else {
                self.certificate_file = Some(cf);
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
        if let Some(addrs) = &common.zpr_addr {
            self.zpr_addr.extend(addrs);
        }

        self.logging.extend(common.logging.iter().cloned());

        self.batch_io_engine = common.io_engine.clone();

        self.km_impl = match common.km_impl.as_str() {
            "noise" => KM_ID_NOISE,
            "null" => KM_ID_NULL,
            oth => {
                return Err(ArgsError::ParseError(format!(
                    "Unknown key management implementation: {oth}"
                )));
            }
        };

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            name: String::new(),
            control_path: get_data_home().join("control.sock"),
            capture_path: get_data_home().join("capture.sock"),
            self_addr: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0),
            ca_file: None,
            certificate_file: None,
            private_key_file: None,
            private_key_data: None,
            auth_private_key: None,
            tun_if: None,
            logging: Vec::new(),
            node_addr: None,
            zpr_addr: Vec::new(),
            node_public_key_file: None,
            bootstrap: None,
            rsaoauth: None,
            batch_io_engine: batch_io::AUTO_ENGINE_NAME.to_owned(),
            km_impl: KM_ID_NOISE,
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
    pub authentication: Option<AuthenticationConfigSection>,
}

// This describes the node configuration file TOML format.
#[derive(Deserialize, Debug, Clone)]
pub struct NodeConfig {
    #[serde(skip)]
    pub config_path: PathBuf,

    pub global: GlobalConfigSection,
    pub authentication: Option<AuthenticationConfigSection>,
}

// Global section is shared by nodes and adapters.
#[derive(Deserialize, Debug, Clone)]
pub struct GlobalConfigSection {
    pub control_path: Option<PathBuf>,
    pub capture_path: Option<PathBuf>,
    pub self_addr: Option<SocketAddr>,
    pub ca_file: Option<PathBuf>,
    pub certificate_file: Option<PathBuf>,
    pub private_key_file: Option<PathBuf>,
    pub tun_if: Option<String>,
    pub zpr_addr: Option<Vec<IpAddr>>,
    pub logging: Option<Vec<(String, String)>>,
    pub io_engine: Option<String>,
}

// Adapter only bits.
#[derive(Deserialize, Debug, Clone)]
pub struct AdapterConfigSection {
    pub name: Option<String>,
    pub node_addr: Option<SocketAddr>,
    pub node_public_key_file: Option<PathBuf>,
    pub bootstrap_key: Option<PathBuf>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AuthenticationConfigSection {
    // TODO move this here: pub bootstrap_key: Option<PathBuf>,
    bas_key: Option<PathBuf>,
    auth_private_key: Option<PathBuf>,
}

/// Configuration of data path & control plane topology.
pub struct TopologyConfig {
    /// Number of packet buffers to allocate per fastpath worker.
    pub buffer_count: usize,

    pub fastpath_concurrency: usize,

    pub fastpath_batch_size: usize,
    pub capture_batch_size: usize,

    pub capture_queue_size: usize,
    pub mgmt_datapath_queue_size: usize,
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
            mgmt_datapath_queue_size: DEFAULT_MGMT_QUEUE_SIZE,
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

/// Parse the `certificate_file` (a noise certificate) and return the CN value found within.
///
/// TODO: This has nothing to do with noise.  And nothing to do with km_cert_exchange.  Move to a pki util file.
pub fn get_noise_cn(certificate_file: &Path) -> Result<String, ArgsError> {
    let cert = load_cert(certificate_file)
        .map_err(|e| ArgsError::ParseError(format!("failed to load noise certificate: {e:?}")))?;
    pki::get_cn_from_cert(&cert).ok_or(ArgsError::ParseError(
        "failed to get CN from certificate".to_string(),
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_deserialize_adapter_config() {
        let toml_str = r#"
            node_addr = "10.0.0.1:5000"
            node_public_key_file = "node_pubkey.pem"
            bootstrap_key = "rsa_key.pem"
            "#;
        let _config: AdapterConfigSection = toml::from_str(toml_str).unwrap();
    }
}
