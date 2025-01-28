//! Static system configuration.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// Size of a packet buffer.
pub const PACKET_BUFFER_SIZE: usize = 4096 * 3;

/// Size of headroom necessary for most messages.
pub const DEFAULT_MESSAGE_HEADROOM: usize = 256;

pub const DEFAULT_REQUEST_RETRY_COUNT: usize = 3;
pub const DEFAULT_REQUEST_RETRY_TIMER: usize = 1;

pub const ANCILLARY_BUFFER_SIZE: usize = 128;

const DEFAULT_BUFFER_COUNT: usize = 256;
const DEFAULT_BATCH_SIZE: usize = 8;
const DEFAULT_DATAPATH_QUEUE_SIZE: usize = 16;
const DEFAULT_MGMT_QUEUE_SIZE: usize = 16;
const DEFAULT_SERVICE_QUEUE_SIZE: usize = 16;

#[cfg(not(target_os = "macos"))]
const DEFAULT_WORKER_CONCURRENCY: usize = 4;

#[cfg(target_os = "macos")]
const DEFAULT_WORKER_CONCURRENCY: usize = 1;

/// This config struct is loaded up from the command line args and used by the
/// ph system to configure itself.  Do not create this directly, use [argparse].
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

    /// Path to a PEM file containing the noise private key.
    pub private_key_file: PathBuf,

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

/// Configuration of data path & control plane topology.
pub struct TopologyConfig {
    /// Number of packet buffers to allocate per fastpath worker.
    pub buffer_count: usize,

    pub substrate_ingress_concurrency: usize,
    pub agent_output_concurrency: usize,

    pub substrate_ingress_batch_size: usize,
    pub agent_output_batch_size: usize,
    pub capture_batch_size: usize,

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

            substrate_ingress_concurrency: DEFAULT_WORKER_CONCURRENCY,
            agent_output_concurrency: DEFAULT_WORKER_CONCURRENCY,

            substrate_ingress_batch_size: DEFAULT_BATCH_SIZE,
            agent_output_batch_size: DEFAULT_BATCH_SIZE,
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
