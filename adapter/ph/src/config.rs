//! Static system configuration.

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

/// Configuration of data path & control plane topology.
pub struct TopologyConfig {
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

            vss_queue_size: DEFAULT_SERVICE_QUEUE_SIZE,
        }
    }
}
