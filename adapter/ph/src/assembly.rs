use crate::adapter_tables;
use crate::buffer_stack::BufferStack;
use crate::capture_worker::CaptureWorker;
use crate::config;
use crate::counters::*;
use crate::flow_control::FlowControl;
use crate::km::ZPIPair;
use crate::km_cert_exchange::KmCertExchange;
use crate::km_multiplexor;
use crate::km_multiplexor::KmState;
use crate::km_noise;
use crate::link_state::LinkType;
use crate::mgmt_processor_worker;
use crate::peer_table;
use crate::peer_table::PeerInsertError;
use crate::queues::*;
use crate::tun_ctl::TunCtl;
use crate::zpr;
use crate::zpr::ZPI_ENCRYPTED_HEADER_FLAG;
use crate::zpr::{LinkId, SubstrateAddr};

use enum_map::EnumMap;
use km_noise::NoiseKeypair;
use std::default::Default;
use std::result::Result;
use tracing::info;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PhMode {
    Node,
    Adapter,
}

/// Interface to full assembly of all stages.
///
/// This is the "public interface" that all stages of the system use to talk
/// to each other (via queues), and to shared resources (e.g. the buffer stack).
///
/// All queues and shared resources here should be bounded, so that
/// backpressure can flow from any processing stage all the way back to the
/// kernel network ingest queues, and that service time of any packet
/// transiting the system is not permitted to grow indefinitely under
/// pressure.
///
/// The intention is that there are no hidden unbounded queues in the system
/// (such as a mutex held over a blocking operation).  If a resource is
/// highly contended resulting in a bottleneck, that should result in some
/// visible queue becoming full.

pub struct Assembly<'pktbuf> {
    pub flags: PhFlags,
    pub ph_mode: PhMode,
    pub topology_config: config::TopologyConfig,

    // Shared resources.  These may be accessed by any part of the system.
    pub system_name: String, // For debugging use

    pub buffer_stack: BufferStack<'pktbuf, { config::PACKET_BUFFER_SIZE }>,

    pub agent_input: AgentInput<'pktbuf>,
    pub substrate_egress: SubstrateEgress<'pktbuf>,

    // Used to intercept packets that are unencrypted but still have ZDP headers
    pub capture_queue: Capture<'pktbuf>,
    pub capture_worker: CaptureWorker,
    pub flow_control: FlowControl,

    pub counters: EnumMap<CounterType, Counter>,

    pub tun_ctl: Box<dyn TunCtl + 'pktbuf>,

    pub peer_table: peer_table::PeerTable<'pktbuf>,
    pub peer_ids: std::sync::Mutex<Vec<zpr::LinkId>>, // HACK until peer_table is enumerable

    // Adapter tables
    // NOTE: only adapter_manager_worker should modify these tables!
    pub alt: adapter_tables::AgentLookupTable<'pktbuf>,
    pub dlt: adapter_tables::DockLookupTable,

    pub mgmt_dispatch: MgmtDispatch<'pktbuf>,
    pub adapter_manager: AdapterManager<'pktbuf>,
    pub km_state: KmState,

    pub self_noise_keypair: Option<NoiseKeypair>,
    pub peer_noise_keypair: Option<NoiseKeypair>,
    pub certx: Option<KmCertExchange>,
}

pub struct PhFlags {
    /// If set TRUE this allows any messages on ZPI 0.  VERY INSECURE!!
    pub allow_insecure_zpi_zero: bool,
    pub disable_key_management: bool,
}

impl Default for PhFlags {
    /// Reasonable (and secure) defaults
    fn default() -> Self {
        Self {
            allow_insecure_zpi_zero: false,
            disable_key_management: false,
        }
    }
}

impl Assembly<'_> {
    pub fn is_node(&self) -> bool {
        self.ph_mode == PhMode::Node
    }

    pub fn is_adapter(&self) -> bool {
        self.ph_mode == PhMode::Adapter
    }

    fn add_peer(
        &'static self,
        link_type: LinkType,
        peer_addr: &SubstrateAddr,
    ) -> Result<LinkId, PeerInsertError> {
        let entry = self.peer_table.vacant_entry()?;

        let worker_config = mgmt_processor_worker::Config {
            link_id: entry.key(),
        };

        let peer_state = peer_table::PeerState::new(link_type, *peer_addr, |q| {
            mgmt_processor_worker::launch(&worker_config, self, q)
        });

        Ok(entry.insert(peer_state))
    }

    /// Add an adapter to the peer table
    pub fn accept_tether(
        &'static self,
        adapter_addr: &SubstrateAddr,
    ) -> Result<LinkId, PeerInsertError> {
        assert!(self.is_node());
        info!(
            "{}: Accepting tether from {}",
            self.system_name, adapter_addr
        );
        let peer_id = self.add_peer(LinkType::NodeToAdapter, adapter_addr)?;
        self.peer_ids.lock().unwrap().push(peer_id);

        if !self.flags.disable_key_management {
            km_multiplexor::add_node_link(
                &self,
                peer_id,
                ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 3, 4),
                self.self_noise_keypair.clone().unwrap(),
                self.certx.clone().unwrap(),
            )
            .unwrap();
        }

        info!(
            "{}: Successfully accepted tether from {}.  Assigned ID {}",
            self.system_name, adapter_addr, peer_id
        );

        return Ok(peer_id);
    }

    /// Add a node to the peer table as an adapter
    pub fn initiate_tether(
        &'static self,
        node_addr: &SubstrateAddr,
    ) -> Result<LinkId, PeerInsertError> {
        assert!(self.is_adapter());
        info!(
            "{}: Initiating tether towards {}",
            self.system_name, node_addr
        );
        let peer_id = self.add_peer(LinkType::AdapterToNode, node_addr)?;
        self.peer_ids.lock().unwrap().push(peer_id);

        if !self.flags.disable_key_management {
            km_multiplexor::add_adapter_link(
                &self,
                peer_id,
                ZPIPair::new(zpr::ZPI_ENCRYPTED_HEADER_FLAG | 5, 6),
                self.self_noise_keypair.clone().unwrap(),
                self.peer_noise_keypair.clone().unwrap().public,
                self.certx.clone().unwrap(),
            )
            .unwrap();
        }

        info!(
            "{}: Successfully initiated tether to {}.  Assigned ID {}",
            self.system_name, node_addr, peer_id
        );

        return Ok(peer_id);
    }

    pub fn hack_get_adapter_docking_session_id(&self) -> zpr::LinkId {
        assert!(matches!(self.ph_mode, PhMode::Adapter));
        let peer_ids = self.peer_ids.lock().unwrap();
        assert_eq!(peer_ids.len(), 1);
        peer_ids[0]
    }
}

#[cfg(test)]
pub mod test {

    use super::*;
    use crate::config::TopologyConfig;
    use crate::sys::ZprTun;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;


    #[allow(dead_code)]
    #[derive(Default)]
    pub struct TestAssemblyBuilder<'a> {
        pub ph_mode: Option<PhMode>,
        pub flags: Option<PhFlags>,
        pub topology_config: Option<TopologyConfig>,
        pub system_name: Option<String>,
        pub buffer_stack: Option<BufferStack<'a, { config::PACKET_BUFFER_SIZE }>>,
        pub agent_input: Option<AgentInput<'a>>,
        pub substrate_egress: Option<SubstrateEgress<'a>>,
        pub capture_queue: Option<Capture<'a>>,
        pub capture_worker: Option<CaptureWorker>,
        pub flow_control: Option<FlowControl>,
        pub counters: Option<EnumMap<CounterType, Counter>>,
        pub tun_ctl: Option<Box<dyn TunCtl + 'a>>,
        pub peer_table: Option<peer_table::PeerTable<'a>>,
        pub peer_ids: Option<Vec<zpr::LinkId>>,
        pub alt: Option<adapter_tables::AgentLookupTable<'a>>,
        pub dlt: Option<adapter_tables::DockLookupTable>,
        pub mgmt_dispatch: Option<MgmtDispatch<'a>>,
        pub adapter_manager: Option<AdapterManager<'a>>,
        pub km_state: Option<KmState>,
    }

    #[allow(dead_code)]
    struct DummyTunCtlImpl;
    impl TunCtl for DummyTunCtlImpl {
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl TestAssemblyBuilder<'_> {
        pub fn new() -> Self {
            Self::default()
        }
    }

    pub fn create_assembly(builder: TestAssemblyBuilder) -> Assembly {
        let flags = builder.flags.unwrap_or_default();
        let ph_mode = builder.ph_mode.unwrap_or(PhMode::Adapter);
        let topology_config = builder.topology_config.unwrap_or_default();
        let system_name = builder.system_name.unwrap_or("test".into());
        let buffer_stack = builder.buffer_stack.unwrap_or_else(|| {
            let buf_storage = vec![[0u8; config::PACKET_BUFFER_SIZE]; 0];
            BufferStack::new(buf_storage.leak::<'static>())
        });
        let agent_input = builder.agent_input.unwrap_or_else(|| {
            let v: Vec<&ZprTun> = Vec::new();
            AgentInput::new(v)
        });
        let substrate_egress = builder.substrate_egress.unwrap_or_else(|| {
            let v: Vec<&UdpSocket> = Vec::new();
            SubstrateEgress::new(v)
        });
        let capture_queue = builder.capture_queue.unwrap_or_else(|| {
            let (cq_inq, _cq_outq) = mpsc::channel(1);
            Capture::new(cq_inq)
        });
        let capture_worker = builder
            .capture_worker
            .unwrap_or_else(|| CaptureWorker::new());
        let flow_control = builder.flow_control.unwrap_or_else(|| FlowControl::new());
        let counters = builder.counters.unwrap_or_default();
        let tun_ctl = builder.tun_ctl.unwrap_or_else(|| Box::new(DummyTunCtlImpl));
        let peer_table = builder
            .peer_table
            .unwrap_or_else(|| peer_table::PeerTable::new());
        let peer_ids = std::sync::Mutex::new(builder.peer_ids.unwrap_or_default());
        let alt = builder
            .alt
            .unwrap_or_else(|| adapter_tables::AgentLookupTable::new());
        let dlt = builder
            .dlt
            .unwrap_or_else(|| adapter_tables::DockLookupTable::new());
        let mgmt_dispatch = builder.mgmt_dispatch.unwrap_or_else(|| {
            let (md_inq, _md_outq) = mpsc::channel(1);
            MgmtDispatch::new(md_inq)
        });
        let adapter_manager = builder.adapter_manager.unwrap_or_else(|| {
            let (am_inq, _am_outq) = mpsc::channel(1);
            AdapterManager::new(am_inq)
        });
        let km_state = builder.km_state.unwrap_or_else(|| {
            let (km_sig_tx, _km_sig_rx) = mpsc::channel(1);
            let (km_tx, _km_rx) = mpsc::channel(1);
            KmState::new(km_tx, km_sig_tx)
        });

        Assembly {
            flags,
            ph_mode,
            topology_config,
            system_name,
            buffer_stack,
            agent_input,
            substrate_egress,
            capture_queue,
            capture_worker,
            flow_control,
            counters,
            tun_ctl,
            peer_table,
            peer_ids,
            alt,
            dlt,
            mgmt_dispatch,
            adapter_manager,
            km_state,
            self_noise_keypair: None,
            peer_noise_keypair: None,
            certx: None,
        }
    }
}
