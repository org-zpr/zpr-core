use crate::adapter_tables;
use crate::buffer_stack::BufferStack;
use crate::capture_worker::CaptureWorker;
use crate::config;
use crate::counters::*;
use crate::flow_control::FlowControl;
use crate::km_cert_exchange::KmCertExchange;
use crate::km_multiplexor::KmState;
use crate::km_noise;
use crate::link_state::{LinkEvent, LinkStateError, LinkType};
use crate::mgmt_processor_worker;
use crate::peer_table;
use crate::peer_table::PeerInsertError;
use crate::queues::*;
use crate::tun_ctl::TunCtl;

use enum_map::EnumMap;
use km_noise::NoiseKeypair;
use std::net::IpAddr;
use std::num::NonZero;
use std::result::Result;
use std::sync::Arc;
use tracing::{error, info};
use zpr::{self, LinkId, SubstrateAddr};

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

pub struct Assembly {
    pub ph_mode: PhMode,
    pub topology_config: config::TopologyConfig,

    // Shared resources.  These may be accessed by any part of the system.
    pub system_name: String, // For debugging use
    pub agent_address: Option<IpAddr>,

    pub buffer_stack: BufferStack<{ config::PACKET_BUFFER_SIZE }>,

    pub agent_input: AgentInput,
    pub substrate_egress: SubstrateEgress,

    // Used to intercept packets that are unencrypted but still have ZDP headers
    pub capture_queue: Capture,
    pub capture_worker: CaptureWorker,
    pub flow_control: FlowControl,

    pub counters: EnumMap<CounterType, Counter>,

    pub tun_ctl: Box<dyn TunCtl + Send>,

    pub peer_table: peer_table::PeerTable,
    pub peer_ids: std::sync::Mutex<Vec<zpr::LinkId>>, // HACK until peer_table is enumerable

    // Adapter tables
    // NOTE: only adapter_manager_worker should modify these tables!
    pub alt: adapter_tables::AgentLookupTable,
    pub dlt: adapter_tables::DockLookupTable,

    pub mgmt_dispatch: MgmtDispatch,
    pub adapter_manager: AdapterManager,
    pub km_state: KmState,

    pub self_noise_keypair: Option<NoiseKeypair>,
    pub peer_noise_keypair: Option<NoiseKeypair>,
    pub certx: Option<KmCertExchange>,
}

impl Assembly {
    pub fn is_node(&self) -> bool {
        self.ph_mode == PhMode::Node
    }

    pub fn process_link_state_event(
        self: &Arc<Self>,
        id: LinkId,
        event: LinkEvent,
    ) -> Result<(), LinkStateError> {
        let Some(peer) = self.peer_table.get(id) else {
            return Err(LinkStateError::NotFound(id));
        };
        peer.link_state_machine.process_event(self, event)
    }

    /// Populates the Peer Table with the "fake" internal peer used to hold
    /// state relating to the local agent / internal dock.
    ///
    /// Must be called prior to adding any other peers; panics otherwise.
    pub fn add_local_agent_peer(&self) {
        let entry = self.peer_table.vacant_entry().unwrap();

        assert_eq!(entry.key().get(), zpr::LOCAL_AGENT_LINK_ID);

        let peer_state = peer_table::PeerState::new(
            entry.key(),
            LinkType::Internal,
            std::net::SocketAddrV6::new(std::net::Ipv6Addr::from_bits(0), 0, 0, 0).into(),
            |_| std::future::pending(),
        );

        entry.insert(peer_state);
    }

    fn add_peer(
        self: &Arc<Self>,
        link_type: LinkType,
        peer_addr: &SubstrateAddr,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        let entry = self.peer_table.vacant_entry()?;

        let worker_config = mgmt_processor_worker::Config {
            link_id: entry.key(),
        };

        let peer_state = peer_table::PeerState::new(entry.key(), link_type, *peer_addr, |q| {
            mgmt_processor_worker::launch(worker_config, self.clone(), q)
        });

        Ok(entry.insert(peer_state))
    }

    /// Add a tether to the peer table
    pub fn start_tether(
        self: &Arc<Self>,
        adapter_addr: &SubstrateAddr,
        link_type: LinkType,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        assert!(link_type != LinkType::NodeToNode);
        info!(
            "{}: Starting tether with {}",
            self.system_name, adapter_addr
        );
        let peer_id = self.add_peer(link_type, adapter_addr)?;
        self.peer_ids.lock().unwrap().push(peer_id.get());

        let Some(peer) = self.peer_table.get(peer_id.get()) else {
            // Peer is gone already
            return Ok(peer_id);
        };

        if let Err(e) = peer
            .link_state_machine
            .process_event(self, LinkEvent::Configure)
        {
            error!(
                "{}: Link {} failed to configure with error {}.  Resetting",
                self.system_name, peer_id, e
            );
            let _ = peer
                .link_state_machine
                .process_event(self, LinkEvent::Reset);
        } else {
            if let Err(e) = peer
                .link_state_machine
                .process_event(self, LinkEvent::Start)
            {
                error!(
                    "{}: Link {} failed to start with error {}.  Resetting",
                    self.system_name, peer_id, e
                );
                let _ = peer
                    .link_state_machine
                    .process_event(self, LinkEvent::Reset);
            } else {
                info!(
                    "{}: Successfully started tether with {}.  Assigned ID {}",
                    self.system_name, adapter_addr, peer_id
                );
            }
        }

        return Ok(peer_id);
    }

    pub fn hack_default_policy(&self, ingress_link_id: LinkId) -> Option<NonZero<LinkId>> {
        if ingress_link_id == zpr::LOCAL_AGENT_LINK_ID {
            None
        } else {
            std::num::NonZero::new(
                ((ingress_link_id - (zpr::DOCK_LINK_ID - 1)) % 2) + zpr::DOCK_LINK_ID,
            )
        }
    }
}

#[cfg(test)]
pub mod test {

    use super::*;
    use crate::config::TopologyConfig;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    #[allow(dead_code)]
    #[derive(Default)]
    pub struct TestAssemblyBuilder {
        pub ph_mode: Option<PhMode>,
        pub topology_config: Option<TopologyConfig>,
        pub system_name: Option<String>,
        pub agent_address: Option<Option<IpAddr>>,
        pub buffer_stack: Option<BufferStack<{ config::PACKET_BUFFER_SIZE }>>,
        pub agent_input: Option<AgentInput>,
        pub substrate_egress: Option<SubstrateEgress>,
        pub capture_queue: Option<Capture>,
        pub capture_worker: Option<CaptureWorker>,
        pub flow_control: Option<FlowControl>,
        pub counters: Option<EnumMap<CounterType, Counter>>,
        pub tun_ctl: Option<Box<dyn TunCtl + Send>>,
        pub peer_table: Option<peer_table::PeerTable>,
        pub peer_ids: Option<Vec<zpr::LinkId>>,
        pub alt: Option<adapter_tables::AgentLookupTable>,
        pub dlt: Option<adapter_tables::DockLookupTable>,
        pub mgmt_dispatch: Option<MgmtDispatch>,
        pub adapter_manager: Option<AdapterManager>,
        pub km_state: Option<KmState>,
    }

    #[allow(dead_code)]
    struct DummyTunCtlImpl;
    impl TunCtl for DummyTunCtlImpl {
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl TestAssemblyBuilder {
        pub fn new() -> Self {
            Self::default()
        }
    }

    pub fn create_assembly(builder: TestAssemblyBuilder) -> Assembly {
        let ph_mode = builder.ph_mode.unwrap_or(PhMode::Adapter);
        let topology_config = builder.topology_config.unwrap_or_default();
        let system_name = builder.system_name.unwrap_or("test".into());
        let agent_address = builder
            .agent_address
            .unwrap_or(Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        let buffer_stack = builder.buffer_stack.unwrap_or_else(|| {
            let buf_storage = vec![Box::new([0u8; config::PACKET_BUFFER_SIZE]); 0];
            BufferStack::new(buf_storage)
        });
        let agent_input = builder
            .agent_input
            .unwrap_or_else(|| AgentInput::new(Vec::new()));
        let substrate_egress = builder
            .substrate_egress
            .unwrap_or_else(|| SubstrateEgress::new(Vec::new()));
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
            ph_mode,
            topology_config,
            system_name,
            agent_address,
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
