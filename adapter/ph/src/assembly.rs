use crate::adapter_tables;
use crate::buffer_stack::BufferStack;
use crate::capture_worker::CaptureWorker;
use crate::config;
use crate::counters::*;
use crate::defs;
use crate::flow_control::FlowControl;
use crate::forwarding_tables;
use crate::km_cert_exchange::KmCertExchange;
use crate::km_multiplexor::KmState;
use crate::km_noise;
use crate::link_state::{LinkEvent, LinkStateError, LinkType};
use crate::logging::targets::PEER_MGMT;
use crate::mgmt;
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
use thiserror::Error;
use tracing::*;
use zpr::{self, LinkId, SubstrateAddr};
use zpr_ext::std::num::NonZeroExt;

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
    pub agent_addresses: Vec<IpAddr>,

    pub buffer_stack: BufferStack<{ config::PACKET_BUFFER_SIZE }>,

    pub agent_input: AgentInput,
    pub substrate_egress: SubstrateEgress,

    pub vsconn: Option<libnode::vsconn::VSConn>, // present only on nodes

    // Used to intercept packets that are unencrypted but still have ZDP headers
    pub capture_queue: Capture,
    pub capture_worker: CaptureWorker,
    pub flow_control: FlowControl,

    pub counters: EnumMap<CounterType, Counter>,

    pub tun_ctl: Box<dyn TunCtl + Send>,

    pub peer_table: peer_table::PeerTable,
    pub peer_ids: std::sync::Mutex<Vec<zpr::LinkId>>, // HACK until peer_table is enumerable

    // Adapter tables
    pub alt: adapter_tables::AgentLookupTable,
    pub dlt: adapter_tables::DockLookupTable,

    pub mgmt_dispatch: MgmtDispatch,
    pub adapter_manager: AdapterManager,
    pub km_state: KmState,

    pub self_noise_keypair: Option<NoiseKeypair>,
    pub peer_noise_keypair: Option<NoiseKeypair>,
    pub certx: Option<KmCertExchange>,
}

#[derive(Debug, Error)]
pub enum AddRouteError {
    #[error("bind failed: {0}")]
    BindFailed(mgmt::requests::BindAgentAddressError),
    #[error("peer gone")]
    PeerGone,
    #[error("PFT full")]
    PftFull,
}

impl Assembly {
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
        debug!(target: PEER_MGMT, "Starting tether with {adapter_addr}");
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
            error!(target: PEER_MGMT, "Link {peer_id} failed to configure with error {e}.  Resetting");
            let _ = peer
                .link_state_machine
                .process_event(self, LinkEvent::Reset);
        } else {
            if let Err(e) = peer
                .link_state_machine
                .process_event(self, LinkEvent::Start)
            {
                error!(target: PEER_MGMT, "Link {peer_id} failed to start with error {e}.  Resetting");
                let _ = peer
                    .link_state_machine
                    .process_event(self, LinkEvent::Reset);
            } else {
                info!(target: PEER_MGMT, "Successfully started tether with {adapter_addr}.  Assigned ID {peer_id}");
            }
        }

        return Ok(peer_id);
    }

    pub async fn add_route(
        &self,
        ingress_link_id: NonZero<LinkId>,
        five_tuple: defs::FiveTuple,
        egress_link_id: NonZero<LinkId>,
        compression_mode: zpr::CompressionMode,
        packet_body: Vec<u8>,
    ) -> Result<zpr::StreamId, AddRouteError> {
        let egress_tether_id;
        if egress_link_id.get() == zpr::LOCAL_AGENT_LINK_ID {
            egress_tether_id = self
                .dlt
                .insert(adapter_tables::DltPep {
                    compression_mode,
                    five_tuple,
                })
                .map_err(|()| {
                    AddRouteError::BindFailed(
                        mgmt::requests::BindAgentAddressError::BindAgentAddressError(
                            "DLT full".into(),
                        ),
                    )
                })?;
        } else {
            egress_tether_id = mgmt::requests::send_bind_agent_address_request(
                self,
                egress_link_id.get(),
                compression_mode,
                five_tuple,
                packet_body,
            )
            .await
            .map_err(|e| AddRouteError::BindFailed(e))?;
        }

        // form PEP
        let pep = forwarding_tables::PftPep {
            next_hop: forwarding_tables::PftNextHop(egress_link_id.get(), egress_tether_id),
        };

        let Some(ingress_peer_state) = self.peer_table.get(ingress_link_id.get()) else {
            return Err(AddRouteError::PeerGone);
        };

        let ingress_tether_id = ingress_peer_state
            .pft
            .insert(pep)
            .map_err(|()| AddRouteError::PftFull)?;

        Ok(ingress_tether_id)
    }

    /// "Default" policy used by the node, in lieu of obtaining forwarding instructions
    /// from the Visa Service.  Consulted after resolving special-peer policy.
    pub fn hack_default_policy(&self, ingress_link_id: NonZero<LinkId>) -> Option<NonZero<LinkId>> {
        if ingress_link_id.get() == zpr::LOCAL_AGENT_LINK_ID {
            // Reject packets from the local agent.
            // (Packets destined to the Visa Service Adapter fall under special-peer policy.)
            None
        } else {
            let visa_server_id = self
                .peer_table
                .lookup_special_peer(crate::special_peers::SpecialPeerName::VisaServiceAdapter)
                .unwrap_or_zero();

            // Unconditionally accept traffic from the Visa Service Adapter;
            // forward it to our local agent.
            if ingress_link_id.get() == visa_server_id {
                return std::num::NonZero::new(zpr::LOCAL_AGENT_LINK_ID);
            }

            let peer_ids = self.peer_ids.lock().unwrap();

            let peer_id_idx = peer_ids
                .iter()
                .position(|id| *id == ingress_link_id.get())?;

            // Unconditionally accept traffice from non-special adapters;
            // forward to the "next" such adapter in a cycle.  (So e.g.
            // two adapters forward between each other.)
            for i in 1..peer_ids.len() {
                let peer_id = peer_ids[(peer_id_idx + i) % peer_ids.len()];
                if peer_id != visa_server_id {
                    return std::num::NonZero::new(peer_id);
                }
            }

            None
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
        pub agent_addresses: Option<Vec<IpAddr>>,
        pub buffer_stack: Option<BufferStack<{ config::PACKET_BUFFER_SIZE }>>,
        pub agent_input: Option<AgentInput>,
        pub substrate_egress: Option<SubstrateEgress>,
        pub vsconn: Option<Option<libnode::vsconn::VSConn>>,
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
        let agent_addresses = builder
            .agent_addresses
            .unwrap_or(Vec::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]));
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
        let vsconn = builder.vsconn.unwrap_or(None);
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
            agent_addresses,
            buffer_stack,
            agent_input,
            substrate_egress,
            vsconn,
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
