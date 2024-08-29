use crate::adapter_tables;
use crate::buffer_stack::BufferStack;
use crate::capture_worker::CaptureWorker;
use crate::config;
use crate::counter::*;
use crate::counters_enum::*;
use crate::flow_control::FlowControl;
use crate::mgmt_processor_worker;
use crate::peer_table;
use crate::queues::*;
use crate::tun_ctl::TunCtl;
use crate::zpr;
use enum_map::EnumMap;

#[derive(Clone, Copy)]
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
    pub ph_mode: PhMode,

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

    pub tun_ctl: TunCtl<'pktbuf>,

    pub peer_table: peer_table::PeerTable<'pktbuf>,
    pub peer_ids: std::sync::Mutex<Vec<zpr::LinkId>>, // HACK until peer_table is enumerable

    // Adapter tables
    // NOTE: only adapter_manager_worker should modify these tables!
    pub alt: adapter_tables::AgentLookupTable,
    pub dlt: adapter_tables::DockLookupTable,

    pub adapter_manager: AdapterManager<'pktbuf>,
}

impl Assembly<'_> {
    pub fn hack_get_adapter_docking_session_id(&self) -> zpr::LinkId {
        assert!(matches!(self.ph_mode, PhMode::Adapter));
        let peer_ids = self.peer_ids.lock().unwrap();
        assert_eq!(peer_ids.len(), 1);
        peer_ids[0]
    }

    pub fn hack_add_peer(
        &'static self,
        peer_type: peer_table::PeerType,
        substrate_addr: zpr::SubstrateAddr,
    ) -> Result<zpr::LinkId, peer_table::PeerInsertError> {
        let entry = self.peer_table.vacant_entry()?;

        let worker_config = mgmt_processor_worker::Config {
            link_id: entry.key(),
        };

        let peer_state = peer_table::PeerState::new(peer_type, substrate_addr, |q| {
            mgmt_processor_worker::launch(&worker_config, self, q)
        });

        Ok(entry.insert(peer_state))
    }
}
