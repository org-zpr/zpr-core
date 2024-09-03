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
use crate::tun_ctl::CarrierSetter;
use crate::zdp::*;
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

    pub tun_ctl: &'pktbuf dyn CarrierSetter,

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

#[cfg(test)]
pub mod test {

    use super::*;
    use enum_map::{enum_map, EnumMap};
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    #[allow(dead_code)]
    pub struct TestAssemblyBuilder<'a> {
        pub buffer_stack: Option<BufferStack<'a, { config::PACKET_BUFFER_SIZE }>>,
        pub mgmt_processor: Option<MgmtProcessor<'a>>,
        pub agent_input: Option<AgentInput<'a>>,
        pub substrate_egress: Option<SubstrateEgress<'a>>,
        pub capture_queue: Option<Capture<'a>>,
        pub capture_worker: Option<CaptureWorker>,
        pub flow_control: Option<FlowControl>,
        pub counters: Option<EnumMap<CounterType, Counter>>,
        pub tun_ctl: Option<&'a dyn CarrierSetter>,
        pub sync_req_state: Option<SyncReqState<'a>>,
        pub peer_table: Option<peer_table::PeerTable>,
        pub adapter_docking_session_id: Option<zpr::LinkId>,
        pub alt: Option<adapter_tables::AgentLookupTable>,
        pub dlt: Option<adapter_tables::DockLookupTable>,
        pub adapter_manager: Option<AdapterManager<'a>>,
    }

    #[allow(dead_code)]
    struct DummyTunCtl;
    impl CarrierSetter for DummyTunCtl {
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[allow(dead_code)]
    impl TestAssemblyBuilder<'_> {
        pub fn new() -> Self {
            Self {
                buffer_stack: None,
                mgmt_processor: None,
                agent_input: None,
                substrate_egress: None,
                capture_queue: None,
                capture_worker: None,
                flow_control: None,
                counters: None,
                tun_ctl: None,
                sync_req_state: None,
                peer_table: None,
                adapter_docking_session_id: None,
                alt: None,
                dlt: None,
                adapter_manager: None,
            }
        }
    }

    #[allow(dead_code)]
    pub fn create_assembly(builder: TestAssemblyBuilder) -> Assembly {
        let buffer_stack = builder.buffer_stack.unwrap_or_else(|| {
            let buf_storage = vec![[0u8; config::PACKET_BUFFER_SIZE]; 0];
            BufferStack::new(buf_storage.leak::<'static>())
        });
        let mgmt_processor = builder.mgmt_processor.unwrap_or_else(|| {
            let (mp_inq, _mp_outq) = mpsc::channel(1);
            MgmtProcessor::new(mp_inq)
        });
        let agent_input = builder.agent_input.unwrap_or_else(|| {
            let v: Vec<&tokio_tun::Tun> = Vec::new();
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
        let counters = builder.counters.unwrap_or_else(|| {
            enum_map! { _ => Counter::new(), }
        });
        let tun_ctl = builder.tun_ctl.unwrap_or_else(|| &DummyTunCtl);
        let sync_req_state = builder
            .sync_req_state
            .unwrap_or_else(|| SyncReqState::new());
        let peer_table = builder
            .peer_table
            .unwrap_or_else(|| peer_table::PeerTable::new());
        let adapter_docking_session_id = builder.adapter_docking_session_id.unwrap_or_else(|| 0);
        let alt = builder
            .alt
            .unwrap_or_else(|| adapter_tables::AgentLookupTable::new());
        let dlt = builder
            .dlt
            .unwrap_or_else(|| adapter_tables::DockLookupTable::new());
        let adapter_manager = builder.adapter_manager.unwrap_or_else(|| {
            let (cq_inq, _cq_outq) = mpsc::channel(1);
            AdapterManager::new(cq_inq)
        });

        Assembly {
            buffer_stack,
            mgmt_processor,
            agent_input,
            substrate_egress,
            capture_queue,
            capture_worker,
            flow_control,
            counters,
            tun_ctl,
            sync_req_state,
            peer_table,
            adapter_docking_session_id,
            alt,
            dlt,
            adapter_manager,
        }
    }
}
