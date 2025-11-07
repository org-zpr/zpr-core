use crate::adapter_tables;
use crate::address_pool::AddressPool;
use crate::capture_worker::CaptureWorker;
use crate::config;
use crate::counters::*;
use crate::flow_control::FlowControl;
use crate::forwarding_tables;
use crate::km_cert_exchange::KmCertExchange;
use crate::km_multiplexor::KmState;
use crate::km_noise;
use crate::link_state::{LinkEvent, LinkStateError, LinkType};
use crate::logging::targets::PEER_MGMT;
use crate::mgmt;
use crate::mgmt_processor_worker;
use crate::net_defs::{self, IpAddress, ScopedIpAddr};
use crate::peer_table;
use crate::peer_table::PeerInsertError;
use crate::queues::*;
use crate::rcu;
use crate::special_peers::SpecialPeerName;
use crate::tc;
use crate::tun_ctl::TunCtl;
use crate::visa_table;
use crate::vs_types::AuthServicesList;
use crate::zdp::TerminateReason;
use crate::zdpr_worker;
use km_noise::NoiseKeypair;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZero;
use std::result::Result;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::*;
use tracing_subscriber::filter::targets::Targets;
#[allow(unused_imports)]
use tracing_subscriber::{Layer, Registry, filter, fmt, reload};
use zpr::{self, LinkId, SubstrateAddr, VisaId};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PhMode {
    Node,
    Adapter,
}

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

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

    pub mgmt_substrate_egress: MgmtSubstrateEgress,
    pub actor_output_requeue: ActorOutputRequeue,

    pub vsconn: Option<libnode::vsconn::VSConnHandle>, // present only on nodes
    pub vs_auth_services: std::sync::RwLock<AuthServicesList>, // present only on nodes, may be empty, managed by visa service

    pub visa_table: tokio::sync::RwLock<visa_table::VisaTable>, // Only for nodes

    // Used to intercept packets that are unencrypted but still have ZDP headers
    pub capture_queue: Capture,
    pub capture_worker: CaptureWorker,
    pub flow_control: FlowControl,

    pub counters: Counters,

    pub tun_ctl: Box<dyn TunCtl + Send>,

    pub peer_table: peer_table::PeerTable,

    // Adapter tables
    pub alt: adapter_tables::ActorLookupTable,
    pub dlt: adapter_tables::DockLookupTable,

    pub mgmt_dispatch_factory: MgmtDispatchFactory,
    pub adapter_manager_factory: AdapterManagerFactory,
    pub km_state: KmState,

    pub self_noise_keypair: Option<NoiseKeypair>,
    pub peer_noise_keypair: Option<NoiseKeypair>,
    pub certx: Option<KmCertExchange>,
    pub system_start_time: std::time::Instant,
    pub address_pool: std::sync::Mutex<Option<AddressPool>>, // Nodes only (and required for nodes)

    /// Note that zpr addressed in config are not our real ZPR addresses until we are granted a ZPR address.
    /// If there is a static ZPR address present in the configuration it is set here in main.
    /// Various get_ and set_ functions are defined for this below.
    pub config: rcu::RcuBox<config::Config>,
    pub logging: Mutex<HashMap<String, String>>,
    pub reload_handle:
        reload::Handle<filter::Filtered<fmt::Layer<Registry>, Targets, Registry>, Registry>,
}

#[derive(Debug, Error)]
pub enum AddRouteError {
    #[error("bind failed: {0}")]
    BindFailed(#[from] mgmt::requests::BindActorAddressError),
    #[error("peer gone")]
    PeerGone,
    #[error("PFT full")]
    PftFull,
    #[error("Visa gone")]
    VisaGone,
}

impl Assembly {
    pub fn get_uptime(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.system_start_time)
    }

    /// Graceful shutdown routine.  Not guaranteed to be called
    pub async fn shutdown(self: &Arc<Self>) {
        if self.ph_mode == PhMode::Node {
            self.shutdown_node().await
        } else {
            self.shutdown_adapter().await
        }
    }

    // The node quickly sends Terminate Indications
    async fn shutdown_node(self: &Arc<Self>) {
        if matches!(self.ph_mode, PhMode::Node) {
            let mut join_set = tokio::task::JoinSet::new();

            let vs_peer = self
                .peer_table
                .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);

            self.peer_table.for_each(|(peer_id, _)| {
                if Some(peer_id) != vs_peer && peer_id.get() != zpr::LOCAL_ACTOR_LINK_ID {
                    // This should be a short block and must be blocked on,
                    // otherwise the messages won't get sent
                    let spawn_self = self.clone();
                    join_set.spawn_local(async move { spawn_self.reset_peer(peer_id.get()).await });
                }
            });

            join_set.join_all().await;

            if let Some(vs_peer) = vs_peer {
                self.reset_peer(vs_peer.get()).await;
            }
        }
    }

    // The adapter sends a more policy Terminate Request.
    async fn shutdown_adapter(self: &Arc<Self>) {
        let mut join_set = tokio::task::JoinSet::new();

        self.peer_table.for_each(|(peer_id, peer)| {
            if peer_id.get() == zpr::LOCAL_ACTOR_LINK_ID {
                return;
            }

            if let Err(e) = peer
                .link_state_machine
                .process_event(self, LinkEvent::Close(TerminateReason::Shutdown))
            {
                error!(target: PEER_MGMT, "Failed to nicely close peer {peer_id}: {e}");
                // So try harder...
                let spawn_self = self.clone();
                join_set.spawn_local(async move { spawn_self.reset_peer(peer_id.get()).await });
            }
        });
        join_set.join_all().await;

        let mut npeers = self.peer_table.len() - 1; // - 1 accounts for local actor
        info!(
            target: PEER_MGMT,
            "Waiting for {} peer{} to disconnect...",
            npeers,
            if npeers == 1 { "" } else { "s" }
        );
        while npeers > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            npeers = self.peer_table.len() - 1; // - 1 accounts for local actor
        }
    }

    pub fn is_link_ready(&self, id: LinkId) -> bool {
        match self.peer_table.get(id) {
            Some(peer) => peer.link_state_machine.is_ready(),
            None => false,
        }
    }

    /// Update the local ZPR addresses of this node or adapter. Though presumably
    /// this is called only on an adapter as a nodes addresses are currently set
    /// through configuration or command line args.
    pub fn set_local_zpr_addrs<T>(&self, addrs: impl IntoIterator<Item = T>)
    where
        T: Into<IpAddr>,
    {
        let addrs: Vec<IpAddr> = addrs.into_iter().map(|a| a.into()).collect();
        self.config
            .update(move |cfg| {
                Some(config::Config {
                    zpr_addr: addrs.clone(),
                    ..cfg.clone()
                })
            })
            .unwrap();
    }

    /// Get a copy of the local ZPR addresses. May be empty on an adapter until we
    /// have been granted a ZPR address.
    pub fn get_local_zpr_addrs_std(&self) -> Vec<IpAddr> {
        self.config.get().zpr_addr.clone()
    }

    /// Node only: the "dock address" is the first local ZPR address.
    ///
    /// In unlikely event that the node has no local ZPR addresses, this returns the
    /// all zeros IPv6 addr.
    ///
    /// TODO: In the future we may want to keep track of the nodes dock address
    /// in a more static way to avoid taking the read lock since we need this
    /// value on every visa request.
    pub fn get_local_dock_addr(&self) -> IpAddr {
        let lza = &self.config.get().zpr_addr;
        if lza.is_empty() {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        } else {
            lza[0]
        }
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
    /// state relating to the local actor / internal dock.
    ///
    /// Must be called prior to adding any other peers; panics otherwise.
    pub fn add_local_actor_peer(&self) {
        let entry = self.peer_table.vacant_entry().unwrap();

        assert_eq!(entry.key().get(), zpr::LOCAL_ACTOR_LINK_ID);

        let peer_state = peer_table::PeerState::new(
            entry.key(),
            LinkType::Internal,
            std::net::SocketAddrV6::new(std::net::Ipv6Addr::from_bits(0), 0, 0, 0).into(),
            net_defs::ScopedIpv6Addr::new(std::net::Ipv6Addr::from_bits(0), 0).into(),
            |_| std::future::pending(),
        );

        entry.insert(peer_state);
    }

    fn add_peer(
        self: &Arc<Self>,
        link_type: LinkType,
        peer_addr: &SubstrateAddr,
        interface_addr: &ScopedIpAddr,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        let entry = self.peer_table.vacant_entry()?;

        let worker_config = mgmt_processor_worker::Config {
            link_id: entry.key(),
        };

        let peer_state =
            peer_table::PeerState::new(entry.key(), link_type, *peer_addr, *interface_addr, |q| {
                mgmt_processor_worker::launch(worker_config, self.clone(), q)
            });

        let link_id = entry.insert(peer_state);

        tokio::task::spawn_local(zdpr_worker::launch(self.clone(), link_id.get()));

        Ok(link_id)
    }

    /// Caled from `LinkStateWrapper::complete_close`.`
    pub fn drop_peer(self: &Arc<Self>, link_id: LinkId) {
        let vs_link_id = self
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
        if vs_link_id.is_some() && link_id == vs_link_id.unwrap().get() {
            debug!(target: PEER_MGMT, "Removing peer {link_id} [VISA SERVICE]");
        } else {
            debug!(target: PEER_MGMT, "Removing peer {link_id}");
        }
        self.peer_table.remove(link_id);
        info!(target: PEER_MGMT, "Removed peer {link_id}");
    }

    /// Part of graceful shutdown (or administrative link shutdown).
    ///
    /// Reset peer at given link.
    ///
    /// Calls down to `LinkStateWrapper::reset` which will ultimately end up calling back
    /// here to [Assembly::drop_peer].
    pub async fn reset_peer(self: &Arc<Self>, link_id: LinkId) {
        let vs_link_id = self
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
        if vs_link_id.is_some() && link_id == vs_link_id.unwrap().get() {
            if let Some(vsconn) = self.vsconn.as_ref() {
                if let Err(e) = vsconn.stop(true).await {
                    error!(target: PEER_MGMT, "stop command to VSConn failed: {e}");
                } else {
                    // Let VSConn runloop process/send the command.
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
        if let Some(peer) = self.peer_table.get(link_id) {
            peer.link_state_machine.reset(self).await;
        }
    }

    /// Add a tether to the peer table
    pub fn start_tether(
        self: &Arc<Self>,
        adapter_addr: &SubstrateAddr,
        interface_addr: &ScopedIpAddr,
        link_type: LinkType,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        assert!(link_type != LinkType::NodeToNode);
        debug!(target: PEER_MGMT, "Starting tether with {adapter_addr} connected to {interface_addr}");
        let peer_id = self.add_peer(link_type, adapter_addr, interface_addr)?;

        let Some(peer) = self.peer_table.get(peer_id.get()) else {
            // Peer is gone already
            return Ok(peer_id);
        };

        if let Err(e) = peer
            .link_state_machine
            .process_event(self, LinkEvent::Start)
        {
            error!(target: PEER_MGMT, "Link {peer_id} failed to start with error {e}.  Resetting");
            peer.link_state_machine
                .process_event(self, LinkEvent::Error)
                .expect("This shouldn't error!");
            return Err(PeerInsertError::FailedToStart(e.to_string()));
        } else {
            info!(target: PEER_MGMT, "Successfully started tether with {adapter_addr}.  Assigned ID {peer_id}");
        }

        return Ok(peer_id);
    }

    /// Temporary? function to find a link based on the actor address
    pub fn find_egress_link(&self, actor_addr: IpAddress) -> Option<NonZero<LinkId>> {
        // First check the local actor addresses to see if it's a locally-destined packet
        if self
            .config
            .get()
            .zpr_addr
            .iter()
            .any(|addr| IpAddress::new_from_std(addr) == actor_addr)
        {
            return Some(NonZero::new(zpr::LOCAL_ACTOR_LINK_ID).unwrap());
        }

        // Check peer actor addresses to see if one of them matches
        self.peer_table
            .find(|(_id, peer)| {
                peer.link_state_machine
                    .get_actor_addresses()
                    .iter()
                    .any(|addr| *addr == actor_addr)
            })
            .map(|(id, _peer)| id)
    }

    // CTP TODO: so much to fix here as we properly implement classification & forwarding
    pub async fn add_route(
        &self,
        ingress_link_id: NonZero<LinkId>,
        visa_id: VisaId,
        tc: tc::Ip5TupleTc,
        egress_link_id: NonZero<LinkId>,
    ) -> Result<zpr::StreamId, AddRouteError> {
        let egress_tether_id;
        if egress_link_id.get() == zpr::LOCAL_ACTOR_LINK_ID {
            egress_tether_id = self
                .dlt
                .insert(adapter_tables::DltPep {
                    compression_mode: tc.compression_mode(),
                    five_tuple: *tc.five_tuple(),
                })
                .map_err(|()| {
                    AddRouteError::BindFailed(
                        mgmt::requests::BindActorAddressError::BindActorAddressError(
                            "DLT full".into(),
                        ),
                    )
                })?;
        } else {
            egress_tether_id =
                mgmt::requests::send_bind_egress_stream_request(self, egress_link_id.get(), tc)
                    .await?;
        }

        // form PEP
        let pep = forwarding_tables::PftPep {
            next_hop: zpr::ForwardingEntry(egress_link_id.get(), egress_tether_id),
            visa_id: visa_id,
        };

        let Some(ingress_peer_state) = self.peer_table.get(ingress_link_id.get()) else {
            return Err(AddRouteError::PeerGone);
        };

        let ingress_tether_id = ingress_peer_state
            .pft
            .insert(pep)
            .map_err(|()| AddRouteError::PftFull)?;

        if self
            .visa_table
            .write()
            .await
            .link_forwarding_entry(
                visa_id,
                zpr::ForwardingEntry(ingress_link_id.get(), ingress_tether_id),
            )
            .is_err()
        {
            // Visa was either never granted or has already been removed
            // Route is no longer valid
            ingress_peer_state.pft.remove(ingress_tether_id);
            return Err(AddRouteError::VisaGone);
        }

        Ok(ingress_tether_id)
    }
}

#[cfg(test)]
pub mod test {

    use super::*;
    use crate::config::TopologyConfig;
    use crate::packet_queue;
    use crate::two_way_queue;
    use tokio::sync::mpsc;

    #[allow(dead_code)]
    #[derive(Default)]
    pub struct TestAssemblyBuilder {
        pub ph_mode: Option<PhMode>,
        pub topology_config: Option<TopologyConfig>,
        pub local_zpr_addresses: Option<Vec<IpAddr>>,
        pub mgmt_substrate_egress: Option<MgmtSubstrateEgress>,
        pub actor_output_requeue: Option<ActorOutputRequeue>,
        pub vsconn: Option<Option<libnode::vsconn::VSConnHandle>>,
        pub visa_table: Option<visa_table::VisaTable>,
        pub capture_queue: Option<Capture>,
        pub capture_worker: Option<CaptureWorker>,
        pub flow_control: Option<FlowControl>,
        pub counters: Option<Counters>,
        pub tun_ctl: Option<Box<dyn TunCtl + Send>>,
        pub peer_table: Option<peer_table::PeerTable>,
        pub alt: Option<adapter_tables::ActorLookupTable>,
        pub dlt: Option<adapter_tables::DockLookupTable>,
        pub mgmt_dispatch_factory: Option<MgmtDispatchFactory>,
        pub adapter_manager_factory: Option<AdapterManagerFactory>,
        pub km_state: Option<KmState>,
        pub system_start_time: Option<std::time::Instant>,
        pub config: Option<rcu::RcuBox<config::Config>>,
        pub logging: Option<Mutex<HashMap<String, String>>>,
        pub reload_handle: Option<
            reload::Handle<filter::Filtered<fmt::Layer<Registry>, Targets, Registry>, Registry>,
        >,
    }

    #[allow(dead_code)]
    struct DummyTunCtlImpl;
    impl TunCtl for DummyTunCtlImpl {
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
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
        let mgmt_substrate_egress = builder
            .mgmt_substrate_egress
            .unwrap_or_else(|| MgmtSubstrateEgress::new(packet_queue::packet_queue(1).0));
        let actor_output_requeue = builder
            .actor_output_requeue
            .unwrap_or_else(|| ActorOutputRequeue::new(Vec::new()));
        let vsconn = builder.vsconn.unwrap_or(None);
        let visa_table = tokio::sync::RwLock::new(
            builder
                .visa_table
                .unwrap_or_else(|| visa_table::VisaTable::new()),
        );
        let capture_queue = builder.capture_queue.unwrap_or_else(|| {
            let (cq_inq, _cq_outq) = std::os::unix::net::UnixDatagram::pair().unwrap();
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
        let alt = builder
            .alt
            .unwrap_or_else(|| adapter_tables::ActorLookupTable::new());
        let dlt = builder
            .dlt
            .unwrap_or_else(|| adapter_tables::DockLookupTable::new());
        let mgmt_dispatch_factory = builder.mgmt_dispatch_factory.unwrap_or_else(|| {
            let (md_inq_factory, _md_outq) = two_way_queue::two_way_queue(1);
            MgmtDispatchFactory::new(md_inq_factory)
        });
        let adapter_manager_factory = builder.adapter_manager_factory.unwrap_or_else(|| {
            let (am_inq_factory, _am_outq) = two_way_queue::two_way_queue(1);
            AdapterManagerFactory::new(am_inq_factory)
        });
        let km_state = builder.km_state.unwrap_or_else(|| {
            let (km_sig_tx, _km_sig_rx) = mpsc::channel(1);
            let (km_tx, _km_rx) = mpsc::channel(1);
            KmState::new(km_tx, km_sig_tx)
        });
        let config = builder.config.unwrap_or_else(|| {
            let config = <config::Config as std::default::Default>::default();
            rcu::RcuBox::new(config)
        });
        let logging = builder
            .logging
            .unwrap_or_else(|| Mutex::new(HashMap::default()));
        let reload_handle = builder.reload_handle.unwrap_or_else(|| {
            let (_reload_layer, reload_handle) =
                reload::Layer::new(fmt::layer().with_filter(Targets::new()));
            reload_handle
        });

        Assembly {
            ph_mode,
            topology_config,
            mgmt_substrate_egress,
            actor_output_requeue,
            vsconn,
            visa_table,
            vs_auth_services: std::sync::RwLock::new(AuthServicesList::default()),
            capture_queue,
            capture_worker,
            flow_control,
            counters,
            tun_ctl,
            peer_table,
            alt,
            dlt,
            mgmt_dispatch_factory,
            adapter_manager_factory,
            km_state,
            self_noise_keypair: None,
            peer_noise_keypair: None,
            certx: None,
            system_start_time: std::time::Instant::now(),
            address_pool: std::sync::Mutex::new(None),
            config,
            logging,
            reload_handle,
        }
    }
}
