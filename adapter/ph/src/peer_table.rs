#![allow(dead_code)]
use crate::dock_tables::DockForwardingTable;
use crate::km::{KeyManager, KmTransportSA, UnimplCodec, ZPIPair};
use crate::queues;
use crate::rcu::{RcuBox, RcuGuard};
use crate::sync_req;
use crate::zpr::{LinkId, SubstrateAddr};
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::DashMap;
use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use tokio::sync::mpsc;
use tokio::task;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const PEER_TABLE_SIZE: usize = 1024;

pub enum PeerType {
    Node,
    Adapter,
}

// FIXME TODO:
// nodes and adapters have different state requirements.
// rather than indirecting through an enum, we could/should
// break adapters/docking sessions out into a separate table.
// this matches the RFC model of separate docks and forwarders.
// for now, everyone has a DFT.......
pub struct PeerState<'pktbuf> {
    pub peer_type: PeerType,
    pub substrate_addr: SubstrateAddr,
    pub sync_req_state: sync_req::SyncReqState<'pktbuf>,
    pub dft: DockForwardingTable,
    pub mgmt_processor: queues::MgmtProcessor<'pktbuf>,
    pub mgmt_processor_worker: task::JoinHandle<()>,
}

struct PeerKmState {
    handle: Option<KmHandle>,
    sa_established: AtomicBool, // if TRUE then `transport_sa` is valid
    transport_sa: KmTransportSA,
}

/// The Key Management "handle" is used by the km_multiplexor to hold per-link
/// state for the key manager state machine.
pub struct KmHandle {
    pub join_handle: JoinHandle<()>,
    pub ctok: CancellationToken, // for this KeyManager
    pub mgr: KeyManager,
}

impl PeerKmState {
    /// Create a new, empty state.
    fn new() -> Self {
        Self {
            handle: None,
            sa_established: AtomicBool::new(false),
            transport_sa: KmTransportSA {
                sa_id: 0,
                recv_zpis: ZPIPair::new_zero(),
                send_zpis: ZPIPair::new_zero(),
                send_hmac_key: [0; 32],
                recv_hmac_key: [0; 32],
                codec: Arc::new(UnimplCodec::new()),
            },
        }
    }
}

const MGMT_PROCESSOR_QUEUE_SIZE: usize = 16;

// FIXME: can we eliminate the reliance on `'static` herein?
impl PeerState<'static> {
    pub fn new<Worker>(
        peer_type: PeerType,
        substrate_addr: SubstrateAddr,
        launch_mgmt_processor_worker: impl FnOnce(
            mpsc::Receiver<queues::MgmtProcessorMessage<'static>>,
        ) -> Worker,
    ) -> Self
    where
        Worker: Future<Output = ()> + Send + 'static,
    {
        let (mp_inq, mp_outq) = mpsc::channel(MGMT_PROCESSOR_QUEUE_SIZE);
        let mgmt_processor = queues::MgmtProcessor::new(mp_inq);

        let mgmt_processor_worker = task::spawn(launch_mgmt_processor_worker(mp_outq));

        Self {
            peer_type,
            substrate_addr,
            dft: DockForwardingTable::new(),
            sync_req_state: sync_req::SyncReqState::new(),
            mgmt_processor,
            mgmt_processor_worker,
        }
    }
}

pub struct PeerTable<'pktbuf> {
    peer_slab: Mutex<RcuCslab<PeerState<'pktbuf>>>,
    peer_slab_reader: RcuBox<RcuCslabReader<PeerState<'pktbuf>>>,
    sa_to_link: DashMap<SubstrateAddr, LinkId>,

    // TODO: put this into the "peer_state" slab! (https://github.com/org-zpr/zpr-core/issues/388)
    link_to_km_state: DashMap<LinkId, PeerKmState>,
}

pub struct PeerStateGuard<'a, 'pktbuf> {
    guard: RcuGuard<'a, RcuCslabReader<PeerState<'pktbuf>>>,
    key: usize,
}

impl<'pktbuf> std::ops::Deref for PeerStateGuard<'_, 'pktbuf> {
    type Target = PeerState<'pktbuf>;

    fn deref(&self) -> &Self::Target {
        self.guard.get(self.key).unwrap()
    }
}

#[derive(Debug)]
pub enum PeerInsertError {
    TableFull,
}

#[derive(Debug)]
pub enum SecurityAssocaitionStateError {
    NoAssociationForLink,
}

impl<'pktbuf> PeerTable<'pktbuf> {
    pub fn new() -> Self {
        let peer_slab = RcuCslab::with_fixed_capacity(PEER_TABLE_SIZE);
        let peer_slab_reader = RcuBox::new(peer_slab.reader());
        let sa_to_link = DashMap::with_capacity(PEER_TABLE_SIZE);
        //let link_to_sec_assoc = DashMap::with_capacity(PEER_TABLE_SIZE);
        //let link_to_km_handle = DashMap::with_capacity(PEER_TABLE_SIZE);
        let link_to_km_state = DashMap::with_capacity(PEER_TABLE_SIZE);

        Self {
            peer_slab: Mutex::new(peer_slab),
            peer_slab_reader,
            sa_to_link,
            link_to_km_state,
        }
    }

    pub fn insert(&self, peer_state: PeerState<'pktbuf>) -> Result<LinkId, PeerInsertError> {
        Ok(self.vacant_entry()?.insert(peer_state))
    }

    pub fn vacant_entry(&self) -> Result<VacantPeerTableEntry<'_, 'pktbuf>, PeerInsertError> {
        let peer_slab_guard = self.peer_slab.lock().unwrap();

        if matches!(peer_slab_guard.vacant_key(), Err(_)) {
            return Err(PeerInsertError::TableFull);
        };

        Ok(VacantPeerTableEntry {
            peer_slab_guard,
            sa_to_link_ref: &self.sa_to_link,
        })
    }

    pub fn remove(&self, link_id: LinkId) {
        let mut peer_slab = self.peer_slab.lock().unwrap();
        let Some(peer_state) = peer_slab.get(link_id as usize) else {
            return;
        };
        self.sa_to_link.remove(&peer_state.substrate_addr);
        let new_reader = peer_slab.remove(link_id as usize);
        std::mem::drop(peer_slab);
        self.peer_slab_reader.write(new_reader);
    }

    pub fn inspect_sync<T>(
        &self,
        link_id: LinkId,
        inspector: impl FnOnce(&PeerState) -> T,
    ) -> Option<T> {
        self.peer_slab
            .lock()
            .unwrap()
            .get(link_id as usize)
            .map(inspector)
    }

    pub fn lookup_peer(&self, substrate_addr: &SubstrateAddr) -> Option<LinkId> {
        self.sa_to_link.get(substrate_addr).map(|id| *id)
    }

    pub fn inspect<T>(
        &self,
        link_id: LinkId,
        inspector: impl FnOnce(&PeerState<'pktbuf>) -> T,
    ) -> Option<T> {
        self.peer_slab_reader
            .inspect(|r| r.get(link_id as usize).map(inspector))
    }

    pub fn get(&self, link_id: LinkId) -> Option<PeerStateGuard<'_, 'pktbuf>> {
        let guard = self.peer_slab_reader.get();
        if guard.get(link_id as usize).is_none() {
            return None;
        }
        Some(PeerStateGuard {
            guard,
            key: link_id as usize,
        })
    }

    /// Initialize state for the security association on the link.  The security association starts out as
    /// not established.
    pub fn init_security_association(&self, link_id: LinkId) {
        if let Some(_) = self.link_to_km_state.insert(link_id, PeerKmState::new()) {
            panic!("duplicate security association");
        }
    }

    /// Sets an established security association on the link.
    pub fn set_security_association(
        &self,
        link_id: LinkId,
        sa: KmTransportSA,
    ) -> Result<(), SecurityAssocaitionStateError> {
        if let Some(mut km_state) = self.link_to_km_state.get_mut(&link_id) {
            km_state.transport_sa = sa;
            km_state.sa_established.store(true, Ordering::Release);
            Ok(())
        } else {
            Err(SecurityAssocaitionStateError::NoAssociationForLink)
        }
    }

    /// At some point shortly after the link security assocaition is initialized, the [km_multiplexor] will
    /// stash its handle in here.
    pub fn set_km_handle(&self, link_id: LinkId, handle: KmHandle) {
        if let Some(mut km_state) = self.link_to_km_state.get_mut(&link_id) {
            km_state.handle = Some(handle);
        } else {
            panic!("no security association for link");
        }
    }

    /// After this, [PeerTable::is_security_assocaition_established] will return false for the link until
    /// a call to [PeerTable::set_security_association].
    pub fn clear_security_association(
        &self,
        link_id: LinkId,
    ) -> Result<(), SecurityAssocaitionStateError> {
        if let Some(km_state) = self.link_to_km_state.get_mut(&link_id) {
            km_state.sa_established.store(false, Ordering::Release);
            Ok(())
        } else {
            Err(SecurityAssocaitionStateError::NoAssociationForLink)
        }
    }

    pub fn is_security_assocaition_established(&self, link_id: LinkId) -> bool {
        if let Some(km_state) = self.link_to_km_state.get(&link_id) {
            km_state.sa_established.load(Ordering::Acquire)
        } else {
            false
        }
    }

    /// Return a clone of the transport SA if there is an SA on the link, and it is established.
    pub fn clone_established_transport_association(
        &self,
        link_id: LinkId,
    ) -> Option<KmTransportSA> {
        match self.link_to_km_state.get(&link_id) {
            Some(km_state) if km_state.sa_established.load(Ordering::Acquire) => {
                Some(km_state.transport_sa.clone())
            }
            _ => None, // either not found or not established
        }
    }

    pub fn clone_km_manager(&self, link_id: LinkId) -> Option<KeyManager> {
        match self.link_to_km_state.get(&link_id) {
            Some(km_state) if km_state.handle.is_some() => {
                Some(km_state.handle.as_ref().unwrap().mgr.clone())
            }
            _ => None,
        }
    }

    /// Remove the key manager state from the link, returning the optional KmHandle that was set.
    pub fn remove_km_state(&self, link_id: LinkId) -> Option<KmHandle> {
        if let Some((_, state)) = self.link_to_km_state.remove(&link_id) {
            state.handle
        } else {
            None
        }
    }
}

pub struct VacantPeerTableEntry<'a, 'pktbuf> {
    peer_slab_guard: MutexGuard<'a, RcuCslab<PeerState<'pktbuf>>>,
    sa_to_link_ref: &'a DashMap<SubstrateAddr, LinkId>,
}

impl<'pktbuf> VacantPeerTableEntry<'_, 'pktbuf> {
    pub fn key(&self) -> LinkId {
        self.peer_slab_guard.vacant_key().unwrap() as LinkId
    }

    pub fn insert(mut self, peer_state: PeerState<'pktbuf>) -> LinkId {
        let sa = peer_state.substrate_addr;

        let link_id = self.peer_slab_guard.insert(peer_state).unwrap() as LinkId;

        if let Some(_) = self.sa_to_link_ref.insert(sa, link_id) {
            panic!("duplicate peer substrate address");
        }

        link_id
    }
}
