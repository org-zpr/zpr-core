#![allow(dead_code)]
use crate::forwarding_tables::PeerForwardingTable;
use crate::km::{KeyManager, KmTransportSA};
use crate::link_state::{LinkStateWrapper, LinkType};
use crate::queues;
use crate::rcu::{RcuBox, RcuCslabEntryGuard, RcuOptionGuard};
use crate::sync_req;
use bytes::Bytes;
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::DashMap;
use enum_map::{enum_map, Enum, EnumMap};
use enumset::{EnumSet, EnumSetType};
use std::future::Future;
use std::sync::atomic::{self, Ordering};
use std::sync::Mutex;
use std::sync::MutexGuard;
use tokio::sync::mpsc;
use tokio::task;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zpr::{LinkId, SubstrateAddr, LINK_ID_UNKNOWN};

const PEER_TABLE_SIZE: usize = 1024;

/// Some peers are "special", e.g. the visa service adapter attached to the initial node.
/// These names let us identify them.
#[derive(Debug, Enum, EnumSetType)]
pub enum SpecialPeerName {
    VisaServiceAdapter,
}

pub struct PeerState {
    pub substrate_addr: SubstrateAddr,
    pub special_names: EnumSet<SpecialPeerName>,
    pub link_state_machine: LinkStateWrapper,
    pub sync_req_state: sync_req::SyncReqState,
    pub pft: PeerForwardingTable,
    pub mgmt_processor: queues::MgmtProcessor,
    pub mgmt_processor_worker: task::JoinHandle<()>,
    km_state: PeerKmState,
}

// Key Management state per peer.
struct PeerKmState {
    handle: Mutex<Option<KmHandle>>, // Once the KM state machine starts, its join handle and related info is stashed here.
    transport_sa: RcuBox<Option<KmTransportSA>>,
}

/// The Key Management "handle" is used by the km_multiplexor to hold per-link
/// state for the key manager state machine.
pub struct KmHandle {
    pub join_handle: JoinHandle<()>,
    pub ctok: CancellationToken, // for this KeyManager
    pub mgr: KeyManager,
    pub km_tx: mpsc::Sender<Bytes>, // for sending in KM payloads
}

impl PeerKmState {
    /// Create a new, empty state.  This is what is attached to a new PeerTable entry.
    fn new() -> Self {
        Self {
            handle: Mutex::new(None),
            transport_sa: RcuBox::new(None),
        }
    }
}

const MGMT_PROCESSOR_QUEUE_SIZE: usize = 16;

impl PeerState {
    pub fn new<Worker>(
        link_id: LinkId,
        link_type: LinkType,
        substrate_addr: SubstrateAddr,
        launch_mgmt_processor_worker: impl FnOnce(
            mpsc::Receiver<queues::MgmtProcessorMessage>,
        ) -> Worker,
    ) -> Self
    where
        Worker: Future<Output = ()> + 'static,
    {
        let (mp_inq, mp_outq) = mpsc::channel(MGMT_PROCESSOR_QUEUE_SIZE);
        let mgmt_processor = queues::MgmtProcessor::new(mp_inq);

        let mgmt_processor_worker = task::spawn_local(launch_mgmt_processor_worker(mp_outq));

        Self {
            substrate_addr,
            special_names: EnumSet::<SpecialPeerName>::empty(),
            link_state_machine: LinkStateWrapper::new(link_id, link_type),
            pft: PeerForwardingTable::new(),
            sync_req_state: sync_req::SyncReqState::new(),
            mgmt_processor,
            mgmt_processor_worker,
            km_state: PeerKmState::new(),
        }
    }

    pub fn add_special_name(&mut self, name: SpecialPeerName) {
        self.special_names |= name;
    }

    /// Return a reference to the transport SA if there is an SA on the link, and if it is established.
    pub fn get_established_transport_association(
        &self,
    ) -> Option<RcuOptionGuard<'_, KmTransportSA>> {
        self.km_state.transport_sa.get().into()
    }
}

type AtomicLinkId = atomic::AtomicU32;
const _: () = assert!(std::mem::size_of::<AtomicLinkId>() == std::mem::size_of::<LinkId>());

pub struct PeerTable {
    peer_slab: Mutex<RcuCslab<PeerState>>,
    peer_slab_reader: RcuBox<RcuCslabReader<PeerState>>,
    sa_to_link: DashMap<SubstrateAddr, LinkId>,
    special_peers: EnumMap<SpecialPeerName, AtomicLinkId>,
}

pub type PeerTableEntryGuard<'a> = RcuCslabEntryGuard<'a, PeerState>;

#[derive(Debug)]
pub enum PeerInsertError {
    TableFull,
}

#[derive(Debug)]
pub enum SecurityAssocaitionStateError {
    NoAssociationForLink,
}

impl PeerTable {
    pub fn new() -> Self {
        let peer_slab = RcuCslab::with_fixed_capacity(PEER_TABLE_SIZE);
        let peer_slab_reader = RcuBox::new(peer_slab.reader());
        Self {
            peer_slab: Mutex::new(peer_slab),
            peer_slab_reader,
            sa_to_link: DashMap::with_capacity(PEER_TABLE_SIZE),
            special_peers: enum_map! { _ => LINK_ID_UNKNOWN.into() },
        }
    }

    pub fn insert(&self, peer_state: PeerState) -> Result<LinkId, PeerInsertError> {
        Ok(self.vacant_entry()?.insert(peer_state))
    }

    pub fn vacant_entry(&self) -> Result<VacantPeerTableEntry<'_>, PeerInsertError> {
        let peer_slab_guard = self.peer_slab.lock().unwrap();

        if matches!(peer_slab_guard.vacant_key(), Err(_)) {
            return Err(PeerInsertError::TableFull);
        };

        Ok(VacantPeerTableEntry {
            peer_slab_guard,
            sa_to_link_ref: &self.sa_to_link,
            special_peers_ref: &self.special_peers,
        })
    }

    pub fn remove(&self, link_id: LinkId) {
        let mut peer_slab = self.peer_slab.lock().unwrap();
        let Some(peer_state) = peer_slab.get((link_id as usize).wrapping_sub(1)) else {
            return;
        };
        self.sa_to_link.remove(&peer_state.substrate_addr);
        for name in peer_state.special_names {
            self.special_peers[name].store(LINK_ID_UNKNOWN, Ordering::Relaxed); // note; no useful ordering possible here
        }
        let new_reader = peer_slab.remove((link_id as usize).wrapping_sub(1));
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
            .get((link_id as usize).wrapping_sub(1))
            .map(inspector)
    }

    pub fn lookup_peer(&self, substrate_addr: &SubstrateAddr) -> Option<LinkId> {
        let id = self.sa_to_link.get(substrate_addr).map(|id| *id);

        // synchronizes with the Release in VacantPeerTableEntry::insert();
        // ensures anyone who reads from the slab following this sees the peer
        // (assuming of course it hasn't been removed!)
        atomic::fence(Ordering::Acquire);

        id
    }

    pub fn lookup_special_peer(&self, name: SpecialPeerName) -> Option<LinkId> {
        // synchronizes with the Release in VacantPeerTableEntry::insert();
        // ensures anyone who reads from the slab following this sees the peer
        // (assuming of course it hasn't been removed!)
        let id = self.special_peers[name].load(Ordering::Acquire);

        if id == LINK_ID_UNKNOWN {
            None
        } else {
            Some(id)
        }
    }

    pub fn inspect<T>(
        &self,
        link_id: LinkId,
        inspector: impl FnOnce(&PeerState) -> T,
    ) -> Option<T> {
        self.peer_slab_reader
            .inspect(|r| r.get((link_id as usize).wrapping_sub(1)).map(inspector))
    }

    pub fn get(&self, link_id: LinkId) -> Option<PeerTableEntryGuard<'_>> {
        self.peer_slab_reader
            .get_guarded((link_id as usize).wrapping_sub(1))
    }

    /// Sets an established security association on the link.
    pub fn set_security_association(
        &self,
        link_id: LinkId,
        sa: KmTransportSA,
    ) -> Result<(), SecurityAssocaitionStateError> {
        let entry = self
            .get(link_id)
            .ok_or(SecurityAssocaitionStateError::NoAssociationForLink)?;
        entry.km_state.transport_sa.write(Some(sa));
        Ok(())
    }

    /// At some point shortly after the link security assocaition is initialized, the [km_multiplexor] will
    /// stash its handle in here.
    ///
    /// Only possible error is if there is no entry in the table under the `link_id`.
    pub fn set_km_handle(
        &self,
        link_id: LinkId,
        handle: KmHandle,
    ) -> Result<(), SecurityAssocaitionStateError> {
        let entry = self
            .get(link_id)
            .ok_or(SecurityAssocaitionStateError::NoAssociationForLink)?;
        entry.km_state.handle.lock().unwrap().replace(handle);
        Ok(())
    }

    /// After this, [PeerTable::is_security_assocaition_established] will return false for the link until
    /// a call to [PeerTable::set_security_association].
    pub fn clear_security_association(
        &self,
        link_id: LinkId,
    ) -> Result<(), SecurityAssocaitionStateError> {
        let entry = self
            .get(link_id)
            .ok_or(SecurityAssocaitionStateError::NoAssociationForLink)?;
        entry.km_state.transport_sa.write(None);
        Ok(())
    }

    /// Check if a security assocaition is estabolished for the link.
    /// False returned here means that either the assocaition is not established, or
    /// that there is no link found under the ID.
    pub fn is_security_assocaition_established(&self, link_id: LinkId) -> bool {
        if let Some(entry) = self.get(link_id) {
            return entry.km_state.transport_sa.get().is_some();
        }
        false
    }

    /// Clone the Key Manager on the link if link exists, and if there is a handle set.
    /// See [PeerTable::set_km_handle].
    pub fn clone_km_manager(&self, link_id: LinkId) -> Option<KeyManager> {
        let entry = self.get(link_id)?;
        let handle = entry.km_state.handle.lock().unwrap();
        handle.as_ref().map(|h| h.mgr.clone())
    }

    /// Clone the key message sender channel on the link if link exists, and if there is a handle set.
    /// See [PeerTable::set_km_handle].
    pub fn clone_km_tx_chan(&self, link_id: LinkId) -> Option<mpsc::Sender<Bytes>> {
        let entry = self.get(link_id)?;
        let handle = entry.km_state.handle.lock().unwrap();
        handle.as_ref().map(|h| h.km_tx.clone())
    }

    /// Remove the key manager state from the link, returning the optional KmHandle that was set.
    /// Doesn't really _remove_ the state, but does invalidate the security assocation and wipes
    /// the reference to the handle.
    pub fn remove_km_state(&self, link_id: LinkId) -> Option<KmHandle> {
        // If SA is set, un-set it - don't care about errors.
        let _ = self.clear_security_association(link_id);

        let entry = self.get(link_id)?;

        // If there is a handle, remove it and return it.
        let mut handle = entry.km_state.handle.lock().unwrap();
        if handle.is_none() {
            return None;
        }
        handle.take()
    }
}

pub struct VacantPeerTableEntry<'a> {
    peer_slab_guard: MutexGuard<'a, RcuCslab<PeerState>>,
    sa_to_link_ref: &'a DashMap<SubstrateAddr, LinkId>,
    special_peers_ref: &'a EnumMap<SpecialPeerName, AtomicLinkId>,
}

impl VacantPeerTableEntry<'_> {
    pub fn key(&self) -> LinkId {
        (self.peer_slab_guard.vacant_key().unwrap() + 1) as LinkId
    }

    pub fn insert(mut self, peer_state: PeerState) -> LinkId {
        let id = self.peer_slab_guard.insert(peer_state).unwrap();
        let peer_state_ref = self.peer_slab_guard.get(id).unwrap();

        let link_id = (id + 1) as LinkId;

        // synchronizes with the Acquire in PeerTable::lookup_*();
        // ensures the peer slab entry is visible to anyone who first reads from one of the
        // below "reverse" tables with Acquire ordering
        atomic::fence(Ordering::Release);

        if let Some(other) = self
            .sa_to_link_ref
            .insert(peer_state_ref.substrate_addr, link_id)
        {
            panic!(
                "duplicate peer substrate address: {link_id} and {other} share {}",
                peer_state_ref.substrate_addr
            );
        }

        for name in peer_state_ref.special_names {
            let other = self.special_peers_ref[name].swap(link_id, Ordering::Relaxed);
            if other != LINK_ID_UNKNOWN {
                panic!(
                    "duplicate special peer name: {link_id} and {other} share {:?}",
                    name
                );
            }
        }

        link_id
    }
}
