#![allow(dead_code)]
use crate::assembly::Assembly;
use crate::dock_tables::DockForwardingTable;
use crate::km::{KeyManager, KmTransportSA};
use crate::link_state::{LinkStateWrapper, LinkType};
use crate::queues;
use crate::rcu::{RcuBox, RcuCslabEntryGuard, RcuOptionGuard};
use crate::sync_req;
use bytes::Bytes;
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::DashMap;
use std::future::Future;
use std::sync::Mutex;
use std::sync::MutexGuard;
use tokio::sync::mpsc;
use tokio::task;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zpr::{LinkId, SubstrateAddr};

const PEER_TABLE_SIZE: usize = 1024;

// FIXME TODO:
// nodes and adapters have different state requirements.
// rather than indirecting through an enum, we could/should
// break adapters/docking sessions out into a separate table.
// this matches the RFC model of separate docks and forwarders.
// for now, everyone has a DFT.......
pub struct PeerState<'pktbuf> {
    pub substrate_addr: SubstrateAddr,
    pub link_state_machine: LinkStateWrapper,
    pub sync_req_state: sync_req::SyncReqState<'pktbuf>,
    pub dft: DockForwardingTable,
    pub mgmt_processor: queues::MgmtProcessor<'pktbuf>,
    pub mgmt_processor_worker: task::JoinHandle<()>,
    km_state: PeerKmState,
}

// Key Management state per peer.
struct PeerKmState {
    handle: Mutex<Option<KmHandle>>, // Once the KM state machine starts, it's join handle and related info is stashed here.
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

// FIXME: can we eliminate the reliance on `'static` herein?
impl PeerState<'static> {
    pub fn new<Worker>(
        link_id: LinkId,
        link_type: LinkType,
        substrate_addr: SubstrateAddr,
        launch_mgmt_processor_worker: impl FnOnce(
            mpsc::Receiver<queues::MgmtProcessorMessage<'static>>,
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
            link_state_machine: LinkStateWrapper::new(link_id, link_type),
            dft: DockForwardingTable::new(),
            sync_req_state: sync_req::SyncReqState::new(),
            mgmt_processor,
            mgmt_processor_worker,
            km_state: PeerKmState::new(),
        }
    }
}

impl PeerState<'_> {
    /// Return a reference to the transport SA if there is an SA on the link, and if it is established.
    pub fn get_established_transport_association(
        &self,
    ) -> Option<RcuOptionGuard<'_, KmTransportSA>> {
        self.km_state.transport_sa.get().into()
    }
}

pub struct PeerTable<'pktbuf> {
    peer_slab: Mutex<RcuCslab<PeerState<'pktbuf>>>,
    peer_slab_reader: RcuBox<RcuCslabReader<PeerState<'pktbuf>>>,
    sa_to_link: DashMap<SubstrateAddr, LinkId>,
}

pub type PeerTableEntryGuard<'a, 'pktbuf> = RcuCslabEntryGuard<'a, PeerState<'pktbuf>>;

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
        Self {
            peer_slab: Mutex::new(peer_slab),
            peer_slab_reader,
            sa_to_link,
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
        let Some(peer_state) = peer_slab.get((link_id as usize).wrapping_sub(1)) else {
            return;
        };
        self.sa_to_link.remove(&peer_state.substrate_addr);
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
        self.sa_to_link.get(substrate_addr).map(|id| *id)
    }

    pub fn inspect<T>(
        &self,
        link_id: LinkId,
        inspector: impl FnOnce(&PeerState<'pktbuf>) -> T,
    ) -> Option<T> {
        self.peer_slab_reader
            .inspect(|r| r.get((link_id as usize).wrapping_sub(1)).map(inspector))
    }

    pub fn get(&self, link_id: LinkId) -> Option<PeerTableEntryGuard<'_, 'pktbuf>> {
        self.peer_slab_reader
            .get_guarded((link_id as usize).wrapping_sub(1))
    }

    /// Sets an established security association on the link.
    pub fn set_security_association(
        &self,
        asm: &'static Assembly<'pktbuf>,
        link_id: LinkId,
        sa: KmTransportSA,
    ) -> Result<(), SecurityAssocaitionStateError> {
        let entry = self
            .get(link_id)
            .ok_or(SecurityAssocaitionStateError::NoAssociationForLink)?;
        entry.km_state.transport_sa.write(Some(sa));
        let _ = entry.link_state_machine.keying_done(asm);
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

pub struct VacantPeerTableEntry<'a, 'pktbuf> {
    peer_slab_guard: MutexGuard<'a, RcuCslab<PeerState<'pktbuf>>>,
    sa_to_link_ref: &'a DashMap<SubstrateAddr, LinkId>,
}

impl<'pktbuf> VacantPeerTableEntry<'_, 'pktbuf> {
    pub fn key(&self) -> LinkId {
        (self.peer_slab_guard.vacant_key().unwrap() + 1) as LinkId
    }

    pub fn insert(mut self, peer_state: PeerState<'pktbuf>) -> LinkId {
        let sa = peer_state.substrate_addr;

        let link_id = (self.peer_slab_guard.insert(peer_state).unwrap() + 1) as LinkId;

        if let Some(_) = self.sa_to_link_ref.insert(sa, link_id) {
            panic!("duplicate peer substrate address");
        }

        link_id
    }
}
