#![allow(dead_code)]
use crate::dock_tables::DockForwardingTable;
use crate::km::KmTransportSA;
use crate::km_multiplexor::SAState;
use crate::queues;
use crate::rcu::RcuBox;
use crate::sync_req;
use crate::zpr::{LinkId, SubstrateAddr};
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::DashMap;
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::sync::MutexGuard;
use tokio::sync::mpsc;
use tokio::task;

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

    // `link_so_sec_assoc` is state info for the security association per link. This is managed by the
    // KM Multiplexor and used during encrypt/decrypt.
    //
    // TODO: put into the slab! (https://github.com/org-zpr/zpr-core/issues/388)
    link_to_sec_assoc: DashMap<LinkId, SAState>,
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
        let link_to_sec_assoc = DashMap::with_capacity(PEER_TABLE_SIZE);

        Self {
            peer_slab: Mutex::new(peer_slab),
            peer_slab_reader,
            sa_to_link,
            link_to_sec_assoc,
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

    /// Initialize state for the security association on the link.  The security association starts out as
    /// not established.
    pub fn init_security_association(&self, link_id: LinkId) {
        if let Some(_) = self.link_to_sec_assoc.insert(link_id, SAState::new()) {
            panic!("duplicate security association");
        }
    }

    /// Sets an established security association on the link.
    pub fn set_security_association(
        &self,
        link_id: LinkId,
        sa: KmTransportSA,
    ) -> Result<(), SecurityAssocaitionStateError> {
        if let Some(mut sa_state) = self.link_to_sec_assoc.get_mut(&link_id) {
            sa_state.transport_sa = sa;
            sa_state.sa_established.store(true, Ordering::Relaxed);
            Ok(())
        } else {
            Err(SecurityAssocaitionStateError::NoAssociationForLink)
        }
    }

    /// After this, [PeerTable::is_security_assocaition_established] will return false for the link until
    /// a call to [PeerTable::set_security_association].
    pub fn clear_security_association(
        &self,
        link_id: LinkId,
    ) -> Result<(), SecurityAssocaitionStateError> {
        if let Some(sa_state) = self.link_to_sec_assoc.get_mut(&link_id) {
            sa_state.sa_established.store(false, Ordering::Relaxed);
            Ok(())
        } else {
            Err(SecurityAssocaitionStateError::NoAssociationForLink)
        }
    }

    pub fn is_security_assocaition_established(&self, link_id: LinkId) -> bool {
        if let Some(sa_state) = self.link_to_sec_assoc.get(&link_id) {
            sa_state.sa_established.load(Ordering::Relaxed)
        } else {
            false
        }
    }

    /// Return a clone of the transport SA if there is an SA on the link, and it is established.
    pub fn clone_established_transport_association(
        &self,
        link_id: LinkId,
    ) -> Option<KmTransportSA> {
        if let Some(sa_state) = self.link_to_sec_assoc.get(&link_id) {
            if sa_state.sa_established.load(Ordering::Relaxed) {
                Some(sa_state.transport_sa.clone())
            } else {
                None
            }
        } else {
            None
        }
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

    /// Remove state entry for the security association on the link.
    /// TODO: We may want this integrated with the [PeerTable::remove] method above.
    pub fn remove_security_association(&self, link_id: LinkId) {
        match self.link_to_sec_assoc.remove(&link_id) {
            None => {}
            Some(_) => (),
        }
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
