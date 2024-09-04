#![allow(dead_code)]
use crate::km::KMTransportSA;
use crate::km_multiplexor::SAState;
use crate::rcu::RcuBox;
use crate::zpr::{LinkId, SubstrateAddr};
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::DashMap;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

const PEER_TABLE_SIZE: usize = 1024;

#[derive(Clone, Copy)]
pub enum PeerType {
    Node,
    Adapter,
}

pub struct PeerState {
    pub peer_type: PeerType,
    pub substrate_addr: SubstrateAddr,
}

impl PeerState {
    pub fn new(peer_type: PeerType, substrate_addr: SubstrateAddr) -> Self {
        Self {
            peer_type,
            substrate_addr,
        }
    }
}

pub struct PeerTable {
    peer_slab: Mutex<RcuCslab<PeerState>>,
    peer_slab_reader: RcuBox<RcuCslabReader<PeerState>>,
    sa_to_link: DashMap<SubstrateAddr, LinkId>,

    // `link_so_sec_assoc` is state info for the security association per link. This is managed by the
    // KM Multiplexor and used during encrypt/decrypt.
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

impl PeerTable {
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

    pub fn insert(&self, peer_state: PeerState) -> Result<LinkId, PeerInsertError> {
        let sa = peer_state.substrate_addr;

        let link_id = match self.peer_slab.lock().unwrap().insert(peer_state) {
            Ok(id) => id as LinkId,
            Err(()) => return Err(PeerInsertError::TableFull),
        };

        if let Some(_) = self.sa_to_link.insert(sa, link_id) {
            panic!("duplicate peer substrate address");
        }

        Ok(link_id)
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
        sa: KMTransportSA,
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
    ) -> Option<KMTransportSA> {
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
        inspector: impl FnOnce(&PeerState) -> T,
    ) -> Option<T> {
        self.peer_slab_reader
            .inspect(|r| r.get(link_id as usize).map(inspector))
    }
}
