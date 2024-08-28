#![allow(dead_code)]
use crate::rcu::RcuBox;
use crate::zpr::{LinkId, SubstrateAddr};
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::DashMap;
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
}

#[derive(Debug)]
pub enum PeerInsertError {
    TableFull,
}

impl PeerTable {
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
        inspector: impl FnOnce(&PeerState) -> T,
    ) -> Option<T> {
        self.peer_slab_reader
            .inspect(|r| r.get(link_id as usize).map(inspector))
    }
}
