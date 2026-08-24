#![allow(dead_code)]
use crate::auth::AUTH_KEY_SIZE_BYTES;
use crate::config;
use crate::forwarding_tables::PeerForwardingTable;
use crate::km::{KeyManager, KmTransportSA};
use crate::link_state::{LinkStateWrapper, LinkType};
use crate::mgmt::{self, txn_mgr};
use crate::prelude::*;
use crate::queues;
use crate::special_peers::*;
use crate::zdpr;
use bytes::Bytes;
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::DashMap;
use enum_map::EnumMap;
use rcu::{RcuBox, RcuCslabEntryGuard, RcuOptionGuard};
use std::default::Default;
use std::future::Future;
use std::num::NonZero;
use std::sync::atomic::{self, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use strum;
use thiserror::Error;
use tokio::sync::{Notify, mpsc};
use tokio::task;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zpr::packet_info::{ForwardingEntry, LINK_ID_UNKNOWN, LinkId, SubstrateAddr};
use zpr_utils::net_defs::{ScopedIpAddr, ScopedIpv6Addr};

const PEER_TABLE_SIZE: usize = config::MAX_ACTIVE_LINKS;

pub struct PeerState {
    pub substrate_addr: SubstrateAddr,
    pub interface_addr: ScopedIpAddr,
    pub link_state_machine: LinkStateWrapper,
    pub pft: PeerForwardingTable,
    pub node_state: mgmt::node::NodePeerState,
    pub mgmt_processor: queues::MgmtProcessor,
    pub mgmt_processor_worker: task::JoinHandle<()>,
    pub auth_key: [u8; 32], // set in ::new and never changed.
    pub a2a_dh_pubkey: RcuBox<Option<x25519_dalek::PublicKey>>,
    pub zdpr_send: Mutex<zdpr::Sender<crate::packet::Packet>>,
    pub zdpr_recv: Mutex<zdpr::Receiver>,
    pub zdpr_retry_timer_reset: Notify,
    pub txn_mgr: Arc<txn_mgr::TxnMgr>,
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

#[derive(Debug, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum PeerType {
    Node,
    Adapter,
    Dock,
    Unknown,
}

const MGMT_PROCESSOR_QUEUE_SIZE: usize = 16;

impl PeerState {
    pub fn new<Worker>(
        link_id: NonZero<LinkId>,
        link_type: LinkType,
        substrate_addr: SubstrateAddr,
        interface_addr: ScopedIpAddr,
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

        let mut key = [0u8; AUTH_KEY_SIZE_BYTES];
        if link_type == LinkType::NodeToAdapter {
            aws_lc_rs::rand::fill(&mut key)
                .expect("failed to generate random bytes for peer auth key");
        }
        Self {
            substrate_addr,
            interface_addr,
            link_state_machine: LinkStateWrapper::new(link_id.get(), link_type),
            pft: PeerForwardingTable::new(),
            node_state: mgmt::node::NodePeerState::new(),
            mgmt_processor,
            mgmt_processor_worker,
            auth_key: key,
            a2a_dh_pubkey: RcuBox::new(None),
            zdpr_send: Mutex::new(zdpr::Sender::new()),
            zdpr_recv: Mutex::new(zdpr::Receiver::new(
                config::DEFAULT_ZDPR_RECEIVE_WINDOW_SIZE,
            )),
            zdpr_retry_timer_reset: Notify::new(),
            txn_mgr: Arc::new(txn_mgr::TxnMgr::new()),
            km_state: PeerKmState::new(),
        }
    }

    /// Return a reference to the transport SA if there is an SA on the link, and if it is established.
    pub fn get_established_transport_association(
        &self,
    ) -> Option<RcuOptionGuard<'_, KmTransportSA>> {
        self.km_state.transport_sa.get().into()
    }

    /// Creates a "dummy" peer for referencing internal links.
    pub fn new_internal_peer<Worker>(
        link_id: NonZero<LinkId>,
        peer_id: Option<NonZero<LinkId>>,
        launch_mgmt_processor_worker: impl FnOnce(
            mpsc::Receiver<queues::MgmtProcessorMessage>,
        ) -> Worker,
    ) -> Self
    where
        Worker: Future<Output = ()> + 'static,
    {
        let mut ps = PeerState::new(
            link_id,
            LinkType::Internal,
            std::net::SocketAddrV6::new(std::net::Ipv6Addr::from_bits(0), 0, 0, 0).into(),
            ScopedIpv6Addr::new(std::net::Ipv6Addr::from_bits(0), 0).into(),
            launch_mgmt_processor_worker,
        );
        ps.link_state_machine.internal_peer_id = peer_id;
        ps
    }

    pub fn is_internal(&self) -> bool {
        self.link_state_machine.is_internal()
    }

    /// What type of peer is this.  Accounts for well-known internal links
    /// (local actor and dock).
    pub fn peer_type(&self) -> PeerType {
        match self.link_state_machine.get_link_type() {
            LinkType::Internal => match self.link_state_machine.id {
                LOCAL_ACTOR_LINK_ID => PeerType::Adapter,
                DOCK_LINK_ID => PeerType::Dock,
                _ => PeerType::Unknown,
            },

            LinkType::NodeToAdapter => PeerType::Adapter,
            LinkType::AdapterToNode => PeerType::Dock,
            LinkType::NodeToNode => PeerType::Node,
        }
    }
}

type AtomicLinkId = atomic::AtomicU32;
const _: () = assert!(std::mem::size_of::<AtomicLinkId>() == std::mem::size_of::<LinkId>());

pub struct PeerTable {
    peer_slab: Mutex<RcuCslab<PeerState>>,
    peer_slab_reader: RcuBox<RcuCslabReader<PeerState>>,
    sa_to_link: DashMap<(SubstrateAddr, ScopedIpAddr), NonZero<LinkId>>,
    // TODO: it would be nice if this lived in the same RCU as peer_slab_reader
    special_peers: RcuBox<EnumMap<SpecialPeerName, LinkId>>,
}

pub type PeerTableEntryGuard<'a> = RcuCslabEntryGuard<'a, PeerState>;

#[derive(Error, Debug)]
pub enum PeerInsertError {
    #[error("The peer table is full")]
    TableFull,
    #[error("Failed to start link with error: {0}")]
    FailedToStart(String),
}

#[derive(Debug)]
pub enum PeerUpdateError {
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
            special_peers: RcuBox::default(),
        }
    }

    /// Adds a "dummy" peer with the expected link ID for referencing internal links.
    ///
    /// Panics if there is no room in the table.  (This is intended to only be invoked
    /// at startup, before dynamic entries have been added.)
    pub fn insert_internal_peer(&self) -> NonZero<LinkId> {
        let entry = self.vacant_entry().unwrap();
        let peer = PeerState::new_internal_peer(entry.key(), None, |_| std::future::pending());
        entry.insert(peer)
    }

    pub fn insert_internal_peer_pair<Worker>(
        &self,
        launch_mgmt_processor_worker: impl Fn(
            NonZero<LinkId>,
            mpsc::Receiver<queues::MgmtProcessorMessage>,
        ) -> Worker,
    ) -> (NonZero<LinkId>, NonZero<LinkId>)
    where
        Worker: Future<Output = ()> + 'static,
    {
        let entry1 = self.vacant_entry().unwrap();
        // we have to "guess" at the next slot, since we can't hold two vacant entries open concurrently
        let link_id1 = entry1.key();
        let link_id2 = link_id1.checked_add(1).unwrap();
        let peer1 = PeerState::new_internal_peer(link_id1, Some(link_id2), |q| {
            launch_mgmt_processor_worker(link_id1, q)
        });
        entry1.insert(peer1);

        let entry2 = self.vacant_entry().unwrap();
        assert_eq!(entry2.key(), link_id2);
        let peer2 = PeerState::new_internal_peer(link_id2, Some(link_id1), |q| {
            launch_mgmt_processor_worker(link_id2, q)
        });
        entry2.insert(peer2);

        (link_id1, link_id2)
    }

    pub fn vacant_entry(&self) -> Result<VacantPeerTableEntry<'_>, PeerInsertError> {
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
        self.sa_to_link
            .remove(&(peer_state.substrate_addr, peer_state.interface_addr));

        self.special_peers
            .update(|sp_ref| {
                let mut new_sp = *sp_ref;
                for (_name, peer_id_ref) in new_sp.iter_mut() {
                    if *peer_id_ref == link_id {
                        *peer_id_ref = LINK_ID_UNKNOWN;
                    }
                }
                Some(new_sp)
            })
            .unwrap();

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

    pub fn lookup_peer(
        &self,
        substrate_addr: &SubstrateAddr,
        interface_addr: &ScopedIpAddr,
    ) -> Option<NonZero<LinkId>> {
        let id = self
            .sa_to_link
            .get(&(*substrate_addr, *interface_addr))
            .map(|id| *id);

        // synchronizes with the Release in VacantPeerTableEntry::insert();
        // ensures anyone who reads from the slab following this sees the peer
        // (assuming of course it hasn't been removed!)
        atomic::fence(Ordering::Acquire);

        id
    }

    pub fn lookup_special_peer(&self, name: SpecialPeerName) -> Option<NonZero<LinkId>> {
        // synchronizes with the Release in VacantPeerTableEntry::insert();
        // ensures anyone who reads from the slab following this sees the peer
        // (assuming of course it hasn't been removed!)
        NonZero::new(self.special_peers.get()[name])
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

    /// Apply the given function to all peers.
    pub fn for_each(&self, mut f: impl FnMut((NonZero<LinkId>, &PeerState))) {
        self.peer_slab_reader.inspect(|r| {
            r.iter()
                .for_each(|(idx, peer)| f((NonZero::new((idx + 1) as LinkId).unwrap(), peer)))
        })
    }

    /// Find and return the first peer matching the given predicate, if any.
    pub fn find(
        &self,
        mut predicate: impl FnMut((NonZero<LinkId>, &PeerState)) -> bool,
    ) -> Option<(NonZero<LinkId>, PeerTableEntryGuard<'_>)> {
        let (idx, guard) = self.peer_slab_reader.find_guarded(|(idx, peer)| {
            predicate((NonZero::new((idx + 1) as LinkId).unwrap(), peer))
        })?;
        Some((NonZero::new((idx + 1) as LinkId).unwrap(), guard))
    }

    /// Gets the number of peers; synchronizes with insert/remove.
    pub fn len(&self) -> usize {
        self.peer_slab.lock().unwrap().len()
    }

    /// Sets an established security association on the link.
    pub fn set_security_association(
        &self,
        link_id: LinkId,
        sa: KmTransportSA,
    ) -> Result<(), PeerUpdateError> {
        let entry = self
            .get(link_id)
            .ok_or(PeerUpdateError::NoAssociationForLink)?;
        entry.km_state.transport_sa.write(Some(sa));
        Ok(())
    }

    /// At some point shortly after the link security association is initialized, the [crate::km_multiplexor] will
    /// stash its handle in here.
    ///
    /// Only possible error is if there is no entry in the table under the `link_id`.
    pub fn set_km_handle(&self, link_id: LinkId, handle: KmHandle) -> Result<(), PeerUpdateError> {
        let entry = self
            .get(link_id)
            .ok_or(PeerUpdateError::NoAssociationForLink)?;
        entry.km_state.handle.lock().unwrap().replace(handle);
        Ok(())
    }

    /// After this, [PeerTable::is_security_association_established] will return false for the link until
    /// a call to [PeerTable::set_security_association].
    pub fn clear_security_association(&self, link_id: LinkId) -> Result<(), PeerUpdateError> {
        let entry = self
            .get(link_id)
            .ok_or(PeerUpdateError::NoAssociationForLink)?;
        entry.km_state.transport_sa.write(None);
        Ok(())
    }

    /// Check if a security association is estabolished for the link.
    /// False returned here means that either the association is not established, or
    /// that there is no link found under the ID.
    pub fn is_security_association_established(&self, link_id: LinkId) -> bool {
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

    pub fn assign_special_name(
        &self,
        name: SpecialPeerName,
        link_id: LinkId,
    ) -> Result<(), PeerUpdateError> {
        // FIXME: This can race peer removal; we ought to place
        // `special_peers` and `peer_slab_reader` in the same RcuBox
        self.special_peers
            .update(|sp_ref| {
                if sp_ref[name] == LINK_ID_UNKNOWN {
                    let mut new_sp = *sp_ref;
                    new_sp[name] = link_id;
                    Some(new_sp)
                } else {
                    None
                }
            })
            .map_err(|()| PeerUpdateError::NoAssociationForLink)
    }

    /// Clear out peer state upon link close/reset
    /// This does not remove the peer, but it clears any relevant tables
    pub fn clear_peer_state(&self, link_id: LinkId) {
        let Some(entry) = self.get(link_id) else {
            // If the entry being cleared is gone, who cares?
            return;
        };
        entry.pft.clear();
    }

    /// Remove a route from a peer forwarding table
    pub fn remove_route(&self, route: ForwardingEntry) {
        let Some(entry) = self.get(route.0) else {
            // If the peer is gone, nothing to be done
            return;
        };
        entry.pft.remove(route.1);
    }
}

pub struct VacantPeerTableEntry<'a> {
    peer_slab_guard: MutexGuard<'a, RcuCslab<PeerState>>,
    sa_to_link_ref: &'a DashMap<(SubstrateAddr, ScopedIpAddr), NonZero<LinkId>>,
}

impl VacantPeerTableEntry<'_> {
    pub fn key(&self) -> NonZero<LinkId> {
        NonZero::new((self.peer_slab_guard.vacant_key().unwrap() + 1) as LinkId).unwrap()
    }

    pub fn insert(mut self, peer_state: PeerState) -> NonZero<LinkId> {
        let id = self.peer_slab_guard.insert(peer_state).unwrap();
        let peer_state_ref = self.peer_slab_guard.get(id).unwrap();

        let link_id = NonZero::new((id + 1) as LinkId).unwrap();

        // synchronizes with the Acquire in PeerTable::lookup_*();
        // ensures the peer slab entry is visible to anyone who first reads from
        // the "reverse" table with Acquire ordering
        atomic::fence(Ordering::Release);

        if !peer_state_ref.substrate_addr.ip().is_unspecified() {
            if let Some(other) = self.sa_to_link_ref.insert(
                (peer_state_ref.substrate_addr, peer_state_ref.interface_addr),
                link_id,
            ) {
                panic!(
                    "duplicate peer substrate address: {link_id} and {other} share {} on dock {}",
                    peer_state_ref.substrate_addr, peer_state_ref.interface_addr,
                );
            }
        }

        link_id
    }
}

#[cfg(test)]
pub mod test {

    use super::*;
    use std::sync::Mutex;

    #[allow(dead_code)]
    pub fn create_dummy_peer_state(
        link_id: NonZero<LinkId>,
        link_type: LinkType,
        substrate_addr: SubstrateAddr,
        interface_addr: ScopedIpAddr,
    ) -> PeerState {
        let (mp_inq, _mp_outq) = mpsc::channel(MGMT_PROCESSOR_QUEUE_SIZE);
        let mgmt_processor = queues::MgmtProcessor::new(mp_inq);

        PeerState {
            substrate_addr,
            interface_addr,
            link_state_machine: LinkStateWrapper::new(link_id.get(), link_type),
            pft: PeerForwardingTable::new(),
            node_state: mgmt::node::NodePeerState::new(),
            mgmt_processor,
            mgmt_processor_worker: task::spawn(async {}),
            auth_key: [42u8; AUTH_KEY_SIZE_BYTES],
            a2a_dh_pubkey: RcuBox::new(None),
            zdpr_send: Mutex::new(zdpr::Sender::new()),
            zdpr_recv: Mutex::new(zdpr::Receiver::new(
                config::DEFAULT_ZDPR_RECEIVE_WINDOW_SIZE,
            )),
            zdpr_retry_timer_reset: Notify::new(),
            txn_mgr: Arc::new(txn_mgr::TxnMgr::new()),
            km_state: PeerKmState::new(),
        }
    }
}
