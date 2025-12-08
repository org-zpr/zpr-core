//! Adapter lookup tables
//!
//! These tables hold the state of all tethers on an adapter, outbound (ALT) or inbound (DLT).
//!
//! RFC 6.5 § 5.1

#![allow(dead_code)]

use crate::defs::FiveTuple;
use crate::mgmt::txn_mgr::TxnHandle;
use crate::packet::Packet;
use crate::rcu::{RcuBox, RcuCslabEntryGuard};
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry as DashMapEntry;
use dashmap::mapref::one::Ref as DashMapRef;
use std::sync::Mutex;
use zpr::packet_info::{CompressionMode, StreamId};

const DOCK_LOOKUP_TABLE_SIZE: usize = 1 << 20; // 1 million

#[derive(Clone, Copy)]
pub struct AltPep {
    pub compression_mode: CompressionMode,
    pub tether_id: StreamId,
}

pub enum AltEntry {
    /// We've requested a tether ID for this flow, but haven't received one yet.
    Pending(Packet, TxnHandle),
    /// There is currently a tether allocated for this flow.
    Active(AltPep),
}

/// The Actor Lookup Table (ALT) holds all state of outbound tethers.
///
/// It is used to map five-tuples (from the endpoint) to compression
/// specifications and tether IDs (for the dock).
pub struct ActorLookupTable {
    table: DashMap<FiveTuple, AltEntry>,
    pending: DashMap<TxnHandle, FiveTuple>,
}

pub struct AltEntryGuard<'a>(DashMapRef<'a, FiveTuple, AltEntry>);

impl std::ops::Deref for AltEntryGuard<'_> {
    type Target = AltEntry;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

pub enum InsertPendingError {
    AlreadyPending(Packet),
    DuplicateTransaction(Packet),
}

impl std::fmt::Debug for InsertPendingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::AlreadyPending(_) => write!(f, "AlreadyPending"),
            Self::DuplicateTransaction(_) => write!(f, "DuplicateTransaction"),
        }
    }
}

#[derive(Debug)]
pub enum LookupPendingError {
    NotFound,
    NotPending,
}

#[derive(Debug)]
pub enum RemoveError {
    NotFound,
}

pub enum SetActiveError {
    NotFound(AltPep),
    NotPending(AltPep),
}

impl std::fmt::Debug for SetActiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::NotFound(_) => write!(f, "NotFound"),
            Self::NotPending(_) => write!(f, "NotPending"),
        }
    }
}

impl ActorLookupTable {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
            pending: DashMap::new(),
        }
    }

    pub fn insert_pending(
        &self,
        five_tuple: FiveTuple,
        init_packet: Packet,
        txn: &TxnHandle,
    ) -> Result<(), InsertPendingError> {
        match self.table.entry(five_tuple) {
            DashMapEntry::Occupied(_) => Err(InsertPendingError::AlreadyPending(init_packet)),

            DashMapEntry::Vacant(entry) => {
                if self.pending.insert(txn.clone(), five_tuple).is_some() {
                    return Err(InsertPendingError::DuplicateTransaction(init_packet));
                }
                entry.insert(AltEntry::Pending(init_packet, txn.clone()));
                Ok(())
            }
        }
    }

    pub fn lookup_pending(&self, txn: &TxnHandle) -> Result<FiveTuple, LookupPendingError> {
        Ok(*self.pending.get(txn).ok_or(LookupPendingError::NotFound)?)
    }

    pub fn set_active(
        &self,
        five_tuple: &FiveTuple,
        pep: AltPep,
    ) -> Result<Packet, SetActiveError> {
        let Some(mut entry) = self.table.get_mut(five_tuple) else {
            return Err(SetActiveError::NotFound(pep));
        };

        if !matches!(entry.value(), AltEntry::Pending(..)) {
            return Err(SetActiveError::NotPending(pep));
        }

        let AltEntry::Pending(packet, txn) =
            std::mem::replace(entry.value_mut(), AltEntry::Active(pep))
        else {
            unreachable!();
        };

        assert!(
            matches!(self.pending.remove(&txn), Some((_txn, ft)) if &ft == five_tuple),
            "ALT consistency error"
        );

        Ok(packet)
    }

    // TODO: figure out whether we want to perform partial matching
    pub fn inspect<T>(
        &self,
        five_tuple: &FiveTuple,
        inspector: impl FnOnce(&AltEntry) -> T,
    ) -> Option<T> {
        self.table.get(five_tuple).map(|entry| inspector(&*entry))
    }

    pub fn get(&self, five_tuple: &FiveTuple) -> Option<AltEntryGuard<'_>> {
        self.table.get(five_tuple).map(AltEntryGuard)
    }

    pub fn remove(&self, five_tuple: &FiveTuple) -> Result<AltEntry, RemoveError> {
        let (_, entry) = self.table.remove(five_tuple).ok_or(RemoveError::NotFound)?;

        match &entry {
            AltEntry::Pending(_, txn) => assert!(
                matches!(self.pending.remove(&txn), Some((_txn, ft)) if &ft == five_tuple),
                "ALT consistency error"
            ),
            AltEntry::Active(_) => (),
        }

        Ok(entry)
    }
}

pub struct DltPep {
    pub compression_mode: CompressionMode,
    pub five_tuple: FiveTuple,
}

/// The Dock Lookup Table (DLT) holds all state of inbound tethers.
///
/// It is used to map tether IDs (from the dock) to decompression
/// specifications and five-tuples (for the endpoint).
pub struct DockLookupTable {
    table: Mutex<RcuCslab<DltPep>>,
    reader: RcuBox<RcuCslabReader<DltPep>>,
}

pub type DltPepGuard<'a> = RcuCslabEntryGuard<'a, DltPep>;

impl DockLookupTable {
    pub fn new() -> Self {
        let table = RcuCslab::with_fixed_capacity(DOCK_LOOKUP_TABLE_SIZE);
        let reader = table.reader();

        Self {
            table: Mutex::new(table),
            reader: RcuBox::new(reader),
        }
    }

    pub fn inspect<T>(
        &self,
        tether_id: StreamId,
        inspector: impl FnOnce(&DltPep) -> T,
    ) -> Option<T> {
        self.reader.inspect(|reader| {
            reader
                .get((tether_id as usize).wrapping_sub(1))
                .map(inspector)
        })
    }

    pub fn get(&self, tether_id: StreamId) -> Option<DltPepGuard<'_>> {
        self.reader
            .get_guarded((tether_id as usize).wrapping_sub(1))
    }

    pub fn insert(&self, pep: DltPep) -> Result<StreamId, ()> {
        Ok((self.table.lock().unwrap().insert(pep)? + 1) as StreamId)
    }

    pub fn remove(&self, tether_id: StreamId) {
        let mut table = self.table.lock().unwrap();
        let new_reader = table.remove((tether_id as usize).wrapping_sub(1));
        std::mem::drop(table);
        self.reader.write(new_reader);
    }
}
