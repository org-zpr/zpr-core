//! Adapter lookup tables
//!
//! RFC 6.5 § 5.1

#![allow(dead_code)]

use crate::defs::FiveTuple;
use crate::packet::Packet;
use crate::rcu::{RcuBox, RcuCslabEntryGuard};
use crate::zpr::{CompressionMode, StreamId};
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::mapref::one::Ref as DashMapRef;
use dashmap::DashMap;
use std::sync::Mutex;

const DOCK_LOOKUP_TABLE_SIZE: usize = 1 << 20; // 1 million

#[derive(Clone, Copy)]
pub struct AltPep {
    pub compression_mode: CompressionMode,
    pub tether_id: StreamId,
}

pub enum AltEntry<'pktbuf> {
    Active(AltPep),
    Pending(Packet<'pktbuf>),
}

pub struct AgentLookupTable<'pktbuf> {
    table: DashMap<FiveTuple, AltEntry<'pktbuf>>,
}

pub struct AltEntryGuard<'a, 'pktbuf>(DashMapRef<'a, FiveTuple, AltEntry<'pktbuf>>);

impl<'pktbuf> std::ops::Deref for AltEntryGuard<'_, 'pktbuf> {
    type Target = AltEntry<'pktbuf>;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<'pktbuf> AgentLookupTable<'pktbuf> {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
        }
    }

    // TODO: figure out whether we want to perform partial matching
    pub fn inspect<T>(
        &self,
        five_tuple: &FiveTuple,
        inspector: impl FnOnce(&AltEntry<'pktbuf>) -> T,
    ) -> Option<T> {
        self.table.get(five_tuple).map(|entry| inspector(&*entry))
    }

    pub fn get(&self, five_tuple: &FiveTuple) -> Option<AltEntryGuard<'_, 'pktbuf>> {
        self.table.get(five_tuple).map(AltEntryGuard)
    }

    // FIXME: ideally we want `try_insert()` but dashmap doesn't support that…
    pub fn insert(&self, five_tuple: FiveTuple, entry: AltEntry<'pktbuf>) {
        self.table.insert(five_tuple, entry);
    }

    /// Alter an ALT entry according to the provided function.
    ///
    /// If the entry exists, returns the alterer function's result.
    ///
    /// If the entry doesn't exist, returns `Err`.
    pub fn alter<T>(
        &self,
        five_tuple: &FiveTuple,
        alterer: impl FnOnce(&mut AltEntry<'pktbuf>) -> T,
    ) -> Result<T, ()> {
        match self.table.get_mut(five_tuple) {
            Some(mut ref_) => Ok(alterer(ref_.value_mut())),
            None => Err(()),
        }
    }

    pub fn remove(&self, five_tuple: &FiveTuple) {
        self.table.remove(five_tuple);
    }
}

pub struct DltPep {
    pub compression_mode: CompressionMode,
    pub five_tuple: FiveTuple,
}

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
        self.reader
            .inspect(|reader| reader.get(tether_id as usize).map(inspector))
    }

    pub fn get(&self, tether_id: StreamId) -> Option<DltPepGuard<'_>> {
        self.reader.get_guarded(tether_id as usize)
    }

    pub fn insert(&self, pep: DltPep) -> Result<StreamId, ()> {
        Ok(self.table.lock().unwrap().insert(pep)? as StreamId)
    }

    pub fn remove(&self, tether_id: StreamId) {
        let mut table = self.table.lock().unwrap();
        let new_reader = table.remove(tether_id as usize);
        std::mem::drop(table);
        self.reader.write(new_reader);
    }
}
