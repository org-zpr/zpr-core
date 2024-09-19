//! Dock lookup tables
//!
//! RFC 6.5 § 5.1

#![allow(dead_code)]

use crate::rcu::{RcuBox, RcuCslabEntryGuard};
use crate::zpr::{LinkId, StreamId};
use cslab::{RcuCslab, RcuCslabReader};
use std::sync::Mutex;

const DOCK_FORWARDING_TABLE_SIZE: usize = 1 << 20; // 1 million

pub enum DftNextHop {
    Tether(LinkId, StreamId),
    Forwarder(StreamId),
}

// TODO: figure out whether a more complex PEP is warranted,
// which can map a single tether ID to possibly different visa IDs
// and recompress
// (necessary since (a) adapter can choose compression level, and (b)
// visas may be more narrowly scoped than what can be compressed out)
pub struct DftPep {
    pub next_hop: DftNextHop,
}

pub struct DockForwardingTable {
    table: Mutex<RcuCslab<DftPep>>,
    reader: RcuBox<RcuCslabReader<DftPep>>,
}

pub type DftPepGuard<'a> = RcuCslabEntryGuard<'a, DftPep>;

impl DockForwardingTable {
    pub fn new() -> Self {
        let table = RcuCslab::with_fixed_capacity(DOCK_FORWARDING_TABLE_SIZE);
        let reader = table.reader();

        Self {
            table: Mutex::new(table),
            reader: RcuBox::new(reader),
        }
    }

    pub fn inspect<T>(
        &self,
        tether_id: StreamId,
        inspector: impl FnOnce(&DftPep) -> T,
    ) -> Option<T> {
        self.reader.inspect(|reader| {
            reader
                .get((tether_id as usize).wrapping_sub(1))
                .map(inspector)
        })
    }

    pub fn get(&self, tether_id: StreamId) -> Option<DftPepGuard<'_>> {
        self.reader
            .get_guarded((tether_id as usize).wrapping_sub(1))
    }

    pub fn insert(&self, pep: DftPep) -> Result<StreamId, ()> {
        Ok((self.table.lock().unwrap().insert(pep)? + 1) as StreamId)
    }

    pub fn remove(&self, tether_id: StreamId) {
        let mut table = self.table.lock().unwrap();
        let new_reader = table.remove((tether_id as usize).wrapping_sub(1));
        std::mem::drop(table);
        self.reader.write(new_reader);
    }
}
