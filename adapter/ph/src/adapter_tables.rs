//! Agent Lookup Table
//!
//! RFC 6.5 § 5.1

#![allow(dead_code)]

use crate::defs::FiveTuple;
use crate::zpr::{CompressionMode, StreamId};
use dashmap::DashMap;

pub struct AltPep {
    pub compression_mode: CompressionMode,
    pub stream_id: StreamId,
}

pub struct AgentLookupTable {
    table: DashMap<FiveTuple, AltPep>,
}

pub struct AltRef<'a>(dashmap::mapref::one::Ref<'a, FiveTuple, AltPep>);

impl std::ops::Deref for AltRef<'_> {
    type Target = AltPep;

    fn deref(&self) -> &AltPep {
        self.0.deref()
    }
}

impl AgentLookupTable {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
        }
    }

    pub fn get<'a>(&'a self, key: &FiveTuple) -> Option<AltRef<'a>> {
        self.table.get(key).map(|r| AltRef(r))
    }

    // FIXME: ideally we want `try_insert()` but dashmap doesn't support that…
    pub fn insert(&self, key: FiveTuple, value: AltPep) {
        self.table.insert(key, value);
    }

    pub fn remove(&self, key: &FiveTuple) {
        self.table.remove(key);
    }
}

pub struct DltPep {
    pub compression_mode: CompressionMode,
    pub five_tuple: FiveTuple,
}

pub struct DockLookupTable {
    table: DashMap<StreamId, DltPep>,
}

pub struct DltRef<'a>(dashmap::mapref::one::Ref<'a, StreamId, DltPep>);

impl std::ops::Deref for DltRef<'_> {
    type Target = DltPep;

    fn deref(&self) -> &DltPep {
        self.0.deref()
    }
}

impl DockLookupTable {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
        }
    }

    pub fn get<'a>(&'a self, key: &StreamId) -> Option<DltRef<'a>> {
        self.table.get(key).map(|r| DltRef(r))
    }

    // FIXME: ideally we want `try_insert()` but dashmap doesn't support that…
    pub fn insert(&self, key: StreamId, value: DltPep) {
        self.table.insert(key, value);
    }

    pub fn remove(&self, key: &StreamId) {
        self.table.remove(key);
    }
}
