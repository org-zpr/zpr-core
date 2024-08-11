//! Agent Lookup Table
//!
//! RFC 6.5 § 5.1

#![allow(dead_code)]

use crate::defs::FiveTuple;
use crate::zpr::{CompressionMode, StreamId};
use dashmap::DashMap;

pub struct AgentPep {
    pub stream_id: StreamId,
    pub compression_mode: CompressionMode,
}

pub struct AgentLookupTable {
    table: DashMap<FiveTuple, AgentPep>,
}

pub struct Ref<'a>(dashmap::mapref::one::Ref<'a, FiveTuple, AgentPep>);

impl std::ops::Deref for Ref<'_> {
    type Target = AgentPep;

    fn deref(&self) -> &AgentPep {
        self.0.deref()
    }
}

impl AgentLookupTable {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
        }
    }

    pub fn get<'a>(&'a self, key: &FiveTuple) -> Option<Ref<'a>> {
        self.table.get(key).map(|r| Ref(r))
    }

    // FIXME: ideally we want `try_insert()` but dashmap doesn't support that…
    pub fn insert(&self, key: FiveTuple, value: AgentPep) {
        self.table.insert(key, value);
    }

    pub fn remove(&self, key: &FiveTuple) {
        self.table.remove(key);
    }
}
