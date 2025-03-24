//! Visa Table

#![allow(dead_code)]

use crate::logging::targets::VISA_MGMT;
use crate::peer_table;

use chrono::{DateTime, Utc};
use libnode::vsapi;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use thiserror::Error;
use tracing::*;
use zpr::{ForwardingEntry, VisaId};

#[derive(Debug, Error)]
pub enum VisaTableError {
    #[error("Visa {0} Not Found")]
    NotFound(VisaId),
    #[error("Failed to parse visa field {0}")]
    ParseError(&'static str),
    #[error("Failed to insert visa into table")]
    InsertError,
}

/// Struct that holds an instance of a visa local to a Node
pub struct Visa {
    pub visa: Option<vsapi::Visa>,
    streams: Vec<ForwardingEntry>,
}

/// Struct for the visa timeout queue
pub struct VisaTimeout {
    pub id: VisaId,
    pub expiration: DateTime<Utc>,
}

// Visas should sort with soonest expiration first
impl Ord for VisaTimeout {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .expiration
            .cmp(&self.expiration)
            .then_with(|| other.id.cmp(&self.id))
    }
}

impl PartialOrd for VisaTimeout {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for VisaTimeout {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.expiration == other.expiration
    }
}

impl Eq for VisaTimeout {}

impl Visa {
    /// Remove all forwarding entries associated with this visa
    pub fn remove_forwarding_entries(&mut self, peer_table: &peer_table::PeerTable) {
        self.streams
            .drain(..)
            .for_each(|entry| peer_table.remove_route(entry));
    }

    /// Link a forwarding entry to this visa
    pub fn link_forwarding_entry(&mut self, forwarding_entry: ForwardingEntry) {
        self.streams.push(forwarding_entry);
    }
}

pub struct VisaTable {
    table: HashMap<VisaId, Visa>,
    timeout_queue: BinaryHeap<VisaTimeout>,
}

impl VisaTable {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            timeout_queue: BinaryHeap::new(),
        }
    }

    /// Insert a dummy visa (temporary functionality until visa bootstrapping works)
    pub fn insert_id(&mut self, visa_id: VisaId, expiration: DateTime<Utc>) {
        debug!(target: VISA_MGMT,
            "Dummy visa inserted into VisaTable ID: {visa_id}, Expiration: {}",
            expiration.format("%y-%m-%d %H:%M:%S"));
        let visa = Visa {
            visa: None,
            streams: Vec::new(),
        };
        let timeout = VisaTimeout {
            id: visa_id,
            expiration: expiration,
        };
        let _ = self.table.insert(visa_id, visa);
        self.timeout_queue.push(timeout);
    }

    /// Insert a visa from the Visa Service into the Visa Table
    pub fn insert_visa(&mut self, visa: vsapi::Visa) -> Result<VisaId, VisaTableError> {
        let Some(visa_id) = visa.issuer_id else {
            return Err(VisaTableError::ParseError("issuer_id"));
        };
        let Some(timestamp) = visa.expires else {
            return Err(VisaTableError::ParseError("expiration"));
        };
        let Some(expiration) = DateTime::from_timestamp_millis(timestamp) else {
            return Err(VisaTableError::ParseError("expiration"));
        };

        info!(target: VISA_MGMT,
            "Visa inserted into VisaTable ID: {visa_id}, Expiration: {}",
            expiration.format("%y-%m-%d %H:%M:%S"));

        let visa = Visa {
            visa: Some(visa),
            streams: Vec::new(),
        };

        let timeout = VisaTimeout {
            id: visa_id,
            expiration: expiration,
        };
        let _ = self.table.insert(visa_id, visa);
        self.timeout_queue.push(timeout);
        Ok(visa_id)
    }

    /// Link a forwarding entry to a given visa
    pub fn link_forwarding_entry(
        &mut self,
        visa_id: VisaId,
        forwarding_entry: ForwardingEntry,
    ) -> Result<(), VisaTableError> {
        let Some(entry) = self.table.get_mut(&visa_id) else {
            error!(target: VISA_MGMT,
                "Failed to link forwarding entry to visa {visa_id} which does not exist");
            return Err(VisaTableError::NotFound(visa_id));
        };
        entry.link_forwarding_entry(forwarding_entry);
        Ok(())
    }

    /// Revoke (or otherwise remove) a visa
    pub fn revoke(
        &mut self,
        peer_table: &peer_table::PeerTable,
        visa_id: VisaId,
    ) -> Result<(), VisaTableError> {
        let Some(mut visa) = self.table.remove(&visa_id) else {
            return Err(VisaTableError::NotFound(visa_id));
        };
        visa.remove_forwarding_entries(peer_table);
        info!(target: VISA_MGMT, "Revoked visa {visa_id}");
        Ok(())
    }

    /// Remove every expired visa from the table
    pub fn handle_expirations(&mut self, peer_table: &peer_table::PeerTable) {
        let current_time = Utc::now();
        while self
            .timeout_queue
            .peek()
            .map_or(false, |entry| entry.expiration < current_time)
        {
            let timeout_entry = self.timeout_queue.pop().unwrap();
            // Ignore if the visa was not found, since it might have been previously revoked
            let _ = self.revoke(peer_table, timeout_entry.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assembly::test::{create_assembly, TestAssemblyBuilder};
    use crate::forwarding_tables::PftPep;
    use crate::link_state::LinkType;
    use crate::peer_table::test::create_dummy_peer_state;
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::NonZero;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_timeouts() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));

        let one_second = std::time::Duration::from_secs(1);
        let visa1 = 12345;
        let visa2 = 67890;
        let visa3 = 234;
        let mut visa_table = asm.visa_table.write().await;
        visa_table.insert_id(visa1, DateTime::<Utc>::MIN_UTC); // An element that will timeout immediately
        visa_table.insert_id(visa2, DateTime::<Utc>::MAX_UTC); // An element that won't timeout
        visa_table.insert_id(visa3, Utc::now() + one_second); // An element that will time out in a second

        assert_eq!(3, visa_table.table.len());
        assert_eq!(3, visa_table.timeout_queue.len());
        assert_eq!(true, visa_table.table.contains_key(&visa1));
        assert_eq!(true, visa_table.table.contains_key(&visa2));
        assert_eq!(true, visa_table.table.contains_key(&visa3));

        visa_table.handle_expirations(&asm.peer_table);

        assert_eq!(2, visa_table.table.len());
        assert_eq!(2, visa_table.timeout_queue.len());
        assert_eq!(false, visa_table.table.contains_key(&visa1));
        assert_eq!(true, visa_table.table.contains_key(&visa2));
        assert_eq!(true, visa_table.table.contains_key(&visa3));

        std::thread::sleep(one_second);

        visa_table.handle_expirations(&asm.peer_table);

        assert_eq!(1, visa_table.table.len());
        assert_eq!(1, visa_table.timeout_queue.len());
        assert_eq!(false, visa_table.table.contains_key(&visa1));
        assert_eq!(true, visa_table.table.contains_key(&visa2));
        assert_eq!(false, visa_table.table.contains_key(&visa3));

        assert!(visa_table.revoke(&asm.peer_table, visa2).is_ok());

        assert_eq!(0, visa_table.table.len());
        assert_eq!(1, visa_table.timeout_queue.len());
        assert_eq!(false, visa_table.table.contains_key(&visa1));
        assert_eq!(false, visa_table.table.contains_key(&visa2));
        assert_eq!(false, visa_table.table.contains_key(&visa3));
    }

    #[tokio::test]
    async fn test_remove_forwarding_entries() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));
        let link_id = asm
            .peer_table
            .insert(create_dummy_peer_state(
                NonZero::new(zpr::LOCAL_AGENT_LINK_ID).unwrap(),
                LinkType::Internal,
                zpr::SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
            ))
            .unwrap()
            .get();

        let one_second = std::time::Duration::from_secs(1);
        let visa1 = 12345;
        let visa2 = 986;
        let pep1 = PftPep {
            next_hop: zpr::ForwardingEntry(link_id, 1),
            visa_id: visa1,
        };

        let pep2 = PftPep {
            next_hop: zpr::ForwardingEntry(link_id, 2),
            visa_id: visa2,
        };

        let peer_state = asm
            .peer_table
            .get(link_id)
            .expect("Failed to get peer_state");

        let tether_id1 = peer_state.pft.insert(pep1).expect("Failed to insert PEP");

        let tether_id2 = peer_state.pft.insert(pep2).expect("Failed to insert PEP");
        assert_eq!(2, peer_state.pft.len());

        let mut visa_table = asm.visa_table.write().await;
        visa_table.insert_id(visa1, DateTime::<Utc>::MAX_UTC); // An element that won't timeout
        visa_table.insert_id(visa2, Utc::now() + one_second); // An element that will time out in a second
        assert!(visa_table
            .link_forwarding_entry(visa1, zpr::ForwardingEntry(link_id, tether_id1))
            .is_ok());
        assert!(visa_table
            .link_forwarding_entry(visa2, zpr::ForwardingEntry(link_id, tether_id2))
            .is_ok());

        std::thread::sleep(one_second);

        visa_table.handle_expirations(&asm.peer_table);
        assert_eq!(1, peer_state.pft.len());

        assert!(visa_table.revoke(&asm.peer_table, visa1).is_ok());
        assert_eq!(0, peer_state.pft.len());
    }
}
