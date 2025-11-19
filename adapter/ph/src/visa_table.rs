//! Visa Table

#![allow(dead_code)]

use crate::defs::FiveTuple;
use crate::five_tuple_lookup_table::FiveTupleLookupTable;
use crate::logging::targets::VISA_MGMT;
use crate::peer_table;

use chrono::{DateTime, Utc};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::*;
use zpr::vsapi_types;
use zpr::{ForwardingEntry, VisaId};
use zpr_utils::net_defs::{IpAddress, ip_number};

// TODO: Figure out correct value for this visa expiration
const VS_VISAS_DURATION: Duration = Duration::from_secs(60 * 60 * 24); // 24 hours

// TODO: This is a placeholder.  We need this in the visa struct but at the time when
// we are creating these we don't have access to a valid configuration ID.
const VS_VISAS_CONFIG_ID: i64 = 100;

#[derive(Debug, Error)]
pub enum VisaTableError {
    #[error("Visa {0} Not Found")]
    NotFound(VisaId),
    #[error("Failed to parse visa field {0}")]
    ParseError(&'static str),
    #[error("Could not find destination {0}")]
    DestNotFound(IpAddress),
    #[error("Failed to insert visa into table")]
    InsertError,
}

/// Struct that holds an instance of a visa local to a Node
#[derive(Default, Clone)]
pub struct Visa {
    // TODO add methods so that these don't have to be made pub
    pub visa: Option<vsapi_types::Visa>,
    streams: Vec<ForwardingEntry>,
    pub ftuple: Option<FiveTuple>,
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
    pub fn new(visa: vsapi_types::Visa) -> Self {
        let ftuple = FiveTuple::from(visa.get_five_tuple());
        Self {
            visa: Some(visa),
            streams: Vec::new(),
            ftuple: Some(ftuple),
        }
    }

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

    // Return true if the visa matches the given traffic description (given in the
    // form of a FiveTuple).
    //
    // Visa may have wildcards.  Eg, a visa with zero for a source port will match
    // any traffic five_tuple source port value.
    pub fn match_traffic(&self, five_tuple: &FiveTuple) -> bool {
        if self.visa.is_none() || self.ftuple.is_none() {
            return false;
        }

        let visa_tuple = self.ftuple.as_ref().unwrap();
        if visa_tuple.src_address != IpAddress::UNSPECIFIED
            && visa_tuple.src_address != five_tuple.src_address
        {
            return false;
        }
        if visa_tuple.dst_address != IpAddress::UNSPECIFIED
            && visa_tuple.dst_address != five_tuple.dst_address
        {
            return false;
        }
        // TODO: Explicitly set this (l3_type) in visa and also allow it to be set to 0?
        if visa_tuple.l3_type != five_tuple.l3_type {
            return false;
        }
        if visa_tuple.l4_protocol != 0 && visa_tuple.l4_protocol != five_tuple.l4_protocol {
            return false;
        }
        if visa_tuple.src_port != 0 && visa_tuple.src_port != five_tuple.src_port {
            return false;
        }
        if visa_tuple.dst_port != 0 && visa_tuple.dst_port != five_tuple.dst_port {
            return false;
        }
        return true;
    }
}

pub struct VisaTable {
    pub table: HashMap<VisaId, Visa>,
    pub timeout_queue: BinaryHeap<VisaTimeout>,
    pub lookup_table: FiveTupleLookupTable,
}

impl VisaTable {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            timeout_queue: BinaryHeap::new(),
            lookup_table: FiveTupleLookupTable::new(),
        }
    }

    /// Create table and populate with two visas to allow for 2-way comms with the
    /// VS-API.
    ///
    /// TODO: Note that the first thing the visa service does after connecting is
    /// hand over visas just like this.  So we should have logic somewhere to get
    /// rid of these.  Maybe?  We might need them again if for example we loose
    /// contact with visa service and the visas it gives us expire.
    pub fn new_with_vs_visas(node_addr: &IpAddr) -> Self {
        // Right away the node wants to reach out to the visa service. So we need visas to match:
        //  1) NODEADDR/any-port -> VISA_SERVICE/VS_PORT
        //  2) VISA_SERVICE/VS_PORT -> NODEADDR/any-port (TODO: not great, really needs to check this is non-syn)

        // Node ZPR address must be IPv6, right?
        let node_zpr_addr = match node_addr {
            IpAddr::V4(addr) => addr.to_ipv6_mapped(),
            IpAddr::V6(addr) => addr.clone(),
        };

        // TODO: This is crazy since VS is always IPv6
        let vs_zpr_addr = match zpr::VISA_SERVICE_ADDR {
            IpAddr::V4(addr) => addr.to_ipv6_mapped(),
            IpAddr::V6(addr) => addr,
        };

        let expires_ms = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + VS_VISAS_DURATION)
            .as_millis() as i64;

        let node2vs = make_tcp_visa(
            1,
            &node_zpr_addr,
            0,
            &vs_zpr_addr,
            zpr::VISA_SERVICE_PORT,
            expires_ms,
            VS_VISAS_CONFIG_ID,
        );
        let vs2node = make_tcp_visa(
            2,
            &vs_zpr_addr,
            zpr::VISA_SERVICE_PORT,
            &node_zpr_addr,
            0,
            expires_ms,
            VS_VISAS_CONFIG_ID,
        );

        let mut visa_table = Self::new();
        visa_table
            .insert_visa(node2vs)
            .expect("Failed to insert node->vs visa into table");
        visa_table
            .insert_visa(vs2node)
            .expect("Failed to insert visa->node visa into table");

        visa_table.lookup_table = FiveTupleLookupTable::new();
        visa_table
            .lookup_table
            .build_table_from_hash(&visa_table.table);

        visa_table
    }

    /// Insert a dummy visa (temporary functionality until visa bootstrapping works)
    /// TODO: This is only used in tests we should remove this and also remove the Options from the Visa struct.
    pub fn insert_id(&mut self, visa_id: VisaId, expiration: DateTime<Utc>) {
        debug!(target: VISA_MGMT,
            "Dummy visa inserted into VisaTable ID: {visa_id}, Expiration: {}",
            expiration.format("%y-%m-%d %H:%M:%S"));
        let visa = Visa::default();
        let timeout = VisaTimeout {
            id: visa_id,
            expiration: expiration,
        };
        let _ = self.table.insert(visa_id, visa.clone());
        self.timeout_queue.push(timeout);

        self.lookup_table.insert_visa(visa_id, visa);
    }

    /// Insert a visa from the Visa Service into the Visa Table
    pub fn insert_visa(&mut self, visa: vsapi_types::Visa) -> Result<VisaId, VisaTableError> {
        let visa_id = visa.issuer_id as i32;

        let expiration = DateTime::from(visa.expires);

        info!(target: VISA_MGMT,
            "Visa inserted into VisaTable ID: {visa_id}, Expiration: {}",
            expiration.format("%y-%m-%d %H:%M:%S"));

        let visa = Visa::new(visa);

        let timeout = VisaTimeout {
            id: visa_id,
            expiration: expiration,
        };
        let _ = self.table.insert(visa_id, visa.clone());
        self.timeout_queue.push(timeout);

        self.lookup_table.insert_visa(visa_id, visa);

        Ok(visa_id)
    }

    /// Match traffic to a visa. Returns all matching visa IDs.
    pub fn match_traffic(&self, five_tuple: &FiveTuple) -> Option<VisaId> {
        self.lookup_table.find_match(*five_tuple)
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
        self.revoke_no_rebuild(peer_table, visa_id)?;
        self.lookup_table = FiveTupleLookupTable::new();
        self.lookup_table.build_table_from_hash(&self.table);

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
            let _ = self.revoke_no_rebuild(peer_table, timeout_entry.id);
        }
        self.lookup_table = FiveTupleLookupTable::new();
        self.lookup_table.build_table_from_hash(&self.table);
    }

    fn revoke_no_rebuild(
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
    /// Given a visa ID, look up the visa and return the destination address.
    /// If visa is not found or does not have a destination address, return an error.
    pub fn get_visa_dest_addr(&self, visa_id: VisaId) -> Result<IpAddress, VisaTableError> {
        let visa_query = self
            .table
            .get(&visa_id)
            .ok_or(VisaTableError::NotFound(visa_id));
        match visa_query {
            Ok(visa) => {
                if let Some(ftuple) = &visa.ftuple {
                    Ok(ftuple.dst_address.clone())
                } else {
                    Err(VisaTableError::ParseError(
                        "visa missing destination address",
                    ))
                }
            }
            Err(e) => Err(e),
        }
    }
}

fn make_tcp_visa(
    visa_id: i32,
    source: &Ipv6Addr,
    source_port: u16,
    dest: &Ipv6Addr,
    dest_port: u16,
    configuration: i64,
    expiration_ms: i64,
) -> vsapi_types::Visa {
    let pepargs = vsapi_types::TcpUdpPep {
        source_port: source_port,
        dest_port: dest_port,
    };
    let dur = Duration::from_millis(expiration_ms as u64);

    vsapi_types::Visa {
        issuer_id: visa_id as u64,
        config: configuration,
        expires: UNIX_EPOCH + dur,
        src_addr: IpAddress::from(*source),
        dst_addr: IpAddress::from(*dest),
        dock_pep: ip_number::TCP,
        tcp_udp_pep: Some(pepargs),
        icmp_pep: None,
        session_key: vsapi_types::KeySet::default(),
        cons: vsapi_types::Constraints::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::forwarding_tables::PftPep;
    use crate::link_state::LinkType;
    use crate::peer_table::test::create_dummy_peer_state;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use zpr_utils::net_defs;

    #[test]
    fn test_timeouts() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));

        let one_second = std::time::Duration::from_secs(1);
        let visa1 = 12345;
        let visa2 = 67890;
        let visa3 = 234;
        let mut visa_table = asm.visa_table.write().unwrap();
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

    #[tokio::test] // must be tokio::test because we create a dummy task in create_dummy_peer_state()
    async fn test_remove_forwarding_entries() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));
        let entry = asm.peer_table.vacant_entry().unwrap();
        let entry_key = entry.key();
        let link_id = entry
            .insert(create_dummy_peer_state(
                entry_key,
                LinkType::Internal,
                zpr::SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
                net_defs::ScopedIpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
            ))
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

        let mut visa_table = asm.visa_table.write().unwrap();
        visa_table.insert_id(visa1, DateTime::<Utc>::MAX_UTC); // An element that won't timeout
        visa_table.insert_id(visa2, Utc::now() + one_second); // An element that will time out in a second
        assert!(
            visa_table
                .link_forwarding_entry(visa1, zpr::ForwardingEntry(link_id, tether_id1))
                .is_ok()
        );
        assert!(
            visa_table
                .link_forwarding_entry(visa2, zpr::ForwardingEntry(link_id, tether_id2))
                .is_ok()
        );

        std::thread::sleep(one_second);

        visa_table.handle_expirations(&asm.peer_table);
        assert_eq!(1, peer_state.pft.len());

        assert!(visa_table.revoke(&asm.peer_table, visa1).is_ok());
        assert_eq!(0, peer_state.pft.len());
    }

    #[test]
    fn test_match_traffic() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));

        let mut visa_table = asm.visa_table.write().unwrap();

        let client1_addr: Ipv6Addr = "fd5a:5052:8::1".parse().unwrap();
        let client2_addr: Ipv6Addr = "fd5a:5052:8::2".parse().unwrap();
        let service_addr: Ipv6Addr = "fd5a:5052:8::10".parse().unwrap();

        let expires_ms = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            + Duration::from_millis(10000))
        .as_millis() as i64;

        let visa1 = make_tcp_visa(1000, &client1_addr, 0, &service_addr, 80, expires_ms, 100);
        let visa2 = make_tcp_visa(1001, &client2_addr, 0, &service_addr, 80, expires_ms, 100);

        visa_table.insert_id(12345, DateTime::<Utc>::MAX_UTC);

        let vid = visa_table.insert_visa(visa1).unwrap();
        assert_eq!(vid, 1000);
        let vid = visa_table.insert_visa(visa2).unwrap();
        assert_eq!(vid, 1001);

        let traffic = FiveTuple {
            src_address: IpAddress::new_from_std_v6(&client1_addr),
            dst_address: IpAddress::new_from_std_v6(&service_addr),
            l3_type: zpr::L3Type::Ipv6,
            l4_protocol: ip_number::TCP,
            src_port: 20345,
            dst_port: 80,
        };
        let matched = visa_table.match_traffic(&traffic);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap(), 1000);
    }
}
