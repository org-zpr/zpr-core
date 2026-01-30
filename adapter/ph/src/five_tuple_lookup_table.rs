use crate::rcu::RcuBox;
use crate::visa_table::Visa;

use ip_network_table_deps_treebitmap::IpLookupTable;
use range_set_blaze::RangeMapBlaze;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::Arc;
use zpr::packet_info::VisaId;
use zpr::vsapi_types::{VsapiFiveTuple, VsapiIpProtocol};

pub type FiveTupleLookup = HashMap<IpAddr, Arc<IpLookupTable<Ipv6Addr, DstPortLookup>>>;
pub type DstPortLookup = PortLookup<SrcPortLookup>;
pub type SrcPortLookup = PortLookup<ProtoLookup>;

pub struct FiveTupleLookupTable {
    table: RcuBox<Arc<FiveTupleLookup>>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ProtoLookup {
    proto_vec: Arc<Vec<Arc<ProtoAndId>>>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ProtoAndId {
    proto: VsapiIpProtocol,
    id: VisaId,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum PortLookup<T: Clone + Eq + PartialEq> {
    Wildcard(T),
    MultiVal(Arc<RangeMapBlaze<u16, T>>),
    SingleVal(Arc<(u16, T)>),
}

// Used to combine two src port levels, two dst port levels, or two proto levels
pub trait Combinable {
    fn combine(&self, other: &Self) -> Self;
}

impl FiveTupleLookupTable {
    // TODO change how construction is done once visas move away from being based on a FiveTuples
    pub fn new() -> Self {
        let hash_table: FiveTupleLookup = HashMap::new();
        Self {
            table: RcuBox::new(Arc::new(hash_table)),
        }
    }

    pub fn build_table_from_hash(&self, visa_table: &HashMap<VisaId, Visa>) {
        let mut dst_addr_intersection: FiveTupleLookup = HashMap::new();
        for (key, val) in self.table.get().iter() {
            dst_addr_intersection.insert(*key, val.clone());
        }
        for (visa_id, visa) in visa_table.iter() {
            Self::add_one_visa(*visa_id, visa, &mut dst_addr_intersection);
        }
        self.table.write(Arc::new(dst_addr_intersection))
    }

    pub fn insert_visa(&self, visa_id: VisaId, visa: Visa) {
        let mut table: FiveTupleLookup = HashMap::new();
        for (key, val) in self.table.get().iter() {
            table.insert(*key, val.clone());
        }
        Self::add_one_visa(visa_id, &visa, &mut table);
        self.table.write(Arc::new(table))
    }

    fn add_one_visa(visa_id: VisaId, visa: &Visa, table: &mut FiveTupleLookup) {
        let five_tuple = visa.ftuple;

        // Create array for protocol
        let mut arr = Vec::new();
        arr.push(Arc::new(ProtoAndId::new(five_tuple.l4_protocol, visa_id)));

        // Determine which enum to use for src level
        let src_level: SrcPortLookup = match five_tuple.source_port {
            0 => PortLookup::Wildcard(ProtoLookup::new(arr)),
            val => PortLookup::SingleVal(Arc::new((val, ProtoLookup::new(arr)))),
        };

        // Determine which enum to use for dst level
        let dst_level: DstPortLookup = match five_tuple.dest_port {
            0 => PortLookup::Wildcard(src_level),
            val => PortLookup::SingleVal(Arc::new((val, src_level))),
        };

        // Create table of src addresses, add map of destination ports
        // NOTE how large do we expect each IpLookupTable to be? I.E. how many src addresses for each dst address, typically?
        let mut ip_table = IpLookupTable::new();
        match five_tuple.source_addr {
            IpAddr::V4(addr) => ip_table.insert(addr.to_ipv6_mapped(), 128, dst_level),
            IpAddr::V6(addr) => ip_table.insert(addr, 128, dst_level),
        };

        // Try to add to hash table, if there is a collision, combine the tables, then add the combined table
        match table.insert(five_tuple.dest_addr, Arc::new(ip_table)) {
            None => (),
            Some(removed_src_addrs) => {
                let in_table_src_addrs = table.get(&five_tuple.dest_addr).unwrap();
                // Create intersection that has the dst port levels from both the src addrs currently in the table and those that were removed
                let mut intersection = IpLookupTable::new();
                for (addr, mask_len, val) in in_table_src_addrs.iter() {
                    intersection.insert(addr, mask_len, val.clone());
                }
                for (og_src_addr, og_mask_len, og_dst_ports) in removed_src_addrs.iter() {
                    // Try to add a source addresses, If the src address is already being used as a key, combine its dst port tables
                    match intersection.insert(og_src_addr, og_mask_len, og_dst_ports.clone()) {
                        None => (),
                        Some(removed_dst_ports) => {
                            let in_table_dst_ports =
                                intersection.exact_match(og_src_addr, og_mask_len).unwrap();
                            let new_dst_level = removed_dst_ports.combine(&in_table_dst_ports);
                            intersection.insert(og_src_addr, og_mask_len, new_dst_level);
                        }
                    }
                }
                // Add the intersection of source addresses to the bucket of the proper dst address
                table.insert(five_tuple.dest_addr, Arc::new(intersection));
            }
        }
    }

    pub fn find_match(&self, ft: VsapiFiveTuple) -> Option<VisaId> {
        match self.table.get().get(&ft.dest_addr) {
            None => return None,
            Some(src_addr_table) => {
                let src_addr = match ft.source_addr {
                    IpAddr::V4(addr) => addr.to_ipv6_mapped(),

                    IpAddr::V6(addr) => addr,
                };
                return match src_addr_table.longest_match(src_addr) {
                    None => None,
                    Some(dst_port_table) => match dst_port_table.2 {
                        PortLookup::Wildcard(src_level) => {
                            Self::find_src_level_match(src_level.clone(), ft)
                        }
                        PortLookup::SingleVal(tuple_val) => {
                            let port = tuple_val.0;
                            let src_level = tuple_val.1.clone();
                            match port == ft.dest_port {
                                false => return None,
                                true => return Self::find_src_level_match(src_level.clone(), ft),
                            };
                        }
                        PortLookup::MultiVal(dst_level) => match dst_level.get(ft.dest_port) {
                            None => None,
                            Some(src_level) => Self::find_src_level_match(src_level.clone(), ft),
                        },
                    },
                };
            }
        };
    }

    fn find_src_level_match(src_level: SrcPortLookup, ft: VsapiFiveTuple) -> Option<VisaId> {
        match src_level {
            PortLookup::Wildcard(protos) => Self::find_proto_level_match(&protos, ft.l4_protocol),
            PortLookup::SingleVal(tuple_val) => {
                let port = tuple_val.0;
                let protos = tuple_val.1.clone();

                match port == ft.source_port {
                    false => None,
                    true => Self::find_proto_level_match(&protos, ft.l4_protocol),
                }
            }
            PortLookup::MultiVal(src_level_map) => match src_level_map.get(ft.source_port) {
                None => None,
                Some(protos) => Self::find_proto_level_match(protos, ft.l4_protocol),
            },
        }
    }

    fn find_proto_level_match(protos: &ProtoLookup, proto: VsapiIpProtocol) -> Option<VisaId> {
        for elem in protos.proto_vec.iter() {
            if elem.proto == proto {
                return Some(elem.id);
            }
        }
        return None;
    }
}

impl<T: Combinable + Clone + Eq + PartialEq> Combinable for PortLookup<T> {
    fn combine(&self, other: &Self) -> Self {
        match (self, other) {
            (PortLookup::Wildcard(level_below1), PortLookup::Wildcard(level_below2)) => {
                PortLookup::Wildcard(level_below1.combine(level_below2))
            }
            (PortLookup::Wildcard(level_below_wild), PortLookup::SingleVal(tuple_val))
            | (PortLookup::SingleVal(tuple_val), PortLookup::Wildcard(level_below_wild)) => {
                let port = tuple_val.0;
                let level_below_single = tuple_val.1.clone();
                let mut curr_level_intersection = RangeMapBlaze::new();
                curr_level_intersection.ranges_insert(0..=65535, level_below_wild.clone());
                let intersection = level_below_wild.combine(&level_below_single);
                curr_level_intersection.insert(port, intersection);
                PortLookup::MultiVal(Arc::new(curr_level_intersection))
            }
            (PortLookup::Wildcard(level_below), PortLookup::MultiVal(curr_level))
            | (PortLookup::MultiVal(curr_level), PortLookup::Wildcard(level_below)) => {
                let mut curr_level_intersection = RangeMapBlaze::new();
                curr_level_intersection.ranges_insert(0..=65535, level_below.clone());
                for (range, lvl_below) in curr_level.range_values() {
                    // We know there will be a collision, so we pre-emptively make the intersection and then insert it
                    let level_below_intersection = level_below.combine(lvl_below);
                    curr_level_intersection.ranges_insert(range, level_below_intersection);
                }
                PortLookup::MultiVal(Arc::new(curr_level_intersection))
            }
            (PortLookup::SingleVal(tuple_val1), PortLookup::SingleVal(tuple_val2)) => {
                let port1 = tuple_val1.0;
                let level_below1 = tuple_val1.1.clone();
                let port2 = tuple_val2.0;
                let level_below2 = tuple_val2.1.clone();

                if port1 == port2 {
                    PortLookup::SingleVal(Arc::new((port1, level_below1.combine(&level_below2))))
                } else {
                    let mut curr_level_intersection = RangeMapBlaze::new();
                    curr_level_intersection.insert(port1, level_below1);
                    curr_level_intersection.insert(port2, level_below2);
                    PortLookup::MultiVal(Arc::new(curr_level_intersection))
                }
            }
            (PortLookup::SingleVal(tuple_val), PortLookup::MultiVal(curr_level))
            | (PortLookup::MultiVal(curr_level), PortLookup::SingleVal(tuple_val)) => {
                let port = tuple_val.0;
                let level_below = tuple_val.1.clone();
                let mut curr_level_intersection = RangeMapBlaze::new();
                for (key, val) in curr_level.range_values() {
                    curr_level_intersection.ranges_insert(key, val.clone());
                }
                match curr_level_intersection.insert(port, level_below.clone()) {
                    None => (),
                    Some(removed_level_below) => {
                        let intersection = level_below.combine(&removed_level_below);
                        curr_level_intersection.insert(port, intersection);
                    }
                };
                PortLookup::MultiVal(Arc::new(curr_level_intersection))
            }
            (PortLookup::MultiVal(curr_level1), PortLookup::MultiVal(curr_level2)) => {
                let mut curr_level_intersection = RangeMapBlaze::new();
                for (key, val) in curr_level1.range_values() {
                    curr_level_intersection.ranges_insert(key, val.clone());
                }
                let mut existing_ranges = curr_level1.ranges();
                let mut curr_existing_range = existing_ranges.next();
                let mut inserting_iterator = curr_level2.range_values();
                let mut curr_inserting_range = inserting_iterator.next();
                while curr_inserting_range.is_some() {
                    let (inserting_range, level_below2) = curr_inserting_range.clone().unwrap();
                    if let Some(ref curr) = curr_existing_range {
                        // check if the ranges overlap, if they do, insert element by element
                        if overlap(&curr, &inserting_range) {
                            for port in inserting_range.into_iter() {
                                match curr_level_intersection.insert(port, level_below2.clone()) {
                                    None => (),
                                    Some(level_below1) => {
                                        let level_below_intersection =
                                            level_below1.combine(&level_below2);
                                        curr_level_intersection
                                            .insert(port, level_below_intersection);
                                    }
                                }
                            }
                            // We only increment the inserting value becuase it is possible that the next inserting range
                            // also overlaps the same existing range
                            curr_inserting_range = inserting_iterator.next();
                        } else {
                            // Don't overlap and the inserting range comes before the first existing range, meaning it
                            // couldn't overlap with a later already existing range
                            if inserting_range.end() < curr.start() {
                                // Don't need to look at return value, know there will be no overlap
                                curr_level_intersection
                                    .ranges_insert(inserting_range, level_below2.clone());
                                // Since the inserted range somes entirely before the current existing range, we only increment the inserting range
                                curr_inserting_range = inserting_iterator.next();
                            } else {
                                // If there was no overlap and the inserting range comes after the existing range, we need to make sure there is
                                // not a later existing range that would overlap the inserting range, so we increase only the existing range
                                curr_existing_range = existing_ranges.next();
                            }
                        }
                    } else {
                        // If the existing range is none, we have passed the end of the existing values and we know we will have no more overlap
                        curr_level_intersection
                            .ranges_insert(inserting_range, level_below2.clone());
                        curr_inserting_range = inserting_iterator.next();
                    }
                }

                PortLookup::MultiVal(Arc::new(curr_level_intersection))
            }
        }
    }
}

impl ProtoLookup {
    pub fn new(v: Vec<Arc<ProtoAndId>>) -> Self {
        Self {
            proto_vec: Arc::new(v),
        }
    }
}

pub fn overlap<T: PartialOrd>(range1: &RangeInclusive<T>, range2: &RangeInclusive<T>) -> bool {
    range1.start() <= range2.end() && range1.end() >= range2.start()
}

impl Combinable for ProtoLookup {
    fn combine(&self, other: &Self) -> Self {
        let mut intersection = Vec::new();
        for elem in other.proto_vec.iter() {
            intersection.push(elem.clone());
        }

        for proto_one in self.proto_vec.iter() {
            let mut exists = false;
            for proto_two in intersection.iter() {
                if proto_one.proto == proto_two.proto {
                    exists = true
                }
            }
            if !exists {
                intersection.push(proto_one.clone())
            }
        }

        ProtoLookup::new(intersection)
    }
}

impl ProtoAndId {
    pub fn new(proto: VsapiIpProtocol, id: VisaId) -> Self {
        Self { proto, id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use libnode::vsapi_thrift;
    use zpr::packet_info::L3Type;
    use zpr::vsapi_types;
    use zpr::vsapi_types::vsapi_ip_number;

    fn make_visa(
        src_addr: [u8; 16],
        dst_addr: [u8; 16],
        l4proto: vsapi_thrift::PEPIndex,
        src_port: i32,
        dst_port: i32,
    ) -> Visa {
        let src_dst = vsapi_thrift::PEPArgsTCPUDP::new(
            Vec::new(),
            Vec::new(),
            src_port,
            dst_port,
            None,
            None,
        );
        let visa: vsapi_thrift::Visa = vsapi_thrift::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            [0u8; 16].to_vec(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst,
            None,
            None,
            None,
            None,
        );

        Visa::new(vsapi_types::Visa::try_from(visa).unwrap())
    }

    #[test]
    fn test_construction_one_visa() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let v = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from from dst port level enum
        let src_port_level;
        if let PortLookup::SingleVal(tuple_val) = un_rcu_table
            .get(&IpAddr::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            let dst = tuple_val.0;
            let src_level = tuple_val.1.clone();
            assert_eq!(dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get proto level from src port level enum
        let proto_level;
        if let PortLookup::SingleVal(tuple_val) = src_port_level.unwrap() {
            let src = tuple_val.0;
            let protos = tuple_val.1.clone();
            assert_eq!(src, src_port as u16);
            proto_level = Some(protos)
        } else {
            proto_level = None
        }
        assert!(proto_level.is_some());

        assert_eq!(proto_level.as_ref().unwrap().proto_vec[0].id, 12);
        assert_eq!(
            proto_level.unwrap().proto_vec[0].proto,
            vsapi_ip_number::TCP
        );
    }

    #[test]
    fn test_construction_diff_protos() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto1 = vsapi_thrift::PEPIndex::TCP;
        let l4proto2 = vsapi_thrift::PEPIndex::UDP;
        let src_port = 10;
        let dst_port = 11;

        let v1 = make_visa(src_addr, dst_addr, l4proto1, src_port, dst_port);
        let v2 = make_visa(src_addr, dst_addr, l4proto2, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level;
        if let PortLookup::SingleVal(tuple_val) = un_rcu_table
            .get(&IpAddr::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            let dst = tuple_val.0;
            let src_level = tuple_val.1.clone();
            assert_eq!(dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get proto level from src port level enum
        let proto_level;
        if let PortLookup::SingleVal(tuple_val) = src_port_level.unwrap() {
            let src = tuple_val.0;
            let protos = tuple_val.1.clone();
            assert_eq!(src, src_port as u16);
            proto_level = Some(protos)
        } else {
            proto_level = None
        }
        assert!(proto_level.is_some());

        assert_eq!(proto_level.as_ref().unwrap().proto_vec.len(), 2);

        let mut tcp_idx = 0;
        let mut udp_idx = 0;

        // protovec is not deterministic in terms of ordering, have to figure out which visa is where
        if proto_level.as_ref().unwrap().proto_vec[0].proto == vsapi_ip_number::TCP {
            udp_idx = 1;
        } else {
            tcp_idx = 1;
        }

        assert_eq!(
            proto_level.as_ref().unwrap().proto_vec[tcp_idx].proto,
            vsapi_ip_number::TCP
        );
        assert_eq!(proto_level.as_ref().unwrap().proto_vec[tcp_idx].id, 12);
        assert_eq!(
            proto_level.as_ref().unwrap().proto_vec[udp_idx].proto,
            vsapi_ip_number::UDP
        );
        assert_eq!(proto_level.unwrap().proto_vec[udp_idx].id, 13);
    }

    #[test]
    fn test_construction_diff_src_ports() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port1 = 10;
        let src_port2 = 14;
        let dst_port = 11;

        let v1 = make_visa(src_addr, dst_addr, l4proto, src_port1, dst_port);
        let v2 = make_visa(src_addr, dst_addr, l4proto, src_port2, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level;
        if let PortLookup::SingleVal(tuple_val) = un_rcu_table
            .get(&IpAddr::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            let dst = tuple_val.0;
            let src_level = tuple_val.1.clone();
            assert_eq!(dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get src port map from src port level enum
        let src_ports;
        if let PortLookup::MultiVal(src_level) = src_port_level.unwrap() {
            src_ports = Some(src_level)
        } else {
            src_ports = None
        }
        assert!(src_ports.is_some());

        assert_eq!(
            src_ports
                .as_ref()
                .unwrap()
                .get(src_port1 as u16)
                .unwrap()
                .proto_vec[0]
                .id,
            12
        );
        assert_eq!(
            src_ports
                .as_ref()
                .unwrap()
                .get(src_port1 as u16)
                .unwrap()
                .proto_vec[0]
                .proto,
            vsapi_ip_number::TCP
        );
        assert_eq!(
            src_ports
                .as_ref()
                .unwrap()
                .get(src_port2 as u16)
                .unwrap()
                .proto_vec[0]
                .id,
            13
        );
        assert_eq!(
            src_ports
                .as_ref()
                .unwrap()
                .get(src_port2 as u16)
                .unwrap()
                .proto_vec[0]
                .id,
            13
        );
        assert_eq!(
            src_ports
                .as_ref()
                .unwrap()
                .get(src_port2 as u16)
                .unwrap()
                .proto_vec[0]
                .proto,
            vsapi_ip_number::TCP
        );
        assert_eq!(
            src_ports
                .as_ref()
                .unwrap()
                .get(src_port2 as u16)
                .unwrap()
                .proto_vec
                .len(),
            1
        );
        assert_eq!(src_ports.unwrap().len(), 2);
    }

    #[test]
    fn test_construction_diff_dst_ports() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 10;
        let dst_port1 = 11;
        let dst_port2 = 14;

        let v1 = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port1);
        let v2 = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port2);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let un_rcu_table = table.table.get();

        // Get dst port map from dst port level enum
        let dst_port_level;
        if let PortLookup::MultiVal(dst_level) = un_rcu_table
            .get(&IpAddr::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            dst_port_level = Some(dst_level)
        } else {
            dst_port_level = None
        }
        assert!(dst_port_level.is_some());

        // Get get protos from dst port level map and src port level enum
        let proto_level1;
        if let PortLookup::SingleVal(tuple_val) =
            dst_port_level.unwrap().get(dst_port1 as u16).unwrap()
        {
            let src = tuple_val.0;
            let protos = tuple_val.1.clone();
            assert_eq!(src, src_port as u16);
            proto_level1 = Some(protos)
        } else {
            proto_level1 = None
        }
        assert!(proto_level1.is_some());

        let proto_level2;
        if let PortLookup::SingleVal(tuple_val) =
            dst_port_level.unwrap().get(dst_port2 as u16).unwrap()
        {
            let src = tuple_val.0;
            let protos = tuple_val.1.clone();
            assert_eq!(src, src_port as u16);
            proto_level2 = Some(protos)
        } else {
            proto_level2 = None
        }
        assert!(proto_level2.is_some());

        assert_eq!(proto_level1.as_ref().unwrap().proto_vec[0].id, 12);
        assert_eq!(
            proto_level1.as_ref().unwrap().proto_vec[0].proto,
            vsapi_ip_number::TCP
        );
        assert_eq!(proto_level2.as_ref().unwrap().proto_vec[0].id, 13);
        assert_eq!(
            proto_level2.as_ref().unwrap().proto_vec[0].proto,
            vsapi_ip_number::TCP
        );
        assert_eq!(proto_level1.unwrap().proto_vec.len(), 1);
        assert_eq!(proto_level2.unwrap().proto_vec.len(), 1);
        assert_eq!(dst_port_level.unwrap().len(), 2);
        assert_eq!(un_rcu_table.get(&IpAddr::from(dst_addr)).unwrap().len(), 1);
        assert_eq!(un_rcu_table.len(), 1);
    }

    #[test]
    fn test_construction_diff_src_addrs() {
        let src_addr1 = [1u8; 16];
        let src_addr2 = [3u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let v1 = make_visa(src_addr1, dst_addr, l4proto, src_port, dst_port);
        let v2 = make_visa(src_addr2, dst_addr, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let un_rcu_table = table.table.get();

        // Get src port levels enum from dst port level enum
        let src_port_level1;
        if let PortLookup::SingleVal(tuple_val) = un_rcu_table
            .get(&IpAddr::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            let dst = tuple_val.0;
            let src_level = tuple_val.1.clone();
            assert_eq!(dst, dst_port as u16);
            src_port_level1 = Some(src_level)
        } else {
            src_port_level1 = None
        }
        assert!(src_port_level1.is_some());

        let src_port_level2;
        if let PortLookup::SingleVal(tuple_val) = un_rcu_table
            .get(&IpAddr::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303,
                ),
                128,
            )
            .unwrap()
        {
            let dst = tuple_val.0;
            let src_level = tuple_val.1.clone();
            assert_eq!(dst, dst_port as u16);
            src_port_level2 = Some(src_level)
        } else {
            src_port_level2 = None
        }
        assert!(src_port_level2.is_some());

        // Get proto levels from src port level enums
        let proto_level1;
        if let PortLookup::SingleVal(tuple_val) = src_port_level1.unwrap() {
            let src = tuple_val.0;
            let protos = tuple_val.1.clone();

            assert_eq!(src, src_port as u16);
            proto_level1 = Some(protos)
        } else {
            proto_level1 = None
        }
        assert!(proto_level1.as_ref().is_some());

        let proto_level2;
        if let PortLookup::SingleVal(tuple_val) = src_port_level2.unwrap() {
            let src = tuple_val.0;
            let protos = tuple_val.1.clone();

            assert_eq!(src, src_port as u16);
            proto_level2 = Some(protos)
        } else {
            proto_level2 = None
        }
        assert!(proto_level2.as_ref().is_some());

        assert_eq!(proto_level1.as_ref().unwrap().proto_vec[0].id, 12);
        assert_eq!(
            proto_level1.unwrap().proto_vec[0].proto,
            vsapi_ip_number::TCP
        );
        assert_eq!(proto_level2.as_ref().unwrap().proto_vec[0].id, 13);
        assert_eq!(
            proto_level2.unwrap().proto_vec[0].proto,
            vsapi_ip_number::TCP
        );
        assert_eq!(un_rcu_table.get(&IpAddr::from(dst_addr)).unwrap().len(), 2);
    }

    #[test]
    fn test_construction_diff_dst_addrs() {
        let src_addr = [1u8; 16];
        let dst_addr1 = [2u8; 16];
        let dst_addr2 = [3u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let v1 = make_visa(src_addr, dst_addr1, l4proto, src_port, dst_port);
        let v2 = make_visa(src_addr, dst_addr2, l4proto, src_port, dst_port);
        let mut hash: HashMap<VisaId, Visa> = HashMap::new();

        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level1;
        if let PortLookup::SingleVal(tuple_val) = un_rcu_table
            .get(&IpAddr::from(dst_addr1))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            let dst = tuple_val.0;
            let src_level = tuple_val.1.clone();
            assert_eq!(dst, dst_port as u16);
            src_port_level1 = Some(src_level)
        } else {
            src_port_level1 = None
        }
        assert!(src_port_level1.is_some());

        let src_port_level2;
        if let PortLookup::SingleVal(tuple_val) = un_rcu_table
            .get(&IpAddr::from(dst_addr2))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            let dst = tuple_val.0;
            let src_level = tuple_val.1.clone();
            assert_eq!(dst, dst_port as u16);
            src_port_level2 = Some(src_level)
        } else {
            src_port_level2 = None
        }
        assert!(src_port_level2.is_some());

        // Get proto levels from src port level enums
        let proto_level1;
        if let PortLookup::SingleVal(tuple_val) = src_port_level1.unwrap() {
            let src = tuple_val.0;
            let protos = tuple_val.1.clone();
            assert_eq!(src, src_port as u16);
            proto_level1 = Some(protos)
        } else {
            proto_level1 = None
        }
        assert!(proto_level1.as_ref().is_some());

        let proto_level2;
        if let PortLookup::SingleVal(tuple_val) = src_port_level2.unwrap() {
            let src = tuple_val.0;
            let protos = tuple_val.1.clone();
            assert_eq!(src, src_port as u16);
            proto_level2 = Some(protos)
        } else {
            proto_level2 = None
        }
        assert!(proto_level2.as_ref().is_some());

        assert_eq!(proto_level1.as_ref().unwrap().proto_vec[0].id, 12);
        assert_eq!(
            proto_level1.unwrap().proto_vec[0].proto,
            vsapi_ip_number::TCP
        );
        assert_eq!(proto_level2.as_ref().unwrap().proto_vec[0].id, 13);
        assert_eq!(
            proto_level2.unwrap().proto_vec[0].proto,
            vsapi_ip_number::TCP
        );
        assert_eq!(un_rcu_table.len(), 2);
        assert_eq!(un_rcu_table.get(&IpAddr::from(dst_addr2)).unwrap().len(), 1);
    }

    #[test]
    fn test_exact_match_visa() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let v = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port);

        let ft = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        assert_eq!(table.find_match(ft), Some(12))
    }

    #[test]
    fn test_no_visa_match_multiple_visas() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let ft = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );

        let l4proto_diff = vsapi_thrift::PEPIndex::UDP;
        let src_port_diff = 13;
        let dst_port_diff = 14;
        let src_addr_diff = [3u8; 16];
        let dst_addr_diff = [4u8; 16];

        let v_diff_proto = make_visa(src_addr, dst_addr, l4proto_diff, src_port, dst_port);
        let v_diff_src_port = make_visa(src_addr, dst_addr, l4proto, src_port_diff, dst_port);
        let v_diff_dst_port = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port_diff);
        let v_diff_src_addr = make_visa(src_addr_diff, dst_addr, l4proto, src_port, dst_port);
        let v_diff_dst_addr = make_visa(src_addr, dst_addr_diff, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(15, v_diff_proto);
        hash.insert(16, v_diff_src_port);
        hash.insert(17, v_diff_dst_port);
        hash.insert(18, v_diff_src_addr);
        hash.insert(19, v_diff_dst_addr);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        assert_eq!(table.find_match(ft), None);
    }

    #[test]
    fn test_no_visa_match_multiple_fts() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let v = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(15, v);
        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let src_port_diff = 13;
        let dst_port_diff = 14;
        let src_addr_diff = [3u8; 16];
        let dst_addr_diff = [4u8; 16];

        let ft_diff_proto = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::UDP,
            src_port as u16,
            dst_port as u16,
        );
        let ft_diff_src_port = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port_diff as u16,
            dst_port as u16,
        );
        let ft_diff_dst_port = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port_diff as u16,
        );
        let ft_diff_src_addr = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr_diff),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );
        let ft_diff_dst_addr = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr_diff),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );

        assert_eq!(table.find_match(ft_diff_proto), None);
        assert_eq!(table.find_match(ft_diff_src_port), None);
        assert_eq!(table.find_match(ft_diff_dst_port), None);
        assert_eq!(table.find_match(ft_diff_src_addr), None);
        assert_eq!(table.find_match(ft_diff_dst_addr), None);
    }

    #[test]
    fn test_match_correct_visa() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let ft = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );

        let l4proto_diff = vsapi_thrift::PEPIndex::UDP;
        let src_port_diff = 13;
        let dst_port_diff = 14;
        let src_addr_diff = [3u8; 16];
        let dst_addr_diff = [4u8; 16];

        let v_diff_proto = make_visa(src_addr, dst_addr, l4proto_diff, src_port, dst_port);
        let v_diff_src_port = make_visa(src_addr, dst_addr, l4proto, src_port_diff, dst_port);
        let v_diff_dst_port = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port_diff);
        let v_diff_src_addr = make_visa(src_addr_diff, dst_addr, l4proto, src_port, dst_port);
        let v_diff_dst_addr = make_visa(src_addr, dst_addr_diff, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(15, v_diff_proto);
        hash.insert(16, v_diff_src_port);
        hash.insert(17, v_diff_dst_port);
        hash.insert(18, v_diff_src_addr);
        hash.insert(19, v_diff_dst_addr);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let ft_diff_proto = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::UDP,
            src_port as u16,
            dst_port as u16,
        );
        let ft_diff_src_port = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port_diff as u16,
            dst_port as u16,
        );
        let ft_diff_dst_port = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port_diff as u16,
        );
        let ft_diff_src_addr = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr_diff),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );
        let ft_diff_dst_addr = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr_diff),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );

        assert_eq!(table.find_match(ft_diff_proto), Some(15));
        assert_eq!(table.find_match(ft_diff_src_port), Some(16));
        assert_eq!(table.find_match(ft_diff_dst_port), Some(17));
        assert_eq!(table.find_match(ft_diff_src_addr), Some(18));
        assert_eq!(table.find_match(ft_diff_dst_addr), Some(19));
        assert_eq!(table.find_match(ft), None);
    }

    #[test]
    fn test_wildcarded_src_ports() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 0;
        let dst_port = 11;

        let v = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let ft1 = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            3423,
            dst_port as u16,
        );
        let ft2 = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            1,
            dst_port as u16,
        );
        let ft3 = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            65535,
            dst_port as u16,
        );
        let ft4 = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            43211,
            dst_port as u16,
        );
        assert_eq!(table.find_match(ft1), Some(12));
        assert_eq!(table.find_match(ft2), Some(12));
        assert_eq!(table.find_match(ft3), Some(12));
        assert_eq!(table.find_match(ft4), Some(12));
        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level;
        if let PortLookup::SingleVal(tuple_val) = un_rcu_table
            .get(&IpAddr::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            let dst = tuple_val.0;
            let src_level = tuple_val.1.clone();
            assert_eq!(dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get proto level from src port level enum
        let proto_level;
        if let PortLookup::Wildcard(protos) = src_port_level.unwrap() {
            proto_level = Some(protos)
        } else {
            proto_level = None
        }
        assert!(proto_level.is_some());

        assert_eq!(proto_level.unwrap().proto_vec.len(), 1);
    }

    #[test]
    fn test_wildcarded_dst_ports() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 0;

        let v = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let ft1 = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            3423,
        );
        let ft2 = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            1,
        );
        let ft3 = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            65535,
        );
        let ft4 = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            43211,
        );
        assert_eq!(table.find_match(ft1), Some(12));
        assert_eq!(table.find_match(ft2), Some(12));
        assert_eq!(table.find_match(ft3), Some(12));
        assert_eq!(table.find_match(ft4), Some(12));

        let un_rcu_table = table.table.get();

        //Get src port level enum from dst port level enum
        let src_port_level;
        if let PortLookup::Wildcard(src_level) = un_rcu_table
            .get(&IpAddr::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        assert_eq!(un_rcu_table.get(&IpAddr::from(dst_addr)).unwrap().len(), 1);

        // Get proto level from src port level enum
        let proto_level;
        if let PortLookup::SingleVal(tuple_val) = src_port_level.unwrap() {
            let src = tuple_val.0;
            let protos = tuple_val.1.clone();
            assert_eq!(src, src_port as u16);
            proto_level = Some(protos)
        } else {
            proto_level = None
        }
        assert!(proto_level.is_some());
    }

    #[test]
    fn test_wildcard_insertion_wildcard_second() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto1 = vsapi_thrift::PEPIndex::UDP;
        let l4proto2 = vsapi_thrift::PEPIndex::TCP;
        let src_port_specified = 10;
        let src_port_wild = 0;
        let dst_port = 11;

        let v1 = make_visa(src_addr, dst_addr, l4proto1, src_port_specified, dst_port);
        let v2 = make_visa(src_addr, dst_addr, l4proto2, src_port_wild, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level;
        if let PortLookup::SingleVal(tuple_val) = un_rcu_table
            .get(&IpAddr::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            let dst = tuple_val.0;
            let src_level = tuple_val.1.clone();
            assert_eq!(dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get src port level map from src port level enum
        let src_level;
        if let PortLookup::MultiVal(src_map) = src_port_level.unwrap() {
            src_level = Some(src_map)
        } else {
            src_level = None
        }
        assert!(src_level.is_some());

        assert_eq!(src_level.unwrap().len(), 65536);

        let specified_src_ft = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::UDP,
            src_port_specified as u16,
            dst_port as u16,
        );
        let random_src_ft = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            4323u16,
            dst_port as u16,
        );

        assert_eq!(table.find_match(specified_src_ft), Some(12));
        assert_eq!(table.find_match(random_src_ft), Some(13));
    }

    #[test]
    fn test_wildcard_insertion_wildcard_first() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto1 = vsapi_thrift::PEPIndex::UDP;
        let l4proto2 = vsapi_thrift::PEPIndex::TCP;
        let src_port_specified = 10;
        let src_port_wild = 0;
        let dst_port = 11;

        let v1 = make_visa(src_addr, dst_addr, l4proto1, src_port_specified, dst_port);
        let v2 = make_visa(src_addr, dst_addr, l4proto2, src_port_wild, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(13, v2);
        hash.insert(12, v1);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level;
        if let PortLookup::SingleVal(tuple_val) = un_rcu_table
            .get(&IpAddr::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            let dst = tuple_val.0;
            let src_level = tuple_val.1.clone();
            assert_eq!(dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get src port level map from src port level ennum
        let src_level;
        if let PortLookup::MultiVal(src_map) = src_port_level.unwrap() {
            src_level = Some(src_map)
        } else {
            src_level = None
        }
        assert!(src_level.is_some());

        assert_eq!(src_level.unwrap().len(), 65536);

        let specified_src_ft = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::UDP,
            src_port_specified as u16,
            dst_port as u16,
        );
        let random_src_ft = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            4323u16,
            dst_port as u16,
        );

        assert_eq!(table.find_match(specified_src_ft), Some(12));
        assert_eq!(table.find_match(random_src_ft), Some(13));
    }

    #[test]
    fn test_match_correct_visa_with_insert() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi_thrift::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let ft = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );

        let l4proto_diff = vsapi_thrift::PEPIndex::UDP;
        let src_port_diff = 13;
        let dst_port_diff = 14;
        let src_addr_diff = [3u8; 16];
        let dst_addr_diff = [4u8; 16];

        let v_diff_proto = make_visa(src_addr, dst_addr, l4proto_diff, src_port, dst_port);
        let v_diff_src_port = make_visa(src_addr, dst_addr, l4proto, src_port_diff, dst_port);
        let v_diff_dst_port = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port_diff);
        let v_diff_src_addr = make_visa(src_addr_diff, dst_addr, l4proto, src_port, dst_port);
        let v_diff_dst_addr = make_visa(src_addr, dst_addr_diff, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(15, v_diff_proto);
        hash.insert(16, v_diff_src_port);

        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);

        table.insert_visa(17, v_diff_dst_port);
        table.insert_visa(18, v_diff_src_addr);
        table.insert_visa(19, v_diff_dst_addr);

        let ft_diff_proto = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::UDP,
            src_port as u16,
            dst_port as u16,
        );
        let ft_diff_src_port = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port_diff as u16,
            dst_port as u16,
        );
        let ft_diff_dst_port = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port_diff as u16,
        );
        let ft_diff_src_addr = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr_diff),
            IpAddr::from(dst_addr),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );
        let ft_diff_dst_addr = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(src_addr),
            IpAddr::from(dst_addr_diff),
            vsapi_ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );

        assert_eq!(table.find_match(ft_diff_proto), Some(15));
        assert_eq!(table.find_match(ft_diff_src_port), Some(16));
        assert_eq!(table.find_match(ft_diff_dst_port), Some(17));
        assert_eq!(table.find_match(ft_diff_src_addr), Some(18));
        assert_eq!(table.find_match(ft_diff_dst_addr), Some(19));
        assert_eq!(table.find_match(ft), None);
    }

    #[test]
    pub fn multival_combine_no_overlap() {
        // Map 1: |-----|            |-----|
        // Map 2:          |-----|
        let mut map1 = RangeMapBlaze::new();
        map1.ranges_insert(
            54u16..=75u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map1.ranges_insert(
            100u16..=101u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        let port_lookup1: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map1));

        let mut map2 = RangeMapBlaze::new();
        map2.ranges_insert(
            80u16..=90u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        let port_lookup2: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map2));

        let intersection = port_lookup1.combine(&port_lookup2);

        let mut map3 = RangeMapBlaze::new();
        map3.ranges_insert(
            54u16..=75u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            100u16..=101u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            80u16..=90u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        let port_lookup3: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map3));

        assert_eq!(port_lookup3, intersection);
    }

    #[test]
    pub fn multival_combine_no_overlap_flipped() {
        // Map 1:           |-----|
        // Map 2: |-----|            |-----|
        let mut map2 = RangeMapBlaze::new();
        map2.ranges_insert(
            54u16..=75u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map2.ranges_insert(
            100u16..=101u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        let port_lookup2: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map2));

        let mut map1 = RangeMapBlaze::new();
        map1.ranges_insert(
            80u16..=90u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        let port_lookup1: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map1));

        let intersection = port_lookup1.combine(&port_lookup2);

        let mut map3 = RangeMapBlaze::new();
        map3.ranges_insert(
            54u16..=75u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            100u16..=101u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            80u16..=90u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        let port_lookup3: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map3));

        assert_eq!(port_lookup3, intersection);
    }

    #[test]
    pub fn multival_combine_no_overlap_flipped_multiple() {
        // Map 1:           |-----|
        // Map 2: |-----|            |-----| |-----|
        let mut map2 = RangeMapBlaze::new();
        map2.ranges_insert(
            54u16..=75u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map2.ranges_insert(
            100u16..=101u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map2.ranges_insert(
            104u16..=107u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        let port_lookup2: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map2));

        let mut map1 = RangeMapBlaze::new();
        map1.ranges_insert(
            80u16..=90u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        let port_lookup1: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map1));

        let intersection = port_lookup1.combine(&port_lookup2);

        let mut map3 = RangeMapBlaze::new();
        map3.ranges_insert(
            54u16..=75u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            100u16..=101u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            104u16..=107u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            80u16..=90u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        let port_lookup3: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map3));

        assert_eq!(port_lookup3, intersection);
    }

    #[test]
    pub fn multival_combine_first_overlap() {
        // Map 1: |-----|            |-----|
        // Map 2:     |-----|
        let mut map1 = RangeMapBlaze::new();
        map1.ranges_insert(
            54u16..=75u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map1.ranges_insert(
            100u16..=101u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        let port_lookup1: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map1));

        let mut map2 = RangeMapBlaze::new();
        map2.ranges_insert(
            60u16..=90u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        let port_lookup2: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map2));

        let intersection = port_lookup1.combine(&port_lookup2);

        let mut map3 = RangeMapBlaze::new();
        map3.ranges_insert(
            54u16..=59u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            60u16..=75u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![
                    Arc::new(ProtoAndId { proto: 2, id: 2 }),
                    Arc::new(ProtoAndId { proto: 1, id: 1 }),
                ]),
            },
        );
        map3.ranges_insert(
            76u16..=90u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        map3.ranges_insert(
            100u16..=101u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        let port_lookup3: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map3));

        assert_eq!(port_lookup3, intersection);
    }

    #[test]
    pub fn multival_combine_second_overlap() {
        // Map 1: |-----|        |-----|          |-----|
        // Map 2:             |-----|      |-----|
        let mut map1 = RangeMapBlaze::new();
        map1.ranges_insert(
            54u16..=75u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map1.ranges_insert(
            95u16..=105u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map1.ranges_insert(
            110u16..=111u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        let port_lookup1: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map1));

        let mut map2 = RangeMapBlaze::new();
        map2.ranges_insert(
            90u16..=100u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        map2.ranges_insert(
            112u16..=113u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        let port_lookup2: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map2));

        let intersection = port_lookup1.combine(&port_lookup2);

        let mut map3 = RangeMapBlaze::new();
        map3.ranges_insert(
            54u16..=75u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            90u16..=94u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        map3.ranges_insert(
            95u16..=100u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![
                    Arc::new(ProtoAndId { proto: 2, id: 2 }),
                    Arc::new(ProtoAndId { proto: 1, id: 1 }),
                ]),
            },
        );
        map3.ranges_insert(
            101u16..=105u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            110u16..=111u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 1, id: 1 })]),
            },
        );
        map3.ranges_insert(
            112u16..=113u16,
            ProtoLookup {
                proto_vec: Arc::new(vec![Arc::new(ProtoAndId { proto: 2, id: 2 })]),
            },
        );
        let port_lookup3: PortLookup<ProtoLookup> = PortLookup::MultiVal(Arc::new(map3));

        assert_eq!(port_lookup3, intersection);
    }
}
