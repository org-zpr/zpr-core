use crate::defs::FiveTuple;
use crate::net_defs::{IpAddress, IpProtocol};
use crate::rcu::RcuBox;
use crate::visa_table::Visa;

use ip_network_table_deps_treebitmap::IpLookupTable;
use range_set_blaze::RangeMapBlaze;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use zpr::{L3Type, VisaId};

// TODO wrap inner structures in Arcs, will make re-creation more efficient
// TODO perhaps change final vec from a vec of tuples to a vec of structs, easier to understand resulting code
pub type FiveTupleLookup = HashMap<IpAddress, IpLookupTable<Ipv6Addr, DstPortLevel>>;

pub struct FiveTupleLookupTable {
    table: RcuBox<FiveTupleLookup>,
}

// TODO could probably combine DstPortLevel and SrcPortLevel with some sort of
// generic variables in place of the specific values inside
#[derive(Clone)]
pub enum DstPortLevel {
    Wildcard(SrcPortLevel),
    MultiVal(RangeMapBlaze<u16, SrcPortLevel>),
    SingleVal((u16, SrcPortLevel)),
}

#[derive(Clone, Eq, PartialEq)]
// Need eq for RangeMapBlaze, and need partialeq for eq - should i explicitly define them myself?
pub enum SrcPortLevel {
    Wildcard(Vec<(IpProtocol, VisaId)>),
    MultiVal(RangeMapBlaze<u16, Vec<(IpProtocol, VisaId)>>),
    SingleVal((u16, Vec<(IpProtocol, VisaId)>)),
}

impl FiveTupleLookupTable {
    // TODO change how construction is done once visas move away from being based on a FiveTuples
    pub fn new(visa_table: &HashMap<VisaId, Visa>) -> Self {
        let mut hash_table: FiveTupleLookup = HashMap::new();
        for (visa_id, visa) in visa_table.iter() {
            let five_tuple = match visa.ftuple {
                Some(ft) => ft,
                None => continue,
            };

            // Create array for protocol
            // 10 elements in the array because there are max 10 ip protocols that the visa could allow
            let mut arr = Vec::new();
            arr.push((five_tuple.l4_protocol, *visa_id));

            // Determine which enum to use for src level
            let src_level = match five_tuple.src_port {
                0 => SrcPortLevel::Wildcard(arr),
                val => SrcPortLevel::SingleVal((val, arr)),
            };

            // Determine which enum to use for dst level
            let dst_level = match five_tuple.dst_port {
                0 => DstPortLevel::Wildcard(src_level),
                val => DstPortLevel::SingleVal((val, src_level)),
            };

            // Create table of src addresses, add map of destination ports
            // NOTE how large do we expect each IpLookupTable to be? I.E. how many src addresses for each dst address, typically?
            let mut ip_table = IpLookupTable::new();
            match five_tuple.l3_type {
                // converting v4 to v6 is temporary until a more elegant solution can be determined, currently fine but a waste of space if using ipv4
                L3Type::Ipv4 => ip_table.insert(
                    Ipv4Addr::try_from(five_tuple.src_address)
                        .unwrap()
                        .to_ipv6_compatible(),
                    128,
                    dst_level,
                ),
                L3Type::Ipv6 => {
                    ip_table.insert(Ipv6Addr::from(five_tuple.src_address), 128, dst_level)
                }
                _ => None,
            };

            // TODO This is quite inefficient, improve
            // Try to add to hash table, if there is a collision, combine the tables, then add the combined table
            match hash_table.insert(five_tuple.dst_address, ip_table) {
                None => (),
                Some(removed_src_addrs) => {
                    let in_table_src_addrs = hash_table.get_mut(&five_tuple.dst_address).unwrap();
                    for (og_src_addr, og_mask_len, og_dst_ports) in removed_src_addrs.iter() {
                        // Try to add a source addresses, If the src address is already being used as a key, combine its dst port tables
                        match in_table_src_addrs.insert(
                            og_src_addr,
                            og_mask_len,
                            og_dst_ports.clone(),
                        ) {
                            None => (),
                            Some(removed_dst_ports) => {
                                let in_table_dst_ports = in_table_src_addrs
                                    .exact_match(og_src_addr, og_mask_len)
                                    .unwrap();
                                let new_dst_level = Self::combine_dst_levels(
                                    removed_dst_ports,
                                    in_table_dst_ports.clone(),
                                );
                                in_table_src_addrs.insert(og_src_addr, og_mask_len, new_dst_level);
                            }
                        }
                    }
                }
            }
        }
        Self {
            table: RcuBox::new(hash_table),
        }
    }

    // TODO combine_dst_levels and combine_src_levels are essentially the same except which function they call to combine
    // the levels, if we generalize enums with generic variables, we could combine them and pass the function in at the func call
    fn combine_dst_levels(
        dst_level_one: DstPortLevel,
        dst_level_two: DstPortLevel,
    ) -> DstPortLevel {
        match (dst_level_one, dst_level_two.clone()) {
            (DstPortLevel::Wildcard(src_port_level1), DstPortLevel::Wildcard(src_port_level2)) => {
                DstPortLevel::Wildcard(Self::combine_src_levels(src_port_level1, src_port_level2))
            }
            (
                DstPortLevel::Wildcard(src_port_level_wild),
                DstPortLevel::SingleVal((dst_port, src_port_level_single)),
            )
            | (
                DstPortLevel::SingleVal((dst_port, src_port_level_single)),
                DstPortLevel::Wildcard(src_port_level_wild),
            ) => {
                let mut dst_level = RangeMapBlaze::new();
                dst_level.ranges_insert(0..=65535, src_port_level_wild.clone());
                let intersection =
                    Self::combine_src_levels(src_port_level_wild, src_port_level_single);
                dst_level.insert(dst_port, intersection);
                DstPortLevel::MultiVal(dst_level)
            }
            (DstPortLevel::Wildcard(src_port_level), DstPortLevel::MultiVal(dst_port_level))
            | (DstPortLevel::MultiVal(dst_port_level), DstPortLevel::Wildcard(src_port_level)) => {
                let mut dst_level = RangeMapBlaze::new();
                dst_level.ranges_insert(0..=65535, src_port_level.clone());
                for (port, src_level) in dst_port_level.iter() {
                    // We know there will be a collision, so we pre-emptively make the intersection and then insert it
                    let intersection =
                        Self::combine_src_levels(src_port_level.clone(), src_level.clone());
                    dst_level.insert(port, intersection);
                }
                DstPortLevel::MultiVal(dst_level)
            }
            (
                DstPortLevel::SingleVal((dst_port1, src_port_level1)),
                DstPortLevel::SingleVal((dst_port2, src_port_level2)),
            ) => {
                if dst_port1 == dst_port2 {
                    DstPortLevel::SingleVal((
                        dst_port1,
                        Self::combine_src_levels(src_port_level1, src_port_level2),
                    ))
                } else {
                    let mut dst_level = RangeMapBlaze::new();
                    dst_level.insert(dst_port1, src_port_level1);
                    dst_level.insert(dst_port2, src_port_level2);
                    DstPortLevel::MultiVal(dst_level)
                }
            }
            (
                DstPortLevel::SingleVal((dst_port, src_port_level)),
                DstPortLevel::MultiVal(dst_port_level),
            )
            | (
                DstPortLevel::MultiVal(dst_port_level),
                DstPortLevel::SingleVal((dst_port, src_port_level)),
            ) => {
                let mut dst_level = dst_port_level.clone();
                match dst_level.insert(dst_port, src_port_level.clone()) {
                    None => (),
                    Some(removed_src_level) => {
                        let intersection =
                            Self::combine_src_levels(src_port_level, removed_src_level);
                        dst_level.insert(dst_port, intersection);
                    }
                };
                DstPortLevel::MultiVal(dst_level)
            }
            (DstPortLevel::MultiVal(dst_port_level1), DstPortLevel::MultiVal(dst_port_level2)) => {
                let mut dst_level = dst_port_level1.clone();
                for (port, src_level2) in dst_port_level2.iter() {
                    match dst_level.insert(port, src_level2.clone()) {
                        None => (),
                        Some(src_level1) => {
                            let intersection =
                                Self::combine_src_levels(src_level1, src_level2.clone());
                            dst_level.insert(port, intersection);
                        }
                    }
                }
                DstPortLevel::MultiVal(dst_level)
            }
        }
    }

    fn combine_src_levels(
        src_level_one: SrcPortLevel,
        src_level_two: SrcPortLevel,
    ) -> SrcPortLevel {
        match (src_level_one, src_level_two) {
            (SrcPortLevel::Wildcard(proto_vec1), SrcPortLevel::Wildcard(proto_vec2)) => {
                SrcPortLevel::Wildcard(Self::combine_protos(proto_vec1, proto_vec2))
            }
            (
                SrcPortLevel::Wildcard(proto_vec_wild),
                SrcPortLevel::SingleVal((port, proto_vec_single)),
            )
            | (
                SrcPortLevel::SingleVal((port, proto_vec_single)),
                SrcPortLevel::Wildcard(proto_vec_wild),
            ) => {
                let mut src_level = RangeMapBlaze::new();
                src_level.ranges_insert(0..=65535, proto_vec_wild.clone());
                let intersection = Self::combine_protos(proto_vec_single, proto_vec_wild);
                src_level.insert(port, intersection);
                SrcPortLevel::MultiVal(src_level)
            }
            (SrcPortLevel::Wildcard(proto_vec), SrcPortLevel::MultiVal(src_ports))
            | (SrcPortLevel::MultiVal(src_ports), SrcPortLevel::Wildcard(proto_vec)) => {
                let mut src_level = RangeMapBlaze::new();
                src_level.ranges_insert(0..=65535, proto_vec.clone());
                for (port, protos) in src_ports.iter() {
                    let intersection = Self::combine_protos(proto_vec.clone(), protos.clone());
                    src_level.insert(port, intersection);
                }
                SrcPortLevel::MultiVal(src_level)
            }
            (
                SrcPortLevel::SingleVal((port1, proto_vec1)),
                SrcPortLevel::SingleVal((port2, proto_vec2)),
            ) => {
                if port1 == port2 {
                    let intersection = Self::combine_protos(proto_vec1, proto_vec2);
                    SrcPortLevel::SingleVal((port1, intersection))
                } else {
                    let mut src_level = RangeMapBlaze::new();
                    src_level.insert(port1, proto_vec1);
                    src_level.insert(port2, proto_vec2);
                    SrcPortLevel::MultiVal(src_level)
                }
            }
            (SrcPortLevel::SingleVal((port, proto_vec)), SrcPortLevel::MultiVal(src_ports))
            | (SrcPortLevel::MultiVal(src_ports), SrcPortLevel::SingleVal((port, proto_vec))) => {
                let mut src_level = src_ports.clone();
                match src_level.insert(port, proto_vec.clone()) {
                    None => (),
                    Some(protos) => {
                        let intersection = Self::combine_protos(proto_vec, protos);
                        src_level.insert(port, intersection);
                    }
                }
                SrcPortLevel::MultiVal(src_level)
            }
            (SrcPortLevel::MultiVal(src_ports1), SrcPortLevel::MultiVal(src_ports2)) => {
                let mut src_level = src_ports1.clone();
                for (port, protos2) in src_ports2.iter() {
                    match src_level.insert(port, protos2.clone()) {
                        None => (),
                        Some(protos1) => {
                            let intersection = Self::combine_protos(protos1, protos2.clone());
                            src_level.insert(port, intersection);
                        }
                    }
                }
                SrcPortLevel::MultiVal(src_level)
            }
        }
    }

    fn combine_protos(
        proto_vec_one: Vec<(IpProtocol, VisaId)>,
        proto_vec_two: Vec<(IpProtocol, VisaId)>,
    ) -> Vec<(IpProtocol, VisaId)> {
        let mut intersection = proto_vec_two.clone();

        for proto_one in proto_vec_one.iter() {
            let mut exists = false;
            for proto_two in intersection.iter() {
                if proto_one.0 == proto_two.0 {
                    exists = true
                }
            }
            if !exists {
                intersection.push(*proto_one)
            }
        }

        intersection
    }

    pub fn find_match(&self, ft: FiveTuple) -> Option<VisaId> {
        // NOTE I didn't make a subfunction for finding the match for the src_level, even though it is essentially repeated three times
        // becuase I know this func is all about speed and sometimes passing to another function can cause minor slowdown, not sure
        // how the rust compiler handles such things or if it is significiant enough to matter, if not I will make a helper func
        match self.table.get().get(&ft.dst_address) {
            None => return None,
            Some(src_addr_table) => {
                return match src_addr_table.longest_match(Ipv6Addr::from(ft.src_address)) {
                    None => None,
                    Some(dst_port_table) => match dst_port_table.2 {
                        DstPortLevel::Wildcard(src_level) => {
                            Self::find_src_level_match(src_level.clone(), ft)
                        }
                        DstPortLevel::SingleVal((port, src_level)) => match *port == ft.dst_port {
                            false => None,
                            true => Self::find_src_level_match(src_level.clone(), ft),
                        },
                        DstPortLevel::MultiVal(dst_level) => match dst_level.get(ft.dst_port) {
                            None => None,
                            Some(src_level) => Self::find_src_level_match(src_level.clone(), ft),
                        },
                    },
                };
            }
        };
    }

    fn find_src_level_match(src_level: SrcPortLevel, ft: FiveTuple) -> Option<VisaId> {
        match src_level {
            SrcPortLevel::Wildcard(protos) => {
                for elem in protos {
                    if elem.0 == ft.l4_protocol {
                        return Some(elem.1);
                    }
                }
                return None;
            }
            SrcPortLevel::SingleVal((port, protos)) => match port == ft.src_port {
                false => None,
                true => {
                    for elem in protos {
                        if elem.0 == ft.l4_protocol {
                            return Some(elem.1);
                        }
                    }
                    return None;
                }
            },
            SrcPortLevel::MultiVal(src_level_map) => match src_level_map.get(ft.src_port) {
                None => None,
                Some(protos) => {
                    for elem in protos {
                        if elem.0 == ft.l4_protocol {
                            return Some(elem.1);
                        }
                    }
                    return None;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::net_defs::ip_number;
    use libnode::vsapi;

    fn make_visa(
        src_addr: [u8; 16],
        dst_addr: [u8; 16],
        l4proto: vsapi::PEPIndex,
        src_port: i32,
        dst_port: i32,
    ) -> Visa {
        let src_dst =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port, dst_port, None, None);
        let visa: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst,
            None,
            None,
            None,
            None,
        );

        Visa::new(visa)
    }

    #[test]
    fn test_construction_one_visa() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let v = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from from dst port level enum
        let src_port_level;
        if let DstPortLevel::SingleVal((dst, src_level)) = un_rcu_table
            .get(&IpAddress::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            assert_eq!(*dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get proto level from src port level enum
        let proto_level;
        if let SrcPortLevel::SingleVal((src, protos)) = src_port_level.unwrap() {
            assert_eq!(*src, src_port as u16);
            proto_level = Some(protos)
        } else {
            proto_level = None
        }
        assert!(proto_level.is_some());

        assert_eq!(proto_level.unwrap()[0].1, 12);
        assert_eq!(proto_level.unwrap()[0].0, ip_number::TCP);
    }

    #[test]
    fn test_construction_diff_protos() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto1 = vsapi::PEPIndex::TCP;
        let l4proto2 = vsapi::PEPIndex::UDP;
        let src_port = 10;
        let dst_port = 11;

        let v1 = make_visa(src_addr, dst_addr, l4proto1, src_port, dst_port);
        let v2 = make_visa(src_addr, dst_addr, l4proto2, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level;
        if let DstPortLevel::SingleVal((dst, src_level)) = un_rcu_table
            .get(&IpAddress::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            assert_eq!(*dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get proto level from src port level enum
        let proto_level;
        if let SrcPortLevel::SingleVal((src, protos)) = src_port_level.unwrap() {
            assert_eq!(*src, src_port as u16);
            proto_level = Some(protos)
        } else {
            proto_level = None
        }
        assert!(proto_level.is_some());

        assert_eq!(proto_level.unwrap().len(), 2);

        let mut tcp_idx = 0;
        let mut udp_idx = 0;

        // protovec is not deterministic in terms of ordering, have to figure out which visa is where
        if proto_level.unwrap()[0].0 == ip_number::TCP {
            udp_idx = 1;
        } else {
            tcp_idx = 1;
        }

        assert_eq!(proto_level.unwrap()[tcp_idx].0, ip_number::TCP);
        assert_eq!(proto_level.unwrap()[tcp_idx].1, 12);
        assert_eq!(proto_level.unwrap()[udp_idx].0, ip_number::UDP);
        assert_eq!(proto_level.unwrap()[udp_idx].1, 13);
    }

    #[test]
    fn test_construction_diff_src_ports() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port1 = 10;
        let src_port2 = 14;
        let dst_port = 11;

        let v1 = make_visa(src_addr, dst_addr, l4proto, src_port1, dst_port);
        let v2 = make_visa(src_addr, dst_addr, l4proto, src_port2, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level;
        if let DstPortLevel::SingleVal((dst, src_level)) = un_rcu_table
            .get(&IpAddress::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            assert_eq!(*dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get src port map from src port level enum
        let src_ports;
        if let SrcPortLevel::MultiVal(src_level) = src_port_level.unwrap() {
            src_ports = Some(src_level)
        } else {
            src_ports = None
        }
        assert!(src_ports.is_some());

        assert_eq!(src_ports.unwrap().get(src_port1 as u16).unwrap()[0].1, 12);
        assert_eq!(
            src_ports.unwrap().get(src_port1 as u16).unwrap()[0].0,
            ip_number::TCP
        );
        assert_eq!(src_ports.unwrap().get(src_port2 as u16).unwrap()[0].1, 13);
        assert_eq!(
            src_ports.unwrap().get(src_port2 as u16).unwrap()[0].0,
            ip_number::TCP
        );
        assert_eq!(src_ports.unwrap().get(src_port2 as u16).unwrap().len(), 1);
        assert_eq!(src_ports.unwrap().len(), 2);
    }

    #[test]
    fn test_construction_diff_dst_ports() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port1 = 11;
        let dst_port2 = 14;

        let v1 = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port1);
        let v2 = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port2);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

        // Get dst port map from dst port level enum
        let dst_port_level;
        if let DstPortLevel::MultiVal(dst_level) = un_rcu_table
            .get(&IpAddress::from(dst_addr))
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
        if let SrcPortLevel::SingleVal((src, src_level)) =
            dst_port_level.unwrap().get(dst_port1 as u16).unwrap()
        {
            assert_eq!(*src, src_port as u16);
            proto_level1 = Some(src_level)
        } else {
            proto_level1 = None
        }
        assert!(proto_level1.is_some());

        let proto_level2;
        if let SrcPortLevel::SingleVal((src, src_level)) =
            dst_port_level.unwrap().get(dst_port2 as u16).unwrap()
        {
            assert_eq!(*src, src_port as u16);
            proto_level2 = Some(src_level)
        } else {
            proto_level2 = None
        }
        assert!(proto_level2.is_some());

        assert_eq!(proto_level1.unwrap()[0].1, 12);
        assert_eq!(proto_level1.unwrap()[0].0, ip_number::TCP);
        assert_eq!(proto_level2.unwrap()[0].1, 13);
        assert_eq!(proto_level2.unwrap()[0].0, ip_number::TCP);
        assert_eq!(proto_level1.unwrap().len(), 1);
        assert_eq!(proto_level2.unwrap().len(), 1);
        assert_eq!(dst_port_level.unwrap().len(), 2);
        assert_eq!(
            un_rcu_table.get(&IpAddress::from(dst_addr)).unwrap().len(),
            1
        );
        assert_eq!(un_rcu_table.len(), 1);
    }

    #[test]
    fn test_construction_diff_src_addrs() {
        let src_addr1 = [1u8; 16];
        let src_addr2 = [3u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let v1 = make_visa(src_addr1, dst_addr, l4proto, src_port, dst_port);
        let v2 = make_visa(src_addr2, dst_addr, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

        // Get src port levels enum from dst port level enum
        let src_port_level1;
        if let DstPortLevel::SingleVal((dst, src_level)) = un_rcu_table
            .get(&IpAddress::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            assert_eq!(*dst, dst_port as u16);
            src_port_level1 = Some(src_level)
        } else {
            src_port_level1 = None
        }
        assert!(src_port_level1.is_some());

        let src_port_level2;
        if let DstPortLevel::SingleVal((dst, src_level)) = un_rcu_table
            .get(&IpAddress::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303,
                ),
                128,
            )
            .unwrap()
        {
            assert_eq!(*dst, dst_port as u16);
            src_port_level2 = Some(src_level)
        } else {
            src_port_level2 = None
        }
        assert!(src_port_level2.is_some());

        // Get proto levels from src port level enums
        let proto_level1;
        if let SrcPortLevel::SingleVal((src, protos)) = src_port_level1.unwrap() {
            assert_eq!(*src, src_port as u16);
            proto_level1 = Some(protos)
        } else {
            proto_level1 = None
        }
        assert!(proto_level1.is_some());

        let proto_level2;
        if let SrcPortLevel::SingleVal((src, protos)) = src_port_level2.unwrap() {
            assert_eq!(*src, src_port as u16);
            proto_level2 = Some(protos)
        } else {
            proto_level2 = None
        }
        assert!(proto_level2.is_some());

        assert_eq!(proto_level1.unwrap()[0].1, 12);
        assert_eq!(proto_level1.unwrap()[0].0, ip_number::TCP);
        assert_eq!(proto_level2.unwrap()[0].1, 13);
        assert_eq!(proto_level2.unwrap()[0].0, ip_number::TCP);
        assert_eq!(
            un_rcu_table.get(&IpAddress::from(dst_addr)).unwrap().len(),
            2
        );
    }

    #[test]
    fn test_construction_diff_dst_addrs() {
        let src_addr = [1u8; 16];
        let dst_addr1 = [2u8; 16];
        let dst_addr2 = [3u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let v1 = make_visa(src_addr, dst_addr1, l4proto, src_port, dst_port);
        let v2 = make_visa(src_addr, dst_addr2, l4proto, src_port, dst_port);
        let mut hash: HashMap<VisaId, Visa> = HashMap::new();

        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level1;
        if let DstPortLevel::SingleVal((dst, src_level)) = un_rcu_table
            .get(&IpAddress::from(dst_addr1))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            assert_eq!(*dst, dst_port as u16);
            src_port_level1 = Some(src_level)
        } else {
            src_port_level1 = None
        }
        assert!(src_port_level1.is_some());

        let src_port_level2;
        if let DstPortLevel::SingleVal((dst, src_level)) = un_rcu_table
            .get(&IpAddress::from(dst_addr2))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            assert_eq!(*dst, dst_port as u16);
            src_port_level2 = Some(src_level)
        } else {
            src_port_level2 = None
        }
        assert!(src_port_level2.is_some());

        // Get proto levels from src port level enums
        let proto_level1;
        if let SrcPortLevel::SingleVal((src, protos)) = src_port_level1.unwrap() {
            assert_eq!(*src, src_port as u16);
            proto_level1 = Some(protos)
        } else {
            proto_level1 = None
        }
        assert!(proto_level1.is_some());

        let proto_level2;
        if let SrcPortLevel::SingleVal((src, protos)) = src_port_level2.unwrap() {
            assert_eq!(*src, src_port as u16);
            proto_level2 = Some(protos)
        } else {
            proto_level2 = None
        }
        assert!(proto_level2.is_some());

        assert_eq!(proto_level1.unwrap()[0].1, 12);
        assert_eq!(proto_level1.unwrap()[0].0, ip_number::TCP);
        assert_eq!(proto_level2.unwrap()[0].1, 13);
        assert_eq!(proto_level2.unwrap()[0].0, ip_number::TCP);
        assert_eq!(un_rcu_table.len(), 2);
        assert_eq!(
            un_rcu_table.get(&IpAddress::from(dst_addr2)).unwrap().len(),
            1
        );
    }

    #[test]
    fn test_exact_match_visa() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let v = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port);

        let ft = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v);

        let table = FiveTupleLookupTable::new(&hash);

        assert_eq!(table.find_match(ft), Some(12))
    }

    #[test]
    fn test_no_visa_match_multiple_visas() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let ft = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );

        let l4proto_diff = vsapi::PEPIndex::UDP;
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

        let table = FiveTupleLookupTable::new(&hash);

        assert_eq!(table.find_match(ft), None);
    }

    #[test]
    fn test_no_visa_match_multiple_fts() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let v = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(15, v);
        let table = FiveTupleLookupTable::new(&hash);

        let src_port_diff = 13;
        let dst_port_diff = 14;
        let src_addr_diff = [3u8; 16];
        let dst_addr_diff = [4u8; 16];

        let ft_diff_proto = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::UDP,
            src_port as u16,
            dst_port as u16,
        );
        let ft_diff_src_port = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port_diff as u16,
            dst_port as u16,
        );
        let ft_diff_dst_port = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            dst_port_diff as u16,
        );
        let ft_diff_src_addr = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr_diff),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );
        let ft_diff_dst_addr = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr_diff),
            ip_number::TCP,
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

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;

        let ft = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );

        let l4proto_diff = vsapi::PEPIndex::UDP;
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

        let table = FiveTupleLookupTable::new(&hash);

        let ft_diff_proto = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::UDP,
            src_port as u16,
            dst_port as u16,
        );
        let ft_diff_src_port = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port_diff as u16,
            dst_port as u16,
        );
        let ft_diff_dst_port = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            dst_port_diff as u16,
        );
        let ft_diff_src_addr = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr_diff),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );
        let ft_diff_dst_addr = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr_diff),
            ip_number::TCP,
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

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 0;
        let dst_port = 11;

        let v = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v);

        let table = FiveTupleLookupTable::new(&hash);

        let ft1 = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            3423,
            dst_port as u16,
        );
        let ft2 = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            1,
            dst_port as u16,
        );
        let ft3 = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            65535,
            dst_port as u16,
        );
        let ft4 = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
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
        if let DstPortLevel::SingleVal((dst, src_level)) = un_rcu_table
            .get(&IpAddress::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            assert_eq!(*dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get proto level from src port level enum
        let proto_level;
        if let SrcPortLevel::Wildcard(protos) = src_port_level.unwrap() {
            proto_level = Some(protos)
        } else {
            proto_level = None
        }
        assert!(proto_level.is_some());

        assert_eq!(proto_level.unwrap().len(), 1);
    }

    #[test]
    fn test_wildcarded_dst_ports() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 0;

        let v = make_visa(src_addr, dst_addr, l4proto, src_port, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v);

        let table = FiveTupleLookupTable::new(&hash);

        let ft1 = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            3423,
        );
        let ft2 = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            1,
        );
        let ft3 = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            65535,
        );
        let ft4 = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
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
        if let DstPortLevel::Wildcard(src_level) = un_rcu_table
            .get(&IpAddress::from(dst_addr))
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

        assert_eq!(
            un_rcu_table.get(&IpAddress::from(dst_addr)).unwrap().len(),
            1
        );

        // Get proto level from src port level enum
        let proto_level;
        if let SrcPortLevel::SingleVal((src, protos)) = src_port_level.unwrap() {
            assert_eq!(*src, src_port as u16);
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

        let l4proto1 = vsapi::PEPIndex::UDP;
        let l4proto2 = vsapi::PEPIndex::TCP;
        let src_port_specified = 10;
        let src_port_wild = 0;
        let dst_port = 11;

        let v1 = make_visa(src_addr, dst_addr, l4proto1, src_port_specified, dst_port);
        let v2 = make_visa(src_addr, dst_addr, l4proto2, src_port_wild, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level;
        if let DstPortLevel::SingleVal((dst, src_level)) = un_rcu_table
            .get(&IpAddress::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            assert_eq!(*dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get src port level map from src port level enum
        let src_level;
        if let SrcPortLevel::MultiVal(src_map) = src_port_level.unwrap() {
            src_level = Some(src_map)
        } else {
            src_level = None
        }
        assert!(src_level.is_some());

        assert_eq!(src_level.unwrap().len(), 65536);

        let specified_src_ft = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::UDP,
            src_port_specified as u16,
            dst_port as u16,
        );
        let random_src_ft = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
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

        let l4proto1 = vsapi::PEPIndex::UDP;
        let l4proto2 = vsapi::PEPIndex::TCP;
        let src_port_specified = 10;
        let src_port_wild = 0;
        let dst_port = 11;

        let v1 = make_visa(src_addr, dst_addr, l4proto1, src_port_specified, dst_port);
        let v2 = make_visa(src_addr, dst_addr, l4proto2, src_port_wild, dst_port);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(13, v2);
        hash.insert(12, v1);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

        // Get src port level enum from dst port level enum
        let src_port_level;
        if let DstPortLevel::SingleVal((dst, src_level)) = un_rcu_table
            .get(&IpAddress::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
        {
            assert_eq!(*dst, dst_port as u16);
            src_port_level = Some(src_level)
        } else {
            src_port_level = None
        }
        assert!(src_port_level.is_some());

        // Get src port level map from src port level ennum
        let src_level;
        if let SrcPortLevel::MultiVal(src_map) = src_port_level.unwrap() {
            src_level = Some(src_map)
        } else {
            src_level = None
        }
        assert!(src_level.is_some());

        assert_eq!(src_level.unwrap().len(), 65536);

        let specified_src_ft = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::UDP,
            src_port_specified as u16,
            dst_port as u16,
        );
        let random_src_ft = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            4323u16,
            dst_port as u16,
        );

        assert_eq!(table.find_match(specified_src_ft), Some(12));
        assert_eq!(table.find_match(random_src_ft), Some(13));
    }
}
