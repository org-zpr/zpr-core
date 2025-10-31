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

#[derive(Clone)]
pub enum DstPortLevel {
    Wildcard(RangeMapBlaze<u16, Vec<(IpProtocol, VisaId)>>),
    MultiVal(RangeMapBlaze<u16, RangeMapBlaze<u16, Vec<(IpProtocol, VisaId)>>>),
    SingleVal((u16, RangeMapBlaze<u16, Vec<(IpProtocol, VisaId)>>)),
}

// TODO add into DsrPortLevel
// enum SrcPortLevel {
//     Wildcard(Vec<(IpProtocol, VisaId)>),
//     MultiVal(RangeMapBlaze<u16, Vec<(IpProtocol, VisaId)>>),
//     SingleVal((u16, Vec<(IpProtocol, VisaId)>))
// }

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

            // Create map for source ports, add array of protocols
            let mut src_map = RangeMapBlaze::new();
            if five_tuple.src_port == 0 {
                src_map.ranges_insert(0..=65535, arr);
            } else {
                src_map.insert(five_tuple.src_port, arr);
            }

            // Determine which enum to use for dst level
            let dst_level = match five_tuple.dst_port {
                0 => DstPortLevel::Wildcard(src_map),
                val => DstPortLevel::SingleVal((val, src_map)),
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
                            Some(mut removed_dst_ports) => {
                                let in_table_dst_ports = in_table_src_addrs
                                    .exact_match_mut(og_src_addr, og_mask_len)
                                    .unwrap();
                                let new_dst_level =
                                    // TODO typing here is bad, both of these being mut references leads to lots of cloning,
                                    // should be better when everything is in an Arc, becuase cloning wil not be a problem
                                    match (&mut removed_dst_ports, in_table_dst_ports) {
                                        (
                                            DstPortLevel::Wildcard(src_port_level1),
                                            DstPortLevel::Wildcard(src_port_level2),
                                        ) => DstPortLevel::Wildcard(Self::combine_src_levels(
                                            src_port_level1,
                                            src_port_level2,
                                        )),
                                        (
                                            DstPortLevel::Wildcard(src_port_level_wild),
                                            DstPortLevel::SingleVal((
                                                dst_port,
                                                src_port_level_single,
                                            )),
                                        )
                                        | (
                                            DstPortLevel::SingleVal((
                                                dst_port,
                                                src_port_level_single,
                                            )),
                                            DstPortLevel::Wildcard(src_port_level_wild),
                                        ) => {
                                            let mut dst_level = RangeMapBlaze::new();
                                            dst_level.ranges_insert(
                                                0..=65535,
                                                src_port_level_wild.clone(),
                                            );
                                            let intersection = Self::combine_src_levels(
                                                src_port_level_wild,
                                                src_port_level_single,
                                            );
                                            dst_level.insert(*dst_port, intersection);
                                            DstPortLevel::MultiVal(dst_level)
                                        }
                                        (
                                            DstPortLevel::Wildcard(src_port_level),
                                            DstPortLevel::MultiVal(dst_port_level),
                                        )
                                        | (
                                            DstPortLevel::MultiVal(dst_port_level),
                                            DstPortLevel::Wildcard(src_port_level),
                                        ) => {
                                            let mut dst_level = RangeMapBlaze::new();
                                            dst_level
                                                .ranges_insert(0..=65535, src_port_level.clone());
                                            for (port, src_level) in dst_port_level.iter() {
                                                // We know there will be a collision, so we pre-emptively make the intersection and then insert it
                                                let intersection = Self::combine_src_levels(
                                                    src_port_level,
                                                    &mut src_level.clone(),
                                                );
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
                                                    *dst_port1,
                                                    Self::combine_src_levels(
                                                        src_port_level1,
                                                        src_port_level2,
                                                    ),
                                                ))
                                            } else {
                                                let mut dst_level = RangeMapBlaze::new();
                                                dst_level
                                                    .insert(*dst_port1, src_port_level1.clone());
                                                dst_level
                                                    .insert(*dst_port2, src_port_level2.clone());
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
                                            match dst_port_level
                                                .insert(*dst_port, src_port_level.clone())
                                            {
                                                None => (),
                                                Some(mut removed_src_level) => {
                                                    let intersection = Self::combine_src_levels(
                                                        src_port_level,
                                                        &mut removed_src_level,
                                                    );
                                                    dst_port_level.insert(*dst_port, intersection);
                                                }
                                            };
                                            DstPortLevel::MultiVal(dst_port_level.clone())
                                        }
                                        (
                                            DstPortLevel::MultiVal(dst_port_level1),
                                            DstPortLevel::MultiVal(dst_port_level2),
                                        ) => {
                                            for (port, src_level1) in dst_port_level1.iter() {
                                                match dst_port_level2
                                                    .insert(port, src_level1.clone())
                                                {
                                                    None => (),
                                                    Some(mut src_level2) => {
                                                        let intersection = Self::combine_src_levels(
                                                            &mut src_level1.clone(),
                                                            &mut src_level2,
                                                        );
                                                        dst_port_level2.insert(port, intersection);
                                                    }
                                                }
                                            }
                                            DstPortLevel::MultiVal(dst_port_level2.clone())
                                        }
                                    };

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

    fn combine_src_levels(
        src_level_one: &mut RangeMapBlaze<u16, Vec<(IpProtocol, VisaId)>>,
        src_level_two: &mut RangeMapBlaze<u16, Vec<(IpProtocol, VisaId)>>,
    ) -> RangeMapBlaze<u16, Vec<(IpProtocol, VisaId)>> {
        for (new_src_port, new_protocols) in src_level_two.iter() {
            // Try to add a src port, If the src port is already being used as a key, combine its protocol tables
            match src_level_one.insert(new_src_port, new_protocols.clone()) {
                None => (),
                Some(mut proto_arr) => {
                    for new_proto in new_protocols.iter() {
                        let mut exists = false;
                        for old_proto in proto_arr.iter() {
                            if old_proto.0 == new_proto.0 {
                                exists = true
                            }
                        }
                        if !exists {
                            proto_arr.push(*new_proto)
                        }
                    }
                    src_level_one.insert(new_src_port, proto_arr);
                }
            }
        }

        src_level_one.clone()
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
                        DstPortLevel::Wildcard(src_level) => match src_level.get(ft.src_port) {
                            None => None,
                            Some(proto_vec) => {
                                for elem in proto_vec {
                                    if elem.0 == ft.l4_protocol {
                                        return Some(elem.1);
                                    }
                                }
                                return None;
                            }
                        },
                        DstPortLevel::SingleVal((port, src_level)) => match *port == ft.dst_port {
                            false => None,
                            true => match src_level.get(ft.src_port) {
                                None => None,
                                Some(proto_vec) => {
                                    for elem in proto_vec {
                                        if elem.0 == ft.l4_protocol {
                                            return Some(elem.1);
                                        }
                                    }
                                    return None;
                                }
                            },
                        },
                        DstPortLevel::MultiVal(dst_level) => match dst_level.get(ft.dst_port) {
                            None => None,
                            Some(src_port_table) => match src_port_table.get(ft.src_port) {
                                None => None,
                                Some(proto_vec) => {
                                    for elem in proto_vec {
                                        if elem.0 == ft.l4_protocol {
                                            return Some(elem.1);
                                        }
                                    }
                                    return None;
                                }
                            },
                        },
                    },
                };
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::net_defs::ip_number;
    use libnode::vsapi;

    #[test]
    fn test_construction_one_visa() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 11;
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

        let v = Visa::new(visa);

        // let ft = FiveTuple::new(L3Type::Ipv6, IpAddress::from(src_addr), IpAddress::from(dst_addr), ip_number::TCP, src_port as u16, dst_port as u16);
        // assert_eq!(Visa::extract_five_tuple(&v.visa.unwrap()), ft);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

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
        assert_eq!(
            src_port_level.unwrap().get(src_port as u16).unwrap()[0].1,
            12
        );
        assert_eq!(
            src_port_level.unwrap().get(src_port as u16).unwrap()[0].0,
            ip_number::TCP
        );
    }

    #[test]
    fn test_construction_diff_protos() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto1 = vsapi::PEPIndex::TCP;
        let l4proto2 = vsapi::PEPIndex::UDP;
        let src_port = 10;
        let dst_port = 11;
        let src_dst =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port, dst_port, None, None);
        let visa1: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto1,
            src_dst.clone(),
            None,
            None,
            None,
            None,
        );

        let visa2: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto2,
            src_dst,
            None,
            None,
            None,
            None,
        );

        let v1 = Visa::new(visa1);
        let v2 = Visa::new(visa2);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

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

        let proto_vec = src_port_level.unwrap().get(src_port as u16).unwrap();

        assert_eq!(proto_vec.len(), 2);

        let mut tcp_idx = 0;
        let mut udp_idx = 0;

        // protovec is not deterministic in terms of ordering, have to figure out which visa is where
        if proto_vec[0].0 == ip_number::TCP {
            udp_idx = 1;
        } else {
            tcp_idx = 1;
        }

        assert_eq!(proto_vec[tcp_idx].0, ip_number::TCP);
        assert_eq!(proto_vec[tcp_idx].1, 12);
        assert_eq!(proto_vec[udp_idx].0, ip_number::UDP);
        assert_eq!(proto_vec[udp_idx].1, 13);
    }

    #[test]
    fn test_construction_diff_src_ports() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port1 = 10;
        let src_port2 = 14;
        let dst_port = 11;
        let src_dst1 =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port1, dst_port, None, None);
        let src_dst2 =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port2, dst_port, None, None);

        let visa1: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst1,
            None,
            None,
            None,
            None,
        );

        let visa2: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst2,
            None,
            None,
            None,
            None,
        );

        let v1 = Visa::new(visa1);
        let v2 = Visa::new(visa2);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

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

        assert_eq!(
            src_port_level.unwrap().get(src_port1 as u16).unwrap()[0].1,
            12
        );
        assert_eq!(
            src_port_level.unwrap().get(src_port1 as u16).unwrap()[0].0,
            ip_number::TCP
        );
        assert_eq!(
            src_port_level.unwrap().get(src_port2 as u16).unwrap()[0].1,
            13
        );
        assert_eq!(
            src_port_level.unwrap().get(src_port2 as u16).unwrap()[0].0,
            ip_number::TCP
        );
        assert_eq!(
            src_port_level.unwrap().get(src_port2 as u16).unwrap().len(),
            1
        );
        assert_eq!(src_port_level.unwrap().len(), 2);
    }

    #[test]
    fn test_construction_diff_dst_ports() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port1 = 11;
        let dst_port2 = 14;
        let src_dst1 =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port, dst_port1, None, None);
        let src_dst2 =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port, dst_port2, None, None);

        let visa1: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst1,
            None,
            None,
            None,
            None,
        );

        let visa2: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst2,
            None,
            None,
            None,
            None,
        );

        let v1 = Visa::new(visa1);
        let v2 = Visa::new(visa2);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

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

        assert_eq!(
            dst_port_level
                .unwrap()
                .get(dst_port1 as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .1,
            12
        );
        assert_eq!(
            dst_port_level
                .unwrap()
                .get(dst_port1 as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .0,
            ip_number::TCP
        );
        assert_eq!(
            dst_port_level
                .unwrap()
                .get(dst_port2 as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .1,
            13
        );
        assert_eq!(
            dst_port_level
                .unwrap()
                .get(dst_port2 as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .0,
            ip_number::TCP
        );
        assert_eq!(
            dst_port_level
                .unwrap()
                .get(dst_port1 as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            dst_port_level.unwrap().get(dst_port1 as u16).unwrap().len(),
            1
        );
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
        let src_dst =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port, dst_port, None, None);
        let visa1: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr1.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst.clone(),
            None,
            None,
            None,
            None,
        );

        let visa2: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr2.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst,
            None,
            None,
            None,
            None,
        );

        let v1 = Visa::new(visa1);
        let v2 = Visa::new(visa2);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

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

        assert_eq!(
            src_port_level1.unwrap().get(src_port as u16).unwrap()[0].1,
            12
        );
        assert_eq!(
            src_port_level1.unwrap().get(src_port as u16).unwrap()[0].0,
            ip_number::TCP
        );
        assert_eq!(
            src_port_level2.unwrap().get(src_port as u16).unwrap()[0].1,
            13
        );
        assert_eq!(
            src_port_level2.unwrap().get(src_port as u16).unwrap()[0].0,
            ip_number::TCP
        );
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
        let src_dst =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port, dst_port, None, None);

        let visa1: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr1.to_vec(),
            l4proto,
            src_dst.clone(),
            None,
            None,
            None,
            None,
        );

        let visa2: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr2.to_vec(),
            l4proto,
            src_dst,
            None,
            None,
            None,
            None,
        );

        let v1 = Visa::new(visa1);
        let v2 = Visa::new(visa2);

        let mut hash: HashMap<VisaId, Visa> = HashMap::new();
        hash.insert(12, v1);
        hash.insert(13, v2);

        let table = FiveTupleLookupTable::new(&hash);

        let un_rcu_table = table.table.get();

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

        assert_eq!(
            src_port_level1.unwrap().get(src_port as u16).unwrap()[0].1,
            12
        );
        assert_eq!(
            src_port_level1.unwrap().get(src_port as u16).unwrap()[0].0,
            ip_number::TCP
        );
        assert_eq!(
            src_port_level2.unwrap().get(src_port as u16).unwrap()[0].1,
            13
        );
        assert_eq!(
            src_port_level2.unwrap().get(src_port as u16).unwrap()[0].0,
            ip_number::TCP
        );
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

        let v = Visa::new(visa);

        let ft = FiveTuple::new(
            L3Type::Ipv6,
            IpAddress::from(src_addr),
            IpAddress::from(dst_addr),
            ip_number::TCP,
            src_port as u16,
            dst_port as u16,
        );
        // assert_eq!(Visa::extract_five_tuple(&v.visa.unwrap()), ft);

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
        let src_dst =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port, dst_port, None, None);

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
        let src_diff_dst =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port_diff, dst_port, None, None);
        let dst_port_diff = 14;
        let src_dst_diff =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port, dst_port_diff, None, None);
        let src_addr_diff = [3u8; 16];
        let dst_addr_diff = [4u8; 16];

        let visa_diff_proto: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto_diff,
            src_dst.clone(),
            None,
            None,
            None,
            None,
        );
        let v_diff_proto = Visa::new(visa_diff_proto);

        let visa_diff_src_port: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_diff_dst,
            None,
            None,
            None,
            None,
        );
        let v_diff_src_port = Visa::new(visa_diff_src_port);

        let visa_diff_dst_port: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst_diff,
            None,
            None,
            None,
            None,
        );
        let v_diff_dst_port = Visa::new(visa_diff_dst_port);

        let visa_diff_src_addr: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr_diff.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst.clone(),
            None,
            None,
            None,
            None,
        );
        let v_diff_src_addr = Visa::new(visa_diff_src_addr);

        let visa_diff_dst_addr: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr_diff.to_vec(),
            l4proto,
            src_dst.clone(),
            None,
            None,
            None,
            None,
        );
        let v_diff_dst_addr = Visa::new(visa_diff_dst_addr);

        // assert_eq!(Visa::extract_five_tuple(&v.visa.unwrap()), ft);

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

        let v = Visa::new(visa);

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
        let src_dst =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port, dst_port, None, None);

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
        let src_diff_dst =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port_diff, dst_port, None, None);
        let dst_port_diff = 14;
        let src_dst_diff =
            vsapi::PEPArgsTCPUDP::new(Vec::new(), Vec::new(), src_port, dst_port_diff, None, None);
        let src_addr_diff = [3u8; 16];
        let dst_addr_diff = [4u8; 16];

        let visa_diff_proto: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto_diff,
            src_dst.clone(),
            None,
            None,
            None,
            None,
        );
        let v_diff_proto = Visa::new(visa_diff_proto);

        let visa_diff_src_port: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_diff_dst,
            None,
            None,
            None,
            None,
        );
        let v_diff_src_port = Visa::new(visa_diff_src_port);

        let visa_diff_dst_port: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst_diff,
            None,
            None,
            None,
            None,
        );
        let v_diff_dst_port = Visa::new(visa_diff_dst_port);

        let visa_diff_src_addr: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr_diff.to_vec(),
            dst_addr.to_vec(),
            l4proto,
            src_dst.clone(),
            None,
            None,
            None,
            None,
        );
        let v_diff_src_addr = Visa::new(visa_diff_src_addr);

        let visa_diff_dst_addr: vsapi::Visa = vsapi::Visa::new(
            0,
            0,
            0,
            Vec::new(),
            Vec::new(),
            src_addr.to_vec(),
            dst_addr_diff.to_vec(),
            l4proto,
            src_dst.clone(),
            None,
            None,
            None,
            None,
        );
        let v_diff_dst_addr = Visa::new(visa_diff_dst_addr);

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

        let v = Visa::new(visa);

        // let ft = FiveTuple::new(L3Type::Ipv6, IpAddress::from(src_addr), IpAddress::from(dst_addr), ip_number::TCP, src_port as u16, dst_port as u16);
        // assert_eq!(Visa::extract_five_tuple(&v.visa.unwrap()), ft);

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

        assert_eq!(src_port_level.unwrap().len(), 65536);
        assert_eq!(src_port_level.unwrap().get(5411).unwrap().len(), 1);
    }

    #[test]
    fn test_wildcarded_dst_ports() {
        let src_addr = [1u8; 16];
        let dst_addr = [2u8; 16];

        let l4proto = vsapi::PEPIndex::TCP;
        let src_port = 10;
        let dst_port = 0;
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

        let v = Visa::new(visa);

        // let ft = FiveTuple::new(L3Type::Ipv6, IpAddress::from(src_addr), IpAddress::from(dst_addr), ip_number::TCP, src_port as u16, dst_port as u16);
        // assert_eq!(Visa::extract_five_tuple(&v.visa.unwrap()), ft);

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

        assert_eq!(src_port_level.unwrap().len(), 1);
    }
}
