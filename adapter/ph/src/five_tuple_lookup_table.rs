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
pub type FiveTupleLookup = HashMap<
    IpAddress,
    IpLookupTable<Ipv6Addr, RangeMapBlaze<u16, RangeMapBlaze<u16, Vec<(IpProtocol, VisaId)>>>>,
>;

pub struct FiveTupleLookupTable {
    table: RcuBox<FiveTupleLookup>,
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

            // Create map for source ports, add array of protocols
            let mut src_map = RangeMapBlaze::new();
            if five_tuple.src_port == 0 {
                src_map.ranges_insert(0..=65535, arr);
            } else {
                src_map.insert(five_tuple.src_port, arr);
            }

            // Create map for dst ports, add map of source ports
            let mut dst_map = RangeMapBlaze::new();
            if five_tuple.dst_port == 0 {
                dst_map.ranges_insert(0..=65535, src_map);
            } else {
                dst_map.insert(five_tuple.dst_port, src_map);
            }

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
                    dst_map,
                ),
                L3Type::Ipv6 => {
                    ip_table.insert(Ipv6Addr::from(five_tuple.src_address), 128, dst_map)
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
                                    .exact_match_mut(og_src_addr, og_mask_len)
                                    .unwrap();
                                // could probably have more efficiency here if we take advantage of some of the other iterators that RangeMapBlaze provides,
                                // perhaps try initially to iterate over the ranges
                                for (og_dst_port, og_src_ports) in removed_dst_ports.iter() {
                                    // Try to add a dst port, If the dst port is already being used as a key, combine its src port tables
                                    match in_table_dst_ports
                                        .insert(og_dst_port, og_src_ports.clone())
                                    {
                                        None => (),
                                        Some(mut removed_src_ports) => {
                                            let in_table_src_ports =
                                                in_table_dst_ports.get(og_dst_port).unwrap();
                                            // have to change the way we have been inserting because RangeMapBlaze does not have a get_mut function
                                            for (new_src_port, new_protocols) in
                                                in_table_src_ports.iter()
                                            {
                                                // Try to add a src port, If the src port is already being used as a key, combine its protocol tables
                                                match removed_src_ports
                                                    .insert(new_src_port, new_protocols.clone())
                                                {
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
                                                        removed_src_ports
                                                            .insert(new_src_port, proto_arr);
                                                    }
                                                }
                                            }
                                            // original_src_ports now contains the values from original_src_ports and new_src_ports
                                            // we don't care about the return value because we know it will be Some(new_src_ports)
                                            in_table_dst_ports
                                                .insert(og_dst_port, removed_src_ports.clone());
                                        }
                                    }
                                }
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

    pub fn find_match(&self, ft: FiveTuple) -> Option<VisaId> {
        match self.table.get().get(&ft.dst_address) {
            None => return None,
            Some(src_addr_table) => {
                return match src_addr_table.longest_match(Ipv6Addr::from(ft.src_address)) {
                    None => None,
                    Some(dst_port_table) => match dst_port_table.2.get(ft.dst_port) {
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

        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .1,
            12
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .0,
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

        let proto_vec = un_rcu_table
            .get(&IpAddress::from(dst_addr))
            .unwrap()
            .exact_match(
                Ipv6Addr::new(
                    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
                ),
                128,
            )
            .unwrap()
            .get(dst_port as u16)
            .unwrap()
            .get(src_port as u16)
            .unwrap();

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

        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port1 as u16)
                .unwrap()[0]
                .1,
            12
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port1 as u16)
                .unwrap()[0]
                .0,
            ip_number::TCP
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port2 as u16)
                .unwrap()[0]
                .1,
            13
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port2 as u16)
                .unwrap()[0]
                .0,
            ip_number::TCP
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port2 as u16)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .len(),
            1
        );
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

        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port1 as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .1,
            12
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port1 as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .0,
            ip_number::TCP
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port2 as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .1,
            13
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port2 as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .0,
            ip_number::TCP
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port1 as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port1 as u16)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .len(),
            2
        );
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

        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .1,
            12
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .0,
            ip_number::TCP
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .1,
            13
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303, 0x0303),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .0,
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

        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr1))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .1,
            12
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr1))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .0,
            ip_number::TCP
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr2))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .1,
            13
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr2))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(src_port as u16)
                .unwrap()[0]
                .0,
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
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .len(),
            65536
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(dst_port as u16)
                .unwrap()
                .get(5411)
                .unwrap()
                .len(),
            1
        );
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
        assert_eq!(
            un_rcu_table.get(&IpAddress::from(dst_addr)).unwrap().len(),
            1
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .len(),
            65536
        );
        assert_eq!(
            un_rcu_table
                .get(&IpAddress::from(dst_addr))
                .unwrap()
                .exact_match(
                    Ipv6Addr::new(0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101),
                    128
                )
                .unwrap()
                .get(4321)
                .unwrap()
                .len(),
            1
        );
    }
}
