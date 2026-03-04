
use openssl::rand::rand_bytes;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use thiserror::Error;
use ipnet::Ipv6Net;

use zpr_utils::net_defs::IpAddress;


/// Maximum allowed AAA ID value (40 bits)
///
/// Note that since we generate the IDs randomly, we can support about
/// one million active addresses until we get into collision issues from
/// the birthday problem.
/// That should be sufficient for the immediate future.
const MAX_AAA_ID: u64 = 0xffffffffff;


#[derive(Debug, Error)]
pub enum AddressPoolError {
    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid prefix length")]
    InvalidPrefixLength,
}

/// A "pool" of addresses for the ZPR network. Only supports AAA addresses
/// at the moment.  Not thread safe.
///
/// Each new address gets a unique 40-bit ID.
///
pub struct AddressPool {
    ipnet: Ipv6Net,
    active: HashSet<u64>, // Holds 40-bit IDs of active addresses
}

impl AddressPool {
    /// Initialize the pool of AAA addresses.  The visa service hands us
    /// a IP network to use for the AAA addresses.  
    /// 
    /// We expect to get at most a /88.
    pub fn new(aaa_net: Ipv6Net) -> Result<Self, AddressPoolError> {
        if aaa_net.prefix_len() > 88 {
            return Err(AddressPoolError::InvalidPrefixLength);
        }
        return Ok(Self {
            ipnet: aaa_net,
            active: HashSet::new(),
         });
    }

    /// Returns the network used by this pool.
    /// For example, "fd5a:5052::/64".
    ///
    /// The lower 40 its is the AAA ID.
    #[allow(dead_code)]
    pub fn get_prefix(&self) -> String {
        return self.ipnet.to_string();
    }

    /// Returns a random AAA address that is not already in our active set,
    /// before returning it is stored in our active set.
    ///
    /// Caller should "return" the address when done with it by calling
    /// [AddressPool::release_address].
    pub fn get_aaa_address(&mut self) -> IpAddress {

        let base_addr = self.ipnet.addr();

        let mut addr_bytes = [0u16; 8];
        addr_bytes[..6].copy_from_slice(&base_addr.segments()[..6]);

        let mut buf = [0u8; 8];
        rand_bytes(&mut buf).unwrap();
        let mut this_id = u64::from_be_bytes(buf) & MAX_AAA_ID;
        while !self.active.insert(this_id) {
            this_id = (this_id.wrapping_add(1)) % MAX_AAA_ID;
        }

        // We use the bottom 40 bits of the ID as the last 40 bits of the IP address.

        addr_bytes[5] = (addr_bytes[5] & 0xFF00) | ((this_id >> 32) & 0xff) as u16;
        addr_bytes[6] = (this_id >> 16) as u16;
        addr_bytes[7] = (this_id & 0xFFFF) as u16;

        let addr = Ipv6Addr::from(addr_bytes);
        IpAddress::new_from_std_v6(&addr)
    }

    /// Returns the number of active AAA addresses in the pool.
    pub fn len(&self) -> usize {
        self.active.len()
    }

    /// Return an address to the pool (by removing it from the active set).
    /// Returns an error of the address is not an AAA address.
    /// Not an error if address is not in the active set.
    pub fn release_address(&mut self, address: IpAddress) -> Result<(), AddressPoolError> {
        if address.v6[6] != 0x0a || address.v6[7] != 0xaa {
            return Err(AddressPoolError::InvalidAddress);
        }

        // Address looks like:
        // fd5a:5052:0000:0aaa:0000:00xx:xxxx:xxxx
        //                            ^^ ^^^^ ^^^^ <-- This is the AAA ID

        // Extract the 40-bit ID from the address
        let id = u64::from_be_bytes([
            0,
            0,
            0,
            address.v6[11],
            address.v6[12],
            address.v6[13],
            address.v6[14],
            address.v6[15],
        ]);
        let _present = self.active.remove(&id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv6Net;

    const AAA_NET: Ipv6Net =
        Ipv6Net::new_assert(Ipv6Addr::new(0xfd5a, 0x5052, 0, 0x0aaa, 0x1234, 0x5600, 0, 0), 88);

    #[test]
    fn test_basic_get_aaa_address() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();

        // Should be able to get an address without panicking
        let addr = pool.get_aaa_address();

        // Should be IPv6 (not IPv4-mapped)
        assert!(!addr.is_v4());

        // Should have the AAA prefix in bytes 6-7
        assert_eq!(addr.v6[6], 0x0a);
        assert_eq!(addr.v6[7], 0xaa);
    }

    #[test]
    fn test_basic_release_address() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();        

        // Get an address
        let addr = pool.get_aaa_address();
        let initial_active_size = pool.len();

        // Should be able to release it without error
        let result = pool.release_address(addr);
        assert!(result.is_ok());

        // Pool should have gained one address back, active should have lost one
        assert_eq!(pool.len(), initial_active_size - 1);
    }

 
 
    #[test]
    fn test_get_aaa_address_structure() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();                
    

        let addr = pool.get_aaa_address();

        // Check the base prefix (first 8 bytes should match BASE_AAA_ADDRESS)
        assert_eq!(addr.v6[0], 0xfd);
        assert_eq!(addr.v6[1], 0x5a);
        assert_eq!(addr.v6[2], 0x50);
        assert_eq!(addr.v6[3], 0x52);
        assert_eq!(addr.v6[4], 0x00);
        assert_eq!(addr.v6[5], 0x00);
        assert_eq!(addr.v6[6], 0x0a);
        assert_eq!(addr.v6[7], 0xaa);

        // Check that node_id[0] is embedded in the address
        // addr_bytes[4] = self.node_id[0] = 0x1234
        assert_eq!(addr.v6[8], 0x12); // high byte of node_id[0]
        assert_eq!(addr.v6[9], 0x34); // low byte of node_id[0]
    }

    #[test]
    fn test_get_aaa_address_uniqueness() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();                        

        let addr1 = pool.get_aaa_address();
        let addr2 = pool.get_aaa_address();

        // Addresses should be different (no duplicates possible)
        assert_ne!(addr1, addr2);

        // They should have the same prefix and node_id part
        assert_eq!(addr1.v6[..10], addr2.v6[..10]);

        // The ID portion should be different (last 5 bytes contain the ID)
        assert_ne!(addr1.v6[10..], addr2.v6[10..]);
    }

    #[test]
    fn test_no_duplicate_active_addresses() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();                                
        let mut allocated_addresses = std::collections::HashSet::new();

        // Allocate "many" addresses and ensure no duplicates
        for _ in 0..1000 {
            let addr = pool.get_aaa_address();
            assert!(
                !allocated_addresses.contains(&addr),
                "Duplicate address generated"
            );
            allocated_addresses.insert(addr);
        }

        assert_eq!(allocated_addresses.len(), 1000);
        assert_eq!(pool.len(), 1000);
    }

    #[test]
    fn test_release_address_invalid_prefix() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();                                

        // Create an IPv4 address (invalid)
        let invalid_addr = IpAddress::new_from_v4([192, 168, 1, 1]);
        let result = pool.release_address(invalid_addr);

        assert!(matches!(result, Err(AddressPoolError::InvalidAddress)));
    }

    #[test]
    fn test_release_address_invalid_aaa_prefix() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();                                

        // Create an IPv6 address with wrong AAA prefix
        let mut addr_bytes = [0u8; 16];
        addr_bytes[0..8].copy_from_slice(&[0xfd, 0x5a, 0x50, 0x52, 0x00, 0x00, 0x0b, 0xbb]); // Wrong AAA prefix
        let invalid_addr = IpAddress { v6: addr_bytes };

        let result = pool.release_address(invalid_addr);

        assert!(matches!(result, Err(AddressPoolError::InvalidAddress)));
    }

    #[test]
    fn test_release_non_active_address() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();                                

        // Create a valid AAA address that was never allocated by this pool
        let mut addr_bytes = [0u8; 16];
        addr_bytes[0..8].copy_from_slice(&[0xfd, 0x5a, 0x50, 0x52, 0x00, 0x00, 0x0a, 0xaa]);
        addr_bytes[11] = 0x12;
        addr_bytes[12] = 0x34;
        addr_bytes[13] = 0x56;
        addr_bytes[14] = 0x78;
        addr_bytes[15] = 0x9a;

        let non_active_addr = IpAddress { v6: addr_bytes };
        let initial_active_size = pool.len();

        // Should succeed but not change pool sizes (address wasn't active)
        let result = pool.release_address(non_active_addr);
        assert!(result.is_ok());

        assert_eq!(pool.len(), initial_active_size);
    }

    #[test]
    fn test_multiple_releases_same_address() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();                                

        let addr = pool.get_aaa_address();

        // Release the same address multiple times
        pool.release_address(addr).unwrap();
        pool.release_address(addr).unwrap();
        pool.release_address(addr).unwrap();

        // Should only be returned to pool once (no duplicates in pool)
        assert!(!pool.active.contains(&extract_id_from_address(&addr)));
    }

    #[test]
    fn test_address_pool_different_node_ids() {

        let net1 = Ipv6Net::new(Ipv6Addr::new(0xfd5a, 0x5052, 0, 0x0aaa, 0x1111, 0x1100, 0, 0), 88).unwrap();
        let net2 = Ipv6Net::new(Ipv6Addr::new(0xfd5a, 0x5052, 0, 0x0aaa, 0x2222, 0x2200, 0, 0), 88).unwrap();        

        let mut pool1 = AddressPool::new(net1).unwrap();
        let mut pool2 = AddressPool::new(net2).unwrap();

        let addr1 = pool1.get_aaa_address();
        let addr2 = pool2.get_aaa_address();

        // Addresses should be different due to different node IDs
        assert_ne!(addr1, addr2);

        // But they should have the same base prefix
        assert_eq!(addr1.v6[..8], addr2.v6[..8]);

        // Node ID portions should be different
        assert_ne!(addr1.v6[8..10], addr2.v6[8..10]);
    }

    #[test]
    fn test_release_address_with_valid_large_id() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();                                

        // Create an address with an ID that's too large
        let mut addr_bytes = [0u8; 16];
        addr_bytes[0..8].copy_from_slice(&[0xfd, 0x5a, 0x50, 0x52, 0x00, 0x00, 0x0a, 0xaa]);

        // Set all bytes to 0xFF to create an ID of MAX_AAA_ID
        addr_bytes[11] = 0xFF;
        addr_bytes[12] = 0xFF;
        addr_bytes[13] = 0xFF;
        addr_bytes[14] = 0xFF;
        addr_bytes[15] = 0xFF;

        let ret_addr = IpAddress { v6: addr_bytes };
        let _result = pool.release_address(ret_addr).unwrap();
    }

    #[test]
    fn test_mixed_allocation_and_release() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();                                

        // Get some addresses
        let addr1 = pool.get_aaa_address();
        let addr2 = pool.get_aaa_address();

        // Release one
        pool.release_address(addr1).unwrap();

        // Get more addresses
        let addr3 = pool.get_aaa_address();
        let addr4 = pool.get_aaa_address();

        assert_ne!(addr4, addr1);
        assert_ne!(addr4, addr2);
        assert_ne!(addr4, addr3);

        // Verify pool state
        assert_eq!(pool.len(), 3); // addr1 (as addr3), addr2, addr4
    }

    #[test]
    fn test_node_id_encoding_in_address() {
        let mut pool = AddressPool::new(AAA_NET).unwrap();                                

        let addr = pool.get_aaa_address();

        // Extract node_id from the address
        // pool.node_id[0] should be (0xABCDEF >> 8) = 0xABCD
        // pool.node_id[1] should be (0xABCDEF & 0xFF) = 0xEF

        // addr_bytes[4] = self.node_id[0]
        let node_id_part1 = u16::from_be_bytes([addr.v6[8], addr.v6[9]]);
        assert_eq!(node_id_part1, 0xABCD);

        // Check that node_id[1] is used in addr_bytes[5]
        // addr_bytes[5] = (self.node_id[1] << 8) | (this_id >> 32) as u16;
        let addr_byte5 = u16::from_be_bytes([addr.v6[10], addr.v6[11]]);
        let node_id_part2 = (addr_byte5 >> 8) as u8;
        assert_eq!(node_id_part2, 0xEF);
    }

    #[test]
    fn test_get_prefix() {
        let pool = AddressPool::new(AAA_NET).unwrap();                                
        let prefix = pool.get_prefix();
        assert_eq!(prefix, "fd5a:5052:0:aaa:1234:5600::/64");
    }

    // Helper function to extract AAA ID from an address for testing
    fn extract_id_from_address(addr: &IpAddress) -> u64 {
        u64::from_be_bytes([
            0,
            0,
            0,
            addr.v6[11],
            addr.v6[12],
            addr.v6[13],
            addr.v6[14],
            addr.v6[15],
        ])
    }
}
