use std::collections::VecDeque;
use openssl::rand::rand_bytes;
use std::sync;
use std::net::Ipv6Addr;
use thiserror::Error;

use crate::net_defs::IpAddress;

/// Maximum allowed AAA ID value (40 bits)
const MAX_AAA_ID: u64 = 0xffffffffff;

/// Maximum allowed node ID value (24 bits)
const MAX_NODE_ID: u32 = 0xffffff;

/// The base AAA address. This just has the constant 8 byte prefix.
/// This will be followed by the node ID and then the AAA ID.
const BASE_AAA_ADDRESS: [u16; 8] = [
    0xfd5a, 0x5052, 0x0000, 0x0aaa,
    0x0000, 0x0000, 0x0000, 0x0000,
];

#[derive(Debug, Error)]
pub enum AddressPoolError {
    #[error("invalid address")]
    InvalidAddress,
}


/// A pool of addresses for the ZPR network. Only supports AAA addresses
/// at the moment.  Not thread safe.
pub struct AddressPool {
    node_id: [u16; 2],
    first_aaa_id: u64,
    next_aaa_id: u64,
    returns: VecDeque<u64>, // FIFO
}


impl AddressPool {
    /// `node_id` is the lower 24 bits of the passed value. If the value is larger
    /// than 24 bits it will be truncated.
    pub fn new(node_id: u32) -> Self {
        let mut initial = [0u8; 8];
        rand_bytes(&mut initial).unwrap();
        let first_aaa_id = u64::from_be_bytes(initial) & MAX_AAA_ID;
        AddressPool {
            node_id: [(node_id >> 16) as u16, (node_id & 0xFF) as u16],
            first_aaa_id,
            next_aaa_id: first_aaa_id,
            returns: VecDeque::new(),
        }
    }

    /// Get an available AAA address.
    ///
    /// If a previosly allocated address is available, it will be reused.
    /// Otherwise, a new address will be allocated.
    ///
    /// ## Panics
    ///   - If the pool runs out of addresses, this function will panic.
    pub fn get_aaa_address(&mut self) -> IpAddress {
        let mut addr_bytes = [0u16; 8];
        addr_bytes.copy_from_slice(&BASE_AAA_ADDRESS[..4]);
        addr_bytes[4] = self.node_id[0];

        let this_id = if self.returns.is_empty() {
            let aaa_id = self.next_aaa_id;
            self.next_aaa_id = (self.next_aaa_id + 1) % MAX_AAA_ID;
            if aaa_id == self.first_aaa_id {
                panic!("ran out of AAA addresses");
            }
            aaa_id
        } else {
            // Reuse an address from the returns queue
            self.returns.pop_front().unwrap()
        };

        // We use the bottom 40 bits of the ID as the last 40 bits of the IP address.

        addr_bytes[5] = (self.node_id[1] << 8) | (this_id >> 32) as u16;
        addr_bytes[6] = (this_id >> 16) as u16;
        addr_bytes[7] = (this_id & 0xFFFF) as u16;

        let addr = Ipv6Addr::from(addr_bytes);
        IpAddress::new_from_std_v6(&addr)
    }


    /// Return an address to the pool.
    /// Currently only AAA addresses are supported.
    pub fn release_address(&mut self, address: IpAddress) -> Result<(), AddressPoolError> {
        if address.v6[6] != 0x0a || address.v6[7] != 0xaa {
            return Err(AddressPoolError::InvalidAddress)
        }

        // Extract the ID from the address
        let id = ((address.v6[5] as u64) << 32)
                | ((address.v6[6] as u64) << 16)
                | (address.v6[7] as u64);
        if id >= MAX_AAA_ID {
            return Err(AddressPoolError::InvalidAddress);
        }

        // Return it to our queue.
        self.returns.push_back(id);
        Ok(())
    }
}
