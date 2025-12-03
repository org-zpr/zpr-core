use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::L3Type;
use crate::vsapi::v1;
use crate::vsapi_types::VsapiTypeError;

/// A description of a packet between a sender and reciever.
#[derive(Debug)]
pub struct PacketDesc {
    pub five_tuple: VsapiFiveTuple,
    /// TODO: Can multiple flags be passed with the PacketDesc?
    pub comm_flags: CommFlag,
}

/// Special hint that is passed with a [PacketDesc].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommFlag {
    /// TODO: document this
    BiDirectional,
    /// TODO: document this
    UniDirectional,
    /// Is-a re-request, includes previous visa id.
    ReRequest(u64),
}

#[derive(Copy, Clone, Debug)]
pub struct VsapiFiveTuple {
    pub src_address: IpAddr,
    pub dst_address: IpAddr,
    pub l3_type: L3Type,
    pub l4_protocol: VsapiIpProtocol,
    pub src_port: u16,
    pub dst_port: u16,
}

pub type VsapiIpProtocol = u8;

pub mod vsapi_ip_number {
    use super::VsapiIpProtocol;

    pub const HOPOPT: VsapiIpProtocol = 0;
    pub const ICMP: VsapiIpProtocol = 1;
    pub const IPINIP: VsapiIpProtocol = 4;
    pub const TCP: VsapiIpProtocol = 6;
    pub const UDP: VsapiIpProtocol = 17;
    pub const IPV6_ROUTE: VsapiIpProtocol = 43;
    pub const IPV6_FRAG: VsapiIpProtocol = 44;
    pub const AH: VsapiIpProtocol = 51;
    pub const IPV6_ICMP: VsapiIpProtocol = 58;
    pub const IPV6_OPTS: VsapiIpProtocol = 60;
}

impl VsapiFiveTuple {
    pub fn new(
        l3_type: L3Type,
        src_address: IpAddr,
        dst_address: IpAddr,
        l4_protocol: VsapiIpProtocol,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            src_address,
            dst_address,
            l3_type,
            l4_protocol,
            src_port,
            dst_port,
        }
    }
}

impl PacketDesc {
    /// Panics on invalid IP.
    pub fn new_tcp(source_addr: &str, dest_addr: &str, source_port: u16, dest_port: u16) -> Self {
        let saddr: IpAddr = source_addr.parse().unwrap();
        PacketDesc {
            five_tuple: VsapiFiveTuple::new(
                L3Type::new_from_addr(&saddr),
                saddr,
                dest_addr.parse().unwrap(),
                vsapi_ip_number::TCP,
                source_port,
                dest_port,
            ),
            comm_flags: CommFlag::BiDirectional,
        }
    }

    /// Panics on invalid IP.
    pub fn new_udp(source_addr: &str, dest_addr: &str, source_port: u16, dest_port: u16) -> Self {
        let saddr: IpAddr = source_addr.parse().unwrap();
        PacketDesc {
            five_tuple: VsapiFiveTuple::new(
                L3Type::new_from_addr(&saddr),
                saddr,
                dest_addr.parse().unwrap(),
                vsapi_ip_number::UDP,
                source_port,
                dest_port,
            ),
            comm_flags: CommFlag::BiDirectional,
        }
    }

    /// Panics on invalid IP.
    pub fn new_icmp(source_addr: &str, dest_addr: &str, icmp_type: u8, icmp_code: u8) -> Self {
        let saddr: IpAddr = source_addr.parse().unwrap();
        PacketDesc {
            five_tuple: VsapiFiveTuple::new(
                L3Type::new_from_addr(&saddr),
                saddr,
                dest_addr.parse().unwrap(),
                if saddr.is_ipv4() {
                    vsapi_ip_number::ICMP
                } else {
                    vsapi_ip_number::IPV6_ICMP
                },
                icmp_type as u16,
                icmp_code as u16,
            ),
            comm_flags: CommFlag::UniDirectional,
        }
    }

    pub fn is_tcpudp(&self) -> bool {
        self.five_tuple.l4_protocol == vsapi_ip_number::TCP
            || self.five_tuple.l4_protocol == vsapi_ip_number::UDP
    }

    /// Get a reference to the five_tuple source address.
    pub fn source_addr(&self) -> &IpAddr {
        &self.five_tuple.src_address
    }
    /// Get a reference to the five_tuple destination address.
    pub fn dest_addr(&self) -> &IpAddr {
        &self.five_tuple.dst_address
    }
    /// Get the source port (or icmp TYPE)
    pub fn source_port(&self) -> u16 {
        self.five_tuple.src_port
    }
    /// Get the destination port (or icmp CODE)
    pub fn dest_port(&self) -> u16 {
        self.five_tuple.dst_port
    }
    /// Get the L4 protocol number.
    pub fn protocol(&self) -> VsapiIpProtocol {
        self.five_tuple.l4_protocol
    }
}

impl TryFrom<v1::packet_desc::Reader<'_>> for PacketDesc {
    type Error = VsapiTypeError;
    fn try_from(reader: v1::packet_desc::Reader<'_>) -> Result<Self, Self::Error> {
        let src_ip = reader.get_source_addr()?;
        let source = match src_ip.which().unwrap() {
            v1::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4?.try_into()?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            v1::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6?.try_into()?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let dest_ip = reader.get_dest_addr()?;
        let dest = match dest_ip.which().unwrap() {
            v1::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4?.try_into()?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            v1::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6?.try_into()?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let source_port = reader.get_source_port();
        let dest_port = reader.get_dest_port();
        let protocol = reader.get_protocol();
        let comm_flags = match reader.get_comm_type().unwrap() {
            v1::CommType::Bidirectional => CommFlag::BiDirectional,
            v1::CommType::Unidirectional => CommFlag::UniDirectional,
            v1::CommType::Rerequest => CommFlag::ReRequest(0), // TODO
        };

        Ok(PacketDesc {
            five_tuple: VsapiFiveTuple::new(
                L3Type::new_from_addr(&source),
                source,
                dest,
                protocol,
                source_port,
                dest_port,
            ),
            comm_flags,
        })
    }
}
