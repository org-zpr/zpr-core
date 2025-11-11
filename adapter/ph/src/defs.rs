//! Common definitions that have no more specific place to live.

use crate::net_defs;
use zerocopy::*;
use zpr;

/// Packet direction with respect to an interface.
/// Primary use is for constructing libpcap link-layer header.
#[derive(Copy, Clone)]
pub enum Direction {
    // Do not change the values!  They are used directly to form the link-layer header.
    Inbound = 0,
    Outbound = 1,
}

/// IP 5-tuple used for hashing.
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct FiveTuple {
    pub src_address: net_defs::IpAddress,
    pub dst_address: net_defs::IpAddress,
    pub l3_type: zpr::L3Type,
    pub l4_protocol: net_defs::IpProtocol,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FiveTuple {
    #[allow(dead_code)]
    pub fn new(
        l3_type: zpr::L3Type,
        src_address: net_defs::IpAddress,
        dst_address: net_defs::IpAddress,
        l4_protocol: net_defs::IpProtocol,
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

    #[allow(dead_code)]
    pub fn reverse(&self) -> FiveTuple {
        Self {
            src_address: self.dst_address,
            dst_address: self.src_address,
            l3_type: self.l3_type,
            l4_protocol: self.l4_protocol,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

impl std::fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "({}, {}, {}, {}, {}, {})",
            self.l3_type,
            self.src_address,
            self.dst_address,
            self.l4_protocol,
            self.src_port,
            self.dst_port
        )
    }
}

#[derive(Default, Debug)]
pub struct FiveTupleOptional {
    pub src_address: Option<net_defs::IpAddress>,
    pub dst_address: Option<net_defs::IpAddress>,
    pub l3_type: Option<zpr::L3Type>,
    pub l4_protocol: Option<net_defs::IpProtocol>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl FiveTupleOptional {
    pub fn set_src_address(&mut self, src_address: net_defs::IpAddress) {
        self.src_address = Some(src_address);
    }
    pub fn set_dst_address(&mut self, dst_address: net_defs::IpAddress) {
        self.dst_address = Some(dst_address);
    }
    pub fn set_l3_type(&mut self, l3_type: zpr::L3Type) {
        self.l3_type = Some(l3_type);
    }
    pub fn set_l4_protocol(&mut self, l4_protocol: net_defs::IpProtocol) {
        self.l4_protocol = Some(l4_protocol);
    }
    pub fn set_src_port(&mut self, src_port: u16) {
        self.src_port = Some(src_port);
    }
    pub fn set_dst_port(&mut self, dst_port: u16) {
        self.dst_port = Some(dst_port);
    }
    pub fn set_vals(
        &mut self,
        l3_type: zpr::L3Type,
        src_address: net_defs::IpAddress,
        dst_address: net_defs::IpAddress,
        l4_protocol: net_defs::IpProtocol,
        src_port: u16,
        dst_port: u16,
    ) {
        self.set_src_address(src_address);
        self.set_dst_address(dst_address);
        self.set_l3_type(l3_type);
        self.set_l4_protocol(l4_protocol);
        self.set_src_port(src_port);
        self.set_dst_port(dst_port);
    }
}

impl TryFrom<FiveTupleOptional> for FiveTuple {
    type Error = &'static str;

    fn try_from(ft: FiveTupleOptional) -> Result<FiveTuple, Self::Error> {
        let src_address = match ft.src_address {
            Some(addr) => addr,
            None => return Err("No source address"),
        };
        let dst_address = match ft.dst_address {
            Some(addr) => addr,
            None => return Err("No destination address"),
        };
        let l3_type = match ft.l3_type {
            Some(ty) => ty,
            None => return Err("No l3 type"),
        };
        let l4_protocol = match ft.l4_protocol {
            Some(proto) => proto,
            None => return Err("No l4 protocol"),
        };
        let src_port = match ft.src_port {
            Some(port) => port,
            None => return Err("No source port"),
        };
        let dst_port = match ft.dst_port {
            Some(port) => port,
            None => return Err("No destination port"),
        };

        Ok(FiveTuple::new(
            l3_type,
            src_address,
            dst_address,
            l4_protocol,
            src_port,
            dst_port,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_full_ft() {
        let src_address = net_defs::IpAddress::from([1u8; 16]);
        let dst_address = net_defs::IpAddress::from([2u8; 16]);
        let l3_type = zpr::L3Type::Ipv6;
        let l4_protocol = net_defs::ip_number::TCP;
        let src_port = 3;
        let dst_port = 4;

        let ft1 = FiveTuple::new(
            l3_type,
            src_address,
            dst_address,
            l4_protocol,
            src_port,
            dst_port,
        );

        let mut ft_optional = FiveTupleOptional::default();
        ft_optional.set_vals(
            l3_type,
            src_address,
            dst_address,
            l4_protocol,
            src_port,
            dst_port,
        );

        let ft2 = FiveTuple::try_from(ft_optional);

        assert_eq!(ft1, ft2.unwrap());
    }

    #[test]
    fn test_from_no_src_addr() {
        let mut ft_optional = FiveTupleOptional::default();
        ft_optional.set_dst_address(net_defs::IpAddress::from([2u8; 16]));
        ft_optional.set_l3_type(zpr::L3Type::Ipv6);
        ft_optional.set_l4_protocol(net_defs::ip_number::TCP);
        ft_optional.set_src_port(3);
        ft_optional.set_dst_port(4);

        let ft2 = FiveTuple::try_from(ft_optional);

        assert!(ft2.is_err());
    }

    #[test]
    fn test_from_no_dst_addr() {
        let mut ft_optional = FiveTupleOptional::default();
        ft_optional.set_src_address(net_defs::IpAddress::from([1u8; 16]));
        ft_optional.set_l3_type(zpr::L3Type::Ipv6);
        ft_optional.set_l4_protocol(net_defs::ip_number::TCP);
        ft_optional.set_src_port(3);
        ft_optional.set_dst_port(4);

        let ft2 = FiveTuple::try_from(ft_optional);

        assert!(ft2.is_err());
    }

    #[test]
    fn test_from_no_l3_type() {
        let mut ft_optional = FiveTupleOptional::default();
        ft_optional.set_src_address(net_defs::IpAddress::from([1u8; 16]));
        ft_optional.set_dst_address(net_defs::IpAddress::from([2u8; 16]));
        ft_optional.set_l4_protocol(net_defs::ip_number::TCP);
        ft_optional.set_src_port(3);
        ft_optional.set_dst_port(4);

        let ft2 = FiveTuple::try_from(ft_optional);

        assert!(ft2.is_err());
    }

    #[test]
    fn test_from_no_l4_proto() {
        let mut ft_optional = FiveTupleOptional::default();
        ft_optional.set_src_address(net_defs::IpAddress::from([1u8; 16]));
        ft_optional.set_dst_address(net_defs::IpAddress::from([2u8; 16]));
        ft_optional.set_l3_type(zpr::L3Type::Ipv6);
        ft_optional.set_src_port(3);
        ft_optional.set_dst_port(4);

        let ft2 = FiveTuple::try_from(ft_optional);

        assert!(ft2.is_err());
    }

    #[test]
    fn test_from_no_src_port() {
        let mut ft_optional = FiveTupleOptional::default();
        ft_optional.set_src_address(net_defs::IpAddress::from([1u8; 16]));
        ft_optional.set_dst_address(net_defs::IpAddress::from([2u8; 16]));
        ft_optional.set_l3_type(zpr::L3Type::Ipv6);
        ft_optional.set_l4_protocol(net_defs::ip_number::TCP);
        ft_optional.set_dst_port(4);

        let ft2 = FiveTuple::try_from(ft_optional);

        assert!(ft2.is_err());
    }

    #[test]
    fn test_from_no_dst_port() {
        let mut ft_optional = FiveTupleOptional::default();
        ft_optional.set_src_address(net_defs::IpAddress::from([1u8; 16]));
        ft_optional.set_dst_address(net_defs::IpAddress::from([2u8; 16]));
        ft_optional.set_l3_type(zpr::L3Type::Ipv6);
        ft_optional.set_l4_protocol(net_defs::ip_number::TCP);
        ft_optional.set_src_port(3);

        let ft2 = FiveTuple::try_from(ft_optional);

        assert!(ft2.is_err());
    }
}
