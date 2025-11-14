//! ZPR Traffic Classifiers
//!
//! Probably, most of this functionality should live in the zpr crate,
//! and the serialization/deserialization should move into the zdp module.
//! For now, it's all here together.

use crate::defs;
use crate::zdp;
use bytes::{Buf, BufMut};
use libnode::net_defs;
use zpr_ext::zerocopy::{FromBytesExt, IntoBytesExt};

/// IP 5-Tuple Traffic Classifier
#[derive(Clone)]
pub struct Ip5TupleTc(defs::FiveTuple);

// TODO: actually add traffic classification code here

impl Ip5TupleTc {
    #[allow(dead_code)]
    /// Interpret a five-tuple as a traffic classifier.  Ports specified as 0
    /// are interpreted as wildcards.
    pub fn new(five_tuple: defs::FiveTuple) -> Self {
        Self(five_tuple)
    }

    /// TEMPORARY: use compression mode flags to indicate which ports of the five-tuple
    /// should be masked out and treated as wildcards.
    pub fn new_with_compression_mode(
        compression_mode: zpr::CompressionMode,
        mut five_tuple: defs::FiveTuple,
    ) -> Self {
        if compression_mode & zpr::compression_mode::SOURCE_PORT_PRESENT == 0 {
            five_tuple.src_port = 0;
        }

        if compression_mode & zpr::compression_mode::DESTINATION_PORT_PRESENT == 0 {
            five_tuple.dst_port = 0;
        }

        Self(five_tuple)
    }

    /// Represent the classifier as a five-tuple.  Wildcard ports are
    /// represented as 0.
    pub fn five_tuple(&self) -> &defs::FiveTuple {
        &self.0
    }

    /// TEMPORARY: Return compression mode flags indicating whether ports are wildcarded.
    pub fn compression_mode(&self) -> zpr::CompressionMode {
        let mut mode: zpr::CompressionMode = 0;

        if self.0.src_port != 0 {
            mode |= zpr::compression_mode::SOURCE_PORT_PRESENT;
        }

        if self.0.dst_port != 0 {
            mode |= zpr::compression_mode::DESTINATION_PORT_PRESENT;
        }

        mode
    }

    /// Serialize.
    pub fn serialize(&self, buf: &mut impl BufMut) {
        let mut flags = 0;

        match self.0.l3_type {
            zpr::L3Type::Ipv4 => flags |= zdp::traffic_classifier_flags::IPV4,
            zpr::L3Type::Ipv6 => (), // default is IPv6
            _ => panic!("must be IPv4 or IPv6"),
        }

        if self.0.src_port != 0 {
            flags |= zdp::traffic_classifier_flags::SOURCE_PORT_PRESENT;
        }

        if self.0.dst_port != 0 {
            flags |= zdp::traffic_classifier_flags::DESTINATION_PORT_PRESENT;
        }

        zdp::ZdpTrafficClassifierHeader {
            flags,
            ip_protocol: self.0.l4_protocol,
        }
        .write_to_buf(buf)
        .unwrap();

        match self.0.l3_type {
            zpr::L3Type::Ipv4 => {
                buf.put(self.0.src_address.read_as_v4().as_slice());
                buf.put(self.0.dst_address.read_as_v4().as_slice());
            }

            zpr::L3Type::Ipv6 => {
                buf.put(self.0.src_address.v6.as_slice());
                buf.put(self.0.dst_address.v6.as_slice());
            }

            _ => panic!("must be IPv4 or IPv6"),
        }

        if self.0.src_port != 0 {
            buf.put_u16(self.0.src_port);
        }

        if self.0.dst_port != 0 {
            buf.put_u16(self.0.dst_port);
        }
    }

    pub fn deserialize(buf: &mut impl Buf) -> Result<Self, ()> {
        let Ok(hdr) = zdp::ZdpTrafficClassifierHeader::read_from_buf(buf) else {
            return Err(());
        };

        let l3_type;
        let src_address;
        let dst_address;

        if hdr.flags & zdp::traffic_classifier_flags::IPV4 != 0 {
            l3_type = zpr::L3Type::Ipv4;

            if buf.remaining() < 2 * net_defs::IPV4_ADDRESS_SIZE {
                return Err(());
            }

            src_address = buf_get_ipv4(buf);
            dst_address = buf_get_ipv4(buf);
        } else {
            l3_type = zpr::L3Type::Ipv6;

            if buf.remaining() < 2 * net_defs::IPV6_ADDRESS_SIZE {
                return Err(());
            }

            src_address = buf_get_ipv6(buf);
            dst_address = buf_get_ipv6(buf);
        }

        let mut src_port = 0;
        let mut dst_port = 0;

        if hdr.flags & zdp::traffic_classifier_flags::SOURCE_PORT_PRESENT != 0 {
            src_port = buf.try_get_u16().map_err(|_| ())?;
        }

        if hdr.flags & zdp::traffic_classifier_flags::DESTINATION_PORT_PRESENT != 0 {
            dst_port = buf.try_get_u16().map_err(|_| ())?;
        }

        return Ok(Self(defs::FiveTuple {
            l3_type,
            l4_protocol: hdr.ip_protocol,
            src_address,
            dst_address,
            src_port,
            dst_port,
        }));
    }
}

impl std::fmt::Display for Ip5TupleTc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

fn buf_get_ipv4(buf: &mut impl Buf) -> net_defs::IpAddress {
    <[u8; net_defs::IPV4_ADDRESS_SIZE]>::try_from(&*buf.copy_to_bytes(net_defs::IPV4_ADDRESS_SIZE))
        .unwrap()
        .into()
}

fn buf_get_ipv6(buf: &mut impl Buf) -> net_defs::IpAddress {
    <[u8; net_defs::IPV6_ADDRESS_SIZE]>::try_from(&*buf.copy_to_bytes(net_defs::IPV6_ADDRESS_SIZE))
        .unwrap()
        .into()
}
