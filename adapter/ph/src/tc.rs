//! ZPR Traffic Classifiers
//!
//! Probably, most of this functionality should live in the zpr crate,
//! and the serialization/deserialization should move into the zdp module.
//! For now, it's all here together.

use crate::classifier::{self, ClassifierResult};
use crate::defs;
use crate::zdp;
use bytes::{Buf, BufMut};
use zpr::packet_info::{CompressionMode, L3Type, compression_mode};
use zpr_ext::zerocopy::{FromBytesExt, IntoBytesExt};
use zpr_utils::net_defs;

/// IP 5-Tuple Traffic Classifier
#[derive(Clone)]
pub struct Ip5TupleTc(defs::FiveTuple);

impl Ip5TupleTc {
    /// Interpret a five-tuple as a traffic classifier.  Ports specified as 0
    /// are interpreted as wildcards.
    pub fn new(five_tuple: defs::FiveTuple) -> Self {
        Self(five_tuple)
    }

    /// Represent the classifier as a five-tuple.  Wildcard ports are
    /// represented as 0.
    pub fn five_tuple(&self) -> &defs::FiveTuple {
        &self.0
    }

    /// TEMPORARY: Return compression mode flags indicating whether ports are wildcarded.
    pub fn compression_mode(&self) -> CompressionMode {
        let mut mode: CompressionMode = 0;

        if self.0.src_port != 0 {
            mode |= compression_mode::SOURCE_PORT_PRESENT;
        }

        if self.0.dst_port != 0 {
            mode |= compression_mode::DESTINATION_PORT_PRESENT;
        }

        mode
    }

    /// Serialize the classifier to a buffer.
    pub fn serialize(&self, buf: &mut impl BufMut) {
        let mut flags = 0;

        match self.0.l3_type {
            L3Type::Ipv4 => flags |= zdp::traffic_classifier_flags::IPV4,
            L3Type::Ipv6 => (), // default is IPv6
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
            L3Type::Ipv4 => {
                buf.put(self.0.src_address.read_as_v4().as_slice());
                buf.put(self.0.dst_address.read_as_v4().as_slice());
            }

            L3Type::Ipv6 => {
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

    /// Deserialize the classifier from a buffer.
    pub fn deserialize(buf: &mut impl Buf) -> Result<Self, ()> {
        let Ok(hdr) = zdp::ZdpTrafficClassifierHeader::read_from_buf(buf) else {
            return Err(());
        };

        let l3_type;
        let src_address;
        let dst_address;

        if hdr.flags & zdp::traffic_classifier_flags::IPV4 != 0 {
            l3_type = L3Type::Ipv4;

            if buf.remaining() < 2 * net_defs::IPV4_ADDRESS_SIZE {
                return Err(());
            }

            src_address = buf_get_ipv4(buf);
            dst_address = buf_get_ipv4(buf);
        } else {
            l3_type = L3Type::Ipv6;

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

    #[allow(dead_code)]
    /// Does the specified packet body match this classifier.
    pub fn classify_packet(&self, l3_type: L3Type, body: &[u8]) -> bool {
        // Derive the 5-tuple from the packet body.  Reject if packet is malformed.
        let mut ft = defs::FiveTuple::default();
        let Ok(classification) = classifier::classify(&mut ft, body) else {
            return false;
        };

        // We do not accept fragments non-IP packets.
        if !matches!(
            classification,
            ClassifierResult::OK | ClassifierResult::UnclassifiedL4
        ) {
            return false;
        }

        // The classifier guesses the L3 type from the packet body; confirm it matches
        // the claimed L3 type from the upper layer.
        if ft.l3_type != l3_type {
            return false;
        }

        self.classify_5t(&ft)
    }

    /// Does a packet with the specified 5-tuple match this classifier.
    pub fn classify_5t(&self, five_tuple: &defs::FiveTuple) -> bool {
        if five_tuple.l3_type != self.0.l3_type {
            return false;
        }

        if five_tuple.src_address != self.0.src_address
            || five_tuple.dst_address != self.0.dst_address
        {
            return false;
        }

        if five_tuple.l4_protocol != self.0.l4_protocol {
            return false;
        }

        if self.0.src_port != 0 && five_tuple.src_port != self.0.src_port {
            return false;
        }

        if self.0.dst_port != 0 && five_tuple.dst_port != self.0.dst_port {
            return false;
        }

        true
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
