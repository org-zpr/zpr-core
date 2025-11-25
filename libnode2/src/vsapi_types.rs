//! VSAPI types - this is placeholder until we have this in centralized location.
//! This copies code from zpr-visaservice/vs-dt

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zpr::vsapi::v1 as vsapi;

use crate::error::DTError;

pub mod ip_proto {
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const IPV6_ICMP: u8 = 58;
}

#[derive(Debug)]
pub struct Visa {
    pub issuer_id: u64,
    pub expiration: u64, // VS uses milliseconds since epoch
    pub source_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub dock_pep: DockPEP,
    pub constraints: Option<Vec<Constraint>>,
    pub session_key: KeySet,
}

#[derive(Debug)]
pub enum DockPEP {
    Tcp(u16, u16, EndpointT), // (source port, dest port)
    Udp(u16, u16, EndpointT), // (source port, dest port)
    Icmp(u8, u8),             // (icmp type, icmp code)
}

#[derive(Debug)]
pub enum EndpointT {
    Any,
    Server,
    Client,
}

#[derive(Debug)]
pub enum Constraint {}

#[derive(Debug)]
pub struct KeySet {
    pub format: KeyFormat,
    pub ingress: Vec<u8>,
    pub egress: Vec<u8>,
}

#[derive(Debug)]
pub enum KeyFormat {
    ZprKF1,
}

#[derive(Debug)]
pub enum VisaDenialReason {
    NoReasonGiven,
    NoMatch,
    Denied,
    SourceNotFound,
    DestNotFound,
    SourceAuthError,
    DestAuthError,
    QuotaExceeded,
}

/// A description of a packet between a sender and reciever.
#[derive(Debug)]
pub struct PacketDesc {
    pub source_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub protocol: u8,
    /// Source port or ICMP type
    pub source_port: u16,
    /// Destination port or ICMP code
    pub dest_port: u16,
    /// TODO: Can multiple flags be passed with the PacketDesc?
    pub comm_flags: CommFlag,
}

/// Special hint that is passed with a [PacketDesc].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommFlag {
    BiDirectional,
    UniDirectional,
    ReRequest(u64),
}

fn write_ip_addr(bldr: &mut vsapi::ip_addr::Builder<'_>, ip: &IpAddr) {
    match ip {
        IpAddr::V4(ipv4) => {
            let v4_buf = bldr.reborrow().init_v4(4);
            v4_buf.copy_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            let v6_buf = bldr.reborrow().init_v6(16);
            v6_buf.copy_from_slice(&ipv6.octets());
        }
    }
}

impl TryFrom<vsapi::key_set::Reader<'_>> for KeySet {
    type Error = DTError;

    fn try_from(reader: vsapi::key_set::Reader<'_>) -> Result<Self, Self::Error> {
        let format = match reader.get_format()? {
            vsapi::KeyFormat::ZprKF01 => KeyFormat::ZprKF1,
        };
        let ingress = reader.get_ingress_key()?.to_vec();
        let egress = reader.get_egress_key()?.to_vec();
        Ok(KeySet {
            format,
            ingress,
            egress,
        })
    }
}

impl From<vsapi::EndpointT> for EndpointT {
    fn from(ept: vsapi::EndpointT) -> Self {
        match ept {
            vsapi::EndpointT::Any => EndpointT::Any,
            vsapi::EndpointT::Server => EndpointT::Server,
            vsapi::EndpointT::Client => EndpointT::Client,
        }
    }
}

impl Into<vsapi::EndpointT> for EndpointT {
    fn into(self) -> vsapi::EndpointT {
        match self {
            EndpointT::Any => vsapi::EndpointT::Any,
            EndpointT::Server => vsapi::EndpointT::Server,
            EndpointT::Client => vsapi::EndpointT::Client,
        }
    }
}

impl Into<vsapi::EndpointT> for &EndpointT {
    fn into(self) -> vsapi::EndpointT {
        match self {
            EndpointT::Any => vsapi::EndpointT::Any,
            EndpointT::Server => vsapi::EndpointT::Server,
            EndpointT::Client => vsapi::EndpointT::Client,
        }
    }
}

impl Into<vsapi::VisaDenyCode> for VisaDenialReason {
    fn into(self) -> vsapi::VisaDenyCode {
        match self {
            VisaDenialReason::NoReasonGiven => vsapi::VisaDenyCode::NoReason,
            VisaDenialReason::NoMatch => vsapi::VisaDenyCode::NoMatch,
            VisaDenialReason::Denied => vsapi::VisaDenyCode::Denied,
            VisaDenialReason::SourceNotFound => vsapi::VisaDenyCode::SourceNotFound,
            VisaDenialReason::DestNotFound => vsapi::VisaDenyCode::DestNotFound,
            VisaDenialReason::SourceAuthError => vsapi::VisaDenyCode::SourceAuthError,
            VisaDenialReason::DestAuthError => vsapi::VisaDenyCode::DestAuthError,
            VisaDenialReason::QuotaExceeded => vsapi::VisaDenyCode::QuotaExceeded,
        }
    }
}

impl From<vsapi::VisaDenyCode> for VisaDenialReason {
    fn from(code: vsapi::VisaDenyCode) -> Self {
        match code {
            vsapi::VisaDenyCode::NoReason => VisaDenialReason::NoReasonGiven,
            vsapi::VisaDenyCode::NoMatch => VisaDenialReason::NoMatch,
            vsapi::VisaDenyCode::Denied => VisaDenialReason::Denied,
            vsapi::VisaDenyCode::SourceNotFound => VisaDenialReason::SourceNotFound,
            vsapi::VisaDenyCode::DestNotFound => VisaDenialReason::DestNotFound,
            vsapi::VisaDenyCode::SourceAuthError => VisaDenialReason::SourceAuthError,
            vsapi::VisaDenyCode::DestAuthError => VisaDenialReason::DestAuthError,
            vsapi::VisaDenyCode::QuotaExceeded => VisaDenialReason::QuotaExceeded,
        }
    }
}

impl TryFrom<vsapi::dock_pep::Reader<'_>> for DockPEP {
    type Error = DTError;
    fn try_from(reader: vsapi::dock_pep::Reader<'_>) -> Result<Self, Self::Error> {
        match reader.which().unwrap() {
            vsapi::dock_pep::Which::Tcp(tcp_rdr) => {
                let tcp = tcp_rdr?;
                let source_port = tcp.get_source_port();
                let dest_port = tcp.get_dest_port();
                let ept = tcp.get_enpoint()?.into();
                Ok(DockPEP::Tcp(source_port, dest_port, ept))
            }
            vsapi::dock_pep::Which::Udp(udp_rdr) => {
                let udp = udp_rdr?;
                let source_port = udp.get_source_port();
                let dest_port = udp.get_dest_port();
                let ept = udp.get_enpoint()?.into();
                Ok(DockPEP::Udp(source_port, dest_port, ept))
            }
            vsapi::dock_pep::Which::Icmp(icmp_rdr) => {
                let icmp = icmp_rdr?;
                let typecode = icmp.get_icmp_type_code();
                let icmp_type = (typecode >> 8) as u8;
                let icmp_code = (typecode & 0xff) as u8;
                Ok(DockPEP::Icmp(icmp_type, icmp_code))
            }
        }
    }
}

impl TryFrom<vsapi::visa::Reader<'_>> for Visa {
    type Error = DTError;
    fn try_from(reader: vsapi::visa::Reader<'_>) -> Result<Self, Self::Error> {
        let issuer_id = reader.get_issuer_id();
        let expiration = reader.get_expiration();
        let src_ip = reader.get_source_addr()?;
        let source_addr = match src_ip.which().unwrap() {
            vsapi::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4?
                    .try_into()
                    .map_err(|_| DTError::InvalidArgument("invalid source_addr".into()))?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            vsapi::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6?
                    .try_into()
                    .map_err(|_| DTError::InvalidArgument("invalid source_addr".into()))?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let dest_ip = reader.get_dest_addr()?;
        let dest_addr = match dest_ip.which().unwrap() {
            vsapi::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4?
                    .try_into()
                    .map_err(|_| DTError::InvalidArgument("invalid dest_addr".into()))?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            vsapi::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6?
                    .try_into()
                    .map_err(|_| DTError::InvalidArgument("invalid dest_addr".into()))?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };

        let pep_rdr = reader.get_dock_pep()?;
        let dock_pep = DockPEP::try_from(pep_rdr)?;

        // TODO: constraints.

        let skey_rdr = reader.get_session_key()?;
        let kset = KeySet::try_from(skey_rdr)?;

        Ok(Visa {
            issuer_id,
            expiration,
            source_addr,
            dest_addr,
            dock_pep,
            constraints: None,
            session_key: kset,
        })
    }
}

impl PacketDesc {
    pub fn write_to(&self, bldr: &mut vsapi::packet_desc::Builder<'_>) {
        let mut ip_bldr = bldr.reborrow().init_source_addr();
        write_ip_addr(&mut ip_bldr, &self.source_addr);
        let mut ip_bldr = bldr.reborrow().init_dest_addr();
        write_ip_addr(&mut ip_bldr, &self.dest_addr);
        bldr.set_protocol(self.protocol);
        bldr.set_source_port(self.source_port);
        bldr.set_dest_port(self.dest_port);
        match self.comm_flags {
            CommFlag::BiDirectional => bldr.set_comm_type(vsapi::CommType::Bidirectional),
            CommFlag::UniDirectional => bldr.set_comm_type(vsapi::CommType::Unidirectional),
            CommFlag::ReRequest(_) => bldr.set_comm_type(vsapi::CommType::Rerequest),
        }
    }
}
