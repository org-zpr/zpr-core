#![allow(dead_code)]

use open_enum::open_enum;
use zerocopy::byteorder::network_endian::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
use zpr::packet_info::{
    A2aSaid, KM_ID_EXPERIMENTAL, KM_ID_IKEV2, KM_ID_NOISE, KM_ID_NULL, L3Type, Tcst,
};

#[open_enum]
#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum ZdpPacketType {
    // Flow-based
    TransitPacket = 0,
    DestinationUnreachable = 1,
    SetPathMtu = 2,
    StreamIdRequest = 3,
    StreamIdResponse = 4,
    StreamIdWithdrawal = 5,
    BindActorAddressRequest = 6,
    BindActorAddressResponse = 7,
    BindEgressStreamRequest = 8,  // TODO: add to RFC 17
    BindEgressStreamResponse = 9, // TODO: add to RFC 17
    UnbindActorAddressRequest = 13,
    UnbindEgressStreamRequest = 14,

    // Not flow-based
    ZprArp = 128,
    KeyManagement = 129,
    Discard = 130,
    Echo = 131,
    Report = 132,
    TerminateLinkOrDockingSession = 133,
    HelloRequest = 134,
    HelloResponse = 135,
    ConfigurationRequest = 136,
    ConfigurationResponse = 137,
    AcquireZprAddress = 138, // TODO: add to RFC 6
    GrantZprAddress = 139,   // TODO: add to RFC 6
    RevokeZprAddress = 140,
    InitAuthenticationRequest = 141, // TODO: add to RFC 6

    Acknowledgement = 254,
    Reserved255 = 255,
}

pub const ZDP_PACKET_TYPE_NON_FLOW_FLAG: u8 = 0x80;

impl ZdpPacketType {
    pub fn is_per_flow(self) -> bool {
        self.0 & ZDP_PACKET_TYPE_NON_FLOW_FLAG == 0
    }

    /// Only "management" packets have a `ZdpMgmtHeader`.
    ///
    /// "Management" packets are everything except transit, ARP, and KM packets.
    pub fn is_mgmt(self) -> bool {
        !matches!(
            self,
            Self::TransitPacket | Self::ZprArp | Self::KeyManagement
        )
    }
}

#[open_enum]
#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum ResponseCode {
    Success = 0,
    Other = 1,
}

#[derive(Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpZpiHeader {
    pub zpi: u8,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpBaseHeader {
    pub packet_type: ZdpPacketType,
    pub excess_length: u8,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpMgmtHeader {
    pub sequence_number: U64,
}

/// Offset into ZDP packet where [ZdpBaseHeader] starts.
pub const ZDP_BASE_HEADER_OFFSET: usize = std::mem::size_of::<ZdpZpiHeader>();

/// Offset into ZDP packet where a non-per-flow header starts.
pub const ZDP_NON_PER_FLOW_MGMT_HEADER_OFFSET: usize =
    ZDP_BASE_HEADER_OFFSET + std::mem::size_of::<ZdpBaseHeader>();

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpPerFlowHeader {
    pub stream_id: U32,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpTransactionHeader {
    pub transaction_id: U16,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpEchoHeader {
    pub additional_length: U16,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpReportHeader {
    pub report_data_length: U16,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpHelloRequestHeader {
    // Followed by any nubmer of request TLVs.  The TLV
    // format is:
    //   - TLV type (u8)
    //   - TLV length (u8)
    //   - TLV value (variable length)
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpHelloResponseHeader {
    pub status: ResponseCode,
    // Followed by any nubmer of response TLVs.  The TLV
    // format is:
    //   - TLV type (u8)
    //   - TLV length (u8)
    //   - TLV value (variable length)
}

/// Bitflags for the [ZdpInitAuthenticationRequestHeader] flags field.
pub mod init_authentication_flags {
    pub const BOOTSTRAP_SUPPORT: u8 = 0x01;
}

/// Tentative -- pending inclusion into spec.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpInitAuthenticationRequestHeader {
    pub flags: u8,
    pub data_len: U16,
    // Followed by challenge payload, eg ZdpInitAuthenticationPayload in auth.rs.
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpAcquireZprAddressHeader {
    pub blob_len: U16,
    pub ip_version: L3Type, // Length of address determined by IP type
    pub addr_count: u8,
    // Followed in memory by:
    //  - BLOB (of blob_len bytes) is-a base64 encoded json string.
    //  - IP addresses (addr_count * IP address size bytes)
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpGrantZprAddressHeader {
    pub status_code: ResponseCode,
    pub ip_version: L3Type, // Length of address determined by IP type
    pub addr_count: u8,
    // Followed in memory by:
    //  - IP addresses (addr_count * IP address size bytes)
}

#[open_enum]
#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum TerminateReason {
    Other = 0,
    Unused1 = 1,
    RequestTimedOut = 2,
    Reset = 3,
    Shutdown = 4, // quell any restart behavior
}

/// Terminate Link or Docking Session (TODO: document)
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpTerminateLinkOrDockingSessionHeader {
    pub reason_code: TerminateReason,
    pub data_len: u8,
    // followed by reason detail
}

/// Bind Actor Address request (§ 6.3.11)
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpBindActorAddressRequestHeader {
    pub l3_type: L3Type,
    pub endpoint_packet_length: U16,
    // Followed in memory by:
    // - <PACKET BODY starting with IP header>
    // (source/dest addresses and layer4 protocol must be extracted from the IP header in the packet)
}

/// Bind Actor Address response (§ 6.3.11)
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpBindActorAddressResponseHeader {
    pub status_code: ResponseCode,
    pub info_len: u8,
    // followed by `info_len` octets of Optional Additional Status Information
    // followed by 8-bit TCST
    // followed by traffic classifier
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
// Alternativelt to the current setup, we could pass the FT instead, not sure
// which is better for how the system is going to be set up
pub struct ZdpUnbindActorAddressRequestHeader {
    pub l3_type: L3Type,
    pub endpoint_packet_length: U16,
    // Followed in memory by:
    // - <PACKET BODY starting with IP header>
    // (source/dest addresses and layer4 protocol must be extracted from the IP header in the packet)
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpBindEgressStreamRequestHeader {
    pub tcst: Tcst,
    // followed by traffic classifier
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpBindEgressStreamResponseHeader {
    pub status_code: ResponseCode,
    pub info_len: u8,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpKeyManagementHeader {
    pub message_type: U16,
    pub message_length: U16,
}

impl ZdpKeyManagementHeader {
    /// TRUE if this is a noise protocol KM message
    pub fn is_noise(&self) -> bool {
        self.message_type.get() == KM_ID_NOISE
    }
    /// TRUE if this is an IKEv2 KM message
    pub fn is_ikev2(&self) -> bool {
        self.message_type.get() == KM_ID_IKEV2
    }
    /// TRUE if this is an experimental KM message
    pub fn is_experiment(&self) -> bool {
        self.message_type.get() == KM_ID_EXPERIMENTAL
    }

    pub fn is_null(&self) -> bool {
        self.message_type.get() == KM_ID_NULL
    }
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpA2aHeader {
    pub a2a_said: A2aSaid,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpTrafficClassifierHeader {
    pub flags: u8,
    pub ip_protocol: u8,
    // Followed by source and destination addresses,
    // then optional source and destination ports.
}

/// Bitflags for the [ZdpTrafficClassifierHeader] flags field.
pub mod traffic_classifier_flags {
    pub const DESTINATION_PORT_PRESENT: u8 = 0x01;
    pub const SOURCE_PORT_PRESENT: u8 = 0x02;
    pub const IPV4: u8 = 0x04;
}

/// Config-specified size of A2A MAC.  Algorithm-specified MAC may be smaller (but not larger).
pub const ZDP_A2A_MAC_SIZE: usize = 8;

/// Size of the ZDP "link" HMAC which is set link-by-link for transit packets.
/// This HMAC is tacked on to the end of the packet (following the A2A HMAC).
pub const ZDP_PACKET_MAC_SIZE: usize = 8;

const _: () = assert!(core::mem::size_of::<ZdpBaseHeader>() == 2);
const _: () = assert!(core::mem::size_of::<ZdpMgmtHeader>() == 8);
const _: () = assert!(core::mem::size_of::<ZdpPerFlowHeader>() == 4);
