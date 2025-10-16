#![allow(dead_code)]

use open_enum::open_enum;
use zerocopy::byteorder::network_endian::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
use zpr;

#[open_enum]
#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum ZdpPacketType {
    // Flow-based
    TransitPacket = 0,
    Unused1 = 1,
    DestinationUnreachable = 2,
    VisaHeraldRequest = 3,
    VisaHeraldResponse = 4,
    VisaUpdateRequest = 5,
    VisaUpdateResponse = 6,
    VisaRetractRequest = 7,
    VisaRetractResponse = 8,
    VisaDeacceptIndication = 9,
    VisaDeacceptAcknowledgement = 10,
    BindActorAddressRequest = 11,
    BindActorAddressResponse = 12,
    UnbindActorAddressRequest = 13,
    UnbindActorAddressResponse = 14,
    //AuthenticationRequest = 15,  // unused/deprecated
    SetPathMtu = 16,
    //AuthenticationResponse = 17,  // unused/deprecated

    // Not flow-based
    ZprArp = 128,
    KeyManagement = 129,
    Discard = 130,
    EchoRequest = 131,
    Unused132 = 132,
    TerminateLinkRequest = 133,
    TerminateLinkResponse = 134,
    TerminateLinkIndication = 135,
    HelloRequest = 136,
    HelloResponse = 137,
    ConfigurationRequest = 138,
    ConfigurationResponse = 139,
    AcquireZprAddressRequest = 140, // TODO: add to RFC 6
    Unused142 = 142,
    UnregisterActorAddressRequest = 143,
    UnregisterActorAddressResponse = 144,
    Report = 145,
    InitAuthenticationRequest = 146, // TODO: add to RFC 6
    Unused147 = 147,
    GrantZprAddressRequest = 148, // TODO: add to RFC 6
    Unused149 = 149,

    Acknowledgement = 255,
}

pub const ZDP_PACKET_TYPE_NON_FLOW_FLAG: u8 = 0x80;

impl ZdpPacketType {
    pub fn is_per_flow(self) -> bool {
        self.0 & ZDP_PACKET_TYPE_NON_FLOW_FLAG == 0
    }

    pub fn is_response(self) -> bool {
        // CTP: I have a pending ask to Frank to group together responses
        // so this logic becomes a simple range check

        match self {
            Self::BindActorAddressResponse => true,
            _ => false,
        }
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
    pub sequence_number: U16,
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
    // Followed by challenge payload, eg ZdpInitAuthenticationPayload below.
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpAcquireZprAddressRequestHeader {
    pub blob_len: U16,
    pub ip_version: zpr::L3Type, // Length of address determined by IP type
    pub addr_count: u8,
    // Followed in memory by:
    //  - BLOB (of blob_len bytes) is-a base64 encoded json string.
    //  - IP addresses (addr_count * IP address size bytes)
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpGrantZprAddressRequestHeader {
    pub status_code: ResponseCode,
    pub ip_version: zpr::L3Type, // Length of address determined by IP type
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

/// Terminate Link Indication (§ 6.3.3)
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpTerminateLinkIndicationHeader {
    pub reason_code: TerminateReason,
    pub data_len: u8,
}

/// Terminate Link Request (§ 6.3.3)
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpTerminateLinkRequestHeader {
    pub reason_code: TerminateReason,
    pub data_len: u8,
}

/// Terminate Link Response (§ 6.3.3)
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpTerminateLinkResponseHeader {
    pub response_code: ResponseCode,
    pub data_len: u8,
}

/// Bind Actor Address request (§ 6.3.11)
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpBindActorAddressRequestHeader {
    pub ip_version: zpr::L3Type,
    pub compression_mode: zpr::CompressionMode,
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
        self.message_type.get() == zpr::KM_ID_NOISE
    }
    /// TRUE if this is an IKEv2 KM message
    pub fn is_ikev2(&self) -> bool {
        self.message_type.get() == zpr::KM_ID_IKEV2
    }
    /// TRUE if this is an experimental KM message
    pub fn is_experiment(&self) -> bool {
        self.message_type.get() == zpr::KM_ID_EXPERIMENTAL
    }

    pub fn is_null(&self) -> bool {
        self.message_type.get() == zpr::KM_ID_NULL
    }
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
pub struct ZdpA2aHeader {
    pub a2a_said: zpr::A2aSaid,
}

/// Config-specified size of A2A MAC.  Algorithm-specified MAC may be smaller (but not larger).
pub const ZDP_A2A_MAC_SIZE: usize = 8;

/// Size of the ZDP "link" HMAC which is set link-by-link for transit packets.
/// This HMAC is tacked on to the end of the packet (following the A2A HMAC).
pub const ZDP_PACKET_MAC_SIZE: usize = 8;

const _: () = assert!(core::mem::size_of::<ZdpBaseHeader>() == 4);
const _: () = assert!(core::mem::size_of::<ZdpPerFlowHeader>() == 4);
