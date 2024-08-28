#![allow(dead_code)]

use open_enum::open_enum;
use zerocopy::byteorder::network_endian::*;
use zerocopy::{AsBytes, FromBytes, FromZeroes, Unaligned};

use crate::zpr;

#[open_enum]
#[derive(Copy, Clone, Debug, FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(u8)]
pub enum ZdpPacketType {
    // Flow-based
    TransitPacket = 0,
    Unused = 1,
    DestinationUnreachable = 2,
    VisaHeraldRequest = 3,
    VisaHeraldResponse = 4,
    VisaUpdateRequest = 5,
    VisaUpdateResponse = 6,
    VisaRetractRequest = 7,
    VisaRetractResponse = 8,
    VisaDeacceptIndication = 9,
    VisaDeacceptAcknowledgement = 10,
    BindAgentAddressRequest = 11,
    BindAgentAddressResponse = 12,
    UnbindAgentAddressRequest = 13,
    UnbindAgentAddressResponse = 14,
    AuthenticationRequest = 15,
    SetPathMtu = 16,
    AuthenticationResponse = 17,
    // Not flow-based
    ZprArp = 128,
    KeyManagement = 129,
    Discard = 130,
    EchoRequest = 131,
    EchoResponse = 132,
    TerminateLinkRequest = 133,
    TerminateLinkResponse = 134,
    TerminateLinkIndication = 135,
    HelloRequest = 136,
    HelloResponse = 137,
    ConfigurationRequest = 138,
    ConfigurationResponse = 139,
    RegisterAgentAddressRequest = 140,
    RegisterAgentAddressResponse = 142,
    UnregisterAgentAddressRequest = 143,
    UnregisterAgentAddressResponse = 144,
    Report = 145,
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
            Self::VisaHeraldResponse
            | Self::VisaUpdateResponse
            | Self::VisaRetractResponse
            | Self::VisaDeacceptAcknowledgement
            | Self::BindAgentAddressResponse
            | Self::UnbindAgentAddressResponse
            | Self::AuthenticationResponse
            | Self::EchoResponse
            | Self::TerminateLinkResponse
            | Self::HelloResponse
            | Self::ConfigurationResponse
            | Self::RegisterAgentAddressResponse
            | Self::UnregisterAgentAddressResponse => true,
            _ => false,
        }
    }
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
pub struct ZdpZpiHeader {
    pub zpi: u8,
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
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

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
pub struct ZdpPerFlowHeader {
    pub stream_id: U32,
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
pub struct ZdpEchoHeader {
    pub base_header: ZdpBaseHeader,
    pub sequence_number: U16, // Only used for the response
    pub additional_length: U16,
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
pub struct ZdpReportHeader {
    pub report_data_length: U16,
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
pub struct ZdpHelloResponseHeader {
    pub status: U16,
}

/// Bind Agent Address request (§ 6.3.11)
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
pub struct ZdpBindAgentAddressRequestHeader {
    pub ip_version: zpr::L3Type,
    pub compression_mode: zpr::CompressionMode,
}

/// Bind Agent Address response (§ 6.3.11)
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
pub struct ZdpBindAgentAddressResponseHeader {
    pub status_code: u8,
    pub info_len: u8,
}

impl ZdpBindAgentAddressResponseHeader {
    pub const STATUS_CODE_SUCCESS: u8 = 0;
    pub const STATUS_CODE_OTHER: u8 = 1;
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
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
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
pub struct ZdpA2aHeader {
    pub a2a_said: zpr::A2aSaid,
}

/// Config-specified size of A2A MAC.  Algorithm-specified MAC may be smaller (but not larger).
pub const ZDP_A2A_MAC_SIZE: usize = 8;

const _: () = assert!(core::mem::size_of::<ZdpBaseHeader>() == 4);
const _: () = assert!(core::mem::size_of::<ZdpPerFlowHeader>() == 4);
