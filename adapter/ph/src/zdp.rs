#![allow(dead_code)]

use open_enum::open_enum;
use zerocopy::byteorder::network_endian::*;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes, Unaligned};

#[open_enum]
#[derive(Copy, Clone, FromZeroes, FromBytes, AsBytes, Unaligned)]
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

impl ZdpPacketType {
    pub fn is_per_flow(self) -> bool {
        self.0 < 128
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
    pub status: u16,
}

const _: () = assert!(core::mem::size_of::<ZdpBaseHeader>() == 4);
const _: () = assert!(core::mem::size_of::<ZdpPerFlowHeader>() == 4);
