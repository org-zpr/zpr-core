//! Allows for easy access to name of each counter as well as index in
//! counters array

use enum_map::Enum;
use std::fmt;

#[derive(Debug, Enum, Copy, Clone)]
pub enum CounterType {
    InPacksRec,
    InPacksDrop,
    InPacksSent,
    OutPacksRec,
    OutPacksDrop,
    OutPacksSent,
    OutPacksErr,
    InCapPacksWrite,
    OutCapPacksWrite,
    InCapPacksDrop,
    OutCapPacksDrop,
    InCapPacksFilt,
    OutCapPacksFilt,

    QueueBackpressure,
    DroppedAwaitingBind,
    DroppedNop,       // normal, not an error drop
    DroppedDuplicate, // some sort of duplicate detected
    DroppedNoSA,      // no security association on link

    BadMgmtResponse,
    UnexpectedMgmtResponse,

    UnknownPeer,
    PeerRemoved,

    // RFC 6.5 § 8.2.1
    UnknownZpi,
    SequenceError,
    MicvFailure,
    DecryptionFailure,
    EncryptionFailure,
    UnknownType,
    UnknownStreamId,
    BadStructure,
    OtherError,

    #[cfg(debug_assertions)]
    AgentPacketsOutOfOrder,
}

impl CounterType {
    pub fn name(&self) -> &'static str {
        match *self {
            Self::InPacksRec => "Inbound Packets Received",
            Self::InPacksDrop => "Inbound Packets Dropped",
            Self::InPacksSent => "Inbound Packets Sent",
            Self::OutPacksRec => "Outbound Packets Received",
            Self::OutPacksDrop => "Outbound Packets Dropped",
            Self::OutPacksSent => "Outbound Packets Sent",
            Self::OutPacksErr => "Outbound Packet Send Errors",
            Self::InCapPacksWrite => "Inbound Capture Packets Written",
            Self::OutCapPacksWrite => "Outbound Capture Packets Written",
            Self::InCapPacksDrop => "Inbound Capture Packets Dropped",
            Self::OutCapPacksDrop => "Outbound Capture Packets Dropped",
            Self::InCapPacksFilt => "Inbound Capture Packets Filtered",
            Self::OutCapPacksFilt => "Outbound Capture Packets Filtered",

            Self::QueueBackpressure => "QueueBackpressure",
            Self::DroppedAwaitingBind => "Dropped Awaiting Bind",
            Self::DroppedDuplicate => "Dropped Duplicate",
            Self::DroppedNop => "Dropped No Operation",
            Self::DroppedNoSA => "Dropped No Security Association",

            Self::BadMgmtResponse => "Bad Management Response",
            Self::UnexpectedMgmtResponse => "Unexpected Management Response",

            Self::UnknownPeer => "Unknown Peer",
            Self::PeerRemoved => "Peer Removed",

            // § 8.2.1
            Self::UnknownZpi => "Unknown ZPI",
            Self::SequenceError => "Sequence Error",
            Self::MicvFailure => "MICV Failure",
            Self::DecryptionFailure => "Decryption Failure",
            Self::EncryptionFailure => "Encryption Failure",
            Self::UnknownType => "Unknown Type",
            Self::UnknownStreamId => "Unknown Stream ID",
            Self::BadStructure => "Bad Structure",
            Self::OtherError => "Other Error",

            #[cfg(debug_assertions)]
            Self::AgentPacketsOutOfOrder => "Agent Packets Out-Of-Order",
        }
    }
}

impl fmt::Display for CounterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
