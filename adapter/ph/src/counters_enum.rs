// Allows for easy access to name of each counter as well as index in
// counters array

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
    BadMgmtResponse,
    UnexpectedMgmtResponse,

    // § 8.2.1
    UnknownZpi,
    SequenceError,
    MicvFailure,
    DecryptionFailure,
    UnknownType,
    UnknownStreamId,
    BadStructure,
    OtherError,
}

pub fn name_counters(count_num: CounterType) -> &'static str {
    match count_num {
        CounterType::InPacksRec => "Inbound Packets Received",
        CounterType::InPacksDrop => "Inbound Packets Dropped",
        CounterType::InPacksSent => "Inbound Packets Sent",
        CounterType::OutPacksRec => "Outbound Packets Received",
        CounterType::OutPacksDrop => "Outbound Packets Dropped",
        CounterType::OutPacksSent => "Outbound Packets Sent",
        CounterType::OutPacksErr => "Outbound Packet Send Errors",
        CounterType::InCapPacksWrite => "Inbound Capture Packets Written",
        CounterType::OutCapPacksWrite => "Outbound Capture Packets Written",
        CounterType::InCapPacksDrop => "Inbound Capture Packets Dropped",
        CounterType::OutCapPacksDrop => "Outbound Capture Packets Dropped",
        CounterType::InCapPacksFilt => "Inbound Capture Packets Filtered",
        CounterType::OutCapPacksFilt => "Outbound Capture Packets Filtered",
        CounterType::BadMgmtResponse => "Bad Management Response",
        CounterType::UnexpectedMgmtResponse => "Unexpected Management Response",

        // § 8.2.1
        CounterType::UnknownZpi => "Unknown ZPI",
        CounterType::SequenceError => "Sequence Error",
        CounterType::MicvFailure => "MICV Failure",
        CounterType::DecryptionFailure => "Decryption Failure",
        CounterType::UnknownType => "Unknown Type",
        CounterType::UnknownStreamId => "Unknown Stream ID",
        CounterType::BadStructure => "Bad Structure",
        CounterType::OtherError => "Other Error",
    }
}

impl fmt::Display for CounterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", name_counters(*self))
    }
}
