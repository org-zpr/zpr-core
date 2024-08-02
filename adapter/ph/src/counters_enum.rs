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
    BadMgmtResponse,
    UnexpectedMgmtResponse,
}

pub fn name_counters(count_num: CounterType) -> String {
    let s;
    match count_num {
        CounterType::InPacksRec => s = "Inbound Packets Recieved",
        CounterType::InPacksDrop => s = "Inbound Packets Dropped",
        CounterType::InPacksSent => s = "Inbound Packets Sent",
        CounterType::OutPacksRec => s = "Outbound Packets Recieved",
        CounterType::OutPacksDrop => s = "Outbound Packets Dropped",
        CounterType::OutPacksSent => s = "Outbound Packets Sent",
        CounterType::OutPacksErr => s = "Outbound Packet Send Errors",
        CounterType::InCapPacksWrite => s = "Inbound Capture Packets Written",
        CounterType::OutCapPacksWrite => s = "Outbound Capture Packets Written",
        CounterType::InCapPacksDrop => s = "Inbound Capture Packets Dropped",
        CounterType::OutCapPacksDrop => s = "Outbound Capture Packets Dropped",
        CounterType::BadMgmtResponse => s = "Bad Management Response",
        CounterType::UnexpectedMgmtResponse => s = "Unexpected Management Response",
    };

    s.to_string()
}

impl fmt::Display for CounterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", name_counters(*self))
    }
}
