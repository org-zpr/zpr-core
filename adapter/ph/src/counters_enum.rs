use enum_map::Enum;

#[derive(Debug, Enum)]
pub enum CounterType {
    InPacksRec,
    InPacksDrop,
    InPacksSent,
    OutPacksRec,
    OutPacksDrop,
    OutPacksSent,
}

// pub fn new_counters_array() {
//     let enum_map: EnumMap<CounterType, Counter> = enum_map! { _ => Counter::new(), };
// }

pub fn name_counters(count_num: CounterType) -> String {
    let s;
    match count_num {
        CounterType::InPacksRec   => s = "Inbound Packets Recieved",
        CounterType::InPacksDrop  => s = "Inbound Packets Dropped",
        CounterType::InPacksSent  => s = "Inbound Packets Sent",
        CounterType::OutPacksRec  => s = "Outbound Packets Recieved",
        CounterType::OutPacksDrop => s = "Outbound Packets Dropped",
        CounterType::OutPacksSent => s = "Outbound Packets Sent",
    };

    s.to_string()
}
