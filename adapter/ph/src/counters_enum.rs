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
