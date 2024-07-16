use pcap::BpfProgram;
// use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
// use tokio::sync::RwLock;

pub const DIRECTION_HEADER_SIZE: usize = 1;

pub struct FlowControl {
    inner_control: Mutex<InnerFlow>,
}

struct InnerFlow {
    flow: Option<BpfProgram>,
}

impl FlowControl {
    pub(crate) fn new() -> Self {
        Self {
            inner_control: InnerFlow { flow: None }.into(),
        }
    }

    pub async fn set_program(&self, program: BpfProgram) {
        self.inner_control.lock().await.flow = Some(program);
    }

    pub async fn delete_program(&self) {
        self.inner_control.lock().await.flow = None;
    }

    pub async fn check_packet(&self, packet: &[u8]) -> bool {
        let inner_flow = &mut self.inner_control.lock().await.flow;
        match inner_flow {
            Some(program) => program.filter(packet),
            None => false,
        }
    }

    pub async fn program_exists(&self) -> bool {
        let inner_flow = &mut self.inner_control.lock().await.flow;
        match inner_flow {
            Some(_) => true,
            None => false,
        }
    }

    // Stubs for now, allow code to compile as I change things incrementally
    pub fn set_inbound(&self, _val: bool) {}
    pub fn set_outbound(&self, _val: bool) {}
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_new_fc() {
//         let fc = FlowControl::new();
//         assert_eq!(fc.get_inbound(), false);
//         assert_eq!(fc.get_outbound(), false);
//     }

//     #[test]
//     fn test_new_fc_reverse() {
//         let fc = FlowControl::new();
//         assert_eq!(fc.get_inbound(), false);
//         fc.set_outbound(true);
//         assert_eq!(fc.get_outbound(), true);
//     }

//     #[test]
//     fn test_store_fc() {
//         let fc = FlowControl::new();
//         assert_eq!(fc.get_inbound(), false);
//         assert_eq!(fc.get_outbound(), false);

//         fc.set_inbound(false);
//         assert_eq!(fc.get_inbound(), false);
//         assert_eq!(fc.get_outbound(), false);

//         fc.set_inbound(true);
//         assert_eq!(fc.get_inbound(), true);
//         assert_eq!(fc.get_outbound(), false);
//     }

//     #[test]
//     fn test_same_fc() {
//         let fc = FlowControl::new();
//         assert_eq!(fc.get_inbound(), false);
//         assert_eq!(fc.get_outbound(), false);

//         fc.set_inbound(true);
//         fc.set_outbound(false);
//         assert_eq!(fc.get_inbound(), true);
//         assert_eq!(fc.get_outbound(), false);
//     }
// }

// pub struct FlowControl {
//     inner_control: RwLock<InnerControl>
// }

// struct InnerControl {
//     flow_control: Option<BpfProgram>
// }

// #[allow(dead_code)]
// impl FlowControl {
//     pub(crate) fn new() -> Self {
//         Self {
//             inner_control: InnerControl {
//                 flow_control: None
//             }
//         }
//     }
// }
