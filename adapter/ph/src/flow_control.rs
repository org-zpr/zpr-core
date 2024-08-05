use cbpf_rs::BpfProgram;
use std::sync::RwLock;

pub struct FlowControl {
    // TODO: replace this with RCU
    inner_control: RwLock<InnerFlow>,
}

struct InnerFlow {
    flow: Option<BpfProgram>,
}

impl FlowControl {
    pub fn new() -> Self {
        Self {
            inner_control: InnerFlow { flow: None }.into(),
        }
    }

    pub fn set_program(&self, program: BpfProgram) {
        self.inner_control.write().unwrap().flow = Some(program);
    }

    pub fn delete_program(&self) {
        self.inner_control.write().unwrap().flow = None;
    }

    pub fn check_packet(&self, packet: &[u8]) -> u32 {
        let inner_flow = &self.inner_control.read().unwrap().flow;
        match inner_flow {
            Some(program) => program.filter(packet),
            None => 0,
        }
    }

    pub fn program_exists(&self) -> bool {
        let inner_flow = &self.inner_control.read().unwrap().flow;
        inner_flow.is_some()
    }
}
