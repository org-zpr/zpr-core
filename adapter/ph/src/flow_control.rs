// Controls whether a packet will be copied and captured in the packet
// capture framework

use crate::rcu::RcuBox;
use cbpf_rs::BpfProgram;

pub struct FlowControl {
    inner_control: RcuBox<InnerFlow>,
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
        self.inner_control.write(InnerFlow {
            flow: Some(program),
        });
    }

    pub fn delete_program(&self) {
        self.inner_control.write(InnerFlow { flow: None });
    }

    pub fn check_packet(&self, packet: &[u8]) -> u32 {
        self.inner_control
            .inspect(|inner_flow| match &inner_flow.flow {
                Some(program) => program.filter(packet),
                None => 0,
            })
    }

    pub fn program_exists(&self) -> bool {
        self.inner_control
            .inspect(|inner_flow| inner_flow.flow.is_some())
    }
}
