use pcap::BpfProgram;
use tokio::sync::Mutex;

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
        inner_flow.is_some()
    }
}