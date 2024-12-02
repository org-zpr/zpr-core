use crate::assembly::Assembly;
use libnode::vss::VSSMsg;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::*;

pub async fn launch(asm: Arc<Assembly>, mut queue: mpsc::Receiver<VSSMsg>) {
    while let Some(msg) = queue.recv().await {
        info!(
            "{}: received VSS message {msg:?}; ignoring! (unimplemented)",
            asm.system_name
        );
    }
}
