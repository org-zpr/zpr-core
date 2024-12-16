use crate::assembly::Assembly;
use crate::logging::targets::VISA_MGMT;
use libnode::vss::VSSMsg;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::*;

pub async fn launch(_asm: Arc<Assembly>, mut queue: mpsc::Receiver<VSSMsg>) {
    while let Some(msg) = queue.recv().await {
        info!(target: VISA_MGMT, "received VSS message {msg:?}; ignoring! (unimplemented)");
    }
}
