use crate::assembly::Assembly;
use libnode::vsconn::VSOutput;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::*;

pub async fn launch(_asm: Arc<Assembly>, mut queue: mpsc::Receiver<VSOutput>) {
    while let Some(msg) = queue.recv().await {
        debug!("received VS message {msg:?}; ignoring! (unimplemented)");
    }
}
