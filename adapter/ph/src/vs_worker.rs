use crate::assembly::Assembly;
use crate::logging::targets::VISA_MGMT;
use libnode::vsconn::VSOutput;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::*;

// TODO: It might be nice to get a message here when we establlish a a node connection to
// the VS API.  Then we could send a request for the services list.  Not a big deal until
// we have more than one node. With one node, we are always going to get a push
// update via the VSS API as we are the only way the VS can talk to the ZPRnet.

pub async fn launch(_asm: Arc<Assembly>, mut queue: mpsc::Receiver<VSOutput>) {
    while let Some(msg) = queue.recv().await {
        // Only thing that comes out of this queue is a ping-success message.
        debug!(target: VISA_MGMT, "received VS message {msg:?}; ignoring! (unimplemented)");
    }
}
