use crate::assembly::Assembly;
use crate::logging::targets::VISA_MGMT;
use crate::visa_mgmt;
use libnode::vss::VSSMsg;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::*;

pub async fn launch(asm: Arc<Assembly>, mut queue: mpsc::Receiver<VSSMsg>) {
    while let Some(msg) = queue.recv().await {
        match msg {
            VSSMsg::PushedVisa(visa) => {
                let _ = visa_mgmt::parse_visa(&asm, visa);
            }
            VSSMsg::PushedRevocation(revocation) => {
                let _ = visa_mgmt::handle_revocation(&asm, revocation);
            }
            _ => {
                error!(target: VISA_MGMT, "received VSS message {msg}; ignoring! (unimplemented)");
            }
        }
    }
}
