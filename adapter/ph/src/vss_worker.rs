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
                let visa_id = visa.issuer_id;
                debug!(target: VISA_MGMT, "Received pushed visa, id={visa_id}");
                if let Err(e) = visa_mgmt::parse_visa(&asm, visa) {
                    error!(target: VISA_MGMT, "Error inserting visa {visa_id}: {e}");
                }
            }
            VSSMsg::PushedRevocation(revocation) => {
                debug!(target: VISA_MGMT, "Received pushed revocation, id={}", revocation.issuer_id.unwrap());
                if let Err(e) = visa_mgmt::handle_revocation(&asm, revocation) {
                    error!(target: VISA_MGMT, "Error revoking visa: {e}");
                }
            }
            VSSMsg::PushedServices(services) => {
                if let Err(e) = visa_mgmt::handle_services_update(&asm, services) {
                    error!(target: VISA_MGMT, "Error processing services update: {e}");
                }
            }
            _ => {
                error!(target: VISA_MGMT, "received VSS message {msg}; ignoring! (unimplemented)");
            }
        }
    }
}
