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
                let visa_id = visa.issuer_id.unwrap_or_default();
                debug!(target: VISA_MGMT, "Received pushed visa, id={visa_id}");
                let result = visa_mgmt::parse_visa(&asm, visa);
                if let Err(e) = result.await {
                    error!(target: VISA_MGMT, "Error inserting visa {visa_id}: {e}");
                }
            }
            VSSMsg::PushedRevocation(revocation) => {
                debug!(target: VISA_MGMT, "Received pushed revocation, id={}", revocation.issuer_id.unwrap());
                let result = visa_mgmt::handle_revocation(&asm, revocation);
                if let Err(e) = result.await {
                    error!(target: VISA_MGMT, "Error revoking visa: {e}");
                }
            }
            VSSMsg::PushedServices(services) => {
                let result = visa_mgmt::handle_services_update(&asm, services);
                if let Err(e) = result.await {
                    error!(target: VISA_MGMT, "Error processing services update: {e}");
                }
            }
            _ => {
                error!(target: VISA_MGMT, "received VSS message {msg}; ignoring! (unimplemented)");
            }
        }
    }
}
