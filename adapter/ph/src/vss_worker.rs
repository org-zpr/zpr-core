use crate::assembly::Assembly;
use crate::logging::targets::VISA_MGMT;
use crate::{visa_mgmt, visa_table};
use libnode::vss::{ListProcessingResponse, VSSMessage};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::*;
use zpr::packet_info::VisaId;
use zpr::vsapi_types::{ErrorCode, VisaOp};

pub async fn launch(asm: Arc<Assembly>, mut queue: mpsc::Receiver<VSSMessage>) {
    while let Some(msg) = queue.recv().await {
        match msg {
            VSSMessage::PushVisaOp(ops, resp_tx) => {
                let mut processed = 0u32;
                let mut failed = false;
                for op in ops {
                    match process_visaop(&asm, op) {
                        Ok(()) => processed += 1,
                        Err(e) => {
                            error!(target: VISA_MGMT, "error processing pushed visa op: {e}");
                            failed = true;
                            break;
                        }
                    }
                }
                let resp = if failed {
                    ListProcessingResponse::Failed {
                        processed,
                        e: ErrorCode::Internal,
                    }
                } else {
                    ListProcessingResponse::Ack { processed }
                };
                let _ = resp_tx.send(resp);
            }

            VSSMessage::RevokeAuth(addrs, resp_tx) => {
                // TODO: Implement auth revocation by ZPR address.
                // If ADDR is docked here we terminate and remove assoicated visas.
                warn!(target: VISA_MGMT, "received revoke_auth for {} addresses (not yet implemented)", addrs.len());
                let _ = resp_tx.send(ListProcessingResponse::Ack {
                    processed: addrs.len() as u32,
                });
            }

            VSSMessage::SetServices(version, services, resp_tx) => {
                debug!(target: VISA_MGMT, "received services update v{version} with {} entries", services.len());
                let mut svcs = asm.vs_auth_services.write().unwrap();
                svcs.update(None, services);
                let _ = resp_tx.send(Ok(()));
            }
        }
    }
}

pub fn process_visaop(asm: &Arc<Assembly>, op: VisaOp) -> Result<(), visa_table::VisaTableError> {
    match op {
        VisaOp::Grant(visa) => {
            let visa_id = visa.issuer_id;
            debug!(target: VISA_MGMT, "received pushed visa, id={visa_id}");
            let _vid = visa_mgmt::insert_visa(asm, visa)?;
        }
        VisaOp::RevokeVisaId(id) => {
            debug!(target: VISA_MGMT, "received pushed revocation, id={id}");
            visa_mgmt::handle_revocation(asm, id as VisaId)?;
        }
    }
    Ok(())
}
