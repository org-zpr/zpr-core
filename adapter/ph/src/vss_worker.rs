use crate::address_pool::AddressPool;
use crate::prelude::*;
use crate::{visa_mgmt, visa_table};

use libnode::vss::{ConfigureResponse, ListProcessingResponse, SetTopologyResponse, VSSMessage};
use tokio::sync::mpsc;
use zpr::packet_info::VisaId;
use zpr::vsapi_types::{ApiResponseError, ErrorCode, Link, Param, ParamValue, VisaOp, pname};

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
                warn!(target: VSS_RPC, "received revoke_auth for {} addresses (not yet implemented)", addrs.len());
                let _ = resp_tx.send(ListProcessingResponse::Ack {
                    processed: addrs.len() as u32,
                });
            }

            VSSMessage::SetServices(services, resp_tx) => {
                debug!(target: VSS_RPC, "received services update with {} entries", services.len());
                let mut svcs = asm.vs_auth_services.write().unwrap();
                svcs.update(None, services);
                let _ = resp_tx.send(Ok(()));
            }

            VSSMessage::Configure(params, resp_tx) => {
                debug!(target: VSS_RPC, "received VSS configuration update with {} entries", params.len());
                let resp = process_configuration(&asm, params);
                let _ = resp_tx.send(resp);
            }

            VSSMessage::SetTopology(links, resp_tx) => {
                debug!(target: VSS_RPC, "received topology update with {} links", links.len());
                let resp = process_topology(&asm, links);
                let _ = resp_tx.send(resp);
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

/// Visa service sends configuration info here. Currently includes:
/// - AAA network to use (will be updated on the assembly).
fn process_configuration(asm: &Arc<Assembly>, params: Vec<Param>) -> ConfigureResponse {
    let mut aaa_ipnet_str = None;

    for param in params {
        match param.name.as_str() {
            pname::AAA_PREFIX => match param.value {
                ParamValue::StrParam(s) => {
                    if aaa_ipnet_str.is_some() {
                        error!(target: VSS_RPC, "multiple AAA_PREFIX parameters received");
                        return Err(ApiResponseError {
                            code: ErrorCode::ParamError,
                            message: "multiple AAA_PREFIX parameters".into(),
                            retry_in: 0,
                        });
                    }
                    aaa_ipnet_str = Some(s);
                }
                _ => {
                    error!(target: VSS_RPC, "invalid value type for AAA_PREFIX param");
                    return Err(ApiResponseError {
                        code: ErrorCode::ParamError,
                        message: "invalid type for AAA_PREFIX".into(),
                        retry_in: 0,
                    });
                }
            },
            _ => {
                info!(target: VSS_RPC, "unrecognized configuration parameter: {}", param.name);
            }
        }
    }

    if let Some(net) = aaa_ipnet_str {
        match net.parse() {
            Ok(ipnet) => {
                let pool = AddressPool::new(ipnet).map_err(|e| {
                    error!(target: VSS_RPC, "rejected AAA_PREFIX value: {e}");
                    ApiResponseError {
                        code: ErrorCode::ParamError,
                        message: format!("AAA_PREFIX rejected"),
                        retry_in: 0,
                    }
                })?;

                debug!(target: VSS_RPC, "updating local AAA address pool with network {}", ipnet);
                asm.address_pool.lock().unwrap().replace(pool);
            }
            Err(e) => {
                error!(target: VSS_RPC, "invalid AAA_PREFIX value: {e}");
                return Err(ApiResponseError {
                    code: ErrorCode::ParamError,
                    message: format!("invalid AAA_PREFIX"),
                    retry_in: 0,
                });
            }
        }
    }

    Ok(())
}

/// Placeholder. Links not yet acted on.
fn process_topology(_asm: &Arc<Assembly>, links: Vec<Link>) -> SetTopologyResponse {
    info!(target: VSS_RPC, "received topology update with {} links (not yet implemented)", links.len());
    for (i, link) in links.iter().enumerate() {
        info!(target: VSS_RPC, "[link {i}]-> {:?}", link.peer);
    }
    Ok(())
}
