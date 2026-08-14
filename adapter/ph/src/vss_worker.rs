use crate::address_pool::AddressPool;
use crate::link_state::PeerMode;
use crate::prelude::*;
use crate::{visa_mgmt, visa_table};

use libnode::vss::{ConfigureResponse, ListProcessingResponse, SetTopologyResponse, VSSMessage};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use zpr::vsapi_types::{ApiResponseError, ErrorCode, Link, Param, ParamValue, VisaOp, pname};
use zpr_utils::net_defs::SocketAddrExt;

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

/// Connect to other nodes as instructed by the Visa Service
fn process_topology(asm: &Arc<Assembly>, links: Vec<Link>) -> SetTopologyResponse {
    let mut self_addr = asm.config.get().self_addr.scoped_ip().clone();

    info!(target: VSS_RPC, "Received topology update with {} links", links.len());
    for (i, link) in links.into_iter().enumerate() {
        info!(target: VSS_RPC, "[link {i}]-> {:?}", link.peer);
        let peer_addr = SocketAddr::from(link.peer.clone());

        // A node binds to the wildcard address, so resolve the dock address we
        // would actually use for this peer *before* the peer table lookup:
        // existing peers are keyed on the real dock address, and looking up with
        // the unspecified address misses them and creates a duplicate.
        if self_addr.ip().is_unspecified() {
            let temp_socket = socket2::Socket::new(
                socket2::Domain::for_address(peer_addr),
                socket2::Type::DGRAM,
                None,
            )
            .unwrap();
            temp_socket
                .connect(&socket2::SockAddr::from(peer_addr))
                .expect(&format!("unable to connect to peer_addr ({})", peer_addr));

            self_addr = temp_socket
                .local_addr()
                .unwrap()
                .as_socket()
                .unwrap()
                .scoped_ip();
            info!(target: VSS_RPC, "assigned substrate address {self_addr}");
        }

        match asm.peer_table.lookup_peer(&peer_addr, &self_addr) {
            Some(link_id) => {
                // The peer beat us to it and tethered inbound; it sends its own
                // bootstrap visas with its hello, so link.visas is redundant here.
                info!(target:VSS_RPC, "Link already exists as {link_id}");
            }
            None => {
                if asm
                    .start_tether(&peer_addr, &self_addr, PeerMode::Node, true, link.visas)
                    .ok()
                    .is_none()
                {
                    error!(target:VSS_RPC, "Failed to start link with {:?}", link.peer);
                }
            }
        }
    }
    Ok(())
}
