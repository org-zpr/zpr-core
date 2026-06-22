//! Async command-handler task for lntest.
//!
//! Connects to the visa service, then drives a `tokio::select!` loop that
//! processes lifecycle events, user commands, and incoming VSS messages until
//! the user disconnects.

use openssl::rand::rand_bytes;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::{broadcast, mpsc};
use tokio::task::AbortHandle;
use tracing::{error, info, warn};
use zpr::vsapi_types::{
    AuthBlob, CommFlag, ConnectRequest, DisconnectNotice, DisconnectReason, NodeConnect,
    PacketDesc, StateFlag, VisaOp, VisaRequest,
};

use crate::vsconn::{VSConnHandle, VSConnLifecycleEvent};
use crate::vss::{ListProcessingResponse, VSSMessage};

use super::cmd::Cmd;
use super::crypto::{build_self_signed_blob, load_private_key};

/// Run the async command handler.
///
/// Connects to the visa service, then loops over lifecycle events from
/// `life_rx`, user commands from `cmd_rx`, and VSS server messages from
/// `vss_rx`. Sends human-readable status strings to `output_tx` for display
/// in the TUI REPL pane.
///
/// When the handler exits (either due to a [Cmd::Disconnect] or a fatal
/// error) it stops the VSConn and aborts `vss_aborter`.
pub async fn run_handler(
    handle: VSConnHandle,
    node_zpr_addr: IpAddr,
    mut life_rx: broadcast::Receiver<VSConnLifecycleEvent>,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    mut vss_rx: mpsc::Receiver<VSSMessage>,
    output_tx: mpsc::UnboundedSender<String>,
    vss_aborter: AbortHandle,
) -> Result<(), crate::error::VSApiError> {
    info!("allowing VSConn to start up...");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let request = NodeConnect {
        zpr_addr: node_zpr_addr,
        state: StateFlag::NoState,
    };

    info!("requesting a connect");
    let mut connected = false;
    match handle.connect(request).await {
        Ok(resp) => {
            info!("Connection response: {:?}", resp);
            let _ = output_tx.send("connected".to_string());
            connected = true;
        }
        Err(e) => {
            error!("connection failed: {:?}", e);
            let _ = output_tx.send(format!("connection failed: {:?}", e));
        }
    }

    if connected {
        loop {
            tokio::select! {
                event_res = life_rx.recv() => {
                    match event_res {
                        Ok(event) => {
                            match event {
                                VSConnLifecycleEvent::RunLoopStarts =>
                                    info!("lifecycle event: VSConn run loop starts"),
                                VSConnLifecycleEvent::ConnectedToVsApi(state_flag) =>
                                    info!("lifecycle event: connected to VS API ({state_flag:?})"),
                                VSConnLifecycleEvent::RunLoopExits =>
                                    info!("lifecycle event: VSConn run loop exits"),
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!("lifecycle event receiver lagged, skipped {} messages", skipped);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            warn!("lifecycle event sender closed");
                        }
                    }
                }

                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        Cmd::Nop => {}
                        Cmd::Disconnect => break,
                        Cmd::VisaRequest(five_tuple) => {
                            let pdesc = PacketDesc {
                                five_tuple,
                                comm_flags: CommFlag::BiDirectional,
                            };
                            let req = VisaRequest {
                                pdesc,
                                previous_id: None,
                            };
                            match handle.visa_request(req).await {
                                Ok(decision) => {
                                    let _ = output_tx.send(format!("visa_request decision: {:?}", decision));
                                }
                                Err(e) => {
                                    let _ = output_tx.send(format!("visa_request failed: {:?}", e));
                                }
                            }
                        }
                        Cmd::RegisterVss(saddr) => {
                            match handle.register_vss(saddr).await {
                                Ok(ops) => {
                                    let _ = output_tx.send(format!(
                                        "register_vss succeeded: got {} VisaOps", ops.len()
                                    ));
                                    for vo in &ops {
                                        match vo {
                                            VisaOp::Grant(v) => {
                                                let _ = output_tx.send(format!("  visa id: {}", v.issuer_id));
                                            }
                                            VisaOp::RevokeVisaId(vid) => {
                                                let _ = output_tx.send(format!("  revoke visa id: {}", vid));
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = output_tx.send(format!("register_vss failed: {:?}", e));
                                }
                            }
                        }
                        Cmd::NotifyDisconnect(zpr_addr) => {
                            let notice = DisconnectNotice {
                                zpr_addr: Some(zpr_addr),
                                reason: DisconnectReason::Admin,
                            };
                            match handle.notify_disconnect(notice).await {
                                Ok(()) => {
                                    let _ = output_tx.send("notify_disconnect succeeded".to_string());
                                }
                                Err(e) => {
                                    let _ = output_tx.send(format!("notify_disconnect failed: {:?}", e));
                                }
                            }
                        }
                        Cmd::AuthorizeConnect(key_path, claims) => {
                            let adapter_key = match load_private_key(&key_path) {
                                Ok(k) => k,
                                Err(e) => {
                                    let _ = output_tx.send(format!("failed to load adapter key: {}", e));
                                    continue;
                                }
                            };

                            let cn = match claims.iter().find(|c| c.key == "endpoint.zpr.adapter.cn") {
                                Some(c) => c.value.clone(),
                                None => {
                                    let _ = output_tx.send("error: endpoint.zpr.adapter.cn claim is required".to_string());
                                    continue;
                                }
                            };

                            let blob = match build_self_signed_blob(&cn, &adapter_key) {
                                Ok(b) => b,
                                Err(e) => {
                                    let _ = output_tx.send(format!("failed to build self-signed blob: {}", e));
                                    continue;
                                }
                            };

                            let mut rand_octets = [0u8; 3];
                            rand_bytes(&mut rand_octets).unwrap();
                            let substrate_addr = IpAddr::V4(Ipv4Addr::new(
                                10, rand_octets[0], rand_octets[1], rand_octets[2],
                            ));

                            let connect_req = ConnectRequest {
                                blobs: vec![AuthBlob::SS(blob)],
                                claims,
                                substrate_addr,
                                dock_interface: 0,
                            };

                            match handle.authorize_connect(connect_req).await {
                                Ok(conn) => {
                                    let _ = output_tx.send(format!(
                                        "authorize_connect succeeded: zpr_addr={}, auth_expires={}",
                                        conn.zpr_addr, conn.auth_expires
                                    ));
                                }
                                Err(e) => {
                                    let _ = output_tx.send(format!("authorize_connect failed: {:?}", e));
                                }
                            }
                        }
                    }
                }

                Some(vss_msg) = vss_rx.recv() => {
                    match vss_msg {
                        VSSMessage::PushVisaOp(visa_ops, resp_tx) => {
                            let _ = output_tx.send(format!(
                                "[VSS incoming] PushVisaOp with {} ops", visa_ops.len()
                            ));
                            let _ = resp_tx.send(ListProcessingResponse::Ack { processed: visa_ops.len() as u32 });
                        }
                        VSSMessage::RevokeAuth(ip_addrs, resp_tx) => {
                            let _ = output_tx.send(format!(
                                "[VSS incoming] RevokeAuth for {} addresses", ip_addrs.len()
                            ));
                            let _ = resp_tx.send(ListProcessingResponse::Ack { processed: ip_addrs.len() as u32 });
                        }
                        VSSMessage::SetServices(services, resp_tx) => {
                            let _ = output_tx.send(format!(
                                "[VSS incoming] SetServices with {} services", services.len()
                            ));
                            let _ = resp_tx.send(Ok(()));
                        }
                        VSSMessage::SetTopology(links, resp_tx) => {
                            let _ = output_tx.send(format!(
                                "[VSS incoming] SetTopology with {} links", links.len()
                            ));
                            let _ = resp_tx.send(Ok(()));
                        }
                        VSSMessage::Configure(params, resp_tx) => {
                            let _ = output_tx.send(format!(
                                "[VSS incoming] Configure with {} params:", params.len())
                            );
                            for p in &params {
                                let _ = output_tx.send(format!("[VSS incoming] param >>  {}: {:?}", p.name, p.value));
                            }
                            let _ = resp_tx.send(Ok(()));
                        }
                    }
                }
            }
        }
    }

    info!("requesting a stop");
    match handle.stop(true).await {
        Ok(_) => {
            info!("stopped VSConn");
            let _ = output_tx.send("stopped vsconn".to_string());
        }
        Err(e) => {
            error!("failed to stop VSConn: {:?}", e);
            let _ = output_tx.send(format!("failed to stop VSConn: {:?}", e));
        }
    }
    vss_aborter.abort();

    Ok(())
}
