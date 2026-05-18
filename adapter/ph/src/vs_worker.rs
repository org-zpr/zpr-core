use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info};

use crate::assembly::Assembly;
use crate::config;
use crate::logging::targets::STARTUP;
use crate::vss_worker;

use libnode::error::VSApiError;
use libnode::vsconn::{VSConnHandle, VSConnLifecycleEvent};
use zpr::vsapi_types::{DisconnectNotice, DisconnectReason, ErrorCode, NodeConnect, StateFlag};

pub async fn launch(
    asm: Arc<Assembly>,
    node_zpr_addr: IpAddr,
    vss_addr: SocketAddr,
    vs_handle: VSConnHandle,
    mut lifecycle_rx: broadcast::Receiver<VSConnLifecycleEvent>,
) {
    // When launched, we have no state with the VS.
    let mut state = StateFlag::NoState;
    // TODO: The new visa service supports a "reconnect" signal. That is not yet exposed by libnode2
    loop {
        // This acts as a gate -- waiting for runloop to start.
        wait_for_runloop_start(&mut lifecycle_rx).await;

        loop {
            // Kick off a connect request to the VS, if it succeeds, notify the VS about our VSS endpoint.
            let req = NodeConnect {
                zpr_addr: node_zpr_addr,
                state,
            };

            // Race the connect call against lifecycle events. We use a bool here because
            // ConnectedToVsApi can fire while connect() is still in-flight (the run loop
            // sends it before replying on the oneshot). Treating it as success avoids
            // issuing a second connect() call against an already-connected run loop.
            let connected = tokio::select! {
                res = vs_handle.connect(req) => {
                    match res {
                        Ok(()) => {
                            info!(target: STARTUP, "node access granted to visa service");
                            true
                        }
                        Err(VSApiError::CodedError(err)) if matches!(err.code, ErrorCode::OutOfSync) => {
                            state = StateFlag::NoState;
                            info!(target: STARTUP, "visa service reports out-of-sync; clearing adapters and visas");
                            asm.disconnect_adapters().await; // drops visas too
                            false
                        }
                        Err(e) => {
                            error!(target: STARTUP, "failed to get access to visa service: {e:?}");
                            false
                        }
                    }
                }

                evt = lifecycle_rx.recv() => {
                    match evt {
                        Ok(VSConnLifecycleEvent::RunLoopExits) => {
                            info!(target: STARTUP, "VSConn runloop exited; aborting connect attempts and re-gating");
                            break; // break inner connect loop, go re-gate on RunLoopStarts
                        }
                        Ok(VSConnLifecycleEvent::RunLoopStarts) => {
                            // harmless duplicate start
                            false
                        }
                        Ok(VSConnLifecycleEvent::ConnectedToVsApi(stateflag)) => {
                            // The connect() future was in-flight when this fired: the run loop
                            // already has a handle. Treat as success; do not retry connect().
                            info!(target: STARTUP, "node access granted to visa service (state = {:?})", stateflag);
                            true
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            error!(target: STARTUP, "lagged on VSConn lifecycle channel, skipped {skipped} events");
                            false
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            error!(target: STARTUP, "VSConn lifecycle channel closed unexpectedly");
                            return; // ABORT entire worker
                        }
                    }
                }
            };

            if connected {
                match vs_handle.register_vss(vss_addr).await {
                    Ok(ops) => {
                        info!(target: STARTUP, "registered VSS, received {} pending visa ops", ops.len());
                        for op in ops {
                            if let Err(e) = vss_worker::process_visaop(&asm, op) {
                                error!(target: STARTUP, "failed to process initial visa op from VS: {e:?}");
                            }
                        }
                        // Next time we connect, we have state.
                        state = StateFlag::HasState;
                        break; // Exit inner loop; go back to waiting for a state change.
                    }
                    Err(e) => {
                        error!(target: STARTUP, "failed to register VSS: {e:?}");

                        let dreq = DisconnectNotice {
                            zpr_addr: None,
                            reason: DisconnectReason::LinkError,
                        };
                        if let Err(e) = vs_handle.notify_disconnect(dreq).await {
                            error!(target: STARTUP, "error disconnecting from VS after failed registration: {e:?}");
                            panic!("failed to establish connection to VS");
                        }
                    }
                }
            }

            // wait a second and retry.
            tokio::time::sleep(config::VSCONN_RETRY_WAIT).await;
        }
    }
}

async fn wait_for_runloop_start(lifecycle_rx: &mut broadcast::Receiver<VSConnLifecycleEvent>) {
    loop {
        match lifecycle_rx.recv().await {
            Ok(VSConnLifecycleEvent::RunLoopStarts) => return,
            Ok(_) => {
                // ignored
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                error!(target: STARTUP, "lagged on VSConn lifecycle channel, skipped {skipped} events");
                continue; // try again
            }
            Err(broadcast::error::RecvError::Closed) => {
                error!(target: STARTUP, "VSConn lifecycle channel closed unexpectedly");
                return; // ABORT entire worker
            }
        }
    }
}
