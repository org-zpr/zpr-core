use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::assembly::Assembly;
use crate::config;
use crate::logging::targets::STARTUP;
use crate::vss_worker;

use libnode::vsconn::{VSConnHandle, VSConnLifecycleEvent, VSDisconnectNotice};
use zpr::vsapi_types::DisconnectReason;

pub async fn launch(
    asm: Arc<Assembly>,
    node_zpr_addr: IpAddr,
    aaa_prefix: IpNet,
    vss_addr: SocketAddr,
    vs_handle: VSConnHandle,
    mut lifecycle_rx: mpsc::Receiver<VSConnLifecycleEvent>,
) {
    // TODO: The new visa service supports a "reconnect" signal. That is not yet exposed by libnode2
    loop {
        // This acts as a gate -- waiting for runloop to start or fail.
        while let Some(event) = lifecycle_rx.recv().await {
            match event {
                VSConnLifecycleEvent::RunLoopStarts => break, // continue on the outer loop - start a connect request.
                VSConnLifecycleEvent::RunLoopExits => {}
                VSConnLifecycleEvent::ConnectedToVsApi => {}
            }
        }
        loop {
            // Kick off a connect request to the VS, if it succeeds, notify the VS about our VSS endpoint.
            let req = libnode::vsconn::VSConnectRequest {
                zpr_addr: node_zpr_addr,
                aaa_prefix,
            };
            // Note: this next call blocks if the VSConn run-loop isn't running.
            if let Err(e) = vs_handle.connect(req).await {
                error!(target: STARTUP, "failed to get access to visa service: {e:?}");
            } else {
                info!(target: STARTUP, "node access granted to visa service");
                match vs_handle.register_vss(vss_addr).await {
                    Ok(ops) => {
                        info!(target: STARTUP, "registered VSS, received {} pending visa ops", ops.len());
                        for op in ops {
                            if let Err(e) = vss_worker::process_visaop(&asm, op) {
                                error!(target: STARTUP, "failed to process initial visa op from VS: {e:?}");
                                // TODO: Currently no way to indicate to VS if we fail to process what is handed to us here.
                            }
                        }
                        break; // Exit inner loop, go to outer loop waiting for state change in VSConn.
                    }
                    Err(e) => {
                        error!(target: STARTUP, "failed to register VSS: {e:?}");

                        // Assume things are messed up and try again.
                        let dreq = VSDisconnectNotice {
                            zpr_addr: None,
                            reason: DisconnectReason::LinkError,
                        };
                        if let Err(e) = vs_handle.notify_disconnect(dreq).await {
                            error!(target: STARTUP, "error disconnecting from VS after failed registration: {e:?}");
                            // ok, time to die:
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
