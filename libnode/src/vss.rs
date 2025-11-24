//! Implements the receiving end of the Visa Support Service.
//!
//! Really doesn't do very much except for translate incoming visa service
//! messages into enums on a channel.

use std::net::SocketAddr;
use thrift::protocol::{TBinaryInputProtocolFactory, TBinaryOutputProtocolFactory};
use thrift::protocol::{TInputProtocolFactory, TOutputProtocolFactory};
use thrift::server::TServer;
use thrift::transport::{TFramedReadTransportFactory, TReadTransportFactory};
use thrift::transport::{TFramedWriteTransportFactory, TWriteTransportFactory};
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info};

use crate::logging::targets::VSS_RPC;
use vsapi::{self, PolicyInfo, ServicesList, VisaSupportSyncHandler, VisaSupportSyncProcessor};
use zpr::vsapi_types::{AuthServicesList, Visa, VisaOp, VsapiTypeError};

/// Default port for the visa support service. Note that the visa support service
/// should only listen on the ZPR interface (not substrate interface!).
#[allow(dead_code)]
pub const DEFAULT_VSS_PORT: u16 = 8183;

/// Messages from the visa service. These wrap the thrift message types.
#[allow(dead_code)]
pub enum VSSMsg {
    /// Indicates a policy has been installed.
    PolicyInstall(PolicyInfo),

    /// Pushed visas from the visa service.
    PushedVisa(Visa),

    /// Pushed visa revokcations from the visa service.
    PushedRevocation(VisaOp),

    /// Pushed list of services. For now will be just Actor Authentication services.
    PushedServices(AuthServicesList),
}

/// The VisaSupportHandlerImpl is a light wrapper around the thrift
/// VisaSupportService client code which takes the messages from the
/// visa service and places them on a channel.
pub struct VisaSupportHandlerImpl {
    msg_chan_out: Sender<VSSMsg>,
}

impl VisaSupportHandlerImpl {
    /// Create a VisaSupportHandlerImpl. Messages from the visa service are placed on the
    /// passed `msg_chan_out` channel.
    #[allow(dead_code)]
    pub fn new(msg_chan_out: Sender<VSSMsg>) -> Self {
        VisaSupportHandlerImpl { msg_chan_out }
    }
}

/// Start the VSS (thrift) server (blocks forever). Messages from the visa service are
/// placed on the provided channel.
/// - `tx_chan` for arriving messages from the visa service.
/// - `listen_addr` is the address to listen on.
///
/// TODO: Need to add TLS to the thrift connection.
#[allow(dead_code)]
pub fn start_vss_server(tx_chan: Sender<VSSMsg>, listen_addr: SocketAddr) {
    // Create the thrift server and run it.
    let handler = VisaSupportHandlerImpl::new(tx_chan);
    let processor = VisaSupportSyncProcessor::new(handler);

    let i_tr_fact: Box<dyn TReadTransportFactory> = Box::new(TFramedReadTransportFactory::new());
    let i_pr_fact: Box<dyn TInputProtocolFactory> = Box::new(TBinaryInputProtocolFactory::new());
    let o_tr_fact: Box<dyn TWriteTransportFactory> = Box::new(TFramedWriteTransportFactory::new());
    let o_pr_fact: Box<dyn TOutputProtocolFactory> = Box::new(TBinaryOutputProtocolFactory::new());

    let mut vss_server = TServer::new(i_tr_fact, i_pr_fact, o_tr_fact, o_pr_fact, processor, 10);

    // TODO: super annoying that thrift gives us no way to run non-blocking or
    //       even a way to stop the server.
    info!(target: VSS_RPC, "starting visa support service on {listen_addr}");
    match vss_server.listen(listen_addr) {
        Ok(_) => info!(target: VSS_RPC, "VSS server completed OK"),
        Err(e) => error!(target: VSS_RPC, "VSS server failed with error: {e}"),
    };
}

impl VisaSupportSyncHandler for VisaSupportHandlerImpl {
    /// Accept the visa service message and put in on the message channel.
    fn handle_network_policy_installed(&self, pi: vsapi::PolicyInfo) -> thrift::Result<()> {
        debug!(target: VSS_RPC, "handle_network_policy_installed: {pi:?}");
        self.msg_chan_out
            .blocking_send(VSSMsg::PolicyInstall(pi))
            .or_else(|e| {
                error!(target: VSS_RPC, "failed to enque policy message to node: {e}");
                Err(thrift::Error::from("enqueue failed"))
            })
    }

    /// Accept the pushed visa(s) and put on to the message channel.
    fn handle_install_visas(&self, vh: Vec<vsapi::VisaHop>) -> thrift::Result<()> {
        debug!(target: VSS_RPC, "handle_install_visas, count={}", vh.len());
        for v in vh {
            let visa = match Visa::try_from(v) {
                Ok(visa) => visa,
                Err(e) => {
                    error!(target: VSS_RPC, "Visa could not be created: {e}");
                    return Err(thrift::Error::from("enqueue failed"));
                }
            };

            self.msg_chan_out
                .blocking_send(VSSMsg::PushedVisa(visa))
                .or_else(|e| {
                    error!(target: VSS_RPC, "failed to enqueue visa message to node: {e}");
                    Err(thrift::Error::from("enqueue failed"))
                })?;
        }
        Ok(())
    }

    /// Accept the visa revocation(s) and put on to the message channel.
    fn handle_revoke_visas(&self, vr: Vec<vsapi::VisaRevocation>) -> thrift::Result<()> {
        debug!(target: VSS_RPC, "handle_revoke_visas, count={}", vr.len());
        for r in vr {
            let vo = VisaOp::try_from(r);
            let op = match vo {
                Ok(op) => op,
                Err(VsapiTypeError::DeserializationError(e)) => return Err(thrift::Error::from(e)),
                _ => {
                    return Err(thrift::Error::from(
                        "Incorrect error type in visa revocation",
                    ));
                }
            };
            self.msg_chan_out
                .blocking_send(VSSMsg::PushedRevocation(op))
                .or_else(|e| {
                    error!(target: VSS_RPC, "failed to enque visa revocation to node: {}", e);
                    Err(thrift::Error::from("enqueue failed"))
                })?;
        }
        Ok(())
    }

    /// Accept the updates list of services from the visa service.  Creates a PushServices
    /// message.
    fn handle_services_update(&self, services: ServicesList) -> thrift::Result<()> {
        debug!(target: VSS_RPC, "handle_services_update");
        let svc_list = match AuthServicesList::try_from(services) {
            Ok(svc_list) => svc_list,
            Err(VsapiTypeError::VisaRevocationError(e)) => return Err(thrift::Error::from(e)),
            _ => {
                return Err(thrift::Error::from("Incorrect error type in services list"));
            }
        };
        self.msg_chan_out
            .blocking_send(VSSMsg::PushedServices(svc_list))
            .or_else(|e| {
                error!(target: VSS_RPC, "failed to enqueue services message to node: {e}");
                Err(thrift::Error::from("enqueue failed"))
            })
    }
}
