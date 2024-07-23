use tokio::sync::mpsc::Sender;

use thrift::protocol::{TBinaryInputProtocolFactory, TBinaryOutputProtocolFactory};
use thrift::protocol::{TInputProtocolFactory, TOutputProtocolFactory};
use thrift::server::TServer;
use thrift::transport::{TFramedReadTransportFactory, TReadTransportFactory};
use thrift::transport::{TFramedWriteTransportFactory, TWriteTransportFactory};

use tracing::{error, info};

use std::collections::BTreeMap;

use crate::vssapi;
use vssapi::{VisaSupportSyncHandler, VisaSupportSyncProcessor};

use crate::vs::vstypes::{PolicyInfo, Revocation, Visa};

#[derive(Debug)]
#[allow(dead_code)]
pub enum VSSMsg {
    PolicyInstall(PolicyInfo),
    PushedVisa(Visa),
    PushedRevocation(Revocation),
}

pub struct VisaSupportHandlerImpl {
    msg_chan_out: Sender<VSSMsg>,
}

impl VisaSupportHandlerImpl {
    pub fn new(msg_chan_out: Sender<VSSMsg>) -> Self {
        VisaSupportHandlerImpl { msg_chan_out }
    }
}

/// Start the VSS server.
/// - `listen_addr` is the address to listen on as 'ADDR:PORT'.
pub fn start_vss_server(tx_chan: Sender<VSSMsg>, listen_addr: &str) {
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
    info!("starting visa support service on {}", listen_addr);
    match vss_server.listen(listen_addr) {
        Ok(_) => info!("VSS server completed OK"),
        Err(e) => error!("VSS server failed with error: {}", e),
    };
}

impl VisaSupportSyncHandler for VisaSupportHandlerImpl {
    fn handle_network_policy_installed(&self, pi: vssapi::PolicyInfo) -> thrift::Result<()> {
        info!("handle_network_policy_installed: {:?}", pi);

        let mut config = BTreeMap::new();
        if let Some(nc) = pi.node_config {
            for (k, v) in nc {
                config.insert(k, v);
            }
        }

        let pi = PolicyInfo {
            policy_id: pi.policy_id as u64,
            configuration_id: pi.config_id as u64,
            node_config: config,
        };

        let msg = VSSMsg::PolicyInstall(pi);
        match self.msg_chan_out.blocking_send(msg) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("failed to enque policy message to node: {}", e);
                Err(thrift::Error::from("enque failed"))
            }
        }
    }

    fn handle_install_visas(&self, vh: Vec<vssapi::VisaHop>) -> thrift::Result<()> {
        println!("handle_install_visas: {:?}", vh);
        Ok(())
    }

    fn handle_revoke_visas(&self, vr: Vec<vssapi::VisaRevocation>) -> thrift::Result<()> {
        println!("handle_revoke_visas: {:?}", vr);
        Ok(())
    }
}
