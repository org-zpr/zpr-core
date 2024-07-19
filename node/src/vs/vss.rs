
use tokio::sync::mpsc::Sender;

use tracing::{error, info};


use std::collections::BTreeMap;

use crate::vssapi;
use vssapi::VisaSupportSyncHandler;

use crate::vs::vstypes::{PolicyInfo, Visa, Revocation};


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
        VisaSupportHandlerImpl {
            msg_chan_out,
        }
    }
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
            Ok(_) => return Ok(()),
            Err(e) => {
                error!("failed to enque policy message to node: {}", e);
                return Err(thrift::Error::from("enque failed"))
            }
        };
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
