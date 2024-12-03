use crate::assembly::{AddRouteError, Assembly};
use crate::defs::FiveTuple;
use crate::special_peers;
use libnode::{vsapi, vsconn};
use std::num::NonZero;
use std::sync::Arc;
use thiserror::Error;
use tracing::*;
use zpr::{self, LinkId, StreamId};

#[derive(Debug, Error)]
pub enum BindAgentAddressError {
    #[error("policy error")]
    PolicyError,
    #[error("adding route failed: {0}")]
    AddRouteError(AddRouteError),
}

/// Fulfills a Bind Agent Address request.
/// Returns the ingress tether ID on success.
pub async fn bind_agent_address(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    compression_mode: zpr::CompressionMode,
    five_tuple: FiveTuple,
    packet_body: Vec<u8>,
) -> Result<StreamId, BindAgentAddressError> {
    let egress_link_id;

    if let Some(spname) = special_peers::default_policy_lookup(ingress_link_id, &five_tuple) {
        if let Some(id) = asm.peer_table.lookup_special_peer(spname) {
            egress_link_id = id;
        } else {
            error!("{}: visa request error: special peer routing applies, but special peer ({spname:?}) not connected",
                asm.system_name);
            return Err(BindAgentAddressError::PolicyError);
        }
    } else {
        // HACK: for now, we assume a visa which forwards through to the other adapter
        // AND ALSO we manually issue a bind request out to that adapter
        let Some(proposed_egress_link_id) = asm.hack_default_policy(ingress_link_id) else {
            return Err(BindAgentAddressError::PolicyError);
        };

        if proposed_egress_link_id.get() == zpr::LOCAL_AGENT_LINK_ID {
            // VERY HACK
            egress_link_id = proposed_egress_link_id;
        } else {
            let visa_req = vsconn::VisaRequest {
                source_tether_addr: five_tuple.src_address.into(),
                l3_type: five_tuple.l3_type,
                packet: packet_body.clone(),
            };

            match asm.vsconn.as_ref().unwrap().request_visa(visa_req).await {
                Ok(vsapi::VisaResponse {
                    status: Some(vsapi::StatusCode::SUCCESS),
                    ..
                }) => {
                    egress_link_id = proposed_egress_link_id;
                }

                Ok(resp) => {
                    info!("{}: visa request rejected: {resp:?}", asm.system_name);
                    return Err(BindAgentAddressError::PolicyError);
                }

                Err(err) => {
                    error!("{}: visa request error: {err}", asm.system_name);
                    return Err(BindAgentAddressError::PolicyError);
                }
            }
        }
    }

    debug!(
        "{}: routing {} from {} to {}",
        asm.system_name, five_tuple, ingress_link_id, egress_link_id
    );

    let route_result = asm
        .add_route(
            ingress_link_id,
            five_tuple,
            egress_link_id,
            compression_mode,
            packet_body,
        )
        .await;

    debug!("{}: route result {:?}", asm.system_name, route_result);

    // TODO: reverse ingress TID needs to be sent to next-hop;
    // this is blocked on switching to new-style bind requests

    route_result.map_err(BindAgentAddressError::AddRouteError)
}
