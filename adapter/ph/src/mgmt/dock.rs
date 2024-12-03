use crate::assembly::{AddRouteError, Assembly};
use crate::defs::FiveTuple;
use crate::special_peers;
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
) -> Result<StreamId, BindAgentAddressError> {
    let Some(egress_link_id) = special_peers::default_policy_lookup(ingress_link_id, &five_tuple)
        .and_then(|id| asm.peer_table.lookup_special_peer(id))
        .or_else(|| {
            // HACK: for now, we assume a visa which forwards through to the other adapter
            // AND ALSO we manually issue a bind request out to that adapter

            // TODO: request visa

            asm.hack_default_policy(ingress_link_id)
        })
    else {
        return Err(BindAgentAddressError::PolicyError);
    };

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
        )
        .await;

    debug!("{}: route result {:?}", asm.system_name, route_result);

    // TODO: reverse ingress TID needs to be sent to next-hop;
    // this is blocked on switching to new-style bind requests

    route_result.map_err(BindAgentAddressError::AddRouteError)
}
