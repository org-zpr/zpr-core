use crate::assembly::{AddRouteError, Assembly};
use crate::counters::CounterType;
use crate::defs::FiveTuple;
use crate::logging::targets::FLOW_MGMT;
use crate::special_peers;
use crate::visa_mgmt;
use crate::visa_table::VisaTableError;

use chrono::{DateTime, Utc};
use libnode::{vsapi, vsconn};
use std::num::NonZero;
use std::sync::Arc;
use thiserror::Error;
use tracing::*;
use zpr::{self, LinkId, StreamId, SPECIAL_VISA_ID};
use zpr_ext::std::num::NonZeroExt;

#[derive(Debug, Error)]
pub enum BindActorAddressError {
    #[error("policy error")]
    PolicyError,
    #[error("parse error: {0}")]
    ParseError(&'static str),
    #[error("adding route failed: {0}")]
    AddRouteError(AddRouteError),
}

/// Fulfills a Bind Actor Address request.
/// Returns the ingress tether ID on success.
pub async fn bind_actor_address(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    compression_mode: zpr::CompressionMode,
    five_tuple: FiveTuple,
    packet_body: Vec<u8>,
) -> Result<StreamId, BindActorAddressError> {
    let egress_link_id;
    let visa_id;

    if let Some(spname) = special_peers::default_policy_lookup(ingress_link_id, &five_tuple) {
        if let Some(id) = asm.peer_table.lookup_special_peer(spname) {
            egress_link_id = id;
            visa_id = SPECIAL_VISA_ID;
            asm.visa_table
                .write()
                .await
                .insert_id(visa_id, DateTime::<Utc>::MAX_UTC);
        } else {
            debug!(target: FLOW_MGMT, "visa request error: special peer routing applies, but special peer ({spname:?}) not connected");
            return Err(BindActorAddressError::PolicyError);
        }
    } else {
        if ingress_link_id.get() == zpr::LOCAL_ACTOR_LINK_ID {
            // Reject packets from the local actor.
            // (Packets destined to the Visa Service Adapter fall under special-peer policy.)
            return Err(BindActorAddressError::PolicyError);
        }

        let visa_server_id = asm
            .peer_table
            .lookup_special_peer(crate::special_peers::SpecialPeerName::VisaServiceAdapter)
            .unwrap_or_zero();
        if ingress_link_id.get() == visa_server_id {
            // VERY HACK
            // Unconditionally accept traffic from the Visa Service Adapter;
            // forward it to our local actor.
            egress_link_id = NonZero::new(zpr::LOCAL_ACTOR_LINK_ID).unwrap();
            visa_id = SPECIAL_VISA_ID;
            asm.visa_table
                .write()
                .await
                .insert_id(visa_id, DateTime::<Utc>::MAX_UTC);
        } else {
            let visa_req = vsconn::VisaRequest {
                source_tether_addr: five_tuple.src_address.into(),
                l3_type: five_tuple.l3_type,
                packet: packet_body.clone(),
            };

            asm.counters[CounterType::VisaRequested].increment();
            match asm.vsconn.as_ref().unwrap().request_visa(visa_req).await {
                Ok(vsapi::VisaResponse {
                    status: Some(vsapi::StatusCode::SUCCESS),
                    visa,
                    ..
                }) => {
                    let Some(visa) = visa else {
                        asm.counters[CounterType::VisaRequestError].increment();
                        error!(target: FLOW_MGMT, "visa request error: Could not parse visa");
                        return Err(BindActorAddressError::ParseError("Could not parse visa"));
                    };
                    (visa_id, egress_link_id) =
                        visa_mgmt::parse_visa(asm, visa)
                            .await
                            .map_err(|e| match e {
                                VisaTableError::ParseError(field) => {
                                    BindActorAddressError::ParseError(field)
                                }
                                e => panic!("Got unexpected error type {e}"),
                            })?;
                    asm.counters[CounterType::VisaRequestSuccess].increment();
                    debug!(
                        target: FLOW_MGMT,
                        "visa request succeeds, egress_link_id = {egress_link_id}"
                    );
                }

                Ok(resp) => {
                    asm.counters[CounterType::VisaRequestDenied].increment();
                    debug!(target: FLOW_MGMT, "visa request rejected: {resp:?}");
                    return Err(BindActorAddressError::PolicyError);
                }

                Err(err) => {
                    asm.counters[CounterType::VisaRequestError].increment();
                    error!(target: FLOW_MGMT, "visa request error: {err}");
                    return Err(BindActorAddressError::PolicyError);
                }
            }
        }
    }

    debug!(target: FLOW_MGMT, "now routing {five_tuple} from {ingress_link_id} to {egress_link_id}");

    let route_result = asm
        .add_route(
            ingress_link_id,
            visa_id,
            five_tuple,
            egress_link_id,
            compression_mode,
            packet_body,
        )
        .await;

    // TODO: reverse ingress TID needs to be sent to next-hop;
    // this is blocked on switching to new-style bind requests

    route_result.map_err(BindActorAddressError::AddRouteError)
}
