use crate::assembly::{AddRouteError, Assembly};
use crate::counters::CounterType;
use crate::defs::FiveTuple;
use crate::logging::targets::FLOW_MGMT;
use crate::special_peers::{self, PolicyForwardingDecision};
use crate::visa_mgmt;
use crate::visa_table::VisaTableError;

use chrono::{DateTime, Utc};
use libnode::{vsapi, vsconn};
use std::num::NonZero;
use std::sync::Arc;
use thiserror::Error;
use tracing::*;
use zpr::{self, LinkId, StreamId};
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
    let mut forwarding_decision: Option<PolicyForwardingDecision> = None;

    debug!(
        target: FLOW_MGMT,
        "DOCK.bind_actor_address called with five_tuple {five_tuple} from ingress_link_id {ingress_link_id}",
    );

    // HACK: We call this "default policy" function which will allow certain communications
    // between the visa service and this node.
    // TODO: We could use real visas here -- if we had a way to look up visas based on five tuple.

    let default_decision = special_peers::default_policy_lookup(asm, ingress_link_id, &five_tuple);
    if let Ok(Some(decision)) = default_decision {
        let spname = decision.spname;
        forwarding_decision = Some(decision);
        debug!(
            target: FLOW_MGMT,
            "default policy lookup applies, using special peer {spname:?} -- inserting DUMMY visa",
        );
        asm.visa_table.write().await.insert_id(
            forwarding_decision.as_ref().unwrap().visa_id,
            DateTime::<Utc>::MAX_UTC,
        );
    } else if let Err(e) = default_decision {
        debug!(target: FLOW_MGMT, "visa request error processing default policy logic: {e}");
        return Err(e);
    } else {
        let visa_server_id = asm
            .peer_table
            .lookup_special_peer(crate::special_peers::SpecialPeerName::VisaServiceAdapter)
            .unwrap_or_zero();
        if ingress_link_id.get() == visa_server_id {
            debug!(
                target: FLOW_MGMT,
                "detected ingress packet from our visa service adapter not matching default policy... continuing...",
            );
        }

        // TODO: Convert that default policy call thing above into inserting some visas into the table.

        if let Some(matched) = asm.visa_table.read().await.match_traffic(&five_tuple) {
            // We matched a visa we already have.
            if matched.len() > 1 {
                warn!(target: FLOW_MGMT, "multiple visas matched for {five_tuple}, using the first one ({matched:?})");
            }
            let matched_visa_id = matched[0];
            let egress_link_id_query =
                visa_mgmt::get_egress_link_for_visa(asm, matched_visa_id).await;
            match egress_link_id_query {
                Ok(link_id) => {
                    forwarding_decision = Some(PolicyForwardingDecision {
                        spname: None,
                        egress_link_id: link_id,
                        visa_id: matched_visa_id,
                    });
                    debug!(
                        target: FLOW_MGMT,
                        "matched existing visa {matched_visa_id} for {five_tuple}, egress_link_id = {link_id}"
                    );
                }
                Err(VisaTableError::ParseError(field)) => {
                    asm.counters[CounterType::VisaRequestError].increment();
                    error!(target: FLOW_MGMT, "visa request matching error: {field}");
                    return Err(BindActorAddressError::ParseError(field));
                }
                Err(VisaTableError::NotFound(_)) => {
                    // This could happen if visa is somehow removed before we get here. In this case we
                    // can just proceed with a request.
                    debug!(
                        target: FLOW_MGMT,
                        "visa request matching error: visa not found for {five_tuple}, proceeding with request"
                    );
                }
                Err(VisaTableError::DestNotFound(addr)) => {
                    asm.counters[CounterType::VisaRequestError].increment();
                    error!(target: FLOW_MGMT, "visa request matching error: destination address {addr} not found so no egress link");
                    return Err(BindActorAddressError::ParseError(
                        "destination address not found",
                    ));
                }
                Err(e) => {
                    panic!("Got unexpected error type {e}");
                }
            }
        }

        if forwarding_decision.is_none() {
            debug!(
                target: FLOW_MGMT,
                "issuing visa request for {five_tuple} from ingress_link_id {ingress_link_id} packet_body.len() = {}",
                packet_body.len()
            );
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
                    let (visa_id, egress_link_id) = visa_mgmt::parse_visa(asm, visa)
                        .await
                        .map_err(|e| match e {
                            VisaTableError::ParseError(field) => {
                                BindActorAddressError::ParseError(field)
                            }
                            e => panic!("Got unexpected error type {e}"),
                        })?;
                    forwarding_decision = Some(PolicyForwardingDecision {
                        spname: None,
                        egress_link_id,
                        visa_id,
                    });
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

    // Now way to get here without forwarding_decision being set.
    let decision = forwarding_decision.unwrap();
    debug!(target: FLOW_MGMT, "now routing {five_tuple} from {ingress_link_id} to {}",
        decision.egress_link_id);

    let route_result = asm
        .add_route(
            ingress_link_id,
            decision.visa_id,
            five_tuple,
            decision.egress_link_id,
            compression_mode,
            packet_body,
        )
        .await;

    // TODO: reverse ingress TID needs to be sent to next-hop;
    // this is blocked on switching to new-style bind requests

    route_result.map_err(BindActorAddressError::AddRouteError)
}
