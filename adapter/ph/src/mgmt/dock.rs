use crate::assembly::{AddRouteError, Assembly};
use crate::counters::ManagementCounterType;
use crate::defs::FiveTuple;
use crate::logging::targets::FLOW_MGMT;
use crate::tc;
use crate::visa_mgmt;
use crate::visa_table::VisaTableError;

use libnode::{vsapi, vsconn};
use std::num::NonZero;
use std::sync::Arc;
use thiserror::Error;
use tracing::*;
use zpr::{self, LinkId, StreamId};

#[derive(Debug, Error)]
pub enum BindActorAddressError {
    #[error("policy error")]
    PolicyError,
    #[error("parse error: {0}")]
    ParseError(&'static str),
    #[error("adding route failed: {0}")]
    AddRouteError(#[from] AddRouteError),
}

pub struct ForwardingDecision {
    pub egress_link_id: NonZero<zpr::LinkId>,
    pub visa_id: zpr::VisaId,
}

/// Fulfills a Bind Actor Address request.
/// Returns the ingress tether ID on success.
pub async fn bind_actor_address(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    five_tuple: &FiveTuple,
    packet_body: &[u8],
) -> Result<(StreamId, tc::Ip5TupleTc), BindActorAddressError> {
    let mut forwarding_decision: Option<ForwardingDecision> = None;

    debug!(
        target: FLOW_MGMT,
        "DOCK.bind_actor_address called with five_tuple {five_tuple} from ingress_link_id {ingress_link_id}",
    );

    if let Some(matched) = asm.visa_table.read().unwrap().match_traffic(&five_tuple) {
        // We matched a visa we already have.
        let matched_visa_id = matched;
        let egress_link_id_query = visa_mgmt::get_egress_link_for_visa(asm, matched_visa_id);
        match egress_link_id_query {
            Ok(link_id) => {
                forwarding_decision = Some(ForwardingDecision {
                    egress_link_id: link_id,
                    visa_id: matched_visa_id,
                });
                debug!(
                    target: FLOW_MGMT,
                    "matched existing visa {matched_visa_id} for {five_tuple}, egress_link_id = {link_id}"
                );
            }
            Err(VisaTableError::ParseError(field)) => {
                asm.counters.management[ManagementCounterType::VisaRequestError].increment();
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
                asm.counters.management[ManagementCounterType::VisaRequestError].increment();
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
            packet: packet_body.to_vec(),
        };

        asm.counters.management[ManagementCounterType::VisaRequested].increment();
        match asm.vsconn.as_ref().unwrap().request_visa(visa_req).await {
            Ok(vsapi::VisaResponse {
                status: Some(vsapi::StatusCode::SUCCESS),
                visa,
                ..
            }) => {
                let Some(visa) = visa else {
                    asm.counters.management[ManagementCounterType::VisaRequestError].increment();
                    error!(target: FLOW_MGMT, "visa request error: Could not parse visa");
                    return Err(BindActorAddressError::ParseError("Could not parse visa"));
                };
                let (visa_id, egress_link_id) =
                    visa_mgmt::parse_visa(asm, visa).map_err(|e| match e {
                        VisaTableError::ParseError(field) => {
                            BindActorAddressError::ParseError(field)
                        }
                        e => panic!("Got unexpected error type {e}"),
                    })?;
                forwarding_decision = Some(ForwardingDecision {
                    egress_link_id,
                    visa_id,
                });
                asm.counters.management[ManagementCounterType::VisaRequestSuccess].increment();
                debug!(
                    target: FLOW_MGMT,
                    "visa request succeeds, egress_link_id = {egress_link_id}"
                );
            }

            Ok(resp) => {
                asm.counters.management[ManagementCounterType::VisaRequestDenied].increment();
                debug!(target: FLOW_MGMT, "visa request rejected: {resp:?}");
                return Err(BindActorAddressError::PolicyError);
            }

            Err(err) => {
                asm.counters.management[ManagementCounterType::VisaRequestError].increment();
                error!(target: FLOW_MGMT, "visa request error: {err}");
                return Err(BindActorAddressError::PolicyError);
            }
        }
    }

    // TODO: get this from the Visa Service
    let tc = tc::Ip5TupleTc::new_with_compression_mode(0, *five_tuple);

    // Now way to get here without forwarding_decision being set.
    let decision = forwarding_decision.unwrap();
    debug!(target: FLOW_MGMT, "now routing {five_tuple} from {ingress_link_id} to {}",
        decision.egress_link_id);

    let route_result = asm
        .add_route(
            ingress_link_id,
            decision.visa_id,
            tc.clone(),
            decision.egress_link_id,
        )
        .await;

    // TODO: reverse ingress TID needs to be sent to next-hop;
    // this is blocked on switching to new-style bind requests

    let ingress_stream_id = route_result?;

    Ok((ingress_stream_id, tc))
}
