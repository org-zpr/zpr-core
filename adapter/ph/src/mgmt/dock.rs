use crate::assembly::{AddRouteError, Assembly};
use crate::counters::CounterType;
use crate::defs::FiveTuple;
use crate::logging::targets::FLOW_MGMT;
use crate::special_peers;
use libnode::{vsapi, vsconn};
use std::net::IpAddr;
use std::num::NonZero;
use std::sync::Arc;
use thiserror::Error;
use tracing::*;
use zpr::{self, LinkId, StreamId};
use zpr_ext::std::num::NonZeroExt;

#[derive(Debug, Error)]
pub enum BindAgentAddressError {
    #[error("policy error")]
    PolicyError,
    #[error("parse error: {0}")]
    ParseError(String),
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
            debug!(target: FLOW_MGMT, "visa request error: special peer routing applies, but special peer ({spname:?}) not connected");
            return Err(BindAgentAddressError::PolicyError);
        }
    } else {
        if ingress_link_id.get() == zpr::LOCAL_AGENT_LINK_ID {
            // Reject packets from the local agent.
            // (Packets destined to the Visa Service Adapter fall under special-peer policy.)
            return Err(BindAgentAddressError::PolicyError);
        }

        let visa_server_id = asm
            .peer_table
            .lookup_special_peer(crate::special_peers::SpecialPeerName::VisaServiceAdapter)
            .unwrap_or_zero();
        if ingress_link_id.get() == visa_server_id {
            // VERY HACK
            // Unconditionally accept traffic from the Visa Service Adapter;
            // forward it to our local agent.
            egress_link_id = NonZero::new(zpr::LOCAL_AGENT_LINK_ID).unwrap();
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
                    asm.counters[CounterType::VisaRequestSuccess].increment();
                    // for now, just pull the destination address tether to set up forwarding
                    let Some(octets) = visa.unwrap().visa.unwrap().dest else {
                        asm.counters[CounterType::VisaRequestError].increment();
                        error!(target: FLOW_MGMT, "visa request error: Could not parse visa");
                        return Err(BindAgentAddressError::ParseError(
                            "Could not parse visa".into(),
                        ));
                    };
                    let addr = match octets.len() {
                        4 => IpAddr::from(
                            <[u8; 4]>::try_from(octets.as_slice()).expect("Bad IP length"),
                        ),
                        16 => IpAddr::from(
                            <[u8; 16]>::try_from(octets.as_slice()).expect("Bad IP length"),
                        ),
                        _ => {
                            asm.counters[CounterType::VisaRequestError].increment();
                            return Err(BindAgentAddressError::ParseError(
                                "Could not parse visa dest address".into(),
                            ));
                        }
                    };
                    match asm.find_egress_link(addr.into()) {
                        Ok(link_id) => egress_link_id = link_id,
                        Err(_) => {
                            asm.counters[CounterType::VisaRequestError].increment();
                            return Err(BindAgentAddressError::ParseError(
                                "Could not parse visa dest address".into(),
                            ));
                        }
                    }
                    debug!(
                        target: FLOW_MGMT,
                        "visa request succeeds, egress_link_id = {egress_link_id}"
                    );
                }

                Ok(resp) => {
                    asm.counters[CounterType::VisaRequestDenied].increment();
                    debug!(target: FLOW_MGMT, "visa request rejected: {resp:?}");
                    return Err(BindAgentAddressError::PolicyError);
                }

                Err(err) => {
                    asm.counters[CounterType::VisaRequestError].increment();
                    error!(target: FLOW_MGMT, "visa request error: {err}");
                    return Err(BindAgentAddressError::PolicyError);
                }
            }
        }
    }

    debug!(target: FLOW_MGMT, "now routing {five_tuple} from {ingress_link_id} to {egress_link_id}");

    let route_result = asm
        .add_route(
            ingress_link_id,
            five_tuple,
            egress_link_id,
            compression_mode,
            packet_body,
        )
        .await;

    // TODO: reverse ingress TID needs to be sent to next-hop;
    // this is blocked on switching to new-style bind requests

    route_result.map_err(BindAgentAddressError::AddRouteError)
}
