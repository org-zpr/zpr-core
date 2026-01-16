//! Dock API.
//!
//! These functions operate the local dock state at a high level.
//!
//! They are meant to be invoked either from [super::handlers] by a node in
//! response to a message from an adapter, or directly by a node managing
//! its local adapter.

// A lot of this functionality is similar/shared between node->adapter
// and node->node links.  It will need to be rearranged somewhat to reflect
// the similarities and differences.  However since for now we don't have
// node->node links, we don't make the distinction (so some terminology
// choices are weird).

use super::txn_mgr::{TxnHandle, TxnId};
use super::{adapter, requests};
use crate::assembly::Assembly;
use crate::classifier;
use crate::counters::ManagementCounterType;
use crate::defs::FiveTuple;
use crate::forwarding_tables;
use crate::logging::targets::FLOW_MGMT;
use crate::visa_mgmt;
use crate::visa_table::VisaTableError;

use dashmap::DashMap;
use libnode::vsconn;
use std::num::NonZero;
use std::sync::Arc;
use tracing::*;
use zpr::packet_info::{
    DOCK_LINK_ID, ForwardingEntry, LOCAL_ACTOR_LINK_ID, LinkId, StreamId, VisaId,
};
use zpr::vsapi_types;

/// State of an in-progress inbound bind request.
enum BindRequestState {
    /// We have issued a visa request and are currently awaiting a response.
    /// The parameter is a join handle for the task which is performing the
    /// visa request.  Note that this join handle is mostly only useful for
    /// monitoring, since the subsequent state transitions are issued from
    /// within the task it references, so we can't usefully join it.
    AwaitingVisaResponse(#[allow(dead_code)] tokio::task::JoinHandle<()>),

    //AwaitingVisaPush(VisaId),  // for future node->node use
    /// We have a visa with the indicated ID, and are now waiting
    /// on completion of the next-hop bind request issued on the indicated
    /// next-hop link and identified by the indicated transaction handle.
    AwaitingNextHopBind {
        visa_id: VisaId,
        egress_link_id: NonZero<LinkId>,
        egress_bind_txn: TxnHandle,
    },
}

/// Per-peer state related to the docking session and managed by the code in this module.
pub struct DockingSessionPeerState {
    /// In-progress inbound bind requests from this peer.  The key is the ID
    /// of a transaction opened by the peer; the value is the state of that
    /// bind request.
    bind_request_state: DashMap<TxnId, BindRequestState>,

    /// In-progress outbound bind requests to this peer.  The key is the handle
    /// of a transaction we opened; the value is a link ID × transaction ID
    /// pair identifying the in-progress inbound bind request this request
    /// was issued on behalf of.
    awaiting_next_hop_bind_table: DashMap<TxnHandle, (NonZero<LinkId>, TxnId)>,
}

impl DockingSessionPeerState {
    pub fn new() -> Self {
        Self {
            bind_request_state: DashMap::new(),
            awaiting_next_hop_bind_table: DashMap::new(),
        }
    }
}

/// Request to bind a stream which ingresses to this dock from an attached adapter.
///
/// `ingress_link_id` indicates the adapter which has made this request.
///
/// `txn_id` is used when issuing responses to the adapter to link them to this request.
///
/// `packet_body` is a prefix of the body of the packet which triggered this request which
/// will be presented to the Visa service to categorize and authorize this flow.
///
/// This launches a state machine associated with the indicated ingress link
/// and transaction which transitions through the following steps:
///
/// ```
///           ↓            [← bind_actor_address()]
///   AwaitingVisaResponse [→ issue visa request]
///           ↓            [← requested_visa_granted()]
///   AwaitingNextHopBind  [→ request next hop tether]
///           ↓            [← requested_tether_granted()]
///         Active         [create entry in visa table]
/// ```
///
/// `AwaitingVisaResponse` is skipped if a matching visa is already present.
///
/// `requested_visa_denied()` and `deny_tether()`, as well as various other errors,
/// result in the bind request being denied.
///
/// On completion of the state machine, a success response (containing the
/// tether ID and traffic classifier) or error response (in the event that
/// the bind request was denied) is then issued to the adapter, where these
/// responses are handled by [`adapter::install_tether()`] and [`adapter::deny_tether()`]
/// respectively.
pub fn bind_actor_address(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    packet_body: &[u8],
) {
    debug!(
        target: FLOW_MGMT,
        "bind_actor_address(ingress_link_id={ingress_link_id}, txn_id={txn_id})");

    // Determine five-tuple of the initial packet.

    let mut five_tuple = FiveTuple::default();

    let classifier_options =
        classifier::ClassifierOptions::default().ignore_truncated_packets(true);

    match classifier::classify_with_options(&mut five_tuple, packet_body, &classifier_options) {
        Ok(classifier::ClassifierResult::OK) => (),
        Ok(classifier::ClassifierResult::UnclassifiedL4) => {
            warn!(target: FLOW_MGMT, "Link {ingress_link_id}: bind request: unsupported IP protocol {}", five_tuple.l4_protocol);
            return requested_visa_denied(asm, ingress_link_id, txn_id);
        }
        _ => {
            warn!(target: FLOW_MGMT, "Link {ingress_link_id}: bind request: invalid initial packet");
            return requested_visa_denied(asm, ingress_link_id, txn_id);
        }
    }

    let Some(peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        return;
    };

    // Ensure this adapter actually owns this source address.

    if !peer_state
        .link_state_machine
        .has_actor_address(&five_tuple.src_address)
    {
        warn!(target: FLOW_MGMT, "Link {ingress_link_id}: bind request: source address {} does not match actor address", &five_tuple.src_address);
        return requested_visa_denied(asm, ingress_link_id, txn_id);
    }

    // Check if we already have a visa which matches this traffic.

    let visa_table = asm.visa_table.read().unwrap();

    if let Some(matched) = visa_table.match_traffic(&five_tuple) {
        // We matched a visa we already have.

        let matched_visa_id = matched;
        drop(visa_table);

        let egress_link_id_query = visa_mgmt::get_egress_link_for_visa(asm, matched_visa_id);
        match egress_link_id_query {
            Ok(link_id) => {
                debug!(
                    target: FLOW_MGMT,
                    "matched existing visa {matched_visa_id} for {five_tuple}, egress_link_id = {link_id}"
                );
                // This visa is valid; treat as an immediate grant.
                return requested_visa_granted(asm, ingress_link_id, txn_id, matched_visa_id);
            }

            Err(VisaTableError::NotFound(_)) => {
                // The visa disappeared.
                // This could happen if visa is somehow removed before we get here. In this case we
                // can just proceed with a request.
                debug!(
                    target: FLOW_MGMT,
                    "visa request matching error: visa {matched_visa_id} for {five_tuple} racily deleted, proceeding with request"
                );
            }

            Err(VisaTableError::DestNotFound(addr)) => {
                // A visa exists, but we have no egress path for this destination address.
                // Treat as an immediate denial.
                asm.counters.management[ManagementCounterType::VisaRequestError].increment();
                error!(target: FLOW_MGMT, "visa request matching error: destination address {addr} not found so no egress link");
                return requested_visa_denied(asm, ingress_link_id, txn_id);
            }

            Err(e) => {
                panic!("Got unexpected error type {e}");
            }
        }
    }

    // We do not have an existing visa.  Request one.

    debug!(
        target: FLOW_MGMT,
        "issuing visa request for {five_tuple} from ingress_link_id {ingress_link_id} packet_body.len() = {}",
        packet_body.len()
    );

    let visa_req = vsconn::VisaRequest {
        source_tether_addr: five_tuple.src_address.into(),
        l3_type: five_tuple.l3_type, // TODO: this should come from the bind request, not the packet body
        packet: packet_body.to_vec(),
    };

    asm.counters.management[ManagementCounterType::VisaRequested].increment();

    // We need to ensure the visa-request task (spawned below) doesn't try
    // to access the docking session state before this entry is in place.
    // Since the task is spawned with `spawn_local()`, it will not start
    // until after we yield somehow, which we don't between now and when we
    // add this entry.  Nonetheless, to ensure this behavior isn't broken should
    // the task be changed to spawn with `spawn()`, we begin instantiating the
    // bind request state machine entry (i.e., take a lock on it) up here.
    let bind_st_entry = peer_state
        .docking_session_state
        .bind_request_state
        .entry(txn_id);

    // Launch the visa-request task while holding a lock on its corresponding entry.
    let jh = tokio::task::spawn_local(visa_request_task(
        asm.clone(),
        ingress_link_id,
        txn_id,
        visa_req,
    ));

    // Finish instantiating the bind request state.
    bind_st_entry.insert(BindRequestState::AwaitingVisaResponse(jh));
}

/// Request a visa, on behalf of a bind request from the given link and transaction ID.
///
/// On completion, advances the bind-request state machine via
/// `requested_visa_granted()` or `requested_visa_denied()` as appropriate.
async fn visa_request_task(
    asm: Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    visa_req: vsconn::VisaRequest,
) {
    match asm.vsconn.as_ref().unwrap().request_visa(visa_req).await {
        Ok(vsapi_types::VisaResponse::Allow(visa)) => {
            let visa_id = match visa_mgmt::insert_visa(&asm, visa) {
                Ok(vid) => vid,

                Err(VisaTableError::ParseError(field)) => {
                    error!(target: FLOW_MGMT, "Could not parse visa: {field}");
                    return requested_visa_denied(&asm, ingress_link_id, txn_id);
                }

                Err(e) => panic!("Got unexpected error type {e}"),
            };

            asm.counters.management[ManagementCounterType::VisaRequestSuccess].increment();
            debug!(target: FLOW_MGMT, "visa request succeeds, visa_id = {visa_id}");

            requested_visa_granted(&asm, ingress_link_id, txn_id, visa_id);
        }

        Ok(vsapi_types::VisaResponse::Deny(denied)) => {
            asm.counters.management[ManagementCounterType::VisaRequestDenied].increment();
            debug!(target: FLOW_MGMT, "visa request denied: {:?}", denied.reason);
            requested_visa_denied(&asm, ingress_link_id, txn_id)
        }

        // Not implemented as part of thrift visas
        Ok(vsapi_types::VisaResponse::VSApiError(error)) => {
            asm.counters.management[ManagementCounterType::VisaRequestError].increment();
            debug!(target: FLOW_MGMT, "visa request error with code: {:?} and message: {:?}", error.code, error.message);
            requested_visa_denied(&asm, ingress_link_id, txn_id)
        }

        Err(err) => {
            error!(target: FLOW_MGMT, "visa request error: {err}");
            requested_visa_denied(&asm, ingress_link_id, txn_id)
        }
    }
}

/// Notify the bind-request state machine that the visa it requested
/// on behalf of transaction `txn_id` from adapter `ingress_link_id`
/// is now available with the specified visa ID.
///
/// Advances the bind-request state machine from AwaitingVisaResponse to
/// AwaitingNextHopBind by issuing a bind request to the next hop.
fn requested_visa_granted(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    visa_id: VisaId,
) {
    debug!(
        target: FLOW_MGMT,
        "requested_visa_granted(ingress_link_id={ingress_link_id}, txn_id={txn_id}, visa_id={visa_id})");

    // Look up the egress link for this visa.

    let Ok(egress_link_id) = visa_mgmt::get_egress_link_for_visa(asm, visa_id) else {
        // visa or egress link was deleted; consider visa denied
        return requested_visa_denied(asm, ingress_link_id, txn_id);
    };
    let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get()) else {
        // egress link was racily deleted; consider visa denied
        return requested_visa_denied(asm, ingress_link_id, txn_id);
    };

    // Look up the traffic classifier for this visa.

    let visa_table = asm.visa_table.read().unwrap();
    let Some(visa) = visa_table.table.get(&visa_id) else {
        // Visa was either never granted or has already been removed
        // Route is no longer valid
        return requested_visa_denied(asm, ingress_link_id, txn_id);
    };
    let tc = visa.get_tc();
    drop(visa_table);

    // Open a transaction on the egress link and move into AwaitingNextHopBind state.

    let egress_bind_txn = egress_peer_state
        .txn_mgr
        .try_open()
        .expect("FIXME TODO: bind backpressure #1176");

    let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        // requestor went away, bail!
        return;
    };
    ingress_peer_state
        .docking_session_state
        .bind_request_state
        .insert(
            txn_id,
            BindRequestState::AwaitingNextHopBind {
                visa_id,
                egress_link_id,
                egress_bind_txn: egress_bind_txn.clone(),
            },
        );

    // Issue a bind request on the egress link (first
    // noting in the `awaiting_next_hop_bind_table` on the egress link
    // how to route the reply).

    let egress_bind_txn_id = egress_bind_txn.id();
    egress_peer_state
        .docking_session_state
        .awaiting_next_hop_bind_table
        .insert(egress_bind_txn, (ingress_link_id, txn_id));

    if egress_link_id.get() == LOCAL_ACTOR_LINK_ID {
        adapter::bind_egress_stream(
            asm,
            NonZero::new(DOCK_LINK_ID).unwrap(),
            egress_bind_txn_id,
            tc,
        );
    } else {
        requests::send_bind_egress_stream_request(
            asm,
            egress_link_id.get(),
            egress_bind_txn_id,
            tc,
        )
        .enqueue();
    }
}

/// Notify the bind-request state machine that the visa it requested
/// on behalf of transaction `txn_id` from adapter `ingress_link_id`
/// was denied.
///
/// Terminates the bind-request state machine by sending a policy error
/// back to the adapter which initiated the request.
fn requested_visa_denied(asm: &Arc<Assembly>, ingress_link_id: NonZero<LinkId>, txn_id: TxnId) {
    bind_actor_address_reject(asm, ingress_link_id, txn_id, "policy error")
}

/// Install the given tether into the PFT.
///
/// Essentially this is the core implementation of `install_tether()`,
/// except (a) it's indexed by the link and transaction ID of the bind request
/// which owns the state machine, and (b) it assumes the reverse mapping
/// in the egress link has already been cleaned up.
fn requested_tether_granted(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    egress_tether_id: StreamId,
) {
    let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        return;
    };

    // Lookup (and hold locked) the bind-request state, to retrieve the
    // associated egress information.  (It's a little redundant that we
    // already have the egress information in our only caller
    // (`install_tether()`), but retrieving it again here lets us maintain a
    // clean API on this state machine.)

    let dashmap::mapref::entry::Entry::Occupied(bind_st) = ingress_peer_state
        .docking_session_state
        .bind_request_state
        .entry(txn_id)
    else {
        error!(target: FLOW_MGMT, "requested_tether_granted() called when no request outstanding (txn_id={txn_id})");
        return;
    };

    let &BindRequestState::AwaitingNextHopBind {
        visa_id,
        egress_link_id,
        ref egress_bind_txn,
    } = bind_st.get()
    else {
        // should never happen; we check this in our only caller
        error!(target: FLOW_MGMT, "requested_tether_granted() called in wrong state (txn_id={txn_id})");
        return;
    };

    // Confirm that any associated next-hop-bind state no longer exists,
    // since we're about to make it invalid.

    if let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get()) {
        assert!(
            !egress_peer_state
                .docking_session_state
                .awaiting_next_hop_bind_table
                .contains_key(&egress_bind_txn)
        );
    }

    // Remove the bind-request state -- the state machine is now complete.

    bind_st.remove();

    // Reserve & lock a slot for (but do not yet insert) the ingress link's PFT.
    // (This lets us query the tether ID which will be assigned before
    // committing to an insert.)

    let Ok(ingress_tether_entry) = ingress_peer_state.pft.vacant_entry() else {
        // PFT full; respond with error message
        // TODO: maybe tick a counter somewhere?
        bind_actor_address_reject(asm, ingress_link_id, txn_id, "PFT full");
        return;
    };

    // Link the PFT entry into the visa (while holding the lock on the PFT entry).

    let mut visa_table = asm.visa_table.write().unwrap();

    let Some(visa) = visa_table.table.get_mut(&visa_id) else {
        // Visa was either never granted or has already been removed
        // Route is no longer valid
        requested_visa_denied(asm, ingress_link_id, txn_id);
        return;
    };

    visa.link_forwarding_entry(ForwardingEntry(
        ingress_link_id.get(),
        ingress_tether_entry.key(),
    ));

    // Retrieve the traffic classifier from the visa.

    let tc = visa.get_tc();

    drop(visa_table);

    // Form the PEP and insert into the PFT slot we reserved (producing a tether ID).

    let pep = forwarding_tables::PftPep {
        next_hop: ForwardingEntry(egress_link_id.get(), egress_tether_id),
        visa_id,
    };

    let ingress_tether_id = ingress_tether_entry.insert(pep);

    // Send a success response to the requestor with the tether ID.

    if ingress_peer_state.is_internal() {
        let adapter_peer_state = asm.peer_table.get(DOCK_LINK_ID).unwrap();
        let txn = adapter_peer_state
            .txn_mgr
            .get(txn_id)
            .expect("local adapter lost transaction");
        adapter::install_tether(asm, &txn, ingress_tether_id, tc)
            .expect("local adapter rejected tether response");
    } else {
        requests::send_bind_actor_address_success_response(
            asm,
            ingress_link_id.get(),
            txn_id,
            ingress_tether_id,
            tc,
        )
        .enqueue();
    }
}

/// Common functionality for exiting the bind request state machine with an error.
///
/// Removes this bind request from the `bind_request_state` table, and
/// sends an error reply back to the requestor.
///
/// It is invalid and racy to call this while a next-hop-bind request is outstanding,
/// as there is neither mechanism to discard replies to such a request, or to
/// synchronize replies with termination of this state machine.
fn bind_actor_address_reject(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    reason: &str,
) {
    debug!(
        target: FLOW_MGMT,
        "bind_actor_address_reject(ingress_link_id={ingress_link_id}, txn_id={txn_id})");

    let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        return;
    };

    // Remove state from the bind-request state table.

    if let Some((_, bind_st)) = ingress_peer_state
        .docking_session_state
        .bind_request_state
        .remove(&txn_id)
    {
        // If we were awaiting the next-hop-bind...
        if let BindRequestState::AwaitingNextHopBind {
            egress_link_id,
            egress_bind_txn,
            ..
        } = bind_st
        {
            // ...ensure we haven't left a lingering next-hop-bind entry.
            // If we did, then we'd leave it referencing a no-longer-valid
            // transaction.  This should never happen, and we can only check
            // this racily since there's no synchronization between these
            // flows, but check nonetheless.
            if let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get()) {
                assert!(
                    !egress_peer_state
                        .docking_session_state
                        .awaiting_next_hop_bind_table
                        .contains_key(&egress_bind_txn)
                );
            }
        };
    }

    // Send an error response to the requestor.

    if ingress_peer_state.is_internal() {
        let adapter_peer_state = asm.peer_table.get(DOCK_LINK_ID).unwrap();
        let txn = adapter_peer_state
            .txn_mgr
            .get(txn_id)
            .expect("local adapter lost transaction");
        adapter::deny_tether(asm, &txn, reason).expect("local adapter rejected tether response");
    } else {
        requests::send_bind_actor_address_error_response(
            asm,
            ingress_link_id.get(),
            txn_id,
            reason,
        )
        .enqueue();
    }
}

#[derive(Debug)]
pub enum InstallTetherError {
    /// The indicated egress transaction does not exist.
    NoSuchTransaction,
    /// The indicated egress link does not exist.
    LinkClosed,
}

/// Install the given tether into the PFT.
///
/// `egress_link_id` indicates the adapter to which this tether is made.
///
/// `egress_txn` must refer to an active transaction on the adapter link which had
/// previously requested a tether to the indicated adapter (e.g. via
/// BindEgressStream).
///
/// `egress_tether_id` is the ID to be used to refer to this tether.
///
/// Completes the indicated transaction.
///
/// Returns an error only if the transaction is invalid.
pub fn install_tether(
    asm: &Arc<Assembly>,
    egress_link_id: NonZero<LinkId>,
    egress_txn: &TxnHandle,
    egress_tether_id: StreamId,
) -> Result<(), InstallTetherError> {
    let (ingress_link_id, ingress_txn_id) =
        resolve_next_hop_bind_originator(asm, egress_link_id, egress_txn)?;
    Ok(requested_tether_granted(
        asm,
        ingress_link_id,
        ingress_txn_id,
        egress_tether_id,
    ))
}

/// Deny the given tether request, removing it from the ALT.
///
/// `egress_link_id` indicates the adapter to which this tether is made.
///
/// `egress_txn` must refer to an active transaction on the adapter link
/// which had previously requested a tether.
///
/// `reason` is a human-readable reason why the tether was denied.
///
/// Completes the indicated transaction.
///
/// Returns an error only if the transaction is invalid.
pub fn deny_tether(
    asm: &Arc<Assembly>,
    egress_link_id: NonZero<LinkId>,
    egress_txn: &TxnHandle,
    reason: &str,
) -> Result<(), InstallTetherError> {
    let (ingress_link_id, ingress_txn_id) =
        resolve_next_hop_bind_originator(asm, egress_link_id, egress_txn)?;
    Ok(bind_actor_address_reject(
        asm,
        ingress_link_id,
        ingress_txn_id,
        reason,
    ))
}

/// Resolve the originating bind-request state machine
/// for the given next-hop-bind transaction.
///
/// Removes next-hop-bind state from the docking session state,
/// and completes the indicated transaction.
fn resolve_next_hop_bind_originator(
    asm: &Arc<Assembly>,
    egress_link_id: NonZero<LinkId>,
    egress_txn: &TxnHandle,
) -> Result<(NonZero<LinkId>, TxnId), InstallTetherError> {
    // Find & remove the backlink to the inbound bind-request which
    // initiated this next-hop-bind.

    let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get()) else {
        return Err(InstallTetherError::LinkClosed);
    };
    let Some((_, (ingress_link_id, ingress_txn_id))) = egress_peer_state
        .docking_session_state
        .awaiting_next_hop_bind_table
        .remove(egress_txn)
    else {
        return Err(InstallTetherError::NoSuchTransaction);
    };

    if let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) {
        // If originator still exists, check consistency
        // (don't bother if originator no longer exists).

        let Some(bind_st) = ingress_peer_state
            .docking_session_state
            .bind_request_state
            .get(&ingress_txn_id)
        else {
            // should never happen
            panic!(
                "dock state consistency error; {ingress_txn_id} referenced by awaiting_next_hop_bind_table but is not an active bind request"
            );
        };

        let &BindRequestState::AwaitingNextHopBind {
            egress_link_id: expected_egress_link_id,
            egress_bind_txn: ref expected_egress_txn,
            ..
        } = &*bind_st
        else {
            // should never happen
            panic!(
                "dock state consistency error; {ingress_txn_id} referenced by awaiting_next_hop_bind_table but not in AwaitingNextHopBind state"
            );
        };

        assert_eq!(
            expected_egress_link_id, egress_link_id,
            "dock state consistency error"
        );
        assert_eq!(
            expected_egress_txn, egress_txn,
            "dock state consistency error"
        );
    }

    Ok((ingress_link_id, ingress_txn_id))
}
