//! Adapter API.
//!
//! These functions operate on the local adapter state at a high level.
//!
//! They are meant to be invoked either from [super::handlers] by an
//! adapter in response to a message from a node, or directly by a node
//! managing its local adapter.

use super::{dock, txn_mgr};
use crate::adapter_tables::{DltPep, EltPep};
use crate::assembly::{Assembly, PhMode};
use crate::counters::ManagementCounterType;
use crate::logging::targets::FLOW_MGMT;
use crate::queues;
use crate::tc;
use std::num::NonZero;
use std::sync::Arc;
use tracing::*;
use zpr::packet_info::{LOCAL_ACTOR_LINK_ID, LinkId, StreamId};

/// Request to bind a stream which egresses from the local adapter.
///
/// `dock_link_id` identifies the link of the dock making this request.
/// (This is currently always [zpr::packet_info::DOCK_LINK_ID]; on adapters,
/// this represents the remote dock; on nodes, this represents the internal
/// dock.)
///
/// `txn_id` is used when issuing responses to the dock to link them to
/// this request.
///
/// `tc` is the traffic classifier for which the request is being made.
///
/// The bind is performed simply by inserting a PEP corresponding to the
/// given TC into the DLT, generating a tether ID.
///
/// A success response (containing the tether ID) or error response (in
/// the event that the DLT is full) is then issued to the dock, where these
/// responses are handled by [`dock::install_tether()`] and [`dock::deny_tether()`]
/// respectively.
pub fn bind_egress_stream(
    asm: &Arc<Assembly>,
    dock_link_id: NonZero<LinkId>,
    txn_id: txn_mgr::TxnId,
    tc: tc::Ip5TupleTc,
) {
    debug!(
        target: FLOW_MGMT,
        "bind_egress_stream(dock_link_id={dock_link_id}, txn_id={txn_id}, tc={tc})");

    // form PEP
    let pep = DltPep { tc };

    // TODO: reverse path

    // attempt to insert into DLT and respond to requestor
    match asm.dlt.insert(pep) {
        Ok(tid) => {
            // TODO: maybe tick a counter somewhere?
            match asm.ph_mode {
                PhMode::Node => {
                    // we're a node operating on our internal adapter; "respond" directly to local dock
                    let dock_peer_state = asm.peer_table.get(LOCAL_ACTOR_LINK_ID).unwrap();
                    let txn = dock_peer_state
                        .txn_mgr
                        .get(txn_id)
                        .expect("local dock lost transaction");
                    dock::install_tether(
                        asm,
                        NonZero::new(LOCAL_ACTOR_LINK_ID).unwrap(),
                        &txn,
                        tid,
                    )
                    .expect("local dock rejected tether response");
                }

                PhMode::Adapter => super::requests::send_bind_egress_stream_success_response(
                    asm,
                    dock_link_id.get(),
                    txn_id,
                    tid,
                )
                .enqueue(),
            }
        }

        Err(()) => {
            // DLT full; respond with error message
            let msg = "DLT full";
            // TODO: maybe tick a counter somewhere?

            match asm.ph_mode {
                PhMode::Node => {
                    // we're a node operating on our internal adapter; "respond" directly to local dock
                    let dock_peer_state = asm.peer_table.get(LOCAL_ACTOR_LINK_ID).unwrap();
                    let txn = dock_peer_state
                        .txn_mgr
                        .get(txn_id)
                        .expect("local dock lost transaction");
                    dock::deny_tether(asm, NonZero::new(LOCAL_ACTOR_LINK_ID).unwrap(), &txn, msg)
                        .expect("local dock rejected tether response");
                }

                PhMode::Adapter => super::requests::send_bind_egress_stream_error_response(
                    asm,
                    dock_link_id.get(),
                    txn_id,
                    msg,
                )
                .enqueue(),
            }
        }
    }
}

pub fn unbind_stream(asm: &Arc<Assembly>, dock_link_id: NonZero<LinkId>, stream_id: StreamId) {
    debug!(
        target: FLOW_MGMT,
        "unbind_egress_stream(dock_link_id={dock_link_id}, stream_id={stream_id})");

    // Remove the stream from the dock lookup table
    asm.dlt.remove(stream_id)
}

#[derive(Debug)]
pub enum InstallTetherError {
    NoSuchTransaction,
}

/// Install the given tether into the ELT.
///
/// `txn` must refer to an active transaction on the dock link
/// which had previously requested a tether (e.g.  via BindActorAddress).
///
/// `tether_id` is the ID to be used to refer to this tether.
///
/// `tc` is the traffic classifier to use to match traffic for this tether.
///
/// On success, the queued initial packet is then forwarded on the new tether.
///
/// Completes the indicated transaction.
///
/// Returns an error only if the transaction is invalid.
pub fn install_tether(
    asm: &Assembly,
    txn: &txn_mgr::TxnHandle,
    tether_id: StreamId,
    tc: tc::Ip5TupleTc,
) -> Result<(), InstallTetherError> {
    let five_tuple = asm
        .elt
        .lookup_pending(txn)
        .map_err(|_| InstallTetherError::NoSuchTransaction)?;

    // Confirm this TC matches our initial packet.
    if !tc.classify_5t(&five_tuple) {
        error!(target: FLOW_MGMT, "Bind of {five_tuple} falied: node supplied TC incompatible with initial packet: {tc}");
        asm.elt.remove(&five_tuple).unwrap();
        return Ok(());
    }

    // Bind succeeded; add to ELT.
    debug!(target: FLOW_MGMT, "Bind of {five_tuple} succeeded: {tether_id}");

    let pep = EltPep {
        compression_mode: tc.compression_mode(),
        tether_id,
    };

    let Ok(initial_packet) = asm.elt.set_active(&five_tuple, pep) else {
        // The only way for a transaction to have exited pending (i.e.,
        // either error from set_active()) at this point (after our earlier
        // lookup of the 5t) is because we got some other response to this
        // same transaction which caused this code to be run twice
        // concurrently.  So from a serialization perspective, the first
        // response ended the transaction, and now this 2nd response is for
        // a non-existent transaction.  For logging, we infer that a duplicate
        // response must be the cause.

        warn!(target: FLOW_MGMT, "Duplicate bind response for {five_tuple}, ignoring");
        return Err(InstallTetherError::NoSuchTransaction);
    };

    // now send out initial packet
    match asm.actor_output_requeue.try_enqueue_packet(initial_packet) {
        Ok(()) => (),
        Err(queues::TryEnqueueError::Full(_pkt)) => {
            debug!(target: FLOW_MGMT, "Requeue backpressure on bind of {five_tuple}, dropping initial packet");
            asm.counters.management[ManagementCounterType::QueueBackpressure].increment();
        }
    }

    Ok(())
}

/// Deny the given tether request, removing it from the ALT.
///
/// `txn` must refer to an active transaction on the dock link
/// which had previously requested a tether.
///
/// `reason` is a human-readable reason why the tether was denied.
///
/// Completes the indicated transaction.
///
/// Returns an error only if the transaction is invalid.
pub fn deny_tether(
    asm: &Assembly,
    txn: &txn_mgr::TxnHandle,
    reason: &str,
) -> Result<(), InstallTetherError> {
    let five_tuple = asm
        .elt
        .lookup_pending(txn)
        .map_err(|_| InstallTetherError::NoSuchTransaction)?;

    debug!(target: FLOW_MGMT, "Bind of {five_tuple} failed: {reason}");

    // TODO FIXME:
    //
    // We could have a weird race where a second (buggy) response for the same
    // transaction comes in, we process it concurrently (which we don't right now),
    // it wins the race and removes the 5t and txn, a _new_ bind request for the
    // _same_ 5t enters the table, and _then_ we remove that one erroneously.
    //
    // We ignore that possibility.

    match asm.elt.remove(&five_tuple) {
        Ok(_) => Ok(()),
        Err(_) => Err(InstallTetherError::NoSuchTransaction),
    }
}
