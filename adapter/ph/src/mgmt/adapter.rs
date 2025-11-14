use super::txn_mgr;
use crate::adapter_tables::AltPep;
use crate::assembly::Assembly;
use crate::counters::ManagementCounterType;
use crate::logging::targets::FLOW_MGMT;
use crate::queues;
use crate::tc;
use tracing::*;
use zpr::StreamId;

#[derive(Debug)]
pub enum InstallTetherError {
    NoSuchTransaction,
}

/// Install the given tether into the ALT.
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
        .alt
        .lookup_pending(txn)
        .map_err(|_| InstallTetherError::NoSuchTransaction)?;

    // Confirm this TC matches our initial packet.
    // TODO: use the TC itself to do this, once we have that code in place.
    if tc.five_tuple()
        != tc::Ip5TupleTc::new_with_compression_mode(tc.compression_mode(), five_tuple).five_tuple()
    {
        error!(target: FLOW_MGMT, "Bind of {five_tuple} falied: node supplied TC incompatible with initial packet: {tc}");
        asm.alt.remove(&five_tuple).unwrap();
        return Ok(());
    }

    // Bind succeeded; add to ALT.
    debug!(target: FLOW_MGMT, "Bind of {five_tuple} succeeded: {tether_id}");

    let pep = AltPep {
        compression_mode: tc.compression_mode(),
        tether_id,
    };

    let Ok(initial_packet) = asm.alt.set_active(&five_tuple, pep) else {
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

/// Deny the given tether request.
///
/// Completes the indicated transaction.
pub fn deny_tether(
    asm: &Assembly,
    txn: &txn_mgr::TxnHandle,
    reason: &str,
) -> Result<(), InstallTetherError> {
    let five_tuple = asm
        .alt
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

    match asm.alt.remove(&five_tuple) {
        Ok(_) => Ok(()),
        Err(_) => Err(InstallTetherError::NoSuchTransaction),
    }
}
