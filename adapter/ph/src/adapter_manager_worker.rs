use crate::adapter_tables::{self, AltPep};
use crate::assembly::{Assembly, PhMode};
use crate::counters::ManagementCounterType;
use crate::logging::targets::FLOW_MGMT;
use crate::mgmt;
use crate::packet::{Packet, PacketBuffer};
use crate::queues::{AdapterManagerMessage, TryEnqueueError};
use crate::tc;
use crate::two_way_queue;
use std::num::NonZero;
use std::sync::Arc;
use tracing::*;
use zpr;

pub async fn launch(
    asm: Arc<Assembly>,
    mut queue: two_way_queue::Receiver<AdapterManagerMessage, PacketBuffer>,
) {
    while let Some(mut msg) = queue.recv().await {
        match &mut *msg {
            AdapterManagerMessage::RequestTetherId(pkt) => {
                let mgmt_pkt = Packet::new_with_existing_metadata(pkt.buffer().clone());
                drop(msg);

                // for now, perform these sequentially...
                // ideally, we place these into a JoinSet,
                // but let's work out how message sequencing works before doing that!!
                do_request_tether_id(&asm, mgmt_pkt).await;
            }
        }
    }
}

// RFC 6.5 § 6.3.11
async fn do_request_tether_id(asm: &Arc<Assembly>, pkt: Packet) {
    let dock_link_id = zpr::DOCK_LINK_ID;

    // copy out five tuple so we can give away packet
    let five_tuple = *pkt.metadata().five_tuple();

    if five_tuple.dst_address.is_v6_unicast_link_local()
        || five_tuple.src_address.is_v6_unicast_link_local()
    {
        // Link local traffic can't issue binds
        return;
    }

    let Some(peer_state) = asm.peer_table.get(dock_link_id) else {
        // Link was dropped
        return;
    };

    if !peer_state.link_state_machine.is_ready() {
        debug!(target: FLOW_MGMT, "Link {dock_link_id} is not ready to receive traffic yet");
        mgmt::core::count_event(asm, ManagementCounterType::DroppedNoSA);
        return;
    }

    // try open a transaction on the link; if we can't due to backpressure, don't wait, just give up
    let Some(txn) = peer_state.txn_mgr.try_open() else {
        debug!(target: FLOW_MGMT, "link {dock_link_id}: backpressure on link prevents issuing bind request for {five_tuple}");
        mgmt::core::count_event(asm, ManagementCounterType::QueueBackpressure);
        return;
    };

    // copy out packet body
    let packet_body = pkt.body().to_owned();

    // mark ALT entry as pending to attempt to (i.e. racily) prevent
    // fastpath from issuing multiple requests
    match asm.alt.insert_pending(five_tuple, pkt, &txn) {
        Ok(()) => (),

        Err(adapter_tables::InsertPendingError::AlreadyPending(_pkt)) => {
            // there's already an entry; this is a duplicate request
            mgmt::core::count_event(asm, ManagementCounterType::DroppedAwaitingBind);
            return;
        }

        Err(adapter_tables::InsertPendingError::DuplicateTransaction(_pkt)) => {
            panic!("duplicate transaction")
        }
    }

    debug!(target: FLOW_MGMT, "link {dock_link_id}: Issuing bind request for {five_tuple} (is now set PENDING)");

    let bind_result = match asm.ph_mode {
        PhMode::Adapter => {
            mgmt::requests::send_bind_actor_address_request(
                asm,
                dock_link_id,
                &five_tuple,
                &packet_body,
            )
            .await
        }

        PhMode::Node => mgmt::dock::bind_actor_address(
            asm,
            NonZero::new(zpr::LOCAL_ACTOR_LINK_ID).unwrap(),
            &five_tuple,
            &packet_body,
        )
        .await
        .map_err(|err| {
            mgmt::requests::BindActorAddressError::BindActorAddressError(err.to_string().into())
        }),
    };

    match bind_result {
        Ok((tether_id, tc)) => {
            // Confirm this TC matches our initial packet.
            // TODO: use the TC itself to do this, once we have that code in place.
            if tc.five_tuple()
                != tc::Ip5TupleTc::new_with_compression_mode(tc.compression_mode(), five_tuple)
                    .five_tuple()
            {
                error!(target: FLOW_MGMT, "Bind of {five_tuple} falied: node supplied TC incompatible with initial packet: {tc}");
                asm.alt.remove(&five_tuple).unwrap();
                return;
            }

            // Bind succeeded; add to ALT.
            debug!(target: FLOW_MGMT, "Bind of {five_tuple} succeeded: {tether_id}");

            let pep = AltPep {
                compression_mode: tc.compression_mode(),
                tether_id,
            };

            let initial_packet = asm.alt.set_active(&five_tuple, pep).unwrap();

            // now send out initial packet
            match asm.actor_output_requeue.try_enqueue_packet(initial_packet) {
                Ok(()) => (),
                Err(TryEnqueueError::Full(_pkt)) => {
                    debug!(target: FLOW_MGMT, "Requeue backpressure on bind of {five_tuple}, dropping initial packet");
                    asm.counters.management[ManagementCounterType::QueueBackpressure].increment();
                }
            }
        }

        Err(err) => {
            // Bind failed; remove pending entry from ALT.
            debug!(target: FLOW_MGMT, "Bind of {five_tuple} failed: {err}");
            asm.alt.remove(&five_tuple).unwrap();
        }
    }
}
