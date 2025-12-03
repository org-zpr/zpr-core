use crate::adapter_tables;
use crate::assembly::{Assembly, PhMode};
use crate::counters::ManagementCounterType;
use crate::logging::targets::FLOW_MGMT;
use crate::mgmt;
use crate::packet::{Packet, PacketBuffer};
use crate::queues::AdapterManagerMessage;
use crate::two_way_queue;
use std::num::NonZero;
use std::sync::Arc;
use tracing::*;
use zpr::packet_info::{DOCK_LINK_ID, LOCAL_ACTOR_LINK_ID};

pub async fn launch(
    asm: Arc<Assembly>,
    mut queue: two_way_queue::Receiver<AdapterManagerMessage, PacketBuffer>,
) {
    while let Some(mut msg) = queue.recv().await {
        match &mut *msg {
            AdapterManagerMessage::RequestTetherId(pkt) => {
                let mgmt_pkt = Packet::new_with_existing_metadata(pkt.buffer().clone());
                drop(msg);

                do_request_tether_id(&asm, mgmt_pkt);
            }
        }
    }
}

// RFC 6.5 § 6.3.11
fn do_request_tether_id(asm: &Arc<Assembly>, pkt: Packet) {
    let dock_link_id = DOCK_LINK_ID;

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

    let txn_id = txn.id();

    // mark ELT entry as pending to attempt to (i.e. racily) prevent
    // fastpath from issuing multiple requests
    match asm.elt.insert_pending(five_tuple, pkt, &txn) {
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

    match asm.ph_mode {
        PhMode::Adapter => {
            mgmt::requests::send_bind_actor_address_request(asm, dock_link_id, txn_id, &packet_body)
                .enqueue()
        }

        PhMode::Node => mgmt::dock::bind_actor_address(
            asm,
            NonZero::new(LOCAL_ACTOR_LINK_ID).unwrap(),
            txn_id,
            &packet_body,
        ),
    }
}
