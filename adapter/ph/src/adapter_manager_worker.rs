use crate::adapter_tables::{AltEntry, AltPep};
use crate::assembly::{Assembly, PhMode};
use crate::counters::CounterType;
use crate::fastpath;
use crate::logging::targets::FLOW_MGMT;
use crate::mgmt;
use crate::packet::Packet;
use crate::queues::{AdapterManagerMessage, TryEnqueueError};
use std::num::NonZero;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::*;
use zpr;

pub async fn launch(asm: Arc<Assembly>, mut queue: mpsc::Receiver<AdapterManagerMessage>) {
    while let Some(msg) = queue.recv().await {
        match msg {
            AdapterManagerMessage::RequestTetherId(pkt) => {
                let mgmt_pkt = Packet::new_with_existing_metadata(pkt.buffer().clone());
                fastpath::drop_and_count(&asm, pkt, CounterType::DispatchedToMgmt);

                // for now, perform these sequentially...
                // ideally, we place these into a JoinSet,
                // but let's work out how message sequencing works before doing that!!
                do_request_tether_id(&asm, mgmt_pkt).await;
            }
        }
    }
}

// RFC 6.5 § 6.3.11
async fn do_request_tether_id(asm: &Arc<Assembly>, mut pkt: Packet) {
    let five_tuple = pkt.metadata().five_tuple();

    // if there's already an entry, this is a duplicate request
    // (NOTE: we should be the only ones modifying this table!)
    if asm.alt.get(five_tuple).is_some() {
        mgmt::core::count_event(asm, &mut pkt, CounterType::DroppedAwaitingBind);
        return;
    }

    // copy out five tuple so we can give away packet
    let five_tuple = *five_tuple;

    let dock_link_id = match asm.ph_mode {
        PhMode::Adapter => zpr::DOCK_LINK_ID,
        PhMode::Node => zpr::LINK_ID_UNKNOWN,
    };

    if dock_link_id != zpr::LINK_ID_UNKNOWN && !asm.is_link_ready(dock_link_id) {
        debug!(target: FLOW_MGMT, "Link {dock_link_id} is not ready to receive traffic yet");
        mgmt::core::count_event(asm, &mut pkt, CounterType::DroppedNoSA);
        return;
    }

    if five_tuple.dst_address.is_v6_unicast_link_local()
        || five_tuple.src_address.is_v6_unicast_link_local()
    {
        // Link local traffic can't issue binds
        return;
    }

    let packet_body: Vec<u8> = pkt.body().into();

    // mark ALT entry as pending to attempt to (i.e. racily) prevent
    // fastpath from issuing multiple requests
    asm.alt.insert(five_tuple, AltEntry::Pending(pkt));

    // compress only IP addresses for now
    let compression_mode: zpr::CompressionMode = 0;

    debug!(target: FLOW_MGMT, "link {dock_link_id}: Issuing bind request for {five_tuple} (is now set PENDING)");

    let bind_result = match asm.ph_mode {
        PhMode::Adapter => {
            mgmt::requests::send_bind_agent_address_request(
                asm,
                dock_link_id,
                compression_mode,
                five_tuple,
                packet_body,
            )
            .await
        }

        PhMode::Node => mgmt::dock::bind_agent_address(
            asm,
            NonZero::new(zpr::LOCAL_AGENT_LINK_ID).unwrap(),
            compression_mode,
            five_tuple,
            packet_body,
        )
        .await
        .map_err(|err| {
            mgmt::requests::BindAgentAddressError::BindAgentAddressError(err.to_string().into())
        }),
    };

    match bind_result {
        Ok(tether_id) => {
            // Bind succeeded; add to ALT.
            debug!(target: FLOW_MGMT, "Bind of {five_tuple} succeeded: {tether_id}");

            let AltEntry::Pending(initial_packet) = asm
                .alt
                .alter(&five_tuple, |entry| {
                    assert!(
                        matches!(entry, AltEntry::Pending(_)),
                        "coding error: race to activate pending ALT entry"
                    );

                    std::mem::replace(
                        entry,
                        AltEntry::Active(AltPep {
                            compression_mode,
                            tether_id,
                        }),
                    )
                })
                .unwrap()
            else {
                unreachable!();
            };

            // now send out initial packet
            match asm.agent_output_requeue.try_enqueue_packet(initial_packet) {
                Ok(()) => (),
                Err(TryEnqueueError::Full(_pkt)) => {
                    debug!(target: FLOW_MGMT, "Requeue backpressure on bind of {five_tuple}, dropping initial packet");
                    asm.counters[CounterType::QueueBackpressure].increment();
                }
            }
        }

        Err(err) => {
            // Bind failed; remove pending entry from ALT.
            debug!(target: FLOW_MGMT, "Bind of {five_tuple} failed: {err}");
            asm.alt.remove(&five_tuple);
        }
    }
}
