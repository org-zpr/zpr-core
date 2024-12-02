use crate::adapter_tables::{AltEntry, AltPep};
use crate::assembly::{Assembly, PhMode};
use crate::counters::CounterType;
use crate::fastpath;
use crate::mgmt;
use crate::packet::BufferPacket;
use crate::queues::AdapterManagerMessage;
use std::num::NonZero;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::*;
use zpr;

pub async fn launch(asm: Arc<Assembly>, mut queue: mpsc::Receiver<AdapterManagerMessage>) {
    while let Some(msg) = queue.recv().await {
        match msg {
            AdapterManagerMessage::RequestTetherId(pkt) => {
                // for now, perform these sequentially...
                // ideally, we place these into a JoinSet,
                // but let's work out how message sequencing works before doing that!!
                do_request_tether_id(&asm, pkt).await;
            }
        }
    }
}

// RFC 6.5 § 6.3.11
async fn do_request_tether_id(asm: &Arc<Assembly>, pkt: BufferPacket) {
    let five_tuple = pkt.metadata().five_tuple();

    // if there's already an entry, this is a duplicate request
    // (NOTE: we should be the only ones modifying this table!)
    if asm.alt.get(five_tuple).is_some() {
        fastpath::drop_and_count(asm, pkt, CounterType::DroppedAwaitingBind);
        return;
    }

    // copy out five tuple so we can give away packet
    let five_tuple = *five_tuple;

    let dock_link_id = match asm.ph_mode {
        PhMode::Adapter => zpr::DOCK_LINK_ID,
        PhMode::Node => zpr::LINK_ID_UNKNOWN,
    };

    // if link is not ready, we cannot proceed
    if dock_link_id != zpr::LINK_ID_UNKNOWN
        && !asm
            .peer_table
            .is_security_assocaition_established(dock_link_id)
    {
        error!(
            "{}: Link {} has no security association, aborting bind request operation",
            asm.system_name, dock_link_id
        );
        fastpath::drop_and_count(asm, pkt, CounterType::DroppedNoSA);
        return;
    }

    // mark ALT entry as pending to attempt to (i.e. racily) prevent
    // fastpath from issuing multiple requests
    asm.alt.insert(five_tuple, AltEntry::Pending(pkt));

    // compress only IP addresses for now
    let compression_mode: zpr::CompressionMode = 0;

    info!(
        "{}: link {}: Issuing bind request for {} (is now set PENDING)",
        asm.system_name, dock_link_id, five_tuple
    );

    let bind_result = match asm.ph_mode {
        PhMode::Adapter => {
            mgmt::requests::send_bind_agent_address_request(
                asm,
                dock_link_id,
                compression_mode,
                five_tuple,
            )
            .await
        }

        PhMode::Node => mgmt::dock::bind_agent_address(
            asm,
            NonZero::new(zpr::LOCAL_AGENT_LINK_ID).unwrap(),
            compression_mode,
            five_tuple,
        )
        .await
        .map_err(|err| {
            mgmt::requests::BindAgentAddressError::BindAgentAddressError(err.to_string().into())
        }),
    };

    match bind_result {
        Ok(tether_id) => {
            // Bind succeeded; add to ALT.
            info!(
                "{}: Bind of {} succeeded: {}",
                asm.system_name, five_tuple, tether_id
            );

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
            fastpath::agent_output_post_classify(
                asm,
                initial_packet,
                /* allow_bind_request */ false,
            );
        }

        Err(err) => {
            // Bind failed; remove pending entry from ALT.
            info!(
                "{}: Bind of {} failed: {}",
                asm.system_name, five_tuple, err
            );
            asm.alt.remove(&five_tuple);
        }
    }
}
