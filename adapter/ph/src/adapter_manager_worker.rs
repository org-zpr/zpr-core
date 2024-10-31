use crate::adapter_tables::{AltEntry, AltPep};
use crate::assembly::{Assembly, PhMode};
use crate::counters::CounterType;
use crate::fastpath;
use crate::mgmt::requests;
use crate::packet::Packet;
use crate::queues::AdapterManagerMessage;
use std::future::Future;
use tokio::sync::mpsc;
use tracing::{debug, error};
use zpr;

async fn worker<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<AdapterManagerMessage<'pktbuf>>,
) {
    while let Some(msg) = queue.recv().await {
        match msg {
            AdapterManagerMessage::RequestTetherId(pkt) => {
                // for now, perform these sequentially...
                // ideally, we place these into a JoinSet,
                // but let's work out how message sequencing works before doing that!!
                do_request_tether_id(asm, pkt).await;
            }
        }
    }
}

pub fn launch<'pktbuf>(
    asm: impl std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync + 'pktbuf,
    mut queue: mpsc::Receiver<AdapterManagerMessage<'pktbuf>>,
) -> impl Future<Output = ()> + 'pktbuf {
    async move { worker(&*asm, &mut queue).await }
}

// RFC 6.5 § 6.3.11
async fn do_request_tether_id<'pktbuf>(asm: &Assembly<'pktbuf>, pkt: Packet<'pktbuf>) {
    // TODO: node version... that just allocates a tether ID directly from the internal dock, no messages exchanged
    if matches!(asm.ph_mode, PhMode::Node) {
        fastpath::drop_and_count(asm, pkt, CounterType::DroppedNop);
        return;
    }

    let five_tuple = pkt.metadata().five_tuple();

    // if there's already an entry, this is a duplicate request
    // (NOTE: we should be the only ones modifying this table!)
    if asm.alt.get(five_tuple).is_some() {
        fastpath::drop_and_count(asm, pkt, CounterType::DroppedAwaitingBind);
        return;
    }

    // copy out five tuple so we can give away packet
    let five_tuple = *five_tuple;

    // if there's already an entry, this is a duplicate request
    // (NOTE: we should be the only ones modifying this table!)
    if asm.alt.get(&five_tuple).is_some() {
        fastpath::drop_and_count(asm, pkt, CounterType::DroppedDuplicate);
        return;
    }

    // NOPE ! not if the link is not ready.
    let link_id = asm.hack_get_adapter_docking_session_id();
    if !asm.peer_table.is_security_assocaition_established(link_id) {
        error!(
            "{}: Link {} has no security association, aborting bind request operation",
            asm.system_name, link_id
        );
        fastpath::drop_and_count(asm, pkt, CounterType::DroppedNoSA);
        return;
    }

    // mark ALT entry as pending to attempt to (i.e. racily) prevent
    // fastpath from issuing multiple requests
    asm.alt.insert(five_tuple, AltEntry::Pending(pkt));

    // compress only IP addresses for now
    let compression_mode: zpr::CompressionMode = 0;

    debug!(
        "{}: link {}: Issuing bind request for {} (is now set PENDING)",
        asm.system_name, link_id, five_tuple
    );

    match requests::send_bind_agent_address_request(
        asm,
        asm.hack_get_adapter_docking_session_id(),
        compression_mode,
        five_tuple,
    )
    .await
    {
        Ok(tether_id) => {
            // Bind succeeded; add to ALT.
            debug!(
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
            debug!(
                "{}: Bind of {} failed: {}",
                asm.system_name, five_tuple, err
            );
            asm.alt.remove(&five_tuple);
        }
    }
}
