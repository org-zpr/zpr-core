use crate::adapter_tables::{AltEntry, AltPep};
use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::fastpath;
use crate::mgmt;
use crate::packet::Packet;
use crate::queues::AdapterManagerMessage;
use crate::zpr;
use std::future::Future;
use tokio::sync::mpsc;

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
) -> impl Future<Output = ()> + Send + 'pktbuf {
    async move { worker(&*asm, &mut queue).await }
}

// RFC 6.5 § 6.3.11
async fn do_request_tether_id<'pktbuf>(asm: &Assembly<'pktbuf>, pkt: Packet<'pktbuf>) {
    // TODO: node version... that just allocates a tether ID directly from the internal dock, no messages exchanged

    // just extract 5t and drop packet for now, storing & resending it later is a TODO
    let five_tuple = *pkt.metadata().five_tuple();
    fastpath::drop_and_count(asm, pkt, CounterType::DroppedAwaitingBind);

    // if there's already an entry, this is a duplicate request
    // (NOTE: we should be the only ones modifying this table!)
    if asm.alt.inspect(&five_tuple, |_entry| ()).is_some() {
        return;
    }

    // mark ALT entry as pending to attempt to (i.e. racily) prevent
    // fastpath from issuing multiple requests
    asm.alt.insert(five_tuple, AltEntry::Pending);

    // compress only IP addresses for now
    let compression_mode: zpr::CompressionMode = 0;

    eprintln!("Issuing bind request for {}", five_tuple);

    // send Bind request

    match mgmt::send_bind_agent_address_request(
        asm,
        asm.adapter_docking_session_id,
        compression_mode,
        five_tuple,
    )
    .await
    {
        Ok(tether_id) => {
            // Bind succeeded; add to ALT.
            eprintln!("Bind of {} succeeded: {}", five_tuple, tether_id);
            asm.alt
                .alter(&five_tuple, |entry| {
                    assert!(matches!(entry, AltEntry::Pending));
                    *entry = AltEntry::Active(AltPep {
                        compression_mode,
                        tether_id,
                    });
                })
                .unwrap();
        }

        Err(err) => {
            // Bind failed; remove pending entry from ALT.
            eprintln!("Bind of {} failed: {}", five_tuple, err);
            asm.alt.remove(&five_tuple);
        }
    }
}
