//! Code which handles active aspects of ZDPR (namely, retries).

use crate::counters;
use crate::mgmt;
use crate::prelude::*;
use tokio::select;
use tokio::time;

pub async fn launch(asm: Arc<Assembly>, link_id: LinkId) {
    let mut retry_interval = time::interval(config::DEFAULT_ZDPR_RETRY_TIMER);
    retry_interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        let Some(peer_state) = asm.peer_table.get(link_id) else {
            // peer removed; we're done
            break;
        };

        let retry_needed = peer_state.zdpr_send.lock().unwrap().retry_needed();

        select! {
            _ = retry_interval.tick(), if retry_needed => {
                let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();
                let mut count = 0;

                // Resend any packets which must be resent.
                zdpr_send.age_retries().for_each(drop);
                let packets = zdpr_send.retry_packets();
                let packets = packets.inspect(|_| count += 1);
                mgmt::core::build_and_egress_packets(&asm, link_id, packets);
                mgmt::core::count_events(&asm, counters::ManagementCounterType::ResentPacket, count);

                // Resend any cancels which must be resent.
                zdpr_send.retry_cancels().for_each(|sn| mgmt::core::send_cancel(&asm, link_id, sn));
            }

            () = peer_state.zdpr_retry_timer_reset.notified() => retry_interval.reset(),
        };
    }
}
