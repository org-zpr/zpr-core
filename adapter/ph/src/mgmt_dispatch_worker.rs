//! Code which handles dispatching management packets from fastpath.
//! There is only one of these in the system.

use crate::mgmt::dispatch;
use crate::prelude::*;
use crate::queues::MgmtDispatchMessage;
use crate::two_way_queue;
use tokio::select;
use tokio::sync::mpsc;

pub async fn launch(
    asm: Arc<Assembly>,
    mut queue: two_way_queue::Receiver<MgmtDispatchMessage, PacketBuffer>,
    mut hairpin_queue: mpsc::Receiver<Packet>,
) {
    loop {
        select! {
            Some(mut msg) = queue.recv() => {
                match &mut *msg {
                    MgmtDispatchMessage::WithLink(pkt) => {
                        dispatch::dispatch_mgmt_packet_with_link(&asm, pkt);
                    }

                    MgmtDispatchMessage::WithAddr {
                        peer_sa,
                        interface_addr,
                        packet,
                    } => {
                        dispatch::dispatch_mgmt_packet_with_addr(&asm, *peer_sa, *interface_addr, packet);
                    }
                }
            },

            Some(mut pkt) = hairpin_queue.recv() =>
                dispatch::dispatch_mgmt_packet_with_link(&asm, &mut pkt),

            else => break,
        }
    }
}
