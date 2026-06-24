//! Code which handles dispatching management packets from fastpath.

use crate::mgmt::dispatch;
use crate::prelude::*;
use crate::queues::MgmtDispatchMessage;
use crate::two_way_queue;

pub async fn launch(
    asm: Arc<Assembly>,
    mut queue: two_way_queue::Receiver<MgmtDispatchMessage, PacketBuffer>,
) {
    while let Some(mut msg) = queue.recv().await {
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
    }
}
