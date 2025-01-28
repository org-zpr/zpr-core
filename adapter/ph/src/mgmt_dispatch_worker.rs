//! Code which handles dispatching management packets from fastpath.

use crate::assembly::Assembly;
use crate::mgmt::dispatch;
use crate::packet::PacketBuffer;
use crate::queues::MgmtDispatchMessage;
use crate::two_way_queue;
use std::sync::Arc;

pub async fn launch(
    asm: Arc<Assembly>,
    mut queue: two_way_queue::Receiver<MgmtDispatchMessage, PacketBuffer>,
) {
    while let Some(mut msg) = queue.recv().await {
        match &mut *msg {
            MgmtDispatchMessage::WithLink(pkt) => {
                dispatch::dispatch_mgmt_packet_with_link(&asm, pkt);
            }
            MgmtDispatchMessage::WithAddr(peer_sa, pkt) => {
                dispatch::dispatch_mgmt_packet_with_addr(&asm, *peer_sa, pkt);
            }
        }
    }
}
