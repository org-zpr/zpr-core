//! Code which handles dispatching management packets from fastpath.

use crate::assembly::Assembly;
use crate::counters;
use crate::fastpath;
use crate::mgmt::dispatch;
use crate::queues::MgmtDispatchMessage;
use std::sync::Arc;
use tokio::sync::mpsc;

pub async fn launch(asm: Arc<Assembly>, mut queue: mpsc::Receiver<MgmtDispatchMessage>) {
    while let Some(msg) = queue.recv().await {
        match msg {
            MgmtDispatchMessage::WithLink(mut pkt) => {
                dispatch::dispatch_mgmt_packet_with_link(&asm, &mut pkt);
                fastpath::drop_and_count(&asm, pkt, counters::CounterType::DispatchedToMgmt);
            }
            MgmtDispatchMessage::WithAddr(peer_sa, mut pkt) => {
                dispatch::dispatch_mgmt_packet_with_addr(&asm, peer_sa, &mut pkt);
                fastpath::drop_and_count(&asm, pkt, counters::CounterType::DispatchedToMgmt);
            }
        }
    }
}
