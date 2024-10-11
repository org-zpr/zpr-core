//! Code which handles dispatching management packets from fastpath.

use crate::assembly::Assembly;
use crate::mgmt::dispatch;
use crate::queues::MgmtDispatchMessage;
use std::future::Future;
use tokio::sync::mpsc;

async fn worker(
    asm: &'static Assembly<'_>,
    queue: &mut mpsc::Receiver<MgmtDispatchMessage<'static>>,
) {
    while let Some(msg) = queue.recv().await {
        match msg {
            MgmtDispatchMessage::WithLink(pkt) => {
                dispatch::dispatch_mgmt_packet_with_link(asm, pkt);
            }
            MgmtDispatchMessage::WithAddr(peer_sa, pkt) => {
                dispatch::dispatch_mgmt_packet_with_addr(asm, peer_sa, pkt);
            }
        }
    }
}

pub fn launch(
    asm: &'static Assembly,
    mut queue: mpsc::Receiver<MgmtDispatchMessage<'static>>,
) -> impl Future<Output = ()> + 'static {
    async move { worker(&*asm, &mut queue).await }
}
