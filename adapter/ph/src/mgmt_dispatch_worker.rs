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
            MgmtDispatchMessage::Packet(ingress_link_id, peer_sa, pkt) => {
                dispatch::dispatch_mgmt_packet(asm, ingress_link_id, peer_sa, pkt);
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
