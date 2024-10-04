//! Code which handles dispatching management packets from fastpath.

use crate::assembly::Assembly;
use crate::mgmt::dispatch;
use crate::queues::MgmtDispatchMessage;
use std::future::Future;
use tokio::sync::mpsc;

async fn worker<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<MgmtDispatchMessage<'pktbuf>>,
) {
    while let Some(msg) = queue.recv().await {
        match msg {
            MgmtDispatchMessage::Packet(ingress_link_id, pkt) => {
                dispatch::dispatch_mgmt_packet(asm, ingress_link_id, pkt);
            }
        }
    }
}

pub fn launch<'pktbuf>(
    asm: impl std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync + 'pktbuf,
    mut queue: mpsc::Receiver<MgmtDispatchMessage<'pktbuf>>,
) -> impl Future<Output = ()> + 'pktbuf {
    async move { worker(&*asm, &mut queue).await }
}
