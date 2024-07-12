use crate::assembly::Assembly;
use crate::InboundSendMessage;
use std::future::Future;
use std::io::IoSlice;
use tokio::sync::mpsc;
use tokio_tun::Tun;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize,
}

async fn worker<'pktbuf>(
    config: &Config,
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<InboundSendMessage<'pktbuf>>,
    tun: &Tun,
) {
    let mut messages = Vec::new();

    while let count @ 1.. = queue.recv_many(&mut messages, config.batch_size).await {
        for msg in &messages {
            match msg {
                InboundSendMessage::Packet(msg) => {
                    tun.send_vectored(&[IoSlice::new(msg.body())])
                        .await
                        .unwrap();
                } // TODO: error handling
                InboundSendMessage::TestPacket(_msg) => (),
            };
        }
        asm.buffer_stack
            .put_buffers(messages.drain(..).filter_map(|msg| match msg {
                InboundSendMessage::Packet(msg) => Some(msg.destroy()),
                // acknowledge had to go here since it consumes the packet, it could not be in
                // the previous match because the program still expected the packet to me in messages
                InboundSendMessage::TestPacket(msg) => {
                    msg.acknowledge(queue.len(), count);
                    None
                }
            }));
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf, TunRef: 'pktbuf>(
    config: &Config,
    asm: AsmRef,
    mut queue: mpsc::Receiver<InboundSendMessage<'pktbuf>>,
    tun: TunRef,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
    TunRef: std::ops::Deref<Target = Tun> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &mut queue, &*tun).await }
}
