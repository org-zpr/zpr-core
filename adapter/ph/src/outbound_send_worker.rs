use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::OutboundSendMessage;
use std::future::Future;
use std::io::ErrorKind;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize,
}

async fn worker<'a>(
    config: &Config,
    asm: &Assembly<'a>,
    socket: &UdpSocket,
    outbound_queue: &mut mpsc::Receiver<OutboundSendMessage<'a>>,
) {
    let mut msgs = Vec::new();

    while let count @ 1.. = outbound_queue.recv_many(&mut msgs, config.batch_size).await {
        for msg in &msgs {
            match msg {
                OutboundSendMessage::Packet(pkt) => {
                    match socket.send(pkt.body()).await {
                        Ok(_) => {
                            asm.counters[CounterType::OutPacksSent].increment();
                        }

                        Err(err) => {
                            match err.kind() {
                                ErrorKind::InvalidInput | ErrorKind::Unsupported => {
                                    panic!("Unrecoverable I/O error {}", err)
                                }

                                // most other network errors are temporary, just count
                                // TODO: it would be nice to report to the user _why_ packets aren't moving;
                                // this depends on <https://github.com/rust-lang/rust/issues/86442> though
                                _ => asm.counters[CounterType::OutPacksErr].increment(),
                            }
                        }
                    }
                }

                OutboundSendMessage::TestPacket(_) => (), /* handled below */
            }
        }

        asm.buffer_stack
            .put_buffers(msgs.drain(..).filter_map(|msg| match msg {
                OutboundSendMessage::Packet(pkt) => Some(pkt.destroy()),

                OutboundSendMessage::TestPacket(pkt) => {
                    pkt.acknowledge(outbound_queue.len(), count);
                    None
                }
            }));
    }
}

pub fn launch<'a, AsmRef: 'a, SocketRef: 'a>(
    config: &Config,
    asm: AsmRef,
    socket: SocketRef,
    mut outbound_queue: mpsc::Receiver<OutboundSendMessage<'a>>,
) -> impl Future<Output = ()> + Send + 'a
where
    AsmRef: std::ops::Deref<Target = Assembly<'a>> + Send + Sync,
    SocketRef: std::ops::Deref<Target = UdpSocket> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &*socket, &mut outbound_queue).await }
}
