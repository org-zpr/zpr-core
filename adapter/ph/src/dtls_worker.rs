use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::packet::{self, Packet};
use crate::OutboundSendMessage;
use std::future::Future;
use std::io::ErrorKind;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[derive(Copy, Clone)]
pub struct Config {
    pub inbound_batch_size: usize,
    pub outbound_batch_size: usize,
}

// NOTE: Packet buffers *must* be at least 16384 bytes, to match TLS maximum
// record size.  This is because OpenSSL read functions provide no way to
// determine whether the provided read buffer was too small to contain a
// full record.  So to ensure correct behavior we must be prepared to accept
// the maximum size record.
const _: () = assert!(
    packet::PACKET_BUFFER_MAX_BODY_SIZE >= 16384,
    "packet buffers too small for OpenSSL DTLS"
);

#[allow(unreachable_code)]
async fn worker<'a>(
    config: &Config,
    asm: &Assembly<'a>,
    socket: &UdpSocket,
    outbound_queue: &mut mpsc::Receiver<OutboundSendMessage<'a>>,
) {
    tokio::join! {
        async {
            let mut bufs = Vec::new();

            loop {
                // grab some buffers from the pool
                asm.buffer_stack.get_buffers(config.inbound_batch_size, &mut bufs).await;

                // TODO: batch receive
                for buf in bufs.drain(..) {
                    let mut pkt = Packet::new(buf, 0);
                    loop {
                        match socket.recv_buf(&mut pkt).await {
                            Ok(_) => (),

                            Err(err) => {
                                match err.kind() {
                                    ErrorKind::ConnectionRefused => (),  // FIXME: do something with this later...
                                    _ => panic!("got socket error {}", err),
                                }
                                continue;
                            }
                        }

                        asm.counters[CounterType::InPacksRec].increment();
                        // FIXME: Detect a too-large packet.
                        asm.inbound_processor.enqueue_packet(pkt).await;
                        break;
                    }
                }
            }
        },

        async {
            let mut msgs = Vec::new();

            while let count @ 1.. = outbound_queue.recv_many(&mut msgs, config.outbound_batch_size).await {
                for msg in &msgs {
                    match msg {
                        OutboundSendMessage::Packet(pkt) => {
                            socket.send(pkt.body()).await.unwrap();  // TODO: error handling
                            asm.counters[CounterType::OutPacksSent].increment();
                        },

                        OutboundSendMessage::TestPacket(_) => ()  /* handled below */
                    }
                }

                asm.buffer_stack.put_buffers(msgs.drain(..).filter_map(
                        |msg|
                            match msg {
                                OutboundSendMessage::Packet(pkt) => Some(pkt.destroy()),

                                OutboundSendMessage::TestPacket(pkt) => {
                                    pkt.acknowledge(outbound_queue.len(), count);
                                    None
                                }
                            }
                    ));
            }
        }
    };
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
