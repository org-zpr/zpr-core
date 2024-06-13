use std::future::Future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_openssl::SslStream;
use crate::assembly::Assembly;
use crate::config;
use crate::packet::{self, Packet};
use crate::udp_stream::UdpStream;
use crate::counters_enum::CounterType;

// NOTE: Packet buffers *must* be at least 16384 bytes, to match TLS maximum
// record size.  This is because OpenSSL read functions provide no way to
// determine whether the provided read buffer was too small to contain a
// full record.  So to ensure correct behavior we must be prepared to accept
// the maximum size record.
const _: () = assert!(packet::PACKET_BODY_BUFFER_MAX_SIZE >= 16384, "packet buffers too small for OpenSSL DTLS");

#[derive(Default)]
enum InboundRecvState<'pktbuf> {
    #[default] GetBuffer,
    ReadPacket{ buf: &'pktbuf mut [u8; config::PACKET_BUFFER_SIZE] },
    EnqueuePacket{ pkt: Packet<'pktbuf> }
}

impl<'pktbuf> InboundRecvState<'pktbuf> {
    async fn step(&mut self,
        asm: &Assembly<'pktbuf>,
        ssl_stream: &mut SslStream<UdpStream<'_>>
    ) {
        match std::mem::take(self) {
            InboundRecvState::GetBuffer =>
                *self = InboundRecvState::ReadPacket{ buf: asm.buffer_stack.get_buffer().await },

            InboundRecvState::ReadPacket{ buf } => {
                let mut pkt = Packet::new(buf, 0);
                match ssl_stream.read_buf(&mut pkt).await {
                    Ok(_) => {
                        asm.counters[CounterType::InPacksRec].increment();
                        // NOTE: There is no way to detect a too-large packet.  See above.
                        *self = InboundRecvState::EnqueuePacket{ pkt };
                    },

                    Err(_) =>  // TODO: count error
                        *self = InboundRecvState::ReadPacket{ buf: pkt.destroy() }
                }
            },

            InboundRecvState::EnqueuePacket{ pkt } => {
                asm.inbound_processor.enqueue(pkt).await;
                *self = InboundRecvState::GetBuffer
            }
        }
    }

    fn reset(self, asm: &Assembly<'pktbuf>) {
        match self {
            InboundRecvState::GetBuffer => (),

            InboundRecvState::ReadPacket{ buf } =>
                asm.buffer_stack.put_buffer(buf),

            InboundRecvState::EnqueuePacket{ pkt } =>
                asm.buffer_stack.put_buffer(pkt.destroy())
        }
    }
}

#[allow(unreachable_code)]
async fn worker<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ssl_stream: &mut SslStream<UdpStream<'_>>,
    outbound_queue: &mut mpsc::Receiver<Packet<'pktbuf>>
) {
    let mut inbound_recv_state = InboundRecvState::default();

    loop {
        // SslStream has no notion of "splitting" into a read half & a write
        // half, but it requires a mut reference for I/O operations.  So
        // we're forced to "manually" multiplex here, via
        // `InboundRecvState`.  (Note this is necessary to avoid deadlock
        // between inbound & outbound paths!)

        tokio::select! {
            () = inbound_recv_state.step(&asm, ssl_stream) => (),

            out_pkt = outbound_queue.recv() => {
                let out_pkt = out_pkt.unwrap();
                // NOTE: We can safely ignore the possibility to deadlock
                // here, since the DTLS connection uses UDP and therefore
                // writes can only block on the L2 network queue, not the
                // path through the node.
                ssl_stream.write(out_pkt.body()).await.unwrap();  // TODO: error handling
                asm.buffer_stack.put_buffer(out_pkt.destroy());
            }
        };
    }

    inbound_recv_state.reset(asm);
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    asm: AsmRef,
    mut ssl_stream: SslStream<UdpStream<'pktbuf>>,
    mut outbound_queue: mpsc::Receiver<Packet<'pktbuf>>)
-> impl Future<Output = ()> + Send + 'pktbuf
    where AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync
{
    async move { worker(&*asm, &mut ssl_stream, &mut outbound_queue).await }
}
