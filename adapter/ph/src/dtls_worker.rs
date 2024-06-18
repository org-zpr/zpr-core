use std::future::Future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
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

struct InboundRecvStream<'a, 'b, 'c, 'pktbuf> {
    asm: &'a Assembly<'pktbuf>,
    ssl_stream: &'a Mutex<&'b mut SslStream<UdpStream<'c>>>,
    state: InboundRecvState<'pktbuf>
}

impl<'a, 'b, 'c, 'pktbuf> InboundRecvStream<'a, 'b, 'c, 'pktbuf> where 'pktbuf: 'a {
    fn new(asm: &'a Assembly<'pktbuf>, ssl_stream: &'a Mutex<&'b mut SslStream<UdpStream<'c>>>) -> Self {
        InboundRecvStream { asm, ssl_stream, state: InboundRecvState::default() }
    }

    async fn step(&mut self) {
        match std::mem::take(&mut self.state) {
            InboundRecvState::GetBuffer =>
                self.state = InboundRecvState::ReadPacket{ buf: self.asm.buffer_stack.get_buffer().await },

            InboundRecvState::ReadPacket{ buf } => {
                let mut pkt = Packet::new(buf, 0);
                { self.ssl_stream.blocking_lock().read_buf(&mut pkt) }.await.unwrap();
                self.asm.counters[CounterType::InPacksRec].increment();
                // NOTE: There is no way to detect a too-large packet.  See above.
                self.state = InboundRecvState::EnqueuePacket{ pkt };
            },

            InboundRecvState::EnqueuePacket{ pkt } => {
                self.asm.inbound_processor.enqueue(pkt).await;
                self.state = InboundRecvState::GetBuffer
            }
        }
    }

    fn reset(&mut self) {
        match std::mem::take(&mut self.state) {
            InboundRecvState::GetBuffer => (),

            InboundRecvState::ReadPacket{ buf } =>
                self.asm.buffer_stack.put_buffer(buf),

            InboundRecvState::EnqueuePacket{ pkt } =>
                self.asm.buffer_stack.put_buffer(pkt.destroy())
        }
    }
}

#[allow(unreachable_code)]
async fn worker<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ssl_stream: &mut SslStream<UdpStream<'_>>,
    outbound_queue: &mut mpsc::Receiver<Packet<'pktbuf>>
) {
    // FIXME: We want to use a RefCell here, but Rust doesn't
    // realize that our use safely implements Send.
    // See <https://github.com/tokio-rs/tokio/discussions/4702>.
    let ssl_stream_cell = Mutex::new(ssl_stream);

    let mut inbound_recv_stream = InboundRecvStream::new(asm, &ssl_stream_cell);

    loop {
        // SslStream has no notion of "splitting" into a read half & a write
        // half, but it requires a mut reference for I/O operations.  So
        // we're forced to "manually" multiplex here, via
        // `InboundRecvState`.  (Note this is necessary to avoid deadlock
        // between inbound & outbound paths!)

        tokio::select! {
            () = inbound_recv_stream.step() => (),

            out_pkt = outbound_queue.recv() => {
                let out_pkt = out_pkt.unwrap();
                // NOTE: We can safely ignore the possibility to deadlock
                // here, since the DTLS connection uses UDP and therefore
                // writes can only block on the L2 network queue, not the
                // path through the node.
                { ssl_stream_cell.blocking_lock().write(out_pkt.body()) }.await.unwrap();  // TODO: error handling
                asm.buffer_stack.put_buffer(out_pkt.destroy());
            }
        };
    }

    inbound_recv_stream.reset();
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
