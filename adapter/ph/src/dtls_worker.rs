use std::future::Future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio_openssl::SslStream;
use crate::assembly::Assembly;
use crate::packet::{self, Packet};
use crate::udp_stream::UdpStream;
use crate::counters_enum::CounterType;

// NOTE: Packet buffers *must* be at least 16384 bytes, to match TLS maximum
// record size.  This is because OpenSSL read functions provide no way to
// determine whether the provided read buffer was too small to contain a
// full record.  So to ensure correct behavior we must be prepared to accept
// the maximum size record.
const _: () = assert!(packet::PACKET_BODY_BUFFER_MAX_SIZE >= 16384, "packet buffers too small for OpenSSL DTLS");

#[allow(unreachable_code)]
async fn worker<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ssl_stream: &mut SslStream<UdpStream<'_>>,
    outbound_queue: &mut mpsc::Receiver<Packet<'pktbuf>>
) {
    // FIXME: We want to use a RefCell here, but Rust doesn't
    // realize that our use safely implements Send.
    // See <https://github.com/tokio-rs/tokio/discussions/4702>.
    let ssl_stream = Mutex::new(ssl_stream);

    tokio::join! {
        async {
            loop {
                let buf = asm.buffer_stack.get_buffer().await;
                let mut pkt = Packet::new(buf, 0);
                { ssl_stream.blocking_lock().read_buf(&mut pkt) }.await.unwrap();
                asm.counters[CounterType::InPacksRec].increment();
                // NOTE: There is no way to detect a too-large packet.  See above.
                asm.inbound_processor.enqueue(pkt).await;
            }
        },

        async {
            loop {
                let out_pkt = outbound_queue.recv().await.unwrap();
                { ssl_stream.blocking_lock().write(out_pkt.body()) }.await.unwrap();  // TODO: error handling
                asm.buffer_stack.put_buffer(out_pkt.destroy());
            }
        }
    };
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
