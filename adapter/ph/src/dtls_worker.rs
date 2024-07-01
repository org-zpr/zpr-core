use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::packet::{self, Packet};
use crate::udp_stream::UdpStream;
use crate::OutboundSendMessage;
use std::future::Future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_openssl::SslStream;

// NOTE: Packet buffers *must* be at least 16384 bytes, to match TLS maximum
// record size.  This is because OpenSSL read functions provide no way to
// determine whether the provided read buffer was too small to contain a
// full record.  So to ensure correct behavior we must be prepared to accept
// the maximum size record.
const _: () = assert!(
    packet::PACKET_BODY_BUFFER_MAX_SIZE >= 16384,
    "packet buffers too small for OpenSSL DTLS"
);

#[allow(unreachable_code)]
async fn worker<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ssl_stream: &mut SslStream<UdpStream<'_>>,
    outbound_queue: &mut mpsc::Receiver<OutboundSendMessage<'pktbuf>>,
) {
    let (mut ssl_read, mut ssl_write) = tokio::io::split(ssl_stream);

    tokio::join! {
        async {
            loop {
                let buf = asm.buffer_stack.get_buffer().await;
                let mut pkt = Packet::new(buf, 0);
                ssl_read.read_buf(&mut pkt).await.unwrap();
                asm.counters[CounterType::InPacksRec].increment();
                // NOTE: There is no way to detect a too-large packet.  See above.
                asm.inbound_processor.enqueue_packet(pkt).await;
            }
        },

        async {
            loop {
                let out_pkt = outbound_queue.recv().await.unwrap();
                match out_pkt {
                    OutboundSendMessage::Packet(pkt) => {
                        ssl_write.write(pkt.body()).await.unwrap();  // TODO: error handling
                        asm.buffer_stack.put_buffer(pkt.destroy());
                    },
                    OutboundSendMessage::TestPacket(pkt) => pkt.acknowledge(outbound_queue.len())

                }

            }
        }
    };
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    asm: AsmRef,
    mut ssl_stream: SslStream<UdpStream<'pktbuf>>,
    mut outbound_queue: mpsc::Receiver<OutboundSendMessage<'pktbuf>>,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
{
    async move { worker(&*asm, &mut ssl_stream, &mut outbound_queue).await }
}
