use crate::assembly::Assembly;
use crate::counters_enum::CounterType;
use crate::packet::{self, Packet};
use crate::udp_stream::UdpStream;
use crate::OutboundSendMessage;
use std::future::Future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_openssl::SslStream;

#[derive(Copy, Clone)]
pub struct Config {
    pub inbound_batch_size: usize,
    pub outbound_batch_size: usize,
}

#[derive(Copy, Clone)]
pub struct Config {
    pub inbound_batch_size: usize,
    pub outbound_batch_size: usize
}

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
    config: &Config,
    asm: &Assembly<'pktbuf>,
    ssl_stream: &mut SslStream<UdpStream<'_>>,
    outbound_queue: &mut mpsc::Receiver<OutboundSendMessage<'pktbuf>>,
) {
    let (mut ssl_read, mut ssl_write) = tokio::io::split(ssl_stream);

    tokio::join! {
        async {
            let mut bufs = Vec::new();

            loop {
                // grab some buffers from the pool
                asm.buffer_stack.get_buffers(config.inbound_batch_size, &mut bufs).await;

                // read & forward packets one at a time, no sense to batch really
                // since neither `read_buf()` nor `enqueue()` support it
                for buf in bufs.drain(..) {
                    let mut pkt = Packet::new(buf, 0);
                    ssl_read.read_buf(&mut pkt).await.unwrap();
                    asm.counters[CounterType::InPacksRec].increment();
                    // NOTE: There is no way to detect a too-large packet.  See above.
                    asm.inbound_processor.enqueue_packet(pkt).await;
                }
            }
        },

        async {
            let mut msgs = Vec::new();

            while let _count @ 1.. = outbound_queue.recv_many(&mut msgs, config.outbound_batch_size).await {
                for msg in &msgs {
                    match msg {
                        OutboundSendMessage::Packet(pkt) => {
                            ssl_write.write(pkt.body()).await.unwrap();  // TODO: error handling
                        },

                        OutboundSendMessage::TestPacket(_) => ()  /* handled below */
                    }
                }

                asm.buffer_stack.put_buffers(msgs.drain(..).filter_map(
                        |msg|
                            match msg {
                                OutboundSendMessage::Packet(pkt) => Some(pkt.destroy()),

                                OutboundSendMessage::TestPacket(pkt) => {
                                    pkt.acknowledge(outbound_queue.len());
                                    None
                                }
                            }
                    ));
            }
        }
    };
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    config: &Config,
    asm: AsmRef,
    mut ssl_stream: SslStream<UdpStream<'pktbuf>>,
    mut outbound_queue: mpsc::Receiver<OutboundSendMessage<'pktbuf>>,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &mut ssl_stream, &mut outbound_queue).await }
}
