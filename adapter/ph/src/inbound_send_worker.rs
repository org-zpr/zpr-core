use crate::assembly::Assembly;
<<<<<<< HEAD
use crate::counters_enum::*;
use crate::ext::tokio_tun::*;
use crate::net_defs;
use crate::queues::InboundSendMessage;
=======
use crate::InboundSendMessage;
>>>>>>> 54f0b6f (merge main into link layer branch (#205))
use std::future::Future;
use std::io::IoSlice;
use tokio::sync::mpsc;
use tokio_tun::Tun;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize,
}

fn ip_version(pkt: &[u8]) -> u8 {
    pkt[0] >> 4
}

fn ip_ethertype(ip_version: u8) -> u16 {
    match ip_version {
        4 => net_defs::ETHERTYPE_IP,
        6 => net_defs::ETHERTYPE_IPV6,
        _ => 0,
    }
}

async fn worker<'pktbuf>(
    config: &Config,
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<InboundSendMessage<'pktbuf>>,
    tun: &Tun,
) {
    let mut messages = Vec::new();

    while let count @ 1.. = queue.recv_many(&mut messages, config.batch_size).await {
        for msg in &mut messages {
            match msg {
                InboundSendMessage::Packet(pkt) => {
                    let proto = ip_ethertype(ip_version(pkt.body()));
                    let mut hdr = pkt.alloc_zeroed_header::<[u8; tun_pi::PI_SIZE]>() as &mut [u8];
                    tun_pi::write_pi(
                        &mut hdr,
                        tun_pi::TunPi {
                            strip: false,
                            proto,
                        },
                    );

                    tun.send_vectored(&[IoSlice::new(pkt.body())])
                        .await
                        .unwrap();

                    asm.counters[CounterType::InPacksSent].increment();
                } // TODO: error handling

                InboundSendMessage::TestPacket(_pkt) => (),
            };
        }

        asm.buffer_stack
            .put_buffers(messages.drain(..).filter_map(|msg| match msg {
                InboundSendMessage::Packet(pkt) => Some(pkt.destroy()),
                // acknowledge had to go here since it consumes the packet, it could not be in
                // the previous match because the program still expected the packet to me in messages
                InboundSendMessage::TestPacket(pkt) => {
                    pkt.acknowledge(queue.len(), count);
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
