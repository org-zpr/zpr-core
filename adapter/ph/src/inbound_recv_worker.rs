use core::future::Future;
use std::io::IoSliceMut;
use tokio::net::UdpSocket;
use crate::ext::std::vec::VecExt;
use crate::ext::tokio::net::*;
use crate::assembly::Assembly;
use crate::packet::Packet;

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize
}

async fn worker(
    config: &Config, asm: &Assembly<'_>, socket: &UdpSocket
) {
    let mut bufs = Vec::new();
    let mut iovs_outer = Vec::new();
    //let mut iovs_slices_outer = Vec::new();  // TODO; see below
    let mut msgs_outer = Vec::new();

    loop {
        // grab some buffers from the pool
        asm.buffer_stack.get_buffers(config.batch_size, &mut bufs).await;

        // construct iovecs
        let mut iovs = iovs_outer;
        for buf in &mut bufs {
            iovs.push([IoSliceMut::new(*buf)])
        }

        // TODO: reuse Vec -- why doesn't the recycle trick work here?
        let mut iovs_slices = Vec::new(); //iovs_slices_outer;
        for iov in &mut iovs {
            iovs_slices.push(&mut iov[..]);
        }

        // make space for msgs
        let mut msgs = msgs_outer;

        // grab at least one packet off the network
        let n_recvd = udp_socket_recv_multiple_vectored_from(socket, &mut iovs_slices[..], &mut msgs).await.unwrap();

        //iovs_slices_outer = iovs_slices.recycle();
        iovs_outer = iovs.recycle();

        // return unused buffers
        asm.buffer_stack.put_buffers(bufs.drain(n_recvd..));

        // enqueue received packets with packet processor
        for (buf, msg) in bufs.drain(..).zip(&msgs) {
            asm.counters[0].increment();
            println!("packet recieved");
            asm.counters[0].print();
            if msg.1 { 
                asm.buffer_stack.put_buffers([buf]); 
                asm.counters[1].increment();
                println!("packet dropped");
                asm.counters[1].print();
            }  // packet was too large; drop TODO: count somewhere
            else { asm.inbound_processor.enqueue(Packet{ len: msg.0, buf }).await; }
        }

        msgs_outer = msgs.recycle();
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf, UdpSocketRef: 'pktbuf>(
    config: &Config, asm: AsmRef, socket: UdpSocketRef)
-> impl Future<Output = ()> + Send + 'pktbuf
    where AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
        UdpSocketRef: std::ops::Deref<Target = UdpSocket> + Send + Sync
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &*socket).await }
}
