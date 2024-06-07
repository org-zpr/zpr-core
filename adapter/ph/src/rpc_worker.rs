use core::future::Future;
use std::io::IoSliceMut;
use tokio::net::UdpSocket;
use crate::ext::std::vec::VecExt;
use crate::ext::tokio::net::*;
use crate::assembly::Assembly;
use crate::packet::Packet;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::io::AsyncWriteExt;
<<<<<<< HEAD
use std::io::prelude::*;
use tokio::io::BufReader;
use tokio::io::BufWriter;

use std::fs::File;
use std::thread;
use tokio::io::AsyncBufReadExt;
=======
>>>>>>> 0d543bf (added first stage of RPC handling to program)

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize
}

async fn worker(
    config: &Config, asm: &Assembly<'_>, socket: &UnixListener
) {

    loop {
        match socket.accept().await {
            Ok((mut stream, _addr)) => {
                eprintln!("Connection recieved");
                let mut str_message = String::new();
                let mut split_buf = stream.split(); // split stream into read/write streams
                let mut buf_reader = BufReader::new(split_buf.0);
                let mut buf_writer = BufWriter::new(split_buf.1);
                buf_reader.read_line(&mut str_message).await;
                str_message.pop(); // Removes \n from end of string

                // TODO remove \n from end of message?
                buf_writer.write("Message Recieved\n".as_bytes()).await;
                
                // TODO there must be a more efficient way to send the OK message, is match statement best suited?
                match str_message.as_str() {
                    "COUNTERS RESET" => {buf_writer.write_all(counters_reset(asm).await.as_bytes()).await;
                                         buf_writer.write_all("OK\n".as_bytes()).await},
                    "COUNTERS"       => {buf_writer.write_all(counters(asm).await.as_bytes()).await;
                                         buf_writer.write_all("OK\n".as_bytes()).await},
                    "ECHO"           => {buf_writer.write_all(echo(asm).await.as_bytes()).await;
                                         buf_writer.write_all("OK\n".as_bytes()).await},
                    _                => buf_writer.write_all("ERR\n".as_bytes()).await,
                };

                buf_writer.flush().await;
                buf_writer.shutdown().await;
            }
            Err(e) => {
                eprintln!("Connection failed");
            }
        }   
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf, UnixListenerRef: 'pktbuf>(
    config: &Config, asm: AsmRef, socket: UnixListenerRef)
-> impl Future<Output = ()> + Send + 'pktbuf
    where AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
        UnixListenerRef: std::ops::Deref<Target = UnixListener> + Send + Sync
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &*socket).await }
}

async fn echo(_asm: &Assembly<'_>) -> String {
    return "echo\n".to_string(); // TODO change the return value of echo
}

// TODO not sure if just printing is what we want this function to do
async fn counters(asm: &Assembly<'_>) -> String {
    for p in 0..2 { // TODO replace 2 with some global var that represents # of packets
        let num = asm.counters[p].get_count();
        println!("{num}");
    }
    return "counters\n".to_string(); // TODO change the return value of counters
}

async fn counters_reset(asm: &Assembly<'_>) -> String {
    for p in 1..2 {
        asm.counters[p - 1].reset();
    }
    return "counters_reset\n".to_string(); // TODO change the return value of counters reset
}