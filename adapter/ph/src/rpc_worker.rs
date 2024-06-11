use core::future::Future;
use crate::assembly::Assembly;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::io::AsyncWriteExt;
use std::io::prelude::*;
use tokio::io::BufReader;
use tokio::io::BufWriter;
use tokio::task::JoinSet;
use tokio::task::LocalSet;
use tokio::io::AsyncBufReadExt;

async fn worker(
    asm: &'static Assembly<'static>, socket: &UnixListener
) {
    let mut set = JoinSet::new();

    loop {
        tokio::select! {
            _ = set.join_next() => (),
            accepted = socket.accept() => {
                println!("accepted");
                match accepted {
                    Ok((mut stream, _addr)) => {
                        set.spawn(async move {

                            eprintln!("Connection recieved");
                            //let local = task::LocalSet::new();
                            let mut str_message = String::new();
                            let mut split_buf = stream.split(); // split stream into read/write streams
                            let mut buf_reader = BufReader::new(split_buf.0);
                            let mut buf_writer = BufWriter::new(split_buf.1);
                            buf_reader.read_line(&mut str_message).await;
                            let last_let = str_message.pop(); // Removes \n from end of string
                            if last_let != Some('\n') {
                                // close stream then skip the rest of the loop and moves to next iteration
                                buf_writer.shutdown();
                            } else {
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
                        });
                    }
                    Err(_e) => {
                        eprintln!("Connection failed");
                    }
                }   
            }
        }TODO
        
    }
}

pub fn launch<'pktbuf, UnixListenerRef: 'pktbuf>(
    asm: &'static Assembly<'static>, socket: UnixListenerRef)
-> impl Future<Output = ()> + Send + 'pktbuf
    where UnixListenerRef: std::ops::Deref<Target = UnixListener> + Send + Sync
{
    async move { worker(&*asm, &*socket).await }
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
    for p in 0..2 {
        asm.counters[p - 1].reset();
    }
    return "counters_reset\n".to_string(); // TODO change the return value of counters reset
}