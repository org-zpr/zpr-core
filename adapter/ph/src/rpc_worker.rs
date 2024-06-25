use core::future::Future;
use crate::assembly::Assembly;
use tokio::net::UnixListener;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::io::BufWriter;
use tokio::task::JoinSet;
use tokio::io::AsyncBufReadExt;
use tokio::net::UnixStream;
use std::io::Error;
use std::fmt::Write;


async fn worker(
    asm: &'static Assembly<'static>, socket: &UnixListener
) {
    let mut set = JoinSet::<Result<(), Error>>::new();

    loop {
        tokio::select! {
            Some(ret) = set.join_next() => 
                match ret {
                    Ok(Ok(())) => (),
                    Ok(Err(err)) => eprintln!("Handle Connection Failed: {err}"),
                    Err(err) => eprintln!("join_next panicked: {err}")
                },
            accepted = socket.accept() => 
                match accepted {
                    Ok((stream, _addr)) => {
                        set.spawn(handle_connection(asm, stream));
                    },
                    Err(_e) => {
                        eprintln!("Connection failed");
                    }
            }
        }
        
    }
}

async fn handle_connection(asm: &'static Assembly<'static>, mut stream: UnixStream, ) -> std::io::Result<()> {
    eprintln!("Connection recieved");
    let mut str_message = String::new();
    let split_buf = stream.split(); // split stream into read/write streams
    let mut buf_reader = BufReader::new(split_buf.0);
    let mut buf_writer = BufWriter::new(split_buf.1);
    buf_reader.read_line(&mut str_message).await?;
    let last_let = str_message.pop(); // Removes \n from end of string
    if last_let != Some('\n') {
        // close stream then skip the rest of the loop and moves to next iteration
        buf_writer.shutdown().await?;
    } else {
        // TODO remove \n from end of message?
        buf_writer.write("Message Recieved\n".as_bytes()).await?;
        
        let vec_message: Vec<&str> = str_message.split_whitespace().collect();

        // TODO there must be a more efficient way to send the OK message, is match statement best suited?
        match vec_message[0] {
            // changed to single word to allow for use of split by space, avoids unnecessary 
            // parsing when command is not PERF-SAMPLE
            "COUNTERS-RESET" => {buf_writer.write_all(counters_reset(asm).await.as_bytes()).await?;
                                buf_writer.write_all("OK\n".as_bytes()).await?},
            "COUNTERS"       => {buf_writer.write_all(counters(asm).await.as_bytes()).await?;
                                buf_writer.write_all("OK\n".as_bytes()).await?},
            "ECHO"           => {buf_writer.write_all(echo(asm).await.as_bytes()).await?;
                                buf_writer.write_all("OK\n".as_bytes()).await?},
            "PERF-SAMPLE"    => {buf_writer.write_all(perf_sample(asm, vec_message[1], vec_message[2]).await.as_bytes()).await?;
                                buf_writer.write_all("OK\n".as_bytes()).await?},
            _                => buf_writer.write_all("ERR\n".as_bytes()).await?,
        };

        buf_writer.flush().await?;
        buf_writer.shutdown().await?;
    }

    Ok(())
}

pub fn launch<'pktbuf, UnixListenerRef: 'pktbuf>(
    asm: &'static Assembly<'static>, socket: UnixListenerRef)
-> impl Future<Output = ()> + Send + 'pktbuf
    where UnixListenerRef: std::ops::Deref<Target = UnixListener> + Send + Sync
{
    async move { worker(&*asm, &*socket).await }
}

async fn echo(_asm: &Assembly<'_>) -> String {
    "echo\n".to_string()
}

// TODO not sure if just printing is what we want this function to do
async fn counters(asm: &Assembly<'_>) -> String {
    let mut counts: String = "".to_string();
    for (key, &ref value) in &asm.counters {
        let _ = write!(&mut counts, "{}: {}\n", key, value.get_count());
    }
    
    counts
}

async fn counters_reset(asm: &Assembly<'_>) -> String {
    for value in asm.counters.values() {
        value.reset();
    }

    "counters_reset\n".to_string()
}

async fn perf_sample(asm: &Assembly<'_>, duration: &str, rate: &str) -> String {

    let mut ret = "".to_string();


    let send = asm.inbound_processor.enqueue_test_packet().await;
    // asm.inbound_send.enqueue_test_packet();
    // asm.outbound_processor.enqueue_test_packet();
    // asm.outbound_send.enqueue_test_packet();

    let _ = write!(&mut ret, "duration: {:?}\n", send.unwrap().in_queue);

    ret
}