use core::future::Future;
use crate::assembly::Assembly;
use tokio::net::UnixListener;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::io::BufWriter;
use tokio::io::AsyncBufReadExt;

async fn worker(
    asm: &Assembly<'_>, socket: &UnixListener
) {

    loop {
        match socket.accept().await {
            Ok((mut stream, _addr)) => {
                eprintln!("Connection recieved");
                let mut str_message = String::new();
                let split_buf = stream.split(); // split stream into read/write streams
                let mut buf_reader = BufReader::new(split_buf.0);
                let mut buf_writer = BufWriter::new(split_buf.1);
                buf_reader.read_line(&mut str_message).await;
                let last_let = str_message.pop(); // Removes \n from end of string
                if last_let != Some('\n') {
                    // close stream then skip the rest of the loop and moves to next iteration
                    buf_writer.shutdown();
                    continue; 
                }
                // TODO remove \n from end of message?
                buf_writer.write("Message Recieved\n".as_bytes()).await;

                match str_message.as_str() {
                    "ECHO" => {buf_writer.write_all(echo(asm).await.as_bytes()).await;
                                  buf_writer.write_all("OK\n".as_bytes()).await}, 
                    _      => buf_writer.write_all("ERR\n".as_bytes()).await,
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
    asm: AsmRef, socket: UnixListenerRef)
-> impl Future<Output = ()> + Send + 'pktbuf
    where AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
        UnixListenerRef: std::ops::Deref<Target = UnixListener> + Send + Sync
{
    async move { worker(&*asm, &*socket).await }
}

async fn echo(_asm: &Assembly<'_>) -> String {
    return "hello\n".to_string(); // TODO change the return value of echo
}