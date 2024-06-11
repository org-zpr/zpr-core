use core::future::Future;
use crate::assembly::Assembly;
use tokio::net::UnixListener;
use tokio::io::AsyncWriteExt;

async fn worker(
    asm: &Assembly<'_>, socket: &UnixListener
) {

    loop {
        match socket.accept().await {
            Ok((mut stream, _addr)) => {
                eprintln!("Connection recieved");
                stream.shutdown();
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