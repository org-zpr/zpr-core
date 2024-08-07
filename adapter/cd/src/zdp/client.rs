use std::io;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use tokio::sync::mpsc;

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use ph::km::{KeyManager, SillyKeyManager};

#[derive(Debug, Clone)]
pub struct ZDPClient {
    addr: String,
}

impl ZDPClient {
    pub fn new(addr_port: &str) -> ZDPClient {
        ZDPClient {
            addr: addr_port.to_string(),
        }
    }

    // Dummy function for my testing only
    pub async fn run(&self, ctok: CancellationToken) -> io::Result<()> {
        let mgr = KeyManager::new(Box::new(SillyKeyManager::new()));

        let remote_addr: SocketAddr = match self.addr.parse() {
            Ok(addr) => addr,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to parse address: {}", e),
                ));
            }
        };

        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect(remote_addr).await?;

        let s_recv = Arc::new(socket);
        let s_send = s_recv.clone();

        let (km_tx, mut km_rx) = mpsc::channel(16);

        let km_ctok = ctok.clone();
        let mut mgr_cc = mgr.clone();
        tokio::spawn(async move {
            mgr_cc.start(true, km_ctok, km_tx).await.unwrap();
        });

        // Now loop -
        //   read from UDP, pass to KM
        //   write KM messages to UDP
        let mut buf = [0u8; 1024];
        loop {
            tokio::select! {
                _ = ctok.cancelled() => {
                    info!("zdp/client - cancelled");
                    break;
                }

                Some(km_buf) = km_rx.recv() => {
                    // This is a KM message to send.  This is a raw KM payload.  Should get a ZDP header
                    // unless we are running 'bare'.
                    match s_send.send(&km_buf).await {
                        Ok(sz) => {
                            info!("zdp/client - sent {} byte KM message", sz);
                        }
                        Err(e) => {
                            info!("zdp/client - send of KM message failed: {}", e);
                        }
                    }
                }

                read_result = s_recv.recv(&mut buf) => {
                    // Input from UDP socket.  Assume it is a KM message.
                    // Normally we could check the TYPE field in ZDP header. Or detect it in some other way if running bare.
                    match read_result {
                        Ok(input_len) => {
                            info!("zdp/client - read {} bytes", input_len);
                            match mgr.handle_km_message(&buf).await {
                                Ok(()) => {},
                                Err(e) => {
                                    info!("zdp/client - handle_km_message failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            info!("zdp/client - read failed: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
