use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tokio::sync::mpsc;

use tracing::info;

use ph::km::{KeyManager, SillyKeyManager};


#[derive(Debug, Clone)]
pub struct ZDPServer {
    addr: String, // listen address, "host:port"
}


// Placeholder or demonstration code for a dock server component on a node.
// Here to help with testing the KM code.
impl ZDPServer {
    pub fn new(addr_port: &str) -> ZDPServer {
        ZDPServer {
            addr: addr_port.to_string(),
        }
    }

    pub async fn run(&self, ctok: CancellationToken) -> io::Result<()> {
        let local_addr: SocketAddr = match self.addr.parse() {
            Ok(addr) => addr,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid address",
                ));
            }
        };

        let socket = UdpSocket::bind(local_addr).await?;
        info!("ZDP server listening on {}", self.addr);        
        let s_recv = Arc::new(socket);
        let s_send = s_recv.clone();

        let (km_tx, mut km_rx) = mpsc::channel(16);
        let km_ctok = ctok.clone();

        // In real implemntation each client gets a KM instance.
        let mgr = KeyManager::new(Box::new(SillyKeyManager::new()));        
        let mut mgr_cc = mgr.clone();
        tokio::spawn(async move {
            mgr_cc.start(false, km_ctok, km_tx).await.unwrap();
        });

        // This dummy node only allows for one connection at a time.
        // We wait to recv some bytes.  We get an (unverified) source address.
        // Then we attempt to set up an SA using our key management system.
        let mut cur_client: Option<SocketAddr> = None;

        let mut buf = [0u8; 1024];
        loop {
            tokio::select! {
                _ = ctok.cancelled() => {
                    info!("ZDP Server cancelled");
                    break;
                }

                Some(km_buf) = km_rx.recv() => {
                    // This is a raw KM message to send to this client (NOTE: the KM needs to be associated with the correct client!)
                    // Needs a ZDP header -- unless we are sending 'bare' KM messages.
                    if cur_client.is_none() {
                        info!("error: KM generated a message but we have no client to send to");
                        continue;
                    }   
                    match s_send.send_to(&km_buf, cur_client.unwrap()).await {
                        Ok(sz) => {
                            info!("zdp/client - sent {} byte KM message", sz);
                        },
                        Err(e) => {
                            info!("zdp/server - error sending KM message: {:?}", e);
                        }
                    }
                }

                Ok((n, src)) = s_recv.recv_from(&mut buf) => {
                    info!("Received {} bytes from {}", n, src);
                    if cur_client.is_none() {
                        cur_client = Some(src);
                    } else if cur_client != Some(src) {
                        info!("Ignoring message from unknown source");
                        continue;
                    }
                    // Normally we would look at the SPI/ZPI or other header information to determine 
                    // what to do with the message.  For now we assume this is a key management message.
                    // If this is a transport message we would also use KM, but would use the decrypt fn instead of 
                    // this channel.
                    match mgr.handle_km_message(&buf[..n]).await {
                        Ok(_) => {},
                        Err(e) => {
                            info!("zdp/server - error handling KM message: {:?}", e);
                            // TODO: Drop client? Reset KM?                            
                        }
                    }
                }
            }
        }

        Ok(())
    }

}