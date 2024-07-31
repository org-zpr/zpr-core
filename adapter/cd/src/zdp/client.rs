use std::io;

use tracing::info;

#[derive(Debug, Clone)]
pub struct ZDPClient {
    addr: String
}

impl ZDPClient {
    pub fn new(addr_port: &str) -> ZDPClient {
        ZDPClient {
            addr: String::from(addr_port),
        }
    }

    pub async fn disconnect(&self) -> io::Result<()> {
        info!("zdp/client - disconnect not implemented");
        Ok(())
    }
}


/// Creates a new ZDPClient.
//
// Not clear yet what a "connect" means, for now this kicks off the
// key management process.
//
// Call disconnect when you are done.
pub async fn connect(addr: &str) -> io::Result<ZDPClient> {
    info!("zdp/client faking connect ....");
    Ok(ZDPClient::new(addr))
}
