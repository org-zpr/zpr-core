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
// One day this may do more stuff, like kick off a state machine or
// something.  For now, after you call this you can call primitive
// methods on the client.
//
// Call disconnect when you are done.
pub async fn connect(addr: &str) -> io::Result<ZDPClient> {
    info!("zdp/client faking connect ....");
    Ok(ZDPClient::new(addr))
}
