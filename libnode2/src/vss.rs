use std::fmt;
use std::net::SocketAddr;
use std::sync::{Condvar, Mutex};

use tokio::sync::mpsc::Sender;

use crate::vsapi_compat as vsapi;
use vsapi::{PolicyInfo, ServicesList, VisaHop, VisaRevocation};

/// Default port for the visa support service. Note that the visa support service
/// should only listen on the ZPR interface (not substrate interface!).
#[allow(dead_code)]
pub const DEFAULT_VSS_PORT: u16 = 8183;

pub enum VSSMsg {
    /// Indicates a policy has been installed.
    PolicyInstall(PolicyInfo),

    /// Pushed visas from the visa service.
    PushedVisa(VisaHop),

    /// Pushed visa revokcations from the visa service.
    PushedRevocation(VisaRevocation),

    /// Pushed list of services. For now will be just Actor Authentication services.
    PushedServices(ServicesList),
}

impl fmt::Display for VSSMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VSSMsg???")
    }
}

/// Start the VSS (thrift) server (blocks forever). Messages from the visa service are
/// placed on the provided channel.
/// - `tx_chan` for arriving messages from the visa service.
/// - `listen_addr` is the address to listen on.
///
pub fn start_vss_server(_tx_chan: Sender<VSSMsg>, _listen_addr: SocketAddr) {
    // Block forever...
    let mtx = Mutex::new(false);
    let sem = Condvar::new();
    let _guard = sem.wait(mtx.lock().unwrap());
}
