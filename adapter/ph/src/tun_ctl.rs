use crate::sys::ZprTun;
use std::io::Result;
use std::net::IpAddr;
use std::sync::Arc;

/// This interface provides shared access to the TUN device for controlling
/// its state.  Its API is limited to restrict coupling of the full system
/// with the TUN device.
pub trait TunCtl: Sync {
    /// Inform the kernel's networking layer whether a carrier is present.
    /// (I.e. whether we are passing packets.)  This is reflected on the
    /// interface itself and is used by the kernel to make routing decisions.
    fn set_carrier(&self, carrier: bool) -> Result<()>;

    /// Adds an IP address of the TUN device.
    fn add_address(&self, addr: IpAddr) -> Result<()>;

    /// Clear an IP address from the TUN device.  Does not error if address is not set to begin with.
    fn clear_address(&self, addr: IpAddr) -> Result<()>;
}

/// Canonical implementation of the `TunCtl` interface, just a thin wrapper
/// around a reference to a `ZprTun` struct.
pub struct TunCtlImpl {
    tun: Arc<ZprTun>,
}

impl TunCtlImpl {
    pub fn new(tun: Arc<ZprTun>) -> Self {
        Self { tun }
    }
}

impl TunCtl for TunCtlImpl {
    fn set_carrier(&self, carrier: bool) -> Result<()> {
        self.tun.set_carrier(carrier)
    }
    fn add_address(&self, addr: IpAddr) -> Result<()> {
        self.tun.add_address(addr)
    }
    fn clear_address(&self, addr: IpAddr) -> Result<()> {
        self.tun.clear_address(addr)
    }
}
