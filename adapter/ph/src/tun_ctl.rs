use std::io::Result;
use tokio_tun::Tun;
use zpr_ext::tokio_tun::TunExt;

// This structure provides shared access to the TUN device
// for controlling its state.  Though it is just a thin wrapper
// around a `Tun` struct, its API is limited to restrict coupling
// of the full system with the TUN device.

pub struct TunCtl<'a> {
    tun: &'a Tun,
}

impl<'a> TunCtl<'a> {
    pub fn new(tun: &'a Tun) -> Self {
        Self { tun }
    }

    // Inform the kernel's networking layer whether a carrier is present.
    // (I.e. whether we are passing packets.)  This is reflected on the
    // interface itself and is used by the kernel to make routing decisions.
    pub fn set_carrier(&self, carrier: bool) -> Result<()> {
        self.tun.set_carrier(carrier)
    }
}
