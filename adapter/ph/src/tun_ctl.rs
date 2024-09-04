use std::io::Result;
use tokio_tun::Tun;
use zpr_ext::tokio_tun::TunExt;

/// This interface provides shared access to the TUN device for controlling
/// its state.  Its API is limited to restrict coupling of the full system
/// with the TUN device.
pub trait TunCtl: Sync {
    /// Inform the kernel's networking layer whether a carrier is present.
    /// (I.e. whether we are passing packets.)  This is reflected on the
    /// interface itself and is used by the kernel to make routing decisions.
    fn set_carrier(&self, carrier: bool) -> Result<()>;
}

/// Canonical implementation of the `TunCtl` interface, just a thin wrapper
/// around a reference to a `Tun` struct.
pub struct TunCtlImpl<'a> {
    tun: &'a Tun,
}

impl<'a> TunCtlImpl<'a> {
    pub fn new(tun: &'a Tun) -> Self {
        Self { tun }
    }
}

impl TunCtl for TunCtlImpl<'_> {
    fn set_carrier(&self, carrier: bool) -> Result<()> {
        self.tun.set_carrier(carrier)
    }
}
