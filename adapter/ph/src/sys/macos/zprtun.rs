use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd};

use crate::sys::macos::tun;
use crate::zprtun::ZprTunError;

pub struct ZprTun(tun::Tun);

impl From<tun::TunError> for ZprTunError {
    fn from(e: tun::TunError) -> Self {
        ZprTunError::PlatformError(e.to_string())
    }
}

impl ZprTun {
    /// Create a new TUN device.
    /// If `ifname` is `None`, the kernel will automatically assign a name.
    /// On macOS if the name is specificed, it must be of the form `utun[0-9]+`.
    pub fn new_mq(
        ifname: Option<String>,
        concurrency: usize,
        address: Option<IpAddr>,
    ) -> std::result::Result<Vec<Self>, ZprTunError> {
        if concurrency != 1 {
            return Err(ZprTunError::PlatformError(String::from(
                "on macos concurrency (queues) must be 1",
            )));
        }
        let addr = address.ok_or_else(|| {
            ZprTunError::PlatformError(String::from("address is required on macos"))
        })?;
        let mut bldr = tun::Tun::builder(addr);
        if let Some(name) = ifname {
            bldr.with_tun_name(&name);
        }
        let dev = tun::Tun::create(&bldr)?;
        Ok(vec![ZprTun(dev)])
    }

    /// A NOP on mac.
    pub fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
        Ok(())
    }
}

impl AsFd for ZprTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
