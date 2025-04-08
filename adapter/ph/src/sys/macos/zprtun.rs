use crate::zprtun::{ZprTunError, DEFAULT_TUN_MTU};

use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::result::Result;
// use tun::{AbstractDevice, Device};

use crate::sys::macos::tun;

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
        if concurrency <= 0 || concurrency > 1 {
            return Err(ZprTunError::PlatformError(String::from(
                "on macos concurrency (queues) must be 1",
            )));
        }
        let mut bldr = tun::Tun::builder();
        if let Some(name) = ifname {
            bldr.set_tun_name(&name);
        }
        if let Some(addr) = address {
            bldr.set_address(addr);
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
        // SAFETY: we know the FD will be live for the lifetime of the `Device`
        unsafe { BorrowedFd::borrow_raw(self.0.as_raw_fd()) }
    }
}

impl AsRawFd for ZprTun {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
