use crate::zprtun::{ZprTunError, DEFAULT_TUN_MTU};
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::result::Result;
use tun::{AbstractDevice, Device};

pub struct ZprTun(tun::Device);

impl From<Device> for ZprTun {
    fn from(tun_device: Device) -> Self {
        ZprTun(tun_device)
    }
}

impl From<tun::Error> for ZprTunError {
    fn from(e: tun::Error) -> Self {
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
        let mut config = tun::Configuration::default();
        if let Some(name) = ifname {
            config.tun_name(&name);
        } else {
            config.mtu(DEFAULT_TUN_MTU);
        }
        if let Some(addr) = address {
            config.address(addr);
        }
        if concurrency <= 0 || concurrency > 1 {
            return Err(ZprTunError::PlatformError(String::from(
                "on macos concurrency (queues) must be 1",
            )));
        }

        let dev = tun::create(&config)?;
        Ok(vec![ZprTun::from(dev)])
    }

    /// A NOP on mac.
    pub fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
        Ok(())
    }

    #[allow(dead_code)]
    pub fn set_address(&mut self, addr: IpAddr) -> Result<(), ZprTunError> {
        let idev = &mut self.0;
        match idev.set_address(addr) {
            Ok(_) => Ok(()),
            Err(e) => Err(ZprTunError::PlatformError(e.to_string())),
        }
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
