use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd};

use tracing::*;

use crate::logging::targets::NET_OS;
use crate::sys::macos::tun;
use crate::zprtun::ZprTunError;
use std::process::Command;
use crate::zprtun::ZPRNET_PREFIX_LEN;

pub struct ZprTun{
    inner: tun::Tun,
    mtx: std::sync::Mutex<()>,
}

impl From<tun::TunError> for ZprTunError {
    fn from(e: tun::TunError) -> Self {
        ZprTunError::PlatformError(e.to_string())
    }
}

impl ZprTun {
    fn new(inner: tun::Tun) -> Self {
        ZprTun {
            inner,
            mtx: std::sync::Mutex::new(()),
        }
    }

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
            // TODO: Temporary
        })?;
        let mut bldr = tun::Tun::builder(addr.into());
        if let Some(name) = ifname {
            bldr.with_tun_name(&name);
        }
        let dev = tun::Tun::create(&bldr)?;
        Ok(vec![ZprTun::new(dev)])
    }

    /// A NOP on mac.
    pub fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
        Ok(())
    }

    pub fn set_zpr_address(&self, addr: IpAddr) -> std::io::Result<()> {
        let mtx = self.mtx.lock().map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex lock failed"))?;

        // Check if we already have this address.
        info!(target: NET_OS, "XXX Checking address on our TUN device ...TODO");

        // TODO: Check to see if we already have this address set.

        info!(target: NET_OS, "XXX Setting ZPR address on our TUN device: {addr} ...TODO");

        let mut c = Command::new("/sbin/ifconfig");
        c.arg(self.inner.get_name());
        match addr {
            IpAddr::V4(_ipv4) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "set_zpr_address with IPv4 is not supported on macOS",
                ));
            }
            IpAddr::V6(ipv6) => {
                c.arg("inet6").arg(format!("{}/{}", ipv6.to_string(), ZPRNET_PREFIX_LEN));
            }
        }
        c.arg("alias");

        c.status()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to set ZPR address: {e}")))?;

        drop(mtx);
        Ok(())
    }

    // Should be called while holding the mutex.
    pub fn get_zpr_address(&self) -> std::io::Result<Option<IpAddr>> {
        info!(target: NET_OS, "XXX asking system for ADDR on tun interface {}", self.inner.get_name());
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "get_zpr_address is not supported on macOS",
        ))
    }

    // Should be called while holding the mutex.
    pub fn clear_zpr_address(&self) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "clear_zpr_address is not supported on macOS",
        ))
    }
}

impl AsFd for ZprTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}
