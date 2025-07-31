use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd};

use tracing::*;

use crate::logging::targets::NET_OS;
use crate::sys::macos::tun;
use crate::zprtun::ZprTunError;
use std::process::Command;

const COMMAND_IFCONFIG: &str = "/sbin/ifconfig";

pub struct ZprTun {
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

    pub fn add_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        let mtx = self
            .mtx
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex lock failed"))?;

        if self.has_address(addr)? {
            debug!(target: NET_OS, "set_address: address {addr} already set on TUN device {}", self.inner.get_name());
            return Ok(());
        }

        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        match addr {
            IpAddr::V4(_ipv4) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "add_address with IPv4 is not supported on macOS",
                ));
            }
            IpAddr::V6(ipv6) => {
                c.arg("inet6")
                    .arg(format!("{}/{}", ipv6.to_string(), prefix_len));
            }
        }
        c.arg("alias");
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to set address on {}: {}",
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        drop(mtx);
        Ok(())
    }

    pub fn clear_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        if !self.has_address(addr)? {
            debug!(target: NET_OS, "clear_address: address {addr} not set on TUN device {}", self.inner.get_name());
            return Ok(());
        }

        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        match addr {
            IpAddr::V4(_ipv4) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "clear_address with IPv4 is not supported on macOS",
                ));
            }
            IpAddr::V6(ipv6) => {
                c.arg("inet6")
                    .arg(format!("{}/{}", ipv6.to_string(), prefix_len));
            }
        }
        c.arg("-alias"); // <-- note the MINUS here
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to clear addresses {} on {}: {}",
                    addr,
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(())
    }

    fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
        if addr.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "has_address with IPv4 is not supported on macos",
            ));
        }
        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;

        // If interface is there, the output will be something like:
        //
        // utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
        //         inet6 fe80::e9b0:1972:d221:2196%utun2 prefixlen 64 scopeid 0x11
        //         nd6 options=201<PERFORMNUD,DAD>
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to show addresses for {}: {}",
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        // Just look for the pattern "inet6 <addr>" + "%" in the output.
        let out_str = String::from_utf8_lossy(&output.stdout);
        Ok(out_str.contains(&format!("inet6 {}%", addr)))
    }
}

impl AsFd for ZprTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}
