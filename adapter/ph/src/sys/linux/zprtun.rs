use nix::ioctl_write_ptr;
use std::io::Result;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::process::Command;
use tokio_tun::{Tun, TunBuilder};
use tracing::*;

use crate::logging::targets::NET_OS;
use crate::zprtun::ZprTunError;

const COMMAND_IP: &str = "/usr/sbin/ip";

// from /usr/include/linux/if_tun.h
ioctl_write_ptr!(tun_set_carrier, b'T', 226, libc::c_int);

pub struct ZprTun {
    ifname: String,
    owned_fd: OwnedFd,
}

impl From<Tun> for ZprTun {
    fn from(tun: Tun) -> Self {
        // SAFETY: the FD is live until we exit this function
        ZprTun {
            ifname: String::from(tun.name()),
            owned_fd: (unsafe { BorrowedFd::borrow_raw(tun.as_raw_fd()) })
                .try_clone_to_owned()
                .unwrap(),
        }
    }
}

impl ZprTun {
    /// Create a new TUN device.
    /// If `ifname` is `None`, the kernel will automatically assign a name.
    /// For optional `address`, only IPv4 is supported currently.
    pub fn new_mq(
        ifname: Option<String>,
        concurrency: usize,
        address: Option<IpAddr>,
    ) -> std::result::Result<Vec<Self>, ZprTunError> {
        let mut bldr = TunBuilder::new();
        if let Some(ifname) = ifname {
            bldr = bldr.name(&ifname);
        }
        if let Some(addr) = address {
            match addr {
                IpAddr::V4(ipa) => bldr = bldr.address(ipa),
                IpAddr::V6(_) => {
                    warn!(target:NET_OS, "IPv6 address on TUN at create time not supported on linux, ignoring");
                }
            }
        }
        let tok_tun_devs = bldr
            .try_build_mq(concurrency)
            .or_else(|e| Err(ZprTunError::PlatformError(e.to_string())))?;

        //let tun_ifname = String::from(tok_tun_devs[0].name());

        Ok(tok_tun_devs.into_iter().map(ZprTun::from).collect())
    }

    pub fn set_carrier(&self, carrier: bool) -> Result<()> {
        // SAFETY: the temporary pointer is valid for the lifetime of the ioctl, which is sufficient
        unsafe { tun_set_carrier(self.owned_fd.as_raw_fd(), &carrier.into()) }?;
        Ok(())
    }

    pub fn add_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        if self.has_address(addr)? {
            debug!(target: NET_OS, "set_address: address {addr} already set on TUN device {}", self.ifname);
            return Ok(());
        }
        let mut c = Command::new(COMMAND_IP);
        c.arg("addr")
            .arg("add")
            .arg(format!("{}/{}", addr, prefix_len))
            .arg("dev")
            .arg(&self.ifname);
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IP} failed to set addresses for {} to '{}' {}",
                    self.ifname,
                    addr,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        // Set UP also:
        let mut c = Command::new(COMMAND_IP);
        c.arg("link").arg("set").arg(&self.ifname).arg("up");
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IP} failed to set link up for {}: {}",
                    self.ifname,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(())
    }

    pub fn clear_address(&self, addr: IpAddr, prefix_len: u8) -> Result<()> {
        if !self.has_address(addr)? {
            debug!(target: NET_OS, "clear_address: address {addr} not set on TUN device {}", self.ifname);
            return Ok(());
        }

        let mut c = Command::new(COMMAND_IP);
        c.arg("addr")
            .arg("del")
            .arg(format!("{}/{}", addr, prefix_len))
            .arg("dev")
            .arg(&self.ifname);
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IP} failed to clear addresses {} on {}: {}",
                    addr,
                    self.ifname,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(())
    }

    fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
        let mut c = Command::new(COMMAND_IP);
        c.arg("addr")
            .arg("show")
            .arg("dev")
            .arg(self.ifname.clone());
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;

        // If interface is there, the output will be something like:
        //
        // 5: tun9: <NO-CARRIER,POINTOPOINT,MULTICAST,NOARP,UP> mtu 1400 qdisc mq state DOWN group default qlen 500
        //     link/none
        //     inet6 fd5a:5052:90de::1/32 scope global
        //        valid_lft forever preferred_lft forever
        //     inet6 fe80::bffd:4029:e0fa:806b/64 scope link stable-privacy
        //        valid_lft forever preferred_lft forever

        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IP} failed to show addresses for {}: {}",
                    self.ifname,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        // Just look for the pattern "inet6 <addr>" in the output.
        let out_str = String::from_utf8_lossy(&output.stdout);
        Ok(out_str.contains(&format!("inet6 {}", addr)))
    }
}

impl AsFd for ZprTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.owned_fd.as_fd()
    }
}

impl AsRawFd for ZprTun {
    fn as_raw_fd(&self) -> RawFd {
        self.owned_fd.as_raw_fd()
    }
}
