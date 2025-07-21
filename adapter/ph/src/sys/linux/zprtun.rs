use nix::ioctl_write_ptr;
use std::io::Result;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::process::Command;
use tokio_tun::{Tun, TunBuilder};
use tracing::*;

use crate::logging::targets::NET_OS;
use crate::zprtun::{ZprTunError, ZPRNET_PREFIX_LEN};

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

    pub fn set_zpr_address(&self, addr: IpAddr) -> std::io::Result<()> {
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

        // If address is already on the interface we are done.
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
        if out_str.contains(&format!("inet6 {}", addr)) {
            debug!(target: NET_OS, "ZPR address {addr} already set on TUN device {}", self.ifname);
            return Ok(());
        }

        // TODO: Remove any existing fd5a:: address from the interface before adding new one.

        let mut c = Command::new(COMMAND_IP);
        c.arg("addr")
            .arg("add")
            .arg(format!("{}/{}", addr, ZPRNET_PREFIX_LEN))
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
        Ok(())
    }

    #[allow(dead_code)]
    pub fn set_address(&mut self, _addr: IpAddr) -> std::result::Result<(), ZprTunError> {
        // This needs work -- the linux tun API only allows address to be set at construction time.
        Err(ZprTunError::PlatformError(
            "cannot set TUN address after creation".to_string(),
        ))
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
