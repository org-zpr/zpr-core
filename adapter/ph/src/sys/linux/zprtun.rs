use nix::ioctl_write_ptr;
use std::io::Result;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use tokio_tun::{Tun, TunBuilder};
use tracing::*;

use crate::logging::targets::NET_OS;
use crate::zprtun::ZprTunError;

// from /usr/include/linux/if_tun.h
ioctl_write_ptr!(tun_set_carrier, b'T', 226, libc::c_int);

pub struct ZprTun(OwnedFd);

impl From<Tun> for ZprTun {
    fn from(tun: Tun) -> Self {
        // SAFETY: the FD is live until we exit this function
        ZprTun(
            (unsafe { BorrowedFd::borrow_raw(tun.as_raw_fd()) })
                .try_clone_to_owned()
                .unwrap(),
        )
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

        Ok(tok_tun_devs.into_iter().map(ZprTun::from).collect())
    }

    pub fn set_carrier(&self, carrier: bool) -> Result<()> {
        // SAFETY: the temporary pointer is valid for the lifetime of the ioctl, which is sufficient
        unsafe { tun_set_carrier(self.0.as_raw_fd(), &carrier.into()) }?;
        Ok(())
    }

    pub fn set_zpr_address(&self, addr: IpAddr) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "set_zpr_address not implemented on linux",
        ))
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
        self.0.as_fd()
    }
}

impl AsRawFd for ZprTun {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
