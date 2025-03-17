use crate::zprtun::ZprTunError;
use bytes::buf;
use nix::ioctl_write_ptr;
use std::io;
use std::io::Result;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use tokio_tun::{Tun, TunBuilder};
use zpr_ext::std::mem::slice_assume_init_mut;

// from /usr/include/linux/if_tun.h
ioctl_write_ptr!(tun_set_carrier, b'T', 226, libc::c_int);

pub struct ZprTun(Tun);

impl From<Tun> for ZprTun {
    fn from(tun: Tun) -> Self {
        ZprTun(tun)
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
                    return Err(ZprTunError::PlatformError("IPv6 not supported".to_string()))
                }
            }
        }
        let tok_tun_devs = bldr
            .try_build_mq(concurrency)
            .or_else(|e| Err(ZprTunError::PlatformError(e.to_string())))?;

        Ok(tok_tun_devs.into_iter().map(ZprTun).collect())
    }

    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.try_send(buf)
    }

    pub async fn recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> Result<usize> {
        let uninit_slice = buf.chunk_mut();
        // SAFETY: we are only writing to this uninitialized slice
        let slice = unsafe { slice_assume_init_mut(uninit_slice.as_uninit_slice_mut()) };
        let size = self.0.recv(slice).await?;
        // SAFETY: we've now initialized this much of the slice
        unsafe {
            buf.advance_mut(size);
        }
        Ok(size)
    }

    #[allow(dead_code)]
    pub fn try_recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> Result<usize> {
        let uninit_slice = buf.chunk_mut();
        // SAFETY: we are only writing to this uninitialized slice
        let slice = unsafe { slice_assume_init_mut(uninit_slice.as_uninit_slice_mut()) };
        let size = self.0.try_recv(slice)?;
        // SAFETY: we've now initialized this much of the slice
        unsafe {
            buf.advance_mut(size);
        }
        Ok(size)
    }

    pub fn set_carrier(&self, carrier: bool) -> Result<()> {
        // SAFETY: the temporary pointer is valid for the lifetime of the ioctl, which is sufficient
        unsafe { tun_set_carrier(self.0.as_raw_fd(), &carrier.into()) }?;
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
