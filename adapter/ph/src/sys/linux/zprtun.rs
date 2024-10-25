use tokio_tun::{Tun, TunBuilder};
use zpr_ext::tokio_tun::*;
use zpr_ext::std::mem::slice_assume_init_mut;
use std::io::Result;
use bytes::buf;
use std::os::fd::AsRawFd;
use std::io;


pub struct LinuxZprTun(Tun);



impl LinuxZprTun {
    #[allow(dead_code)]
    pub fn new(tun: Tun) -> Self {
        LinuxZprTun(tun)
    }

    pub fn new_mq(ifname: &str, concurrency: usize) -> Vec<Self> {
        let tok_tun_devs = TunBuilder::new()
            .name(ifname)
            .try_build_mq(concurrency)
            .expect("unable to open TUN device");

        tok_tun_devs.into_iter().map(LinuxZprTun).collect()
    }

    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.try_send(buf)
    }
}


impl TunExt for LinuxZprTun {
    async fn recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> Result<usize> {
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

    fn try_recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> Result<usize> {
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

    fn set_carrier(&self, carrier: bool) -> Result<()> {
        // SAFETY: the temporary pointer is valid for the lifetime of the ioctl, which is sufficient
        unsafe { tun_set_carrier(self.0.as_raw_fd(), &carrier.into()) }?;
        Ok(())
    }
}
