#![allow(dead_code)]

use crate::ext::std::mem::slice_assume_init_mut;
use bytes::buf;
use libc;
use nix::ioctl_write_ptr;
use std::io::Result;
use std::os::fd::AsRawFd;
use tokio_tun::*;

ioctl_write_ptr!(tun_set_carrier, b'T', 226, libc::c_int);

pub trait TunExt {
    // no support yet in Rust for async trait fns
    //async fn recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> Result<usize>;
    fn try_recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> Result<usize>;
    fn set_carrier(&self, carrier: bool) -> Result<()>;
}

pub async fn tun_recv_buf<B: buf::BufMut>(self_: &Tun, buf: &mut B) -> Result<usize> {
    let uninit_slice = buf.chunk_mut();
    // SAFETY: we are only writing to this uninitialized slice
    let slice = unsafe { slice_assume_init_mut(uninit_slice.as_uninit_slice_mut()) };
    let size = self_.recv(slice).await?;
    // SAFETY: we've now initialized this much of the slize
    unsafe {
        buf.advance_mut(size);
    }
    Ok(size)
}

impl TunExt for Tun {
    fn try_recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> Result<usize> {
        let uninit_slice = buf.chunk_mut();
        // SAFETY: we are only writing to this uninitialized slice
        let slice = unsafe { slice_assume_init_mut(uninit_slice.as_uninit_slice_mut()) };
        let size = self.try_recv(slice)?;
        // SAFETY: we've now initialized this much of the slize
        unsafe {
            buf.advance_mut(size);
        }
        Ok(size)
    }

    fn set_carrier(&self, carrier: bool) -> Result<()> {
        unsafe { tun_set_carrier(self.as_raw_fd(), &carrier.into()) }?;
        Ok(())
    }
}
