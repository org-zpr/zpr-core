use crate::std::mem::slice_assume_init_mut;
use bytes::buf;
use libc;
use nix::ioctl_write_ptr;
use std::io::Result;
use std::os::fd::AsRawFd;
use tokio_tun::*;

// from /usr/include/linux/if_tun.h
ioctl_write_ptr!(tun_set_carrier, b'T', 226, libc::c_int);

#[allow(async_fn_in_trait)]
pub trait TunExt {
    /// Like `Tun::recv()`, but reads into a `BufMut`.
    async fn recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> Result<usize>;

    /// Like `try_recv()`, but reads into a `BufMut`.
    fn try_recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> Result<usize>;

    /// Set the carrier status of the TUN link.
    fn set_carrier(&self, carrier: bool) -> Result<()>;
}

impl TunExt for Tun {
    async fn recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> Result<usize> {
        let uninit_slice = buf.chunk_mut();
        // SAFETY: we are only writing to this uninitialized slice
        let slice = unsafe { slice_assume_init_mut(uninit_slice.as_uninit_slice_mut()) };
        let size = self.recv(slice).await?;
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
        let size = self.try_recv(slice)?;
        // SAFETY: we've now initialized this much of the slice
        unsafe {
            buf.advance_mut(size);
        }
        Ok(size)
    }

    fn set_carrier(&self, carrier: bool) -> Result<()> {
        // SAFETY: the temporary pointer is valid for the lifetime of the ioctl, which is sufficient
        unsafe { tun_set_carrier(self.as_raw_fd(), &carrier.into()) }?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub mod tun_pi {
    //! Structures and functions for working with per-packet packet info.

    use bytes::buf;

    /// per-packet packet info
    #[derive(Clone, Copy)]
    pub struct TunPi {
        // the inbound packet was truncated (ignored outbound)
        pub strip: bool,
        /// Ethertype of packet
        pub proto: u16,
    }

    #[cfg(target_os = "linux")]
    mod os {
        const TUN_PKT_STRIP: u16 = 0x0001;

        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct TunPi {
            flags: u16,
            proto: [u8; 2],
        }

        impl From<TunPi> for super::TunPi {
            fn from(pi: TunPi) -> super::TunPi {
                super::TunPi {
                    strip: pi.flags & TUN_PKT_STRIP != 0,
                    proto: u16::from_be_bytes(pi.proto),
                }
            }
        }

        impl From<super::TunPi> for TunPi {
            fn from(pi: super::TunPi) -> TunPi {
                TunPi {
                    flags: 0,
                    proto: pi.proto.to_be_bytes(),
                }
            }
        }
    }

    /// Read per-packet packet info from a `Buf`.
    pub fn read_pi<B: buf::Buf>(buf: &mut B) -> TunPi {
        let mut os_pi = std::mem::MaybeUninit::<os::TunPi>::uninit();
        let slice = os_pi.as_mut_ptr();
        buf.copy_to_slice(unsafe {
            /* SAFETY: we immediately initialize */
            std::slice::from_raw_parts_mut(slice as *mut u8, std::mem::size_of::<os::TunPi>())
        });
        unsafe {
            /* SAFETY: was just initialized */
            os_pi.assume_init()
        }
        .into()
    }

    /// The size of a per-packet packet info structure.
    pub const PI_SIZE: usize = std::mem::size_of::<os::TunPi>();

    /// Write per-packet packet info into a `BufMut`.
    pub fn write_pi<B: buf::BufMut>(buf: &mut B, pi: TunPi) {
        let os_pi: os::TunPi = pi.into();
        buf.put(unsafe {
            /* SAFETY: we are reading exactly the structure */
            std::slice::from_raw_parts(
                (&os_pi as *const _) as *const u8,
                std::mem::size_of::<os::TunPi>(),
            )
        });
    }
}
