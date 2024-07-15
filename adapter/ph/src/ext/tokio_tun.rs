#![allow(dead_code)]

use crate::ext::std::mem::slice_assume_init_mut;
use bytes::buf;
use tokio::io;
use tokio_tun::*;

pub trait TunExt {
    // no support yet in Rust for async trait fns
    //async fn recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> io::Result<usize>;
    fn try_recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> io::Result<usize>;
}

pub async fn tun_recv_buf<B: buf::BufMut>(self_: &Tun, buf: &mut B) -> io::Result<usize> {
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
    fn try_recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> io::Result<usize> {
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
}

pub mod tun_pi {
    use bytes::buf;

    // per-packet packet info
    #[derive(Clone, Copy)]
    pub struct TunPi {
        pub strip: bool, // the inbound packet was truncated (ignored outbound)
        pub proto: u16,  // Ethertype of packet
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

    pub const PI_SIZE: usize = std::mem::size_of::<os::TunPi>();

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
