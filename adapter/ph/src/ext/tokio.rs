#![allow(dead_code)]

pub mod io {
    pub mod unix {
        use std::io::{IoSlice, IoSliceMut};
        use std::os::fd::{AsFd, AsRawFd};
        use bytes::buf;
        use tokio::io::{self, Interest};
        use tokio::io::unix::AsyncFd;
        use crate::ext::std::mem::slice_assume_init_mut;

        // Asynchronous read/write operations on raw FDs,
        // following the model in `std::io::{Read, Write}`.

        pub trait AsyncFdExt {
            // no support yet in Rust for async trait fns
            //async fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
            fn try_read(&self, buf: &mut [u8]) -> io::Result<usize>;

            //async fn read_buf<B: buf::BufMut>(&self, buf: &mut B) -> io::Result<usize>;
            fn try_read_buf<B: buf::BufMut>(&self, buf: &mut B) -> io::Result<usize>;

            //async fn write(&self, buf: &[u8]) -> io::Result<usize>;
            fn try_write(&self, buf: &[u8]) -> io::Result<usize>;

            //async fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize>;
            fn try_read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize>;

            //async fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize>;
            fn try_write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize>;
        }

        pub async fn async_fd_read<T: AsFd + AsRawFd>(afd: &AsyncFd<T>, buf: &mut [u8]) -> io::Result<usize> {
            afd.async_io(Interest::READABLE,
                |fd| nix::unistd::read(fd.as_raw_fd(), buf).map_err(std::io::Error::from)).await
        }

        pub async fn async_fd_read_buf<T: AsFd + AsRawFd, B: buf::BufMut>(afd: &AsyncFd<T>, buf: &mut B) -> io::Result<usize> {
            let uninit_slice = buf.chunk_mut();
            // SAFETY: we are only writing to this uninitialized slice
            let slice = unsafe { slice_assume_init_mut(uninit_slice.as_uninit_slice_mut()) };
            let size = async_fd_read(afd, slice).await?;
            // SAFETY: we've now initialized this much of the slize
            unsafe { buf.advance_mut(size); }
            Ok(size)
        }

        pub async fn async_fd_write<T: AsFd + AsRawFd>(afd: &AsyncFd<T>, buf: &[u8]) -> io::Result<usize> {
            afd.async_io(Interest::WRITABLE,
                |fd| nix::unistd::write(fd, buf).map_err(std::io::Error::from)).await
        }

        pub async fn async_fd_read_vectored<T: AsFd + AsRawFd>(afd: &AsyncFd<T>, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
            afd.async_io(Interest::READABLE,
                |fd| nix::sys::uio::readv(fd, bufs).map_err(std::io::Error::from)).await
        }

        pub async fn async_fd_write_vectored<T: AsFd + AsRawFd>(afd: &AsyncFd<T>, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            afd.async_io(Interest::WRITABLE,
                |fd| nix::sys::uio::writev(fd, bufs).map_err(std::io::Error::from)).await
        }

        impl<T: AsFd + AsRawFd> AsyncFdExt for AsyncFd<T> {
            fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
                nix::unistd::read(self.get_ref().as_raw_fd(), buf).map_err(std::io::Error::from)
            }

            fn try_read_buf<B: buf::BufMut>(&self, buf: &mut B) -> io::Result<usize> {
                let uninit_slice = buf.chunk_mut();
                // SAFETY: we are only writing to this uninitialized slice
                let slice = unsafe { slice_assume_init_mut(uninit_slice.as_uninit_slice_mut()) };
                let size = self.try_read(slice)?;
                // SAFETY: we've now initialized this much of the slize
                unsafe { buf.advance_mut(size); }
                Ok(size)
            }

            fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
                nix::unistd::write(self.get_ref(), buf).map_err(std::io::Error::from)
            }

            fn try_read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
                nix::sys::uio::readv(self.get_ref(), bufs).map_err(std::io::Error::from)
            }

            fn try_write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
                nix::sys::uio::writev(self.get_ref(), bufs).map_err(std::io::Error::from)
            }
        }
    }
}

pub mod net {
    use std::io;
    use nix::sys::socket;
    use tokio::net::UdpSocket;

    pub trait UdpSocketExt {
        fn mtu(&self) -> io::Result<u32>;
    }

    impl UdpSocketExt for UdpSocket {
        fn mtu(&self) -> io::Result<u32> {
            match socket::getsockopt(self, socket::sockopt::IpMtu) {
                Ok(mtu) => Ok(mtu as u32),
                Err(errno) => Err(io::Error::from(errno))
            }
        }
    }
}
