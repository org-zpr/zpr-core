use std::io;
use std::net::UdpSocket;

#[cfg(any(target_os = "linux", target_os = "android"))]
use nix::sys::socket;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;

pub trait UdpSocketExt {
    fn mtu(&self) -> io::Result<u32>;
    #[cfg(any(doc, target_os = "android", target_os = "linux"))]
    fn attach_reuse_port_cbpf(&self, filter: &[libc::sock_filter]) -> io::Result<()>;
}

impl UdpSocketExt for UdpSocket {
    /// Retrieve the socket's current known path MTU.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn mtu(&self) -> io::Result<u32> {
        match socket::getsockopt(self, socket::sockopt::IpMtu) {
            Ok(mtu) => Ok(mtu as u32),
            Err(errno) => Err(io::Error::from(errno)),
        }
    }

    #[cfg(target_os = "macos")]
    fn mtu(&self) -> io::Result<u32> {
        // TODO:
        // For mac I need to get the interface name and then call
        // an ioctl to get MTU.
        return Ok(1400);
    }

    #[cfg(any(doc, target_os = "android", target_os = "linux"))]
    fn attach_reuse_port_cbpf(&self, filter: &[libc::sock_filter]) -> io::Result<()> {
        let fprog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr().cast_mut(),
        };

        let fprog_ptr = (&fprog as *const libc::sock_fprog).cast();
        let fprog_size = std::mem::size_of_val(&fprog) as libc::socklen_t;

        // SAFETY: `fprog_ptr` and `fprog_size` are of the appropriate type for SOL_SOCKET:SO_ATTACH_REUSEPORT_CBPF
        let res = unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_REUSEPORT_CBPF,
                fprog_ptr,
                fprog_size,
            )
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
