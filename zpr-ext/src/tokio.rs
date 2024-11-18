pub mod net {
    use crate::std::os::unix::net::{
        uds_recv_vectored_with_ancillary, uds_send_vectored_with_ancillary, SocketAncillary,
    };
    use std::io::{self, IoSlice, IoSliceMut};
    use std::os::fd::AsFd;
    use tokio::io::Interest;
    use tokio::net::{UdpSocket, UnixStream};

    #[cfg(any(target_os = "linux", target_os = "android"))]
    use nix::sys::socket;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::os::fd::AsRawFd;

    pub trait UdpSocketExt {
        fn mtu(&self) -> io::Result<u32>;
        #[cfg(any(doc, target_os = "android", target_os = "linux"))]
        fn attach_reuse_port_cbpf(&self, filter: &[libc::sock_filter]) -> io::Result<()>;
    }

    #[cfg(target_os = "macos")]
    mod os {
        use libc::{self, c_char, ifreq, AF_INET, SOCK_DGRAM};
        use nix::ioctl_readwrite;
        use std::net::IpAddr;
        use std::{mem, ptr};

        ioctl_readwrite!(siocgifmtu, b'i', 51, ifreq);

        // Since the raw-fd traits are not present for MacOs on the tokio UdpSocket
        // we use a different approach to get MTU for this MacOS socket:
        //  - figure out the interface name by looking at the IP address
        //  - send an ioctl into the kernel to get the MTU for the interface
        pub fn get_mtu(s: &tokio::net::UdpSocket) -> std::io::Result<u32> {
            let saddr = s.local_addr()?;
            let tun_ip = saddr.ip();

            let ifname: String = match get_ifname(tun_ip) {
                Some(name) => name,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unable to get interface name",
                    ))
                }
            };

            unsafe {
                let c_fd = libc::socket(AF_INET, SOCK_DGRAM, 0);
                if c_fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let mut req = request(&ifname);
                if let Err(err) = siocgifmtu(c_fd, &mut req) {
                    libc::close(c_fd);
                    return Err(std::io::Error::from(err).into());
                }
                libc::close(c_fd);

                let mtu = req.ifr_ifru.ifru_mtu as u32;
                return Ok(mtu);
            }
        }

        fn get_ifname(addr: IpAddr) -> Option<String> {
            let interfaces = netdev::get_interfaces();
            for iface in interfaces {
                if addr.is_ipv6() {
                    let ip6addr = match addr {
                        IpAddr::V6(ip6addr) => ip6addr,
                        _ => return None,
                    };
                    for ipnet in iface.ipv6 {
                        if ipnet.contains(&ip6addr) {
                            return Some(iface.name);
                        }
                    }
                } else {
                    let ip4addr = match addr {
                        IpAddr::V4(ip4addr) => ip4addr,
                        _ => return None,
                    };
                    for ipnet in iface.ipv4 {
                        if ipnet.contains(&ip4addr) {
                            return Some(iface.name);
                        }
                    }
                }
            }
            None
        }

        // prepare an ifreq data structure
        unsafe fn request(if_name: &str) -> libc::ifreq {
            let mut req: libc::ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(
                if_name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                if_name.len(),
            );
            req
        }
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

        /// Retrieve the socket's current known path MTU.
        /// On MacOS this will not work if the socket address is `0.0.0.0`.
        #[cfg(target_os = "macos")]
        fn mtu(&self) -> io::Result<u32> {
            return os::get_mtu(self);
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

    #[cfg(any(doc, unix))]
    #[allow(async_fn_in_trait)]
    pub trait UnixStreamExt {
        async fn send_vectored_with_ancillary(
            &self,
            bufs: &[IoSlice<'_>],
            ancillary: &mut SocketAncillary<'_>,
        ) -> io::Result<usize>;

        async fn recv_vectored_with_ancillary(
            &self,
            bufs: &mut [IoSliceMut<'_>],
            ancillary: &mut SocketAncillary<'_>,
        ) -> io::Result<usize>;
    }

    #[cfg(any(doc, unix))]
    impl UnixStreamExt for UnixStream {
        async fn send_vectored_with_ancillary(
            &self,
            bufs: &[IoSlice<'_>],
            ancillary: &mut SocketAncillary<'_>,
        ) -> io::Result<usize> {
            loop {
                self.writable().await?;
                match self.try_io(Interest::WRITABLE, || {
                    uds_send_vectored_with_ancillary(self.as_fd(), bufs, ancillary)
                }) {
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    res => break res,
                }
            }
        }

        async fn recv_vectored_with_ancillary(
            &self,
            bufs: &mut [IoSliceMut<'_>],
            ancillary: &mut SocketAncillary<'_>,
        ) -> io::Result<usize> {
            loop {
                self.readable().await?;
                match self.try_io(Interest::WRITABLE, || {
                    uds_recv_vectored_with_ancillary(self.as_fd(), bufs, ancillary)
                }) {
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    res => break res,
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::std::os::unix::net::{AncillaryData, SocketAncillary};
        use std::fs::File;
        use std::io::Read;
        use tokio::net::UnixStream;
        use tokio::{task, time};

        #[tokio::test]
        async fn ancillary_fd() {
            let zero_file = File::open("/dev/zero").unwrap();

            let (s1, s2) = UnixStream::pair().unwrap();

            let receiver = task::spawn(async move {
                let mut data_out = [0u8; 4];
                let mut ancillary_out_buf = [0u8; 256];
                let mut ancillary_out = SocketAncillary::new(&mut ancillary_out_buf);
                assert_eq!(
                    s2.recv_vectored_with_ancillary(
                        &mut [IoSliceMut::new(&mut data_out[..])],
                        &mut ancillary_out
                    )
                    .await
                    .unwrap(),
                    3
                );

                let mut messages = ancillary_out.into_messages();

                let fds: Vec<_> = match messages.next().unwrap().unwrap() {
                    AncillaryData::ScmRights(fds) => fds.collect(),
                    AncillaryData::ScmCredentials(_) => panic!("expected ScmRights"),
                };
                assert!(fds.len() == 1);

                assert!(messages.next().is_none());

                for fd in fds {
                    let mut buf = 123u8;
                    File::from(fd.try_into_owned().unwrap())
                        .read_exact(std::slice::from_mut(&mut buf))
                        .unwrap();
                    assert_eq!(buf, 0u8);
                }
            });

            time::sleep(std::time::Duration::from_secs(1)).await;

            let data_in = &[1u8, 2u8, 3u8];
            let mut ancillary_in_buf = [0u8; 256];
            let mut ancillary_in = SocketAncillary::new(&mut ancillary_in_buf);
            ancillary_in.add_fds(&[zero_file.as_fd()]);
            assert_eq!(
                s1.send_vectored_with_ancillary(&[IoSlice::new(data_in)], &mut ancillary_in)
                    .await
                    .unwrap(),
                3
            );

            receiver.await.unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use super::net::UdpSocketExt;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_tokio_get_udp_socket_mtu() {
        let sock = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind socket");
        let mtu = sock.mtu().expect("MTU call failed");
        assert!(mtu > 0);
    }
}
