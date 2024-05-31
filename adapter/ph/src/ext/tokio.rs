pub mod io {
    pub mod unix {
        use std::io::{IoSlice, IoSliceMut};
        use std::os::fd::{AsFd, AsRawFd};
        use tokio::io::{self, Interest};
        use tokio::io::unix::AsyncFd;

        // Asynchronous read/write operations on raw FDs,
        // following the model in `std::io::{Read, Write}`.

        pub trait AsyncFdExt {
            // no support yet in Rust for async trait fns
            //async fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
            fn try_read(&self, buf: &mut [u8]) -> io::Result<usize>;

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
    use std::io::{IoSlice, IoSliceMut};
    use std::net::{SocketAddr, IpAddr, Ipv6Addr};
    use std::os::fd::{AsRawFd, RawFd};
    use tokio::io;
    use tokio::net::UdpSocket;
    use nix::sys::socket::{MsgFlags, MultiHeaders, RecvMsg, SockaddrLike, SockaddrStorage};

    // Asynchronous vectored and multiple send/recv on sockets,
    // following the model in `std::os::unix::net::UnixDatagram`.

    pub trait SocketExt {
        // Result tuples `(usize, bool, SocketAddr)` indicate packet size,
        // whether the packet was truncated, and the sender address.

        // no support yet in Rust for async trait fns
        /*async fn recv_vectored_from(
            &self, iovs: &mut [IoSliceMut<'_>]
        ) -> io::Result<(usize, bool, SocketAddr)>;*/

        fn try_recv_vectored_from(
            &self, iovs: &mut [IoSliceMut<'_>]
        ) -> io::Result<(usize, bool, SocketAddr)>;

        // Result value is number of bytes sent.

        /*async fn send_vectored_to(
            &self, iovs: &[IoSlice<'_>], target: Option<SocketAddr>
        ) -> io::Result<usize>;*/

        fn try_send_vectored_to(
            &self, iovs: &[IoSlice<'_>], target: Option<SocketAddr>
        ) -> io::Result<usize>;

        // Output tuples are same as `recv_vectored_from`.
        // Result value is number of packets received.

        /*async fn recv_multiple_vectored_from(
            &self, iovs: &mut [&mut [IoSliceMut<'_>]], msgs_out: &mut Vec<(usize, bool, SocketAddr)>
        ) -> io::Result<usize>;*/

        fn try_recv_multiple_vectored_from(
            &self, iovs: &mut [&mut [IoSliceMut<'_>]], msgs_out: &mut Vec<(usize, bool, SocketAddr)>
        ) -> io::Result<usize>;

        // Result value is number of packets sent.

        /*async fn send_multiple_vectored_to(
            &self, msgs: &[(&[IoSlice<'_>], Option<SocketAddr>)], res_out: &mut Vec<usize>
        ) -> io::Result<usize>;*/

        fn try_send_multiple_vectored_to(
            &self, msgs: &[(&[IoSlice<'_>], Option<SocketAddr>)], res_out: &mut Vec<usize>
        ) -> io::Result<usize>;
    }


    const DUMMY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

    fn sockaddr_storage_as_socket_addr(sas: &SockaddrStorage) -> Option<SocketAddr> {
        match sas.family()? {
            nix::sys::socket::AddressFamily::Inet => Some(SocketAddr::V4((*sas.as_sockaddr_in()?).into())),
            nix::sys::socket::AddressFamily::Inet6 => Some(SocketAddr::V6((*sas.as_sockaddr_in6()?).into())),
            _ => None
        }
    }

    fn recv_msg_as_result_tuple(rm: &RecvMsg<SockaddrStorage>) -> (usize, bool, SocketAddr) {
        (
            rm.bytes,
            rm.flags.contains(MsgFlags::MSG_TRUNC),
            rm.address.and_then(|sa| sockaddr_storage_as_socket_addr(&sa)).unwrap_or(DUMMY_ADDR)
        )
    }


    fn recvmsg_inner(
        sock: RawFd, iov: &mut [IoSliceMut<'_>]
    ) -> io::Result<(usize, bool, SocketAddr)> {
        match nix::sys::socket::recvmsg(sock, iov, None, MsgFlags::empty()) {
            nix::Result::Ok(res) => io::Result::Ok(recv_msg_as_result_tuple(&res)),
            nix::Result::Err(err) => io::Result::Err(std::io::Error::from(err))
        }
    }

    fn sendmsg_inner(
        sock: RawFd, iov: &[IoSlice<'_>], target: Option<SocketAddr>
    ) -> io::Result<usize> {
        let target_sas = target.map(SockaddrStorage::from);
        match nix::sys::socket::sendmsg(sock, iov, &[], MsgFlags::empty(), target_sas.as_ref()) {
            nix::Result::Ok(res) => io::Result::Ok(res),
            nix::Result::Err(err) => io::Result::Err(std::io::Error::from(err))
        }
    }

    fn recvmmsg_inner(
        sock: RawFd, iovs: &mut [&mut [IoSliceMut<'_>]], msgs_out: &mut Vec<(usize, bool, SocketAddr)>
    ) -> io::Result<usize> {
        // TODO: figure out how to hoist this out of the closure --
        // outside though we get complaints about MH not being Send --
        // and using a Box to fix this fails b/c we need to move the box
        // but not iovs (which Rust's closure syntax doesn't allow)
        let mut headers = MultiHeaders::<SockaddrStorage>::preallocate(iovs.len(), None);
        match
            nix::sys::socket::recvmmsg(
                sock, &mut headers,
                // this is incredibly silly but I'm pretty sure the lifetimes
                // in recvmmsg are overly strict -- slices need only outlive MultiHeaders,
                // not be equal
                unsafe { std::mem::transmute::<&mut [&mut [IoSliceMut<'_>]], &mut [&mut [IoSliceMut<'_>]]>(iovs) },
                MsgFlags::empty(), None)
        {
            nix::Result::Ok(mr) => {
                let mut count = 0;
                for res in mr {
                    msgs_out.push(recv_msg_as_result_tuple(&res));
                    count += 1;
                }

                io::Result::Ok(count)
            }

            nix::Result::Err(err) =>
                io::Result::Err(std::io::Error::from(err))
        }
    }

    fn sendmmsg_inner(
        sock: RawFd, msgs: &[(&[IoSlice<'_>], Option<SocketAddr>)], res_out: &mut Vec<usize>
    ) -> io::Result<usize> {
        let mut headers = MultiHeaders::<SockaddrStorage>::preallocate(msgs.len(), None);
        let addrs: Vec<_> = msgs.iter().map(|(_iov, addr)| addr.map(SockaddrStorage::from)).collect();  // FIXME: can we avoid this allocation?
        match
            nix::sys::socket::sendmmsg(
                sock, &mut headers, msgs.iter().map(|(iov, _addr)| iov), addrs,
                &[], MsgFlags::empty())
        {
            nix::Result::Ok(mr) => {
                let mut count = 0;
                for res in mr {
                    res_out.push(res.bytes);
                    count += 1;
                }

                io::Result::Ok(count)
            }

            nix::Result::Err(err) =>
                io::Result::Err(std::io::Error::from(err))
        }
    }


    pub async fn udp_socket_recv_vectored_from(
        self_: &UdpSocket, iovs: &mut [IoSliceMut<'_>]
    ) -> io::Result<(usize, bool, SocketAddr)> {
        let rfd = self_.as_raw_fd();
        self_.async_io(tokio::io::Interest::READABLE, || recvmsg_inner(rfd, iovs)).await
    }

    pub async fn udp_socket_send_vectored_to(
        self_: &UdpSocket, iovs: &[IoSlice<'_>], target: Option<SocketAddr>
    ) -> io::Result<usize> {
        let rfd = self_.as_raw_fd();
        self_.async_io(tokio::io::Interest::WRITABLE, || sendmsg_inner(rfd, iovs, target)).await
    }

    pub async fn udp_socket_recv_multiple_vectored_from(
        self_: &UdpSocket, iovs: &mut [&mut [IoSliceMut<'_>]], msgs_out: &mut Vec<(usize, bool, SocketAddr)>
    ) -> io::Result<usize> {
        let rfd = self_.as_raw_fd();
        self_.async_io(tokio::io::Interest::READABLE,
            || recvmmsg_inner(rfd, unsafe { std::mem::transmute::<&mut [&mut [IoSliceMut<'_>]], &mut [&mut [IoSliceMut<'_>]]>(iovs) }, msgs_out)).await
    }

    pub async fn udp_socket_send_multiple_vectored_to(
        self_: &UdpSocket, msgs: &[(&[IoSlice<'_>], Option<SocketAddr>)], res_out: &mut Vec<usize>
    ) -> io::Result<usize> {
        let rfd = self_.as_raw_fd();
        self_.async_io(tokio::io::Interest::WRITABLE, || sendmmsg_inner(rfd, msgs, res_out)).await
    }

    impl SocketExt for UdpSocket {
        fn try_recv_vectored_from(
            &self, iovs: &mut [IoSliceMut<'_>]
        ) -> io::Result<(usize, bool, SocketAddr)> {
            let rfd = self.as_raw_fd();
            self.try_io(tokio::io::Interest::READABLE, || recvmsg_inner(rfd, iovs))
        }

        fn try_send_vectored_to(
            &self, iovs: &[IoSlice<'_>], target: Option<SocketAddr>
        ) -> io::Result<usize> {
            let rfd = self.as_raw_fd();
            self.try_io(tokio::io::Interest::WRITABLE, || sendmsg_inner(rfd, iovs, target))
        }

        fn try_recv_multiple_vectored_from(
            &self, iovs: &mut [&mut [IoSliceMut<'_>]], msgs_out: &mut Vec<(usize, bool, SocketAddr)>
        ) -> io::Result<usize> {
            let rfd = self.as_raw_fd();
            self.try_io(tokio::io::Interest::READABLE, || recvmmsg_inner(rfd, iovs, msgs_out))
        }

        fn try_send_multiple_vectored_to(
            &self, msgs: &[(&[IoSlice<'_>], Option<SocketAddr>)], res_out: &mut Vec<usize>
        ) -> io::Result<usize> {
            let rfd = self.as_raw_fd();
            self.try_io(tokio::io::Interest::WRITABLE, || sendmmsg_inner(rfd, msgs, res_out))
        }
    }
}
