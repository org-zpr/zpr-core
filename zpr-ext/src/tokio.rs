pub mod net {
    use crate::std::os::unix::net::{
        uds_recv_vectored_with_ancillary, uds_send_vectored_with_ancillary, SocketAncillary,
    };
    use nix::sys::socket;
    use std::io::{self, IoSlice, IoSliceMut};
    use std::os::fd::{AsFd, AsRawFd};
    use tokio::io::Interest;
    use tokio::net::{UdpSocket, UnixStream};

    pub trait UdpSocketExt {
        fn mtu(&self) -> io::Result<u32>;
        #[cfg(any(doc, target_os = "android", target_os = "linux"))]
        fn attach_reuse_port_cbpf(&self, filter: &[libc::sock_filter]) -> io::Result<()>;
    }

    impl UdpSocketExt for UdpSocket {
        /// Retrieve the socket's current known path MTU.
        fn mtu(&self) -> io::Result<u32> {
            match socket::getsockopt(self, socket::sockopt::IpMtu) {
                Ok(mtu) => Ok(mtu as u32),
                Err(errno) => Err(io::Error::from(errno)),
            }
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

    #[allow(async_fn_in_trait)]
    pub trait UnixStreamExt {
        #[cfg(any(doc, target_os = "android", target_os = "linux"))]
        async fn send_vectored_with_ancillary(
            &self,
            bufs: &[IoSlice<'_>],
            ancillary: &mut SocketAncillary<'_>,
        ) -> io::Result<usize>;

        #[cfg(any(doc, target_os = "android", target_os = "linux"))]
        async fn recv_vectored_with_ancillary(
            &self,
            bufs: &mut [IoSliceMut<'_>],
            ancillary: &mut SocketAncillary<'_>,
        ) -> io::Result<usize>;
    }

    impl UnixStreamExt for UnixStream {
        #[cfg(any(doc, target_os = "android", target_os = "linux"))]
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

        #[cfg(any(doc, target_os = "android", target_os = "linux"))]
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
                s1.send_vectored_with_ancillary(
                    &[IoSlice::new(data_in)],
                    &mut ancillary_in
                )
                .await
                .unwrap(),
                3
            );

            receiver.await.unwrap();
        }
    }
}
