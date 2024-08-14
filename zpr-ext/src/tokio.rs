pub mod net {
    use crate::std::os::unix::net::{
        uds_recv_vectored_with_ancillary, uds_send_vectored_with_ancillary, SocketAncillary,
    };
    use nix::sys::socket;
    use std::io::{self, IoSlice, IoSliceMut};
    use std::os::fd::AsFd;
    use tokio::io::Interest;
    use tokio::net::{UdpSocket, UnixStream};

    pub trait UdpSocketExt {
        fn mtu(&self) -> io::Result<u32>;
    }

    impl UdpSocketExt for UdpSocket {
        /// Retrieve the socket's current known path MTU.
        fn mtu(&self) -> io::Result<u32> {
            match socket::getsockopt(self, socket::sockopt::IpMtu) {
                Ok(mtu) => Ok(mtu as u32),
                Err(errno) => Err(io::Error::from(errno)),
            }
        }
    }

    #[cfg(any(doc, target_os = "android", target_os = "linux"))]
    pub async fn unix_stream_send_vectored_with_ancillary(
        stream: &UnixStream,
        bufs: &[IoSlice<'_>],
        ancillary: &mut SocketAncillary<'_>,
    ) -> io::Result<usize> {
        loop {
            stream.writable().await?;
            match stream.try_io(Interest::WRITABLE, || {
                uds_send_vectored_with_ancillary(stream.as_fd(), bufs, ancillary)
            }) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                res => break res,
            }
        }
    }

    #[cfg(any(doc, target_os = "android", target_os = "linux"))]
    pub async fn unix_stream_recv_vectored_with_ancillary(
        stream: &UnixStream,
        bufs: &mut [IoSliceMut<'_>],
        ancillary: &mut SocketAncillary<'_>,
    ) -> io::Result<usize> {
        loop {
            stream.readable().await?;
            match stream.try_io(Interest::WRITABLE, || {
                uds_recv_vectored_with_ancillary(stream.as_fd(), bufs, ancillary)
            }) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                res => break res,
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
                    unix_stream_recv_vectored_with_ancillary(
                        &s2,
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
                unix_stream_send_vectored_with_ancillary(
                    &s1,
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
