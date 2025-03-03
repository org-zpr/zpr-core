pub mod net {
    use crate::std::os::fd::CowFd;
    use libc;
    use std::io::{Error, IoSlice, IoSliceMut, Result};
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::ptr;
    use std::vec::Vec;

    #[cfg(any(doc, target_os = "android", target_os = "linux"))]
    type MsghdrIovlenT = libc::size_t;

    #[cfg(not(doc))]
    #[cfg(target_os = "macos")]
    type MsghdrIovlenT = libc::c_int;

    pub struct SocketAncillary<'a> {
        buffer: &'a mut [u8],
        fds: Vec<CowFd<'a>>,
    }

    impl<'a> SocketAncillary<'a> {
        pub fn new(buffer: &'a mut [u8]) -> Self {
            Self {
                buffer,
                fds: Vec::new(),
            }
        }

        pub fn add_fds(&mut self, fds: &[BorrowedFd<'a>]) -> bool {
            for fd in fds {
                self.fds.push((*fd).into());
            }
            true // FIXME: it's a lie!
        }

        pub fn clear(&mut self) {
            self.fds.clear();
        }

        pub fn is_empty(&self) -> bool {
            self.fds.is_empty()
        }

        // NOTE: This differs from the proposed API, which suffers from a resource leak
        // (and potential DoS) if the ancillary data is not consumed.  So here,
        // we instead own the FDs; into_messages() here is then used to avoid duping the FDs.
        pub fn into_messages(self) -> OwnedMessages<'a> {
            if self.fds.is_empty() {
                None.into_iter()
            } else {
                Some(Ok(AncillaryData::ScmRights(self.fds.into_iter()))).into_iter()
            }
        }
    }

    pub type OwnedMessages<'a> =
        std::option::IntoIter<std::result::Result<AncillaryData<'a>, AncillaryError>>;

    pub enum AncillaryData<'a> {
        ScmRights(ScmRights<'a>),
        ScmCredentials(ScmCredentials<'a>),
    }

    pub type AncillaryError = ();

    pub type ScmRights<'a> = std::vec::IntoIter<CowFd<'a>>;

    pub struct ScmCredentials<'a>(std::marker::PhantomData<&'a ()>);

    pub trait UnixStreamExt {
        fn send_vectored_with_ancillary(
            &self,
            bufs: &[IoSlice<'_>],
            ancillary: &mut SocketAncillary<'_>,
        ) -> Result<usize>;

        fn recv_vectored_with_ancillary(
            &self,
            bufs: &mut [IoSliceMut<'_>],
            ancillary: &mut SocketAncillary<'_>,
        ) -> Result<usize>;
    }

    pub(crate) fn uds_send_vectored_with_ancillary(
        fd: BorrowedFd<'_>,
        bufs: &[IoSlice<'_>],
        ancillary: &mut SocketAncillary<'_>,
    ) -> Result<usize> {
        let fds: Box<[BorrowedFd<'_>]> = ancillary.fds.iter().map(|fd| fd.as_fd()).collect();
        let fds_size = fds.len() * std::mem::size_of::<RawFd>();

        let mut msghdr = libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: bufs.as_ptr() as *mut _,
            msg_iovlen: bufs.len() as MsghdrIovlenT,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        if fds_size > 0 {
            unsafe {
                msghdr.msg_control = (&mut ancillary.buffer).as_mut_ptr().cast();
                msghdr.msg_controllen = libc::CMSG_SPACE(fds_size as _) as _;

                let cmsghdr = libc::CMSG_FIRSTHDR(&msghdr);
                (*cmsghdr).cmsg_len = libc::CMSG_LEN(fds_size as _) as _;
                (*cmsghdr).cmsg_level = libc::SOL_SOCKET;
                (*cmsghdr).cmsg_type = libc::SCM_RIGHTS;
                libc::CMSG_DATA(cmsghdr)
                    .copy_from_nonoverlapping((&fds[..]).as_ptr().cast(), fds_size);
            }
        }

        let res = unsafe { libc::sendmsg(fd.as_raw_fd(), &msghdr, 0) };

        if res > 0 {
            Ok(res as usize)
        } else {
            Err(Error::last_os_error())
        }
    }

    pub(crate) fn uds_recv_vectored_with_ancillary(
        fd: BorrowedFd<'_>,
        bufs: &mut [IoSliceMut<'_>],
        ancillary: &mut SocketAncillary<'_>,
    ) -> Result<usize> {
        let mut msghdr = libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: bufs.as_ptr() as *mut _,
            msg_iovlen: bufs.len() as MsghdrIovlenT,
            msg_control: (&mut ancillary.buffer).as_mut_ptr().cast(),
            msg_controllen: ancillary.buffer.len() as _,
            msg_flags: 0,
        };

        let res = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msghdr, 0) };

        unsafe {
            let cmsghdr = libc::CMSG_FIRSTHDR(&msghdr);
            if !cmsghdr.is_null()
                && (*cmsghdr).cmsg_level == libc::SOL_SOCKET
                && (*cmsghdr).cmsg_type == libc::SCM_RIGHTS
            {
                let size_of_hdr = (2 * libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _)
                    - libc::CMSG_LEN((2 * std::mem::size_of::<RawFd>()) as _))
                    as usize;
                let num_fds =
                    (((*cmsghdr).cmsg_len as usize) - size_of_hdr) / std::mem::size_of::<RawFd>();
                ancillary.fds =
                    std::slice::from_raw_parts(libc::CMSG_DATA(cmsghdr).cast(), num_fds)
                        .into_iter()
                        .map(|&fd| CowFd::from_raw_fd(fd))
                        .collect();
            }
        }

        if res > 0 {
            Ok(res as usize)
        } else {
            Err(Error::last_os_error())
        }
    }

    impl UnixStreamExt for UnixStream {
        /// This is a very silly and limited implementation of `send_vectored_with_ancillary()` as we await
        /// stabilization of [unix_socket_ancillary_data](https://github.com/rust-lang/rust/issues/76915).
        fn send_vectored_with_ancillary(
            &self,
            bufs: &[IoSlice<'_>],
            ancillary: &mut SocketAncillary<'_>,
        ) -> Result<usize> {
            uds_send_vectored_with_ancillary(self.as_fd(), bufs, ancillary)
        }

        fn recv_vectored_with_ancillary(
            &self,
            bufs: &mut [IoSliceMut<'_>],
            ancillary: &mut SocketAncillary<'_>,
        ) -> Result<usize> {
            uds_recv_vectored_with_ancillary(self.as_fd(), bufs, ancillary)
        }
    }

    #[cfg(test)]
    #[allow(unstable_name_collisions)]
    mod tests {
        use super::*;
        use std::fs::File;
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        #[test]
        fn ancillary_no_ancillary() {
            let (s1, s2) = UnixStream::pair().unwrap();

            let data_in = &[1u8, 2u8, 3u8];
            let mut ancillary_in_buf = [0u8; 256];
            let mut ancillary_in = SocketAncillary::new(&mut ancillary_in_buf);
            assert_eq!(
                s1.send_vectored_with_ancillary(&[IoSlice::new(data_in)], &mut ancillary_in)
                    .unwrap(),
                3
            );

            let mut data_out = [0u8; 4];
            let mut ancillary_out_buf = [0u8; 256];
            let mut ancillary_out = SocketAncillary::new(&mut ancillary_out_buf);
            assert_eq!(
                s2.recv_vectored_with_ancillary(
                    &mut [IoSliceMut::new(&mut data_out[..])],
                    &mut ancillary_out
                )
                .unwrap(),
                3
            );

            assert!(ancillary_out.into_messages().next().is_none());
        }

        #[test]
        fn ancillary_fd() {
            let zero_file = File::open("/dev/zero").unwrap();

            let (s1, s2) = UnixStream::pair().unwrap();

            let data_in = &[1u8, 2u8, 3u8];
            let mut ancillary_in_buf = [0u8; 256];
            let mut ancillary_in = SocketAncillary::new(&mut ancillary_in_buf);
            ancillary_in.add_fds(&[zero_file.as_fd()]);
            assert_eq!(
                s1.send_vectored_with_ancillary(&[IoSlice::new(data_in)], &mut ancillary_in)
                    .unwrap(),
                3
            );

            let mut data_out = [0u8; 4];
            let mut ancillary_out_buf = [0u8; 256];
            let mut ancillary_out = SocketAncillary::new(&mut ancillary_out_buf);
            assert_eq!(
                s2.recv_vectored_with_ancillary(
                    &mut [IoSliceMut::new(&mut data_out[..])],
                    &mut ancillary_out
                )
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
        }
    }
}
