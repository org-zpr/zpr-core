pub mod mem {
    use std::mem::ManuallyDrop;
    use std::ops::{Deref, DerefMut, Drop};

    /// Backport of the nightly-only experimental API.
    pub unsafe fn slice_assume_init_mut<T>(slice: &mut [std::mem::MaybeUninit<T>]) -> &mut [T] {
        unsafe { &mut *(slice as *mut _ as *mut [T]) }
    }

    struct DropGuardImplInner<T, F: FnOnce(T)> {
        item: T,
        destructor: F,
    }

    struct DropGuardImpl<T, F: FnOnce(T)>(ManuallyDrop<DropGuardImplInner<T, F>>);

    impl<T, F: FnOnce(T)> Deref for DropGuardImpl<T, F> {
        type Target = T;

        fn deref(&self) -> &T {
            &self.0.deref().item
        }
    }

    impl<T, F: FnOnce(T)> DerefMut for DropGuardImpl<T, F> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.0.deref_mut().item
        }
    }

    impl<T, F: FnOnce(T)> Drop for DropGuardImpl<T, F> {
        fn drop(&mut self) {
            // SAFETY: we are calling this in the drop handler, and
            // do not ourselves reuse `inner`
            let inner = unsafe { ManuallyDrop::take(&mut self.0) };
            (inner.destructor)(inner.item);
        }
    }

    #[allow(drop_bounds)]
    pub trait DropGuard<T>: Deref<Target = T> + DerefMut<Target = T> + Drop {
        //! A `DropGuard` is a wrapper for a value which calls a specified
        //! destructor on the value when the guard is dropped.  This is
        //! useful for specifying a "temporary" destructor, e.g.  across a
        //! cancellation point.

        /// Destroy the wrapper and return the wrapped value.  The destructor
        /// will no longer be called.
        fn into_inner(self) -> T;

        /// Convert the wrapped value into another type, using `into_fn`.
        /// The new value will be converted back to the original type using
        /// `from_fn` in order to be destructed.
        fn map<U: Send, IntoFn: FnOnce(T) -> U, FromFn: FnOnce(U) -> T + Send>(
            self,
            into_fn: IntoFn,
            from_fn: FromFn,
        ) -> impl DropGuard<U> + Send;
    }

    impl<T, F: FnOnce(T) + Send> DropGuard<T> for DropGuardImpl<T, F> {
        fn into_inner(mut self) -> T {
            // SAFETY: we are consuming `self`, and forget it immediately after
            let inner = unsafe { ManuallyDrop::take(&mut self.0) };
            std::mem::forget(self);
            inner.item
        }

        fn map<U: Send, IntoFn: FnOnce(T) -> U, FromFn: FnOnce(U) -> T + Send>(
            mut self,
            into_fn: IntoFn,
            from_fn: FromFn,
        ) -> impl DropGuard<U> + Send {
            // SAFETY: we are consuming `self`, and forget it immediately after
            let inner = unsafe { ManuallyDrop::take(&mut self.0) };
            std::mem::forget(self);
            let inner_item = inner.item;
            let inner_destructor = inner.destructor;
            drop_guard(into_fn(inner_item), |outer| {
                inner_destructor(from_fn(outer))
            })
        }
    }

    /// Construct a `DropGuard`, wrapping the specified item, with the specified destructor.
    pub fn drop_guard<T, F: FnOnce(T) + Send>(item: T, destructor: F) -> impl DropGuard<T> {
        DropGuardImpl(ManuallyDrop::new(DropGuardImplInner { item, destructor }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        //use std::cell::RefCell;

        // FIXME: RefCell isn't send, but DropGuard now requires it
        // how to allow??
        /*#[test]
        fn drop_guard_drop_test() {
            let dropped = RefCell::new(false);
            {
                let _guard = drop_guard(123, |x| {
                    assert_eq!(x, 123);
                    *dropped.borrow_mut() = true
                });
                assert!(!*dropped.borrow());
            }
            assert!(dropped.take());
        }*/

        #[test]
        fn drop_guard_into_inner_test() {
            let mut dropped = false;
            {
                let guard = drop_guard(123, |_| dropped = true);
                assert_eq!(guard.into_inner(), 123);
            }
            assert!(!dropped);
        }

        #[test]
        fn drop_guard_deref_test() {
            let mut guard = drop_guard(123, |_| ());
            assert_eq!(*guard, 123);
            *guard = 456;
            assert_eq!(*guard, 456);
        }

        // FIXME: RefCell isn't send, but DropGuard now requires it
        // how to allow??
        /*#[test]
        fn drop_guard_map_test() {
            let dropped = RefCell::new(false);
            {
                let guard_outer = drop_guard(123, |x| {
                    assert_eq!(x, 123);
                    *dropped.borrow_mut() = true
                });
                let guard_inner = guard_outer.map(|x| x + 333, |x| x - 333);
                assert!(!*dropped.borrow());
                assert_eq!(*guard_inner, 456);
            }
            assert!(dropped.take());
        }*/
    }
}

pub mod os {
    pub mod fd {
        use std::io;
        use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

        /// Copy-on-"write" FD.  Analogous to `Cow` but for file descriptors.
        ///
        /// A `CowFd` references a FD, which may be _either_ borrowed _or_ owned.
        #[derive(Debug)]
        pub enum CowFd<'a> {
            Borrowed(BorrowedFd<'a>),
            Owned(OwnedFd),
        }

        impl<'a> CowFd<'a> {
            /// Clone this `CowFd` into a new `CowFd` as the same kind.
            ///
            /// That is – if the FD is borrowed, the borrow is simply copied (which cannot fail).
            /// If the FD is owned, it is duplicated (which may fail).
            pub fn try_clone(&self) -> io::Result<CowFd<'a>> {
                match self {
                    Self::Borrowed(fd) => Ok(Self::Borrowed(fd.clone())),
                    Self::Owned(fd) => Ok(Self::Owned(fd.try_clone()?)),
                }
            }

            /// Create an independent owned copy of the referenced FD by duplicating it.
            ///
            /// This may fail regardless of ownership status.
            pub fn try_clone_to_owned(&self) -> io::Result<OwnedFd> {
                match self {
                    Self::Borrowed(fd) => fd.try_clone_to_owned(),
                    Self::Owned(fd) => fd.try_clone(),
                }
            }

            /// Convert this `CowFd` into an `OwnedFd`.
            ///
            /// If the FD is borrowed, it is duplicated (which may fail).
            /// If the FD is owned, it is simply returned (which cannot fail).
            pub fn try_into_owned(self) -> io::Result<OwnedFd> {
                match self {
                    Self::Borrowed(fd) => fd.try_clone_to_owned(),
                    Self::Owned(fd) => Ok(fd),
                }
            }

            /// Is this FD borrowed?
            pub fn is_borrowed(&self) -> bool {
                match self {
                    Self::Borrowed(_) => true,
                    Self::Owned(_) => false,
                }
            }

            /// Is this FD owned?
            pub fn is_owned(&self) -> bool {
                match self {
                    Self::Borrowed(_) => false,
                    Self::Owned(_) => true,
                }
            }
        }

        impl<'a> From<BorrowedFd<'a>> for CowFd<'a> {
            /// Wrap a `BorrowedFd` as a `CowFd` which is borrowed.
            fn from(fd: BorrowedFd<'a>) -> Self {
                Self::Borrowed(fd)
            }
        }

        impl From<OwnedFd> for CowFd<'_> {
            /// Wrap an `OwnedFd` as a `CowFd` which is owned.
            fn from(fd: OwnedFd) -> Self {
                Self::Owned(fd)
            }
        }

        impl AsFd for CowFd<'_> {
            /// Borrow the FD referenced by this `CowFd`.
            fn as_fd(&self) -> BorrowedFd<'_> {
                match self {
                    Self::Borrowed(fd) => fd.as_fd(),
                    Self::Owned(fd) => fd.as_fd(),
                }
            }
        }

        impl AsRawFd for CowFd<'_> {
            /// Returns the raw FD referenced by this `CowFd`.
            fn as_raw_fd(&self) -> RawFd {
                match self {
                    Self::Borrowed(fd) => fd.as_raw_fd(),
                    Self::Owned(fd) => fd.as_raw_fd(),
                }
            }
        }

        impl FromRawFd for CowFd<'_> {
            /// Takes ownership of the given raw FD as an owned `CowFd`.
            ///
            /// # Safety
            ///
            /// The referenced FD must be open and suitable for assuming ownership.
            /// (Same as for `OwnedFd::from_raw_fd()`.)
            unsafe fn from_raw_fd(fd: RawFd) -> Self {
                Self::Owned(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        }
    }

    #[cfg(unix)]
    pub mod unix {
        pub mod net {
            use crate::std::os::fd::CowFd;
            use libc;
            use std::io::{Error, IoSlice, IoSliceMut, Result};
            use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, RawFd};
            use std::os::unix::net::UnixStream;
            use std::ptr;
            use std::vec::Vec;

            #[cfg(any(target_os = "android", target_os = "linux"))]
            type MsghdrIovlenT = libc::size_t;

            #[cfg(any(target_os = "macos"))]
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
                let fds: Box<[BorrowedFd<'_>]> =
                    ancillary.fds.iter().map(|fd| fd.as_fd()).collect();
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
                        let num_fds = (((*cmsghdr).cmsg_len as usize) - size_of_hdr)
                            / std::mem::size_of::<RawFd>();
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
                        s1.send_vectored_with_ancillary(
                            &[IoSlice::new(data_in)],
                            &mut ancillary_in
                        )
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
                        s1.send_vectored_with_ancillary(
                            &[IoSlice::new(data_in)],
                            &mut ancillary_in
                        )
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
    }
}

pub mod vec {
    pub trait VecExt<T> {
        fn recycle<U>(self) -> Vec<U>;
    }

    impl<T> VecExt<T> for Vec<T> {
        /// Recycle the underlying storage pool of a vector, while ending
        /// the lifetimes of everything contained in it.  Example usage:
        ///   let mut outer_vec = Vec::new();
        ///   loop {
        ///     // invariant: outer_vec is empty
        ///     let mut inner_vec = outer_vec;
        ///     // ... use inner_vec ...
        ///     outer_vec = inner_vec.recycle();
        ///   }
        /// See <https://github.com/rust-lang/rfcs/pull/2802#issuecomment-871512348>
        /// Also available here: <https://docs.rs/vec-utils/0.3.0/src/vec_utils/vec.rs.html#234>
        /// and here: <https://docs.rs/recycle_vec/1.0.4/src/recycle_vec/lib.rs.html#88>
        fn recycle<U>(mut self) -> Vec<U> {
            self.clear();
            self.into_iter().map(|_| unreachable!()).collect()
        }
    }
}
