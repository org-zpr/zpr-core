#![allow(dead_code)]
#![allow(unused_imports)]

//! Batch I/O operations.
//!
//! These vary both by operating system and feature set.
//!
//! All these operations assume a file descriptor which has been set
//! non-blocking, and they perform non-blocking I/O operations.

use nix::sys::socket::{AddressFamily, SockaddrLike, SockaddrStorage};
use std::net::SocketAddr;

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod io_uring {
    //! io_uring(7)-based implementation.  Only available for Linux.

    use super::sockaddr_to_socket_addr;
    use bytes::BufMut;
    use io_uring::{cqueue, opcode, squeue, types, IoUring};
    use libc;
    use nix::sys::socket::{SockaddrLike, SockaddrStorage};
    use std::io::Result;
    use std::mem::MaybeUninit;
    use std::net::SocketAddr;
    use std::os::fd::{AsFd, AsRawFd};

    pub const MAX_ENTRIES: usize = 1024;

    /// This is a very basic on-stack vector/slab.
    struct Slab<T> {
        allocated: usize,
        storage: [MaybeUninit<T>; MAX_ENTRIES],
    }

    impl<T> Slab<T> {
        fn new() -> Self {
            Self {
                allocated: 0,
                storage: [const { MaybeUninit::uninit() }; MAX_ENTRIES],
            }
        }

        #[allow(dead_code)]
        fn get(&self, idx: usize) -> &T {
            assert!(idx < self.allocated);
            // SAFETY: we've written to all entries which have been allocated
            unsafe { self.storage[idx].assume_init_ref() }
        }

        fn get_mut(&mut self, idx: usize) -> &mut T {
            assert!(idx < self.allocated);
            // SAFETY: we've written to all entries which have been allocated
            unsafe { self.storage[idx].assume_init_mut() }
        }

        fn push(&mut self, val: T) -> &mut T {
            assert!(self.allocated < self.storage.len());
            let idx = self.allocated;
            self.allocated += 1;
            self.storage[idx].write(val)
        }
    }

    impl<T> Drop for Slab<T> {
        fn drop(&mut self) {
            for i in 0..self.allocated {
                // SAFETY: we've written to all entries which have been allocated
                unsafe {
                    self.storage[i].assume_init_drop();
                }
            }
        }
    }

    trait BatchOp<Item, State, Res> {
        fn new() -> Self;
        fn build_op(&mut self, fd: types::Fd, item: Item, idx: usize) -> (squeue::Entry, State);
        fn process_result(&self, idx: usize, state: State, amt: usize) -> Res;
    }

    struct TryWriteBatchOp {}

    impl BatchOp<&[u8], (), usize> for TryWriteBatchOp {
        fn new() -> Self {
            Self {}
        }

        fn build_op(&mut self, fd: types::Fd, buf: &[u8], _idx: usize) -> (squeue::Entry, ()) {
            (
                opcode::Write::new(fd, buf.as_ptr(), buf.len() as u32).build(),
                (),
            )
        }

        fn process_result(&self, _idx: usize, (): (), amt: usize) -> usize {
            amt
        }
    }

    struct TryReadBufBatchOp<'a, B> {
        phantom: std::marker::PhantomData<&'a B>,
    }

    impl<'a, B: BufMut> BatchOp<&'a mut B, &'a mut B, usize> for TryReadBufBatchOp<'a, B> {
        fn new() -> Self {
            Self {
                phantom: std::marker::PhantomData,
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            buf: &'a mut B,
            _idx: usize,
        ) -> (squeue::Entry, &'a mut B) {
            let chunk = buf.chunk_mut();
            (
                opcode::Read::new(fd, chunk.as_mut_ptr(), chunk.len() as u32).build(),
                buf,
            )
        }

        fn process_result(&self, _idx: usize, buf: &'a mut B, amt: usize) -> usize {
            // SAFETY: We know we've written the given number of bytes in the BufMut.
            unsafe { buf.advance_mut(amt) };
            amt
        }
    }

    struct TrySendToBatchOp {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: Slab<SockaddrStorage>,
        msghdr_slab: Slab<libc::msghdr>,
    }

    impl BatchOp<(&[u8], SocketAddr), (), usize> for TrySendToBatchOp {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: Slab::new(),
                msghdr_slab: Slab::new(),
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            (buf, addr): (&[u8], SocketAddr),
            _idx: usize,
        ) -> (squeue::Entry, ()) {
            let iovec_ref = self.iovec_slab.push(slice_as_iovec(buf));
            let sockaddr_ref = self.sockaddr_slab.push(SockaddrStorage::from(addr));
            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref as *mut _ as *mut libc::c_void,
                msg_namelen: sockaddr_ref.len(),
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            });

            (opcode::SendMsg::new(fd, msghdr_ref as *const _).build(), ())
        }

        fn process_result(&self, _idx: usize, (): (), amt: usize) -> usize {
            amt
        }
    }

    struct TryRecvBufFromBatchOp<'a, B> {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: [MaybeUninit<SockaddrStorage>; MAX_ENTRIES],
        msghdr_slab: Slab<libc::msghdr>,
        phantom: std::marker::PhantomData<&'a B>,
    }

    impl<'a, B: BufMut> BatchOp<&'a mut B, &'a mut B, (usize, Option<SocketAddr>)>
        for TryRecvBufFromBatchOp<'a, B>
    {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: [MaybeUninit::uninit(); MAX_ENTRIES],
                msghdr_slab: Slab::new(),
                phantom: std::marker::PhantomData,
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            buf: &'a mut B,
            idx: usize,
        ) -> (squeue::Entry, &'a mut B) {
            let iovec_ref = self.iovec_slab.push(buf_mut_as_iovec(buf));
            let sockaddr_ref = &mut self.sockaddr_slab[idx];
            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref.as_mut_ptr() as *mut libc::c_void,
                msg_namelen: std::mem::size_of_val(sockaddr_ref) as u32,
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: libc::MSG_TRUNC,
            });

            (opcode::RecvMsg::new(fd, msghdr_ref as *mut _).build(), buf)
        }

        fn process_result(
            &self,
            idx: usize,
            buf: &'a mut B,
            amt: usize,
        ) -> (usize, Option<SocketAddr>) {
            // SAFETY: We know we've written the given number of bytes in the BufMut.
            unsafe { buf.advance_mut(amt) };
            // SAFETY: We know the sockaddr is now filled.
            let addr = sockaddr_to_socket_addr(unsafe { self.sockaddr_slab[idx].assume_init() });
            (amt, addr)
        }
    }

    pub struct BatchIo {
        io_uring: IoUring<squeue::Entry, cqueue::Entry>,
    }

    // NOTE: Limit io_uring features used to those available in 5.10 or later.
    // (= oldest LTS release with EOL > end of 2025)

    impl BatchIo {
        pub fn new(entries: usize) -> Result<Self> {
            assert!(entries <= MAX_ENTRIES);

            let io_uring = IoUring::<squeue::Entry, cqueue::Entry>::builder()
                .dontfork()
                .build((2 * entries) as u32)?;

            Ok(Self { io_uring })
        }

        fn do_batch_op<Item, State, Res>(
            &mut self,
            mut batch_op: impl BatchOp<Item, State, Res>,
            fd: &impl AsFd,
            items: impl IntoIterator<Item = Item>,
            results: &mut Vec<Result<Res>>,
        ) -> Result<usize> {
            let fd = types::Fd(fd.as_fd().as_raw_fd());

            let mut submitted = 0;

            let mut squeue = self.io_uring.submission();

            // Each operation consumes two entries (one for the operation, one for the cancel request).
            let max_to_submit = (squeue.capacity() - squeue.len()) / 2;

            let mut state_slab = Slab::new();

            // Enter the operations into the submission queue.
            for item in items {
                if submitted >= max_to_submit {
                    break;
                }

                // Attach a unique identifier to each item in the batch.
                // Needed for canceling the operations, and for identifying their results.
                let user_data = (submitted as u64) + 1;

                // Build the operation entry, and stow any state we need for processing the result.
                let (entry, state) = batch_op.build_op(fd, item, submitted);
                state_slab.push(Some(state));

                let entries = [
                    entry.user_data(user_data),
                    opcode::AsyncCancel::new(user_data).build(),
                ];

                // NOTE: ideally we'd use LINK and O_NONBLOCK, but:
                // (a) since all reads from a TUN are "short", LINK treats them as failures,
                // (b) O_NONBLOCK is ignored by io_uring, and
                // (c) RWF_NOWAIT is not supported by TUN devices.
                //
                // So instead we must manually cancel all requests which
                // weren't immediately fulfilled (since they otherwise will
                // run asynchronously).  This means we must live with the
                // (rare) possibility that reads after the first which would
                // have blocked actually complete (since we are racing with
                // the TUN device).
                //
                // (Note, even if (b) and (c) were solved, HARDLINK puts us in the same situation.)
                //
                // (Note also that, batch cancellation (which is supported
                // only on newer kernels anyway) only cancels the first item
                // of a linked chain!)

                // SAFETY: the buf ptrs are valid for our entire body, and we
                // are waiting on completion before we exit.
                unsafe { squeue.push_multiple(&entries) }.unwrap();
                submitted += 1;
            }

            drop(squeue);

            // Submit the operations and "wait" for completion (which should not block,
            // thanks to our cancels).
            // TODO: do we actually need `_and_wait` here?
            let completed = self.io_uring.submit_and_wait(2 * submitted)?;
            assert_eq!(completed, 2 * submitted);

            // Read results from the completion queue.
            let mut cqueue = self.io_uring.completion();
            let mut completions = [const { MaybeUninit::uninit() }; MAX_ENTRIES * 2];
            let completions = cqueue.fill(&mut completions);
            assert_eq!(completions.len(), 2 * submitted);

            let results_base = results.len();
            results.reserve(submitted);

            // Process results, skipping over the results of our cancel operations.
            for entry in completions {
                if entry.user_data() == 0 {
                    // a cancel request
                    continue;
                }

                let result = entry.result();

                if result == -libc::ECANCELED {
                    // This operation was cancelled.  Don't append to `results`,
                    // under the assumption that the remainder of operations were
                    // cancelled as well.
                    //
                    // Note though that, because io_uring processing is racing
                    // against the rest of the system, and we are unable to use
                    // linking to stop processing at the first error for the reasons
                    // above, we may see successful operations after cancelled ones.
                    // So we must `continue` here, and not `break`.
                    // Filling in the gaps in the `results` vector is handled below.

                    continue;
                }

                // Grab the unique identifier of the operation.
                let idx = (entry.user_data() - 1) as usize;

                if idx >= results.len() - results_base {
                    // Note that, for some reason, results may come out of order.
                    // (It seems that cancel operations may be processed asynchronously.)
                    // So, fill skipped-over results with EWOULDBLOCK.

                    results.resize_with(results_base + idx + 1, || {
                        Err(std::io::Error::from_raw_os_error(libc::EWOULDBLOCK))
                    });
                }

                // Translate the result.
                results[results_base + idx] = if result < 0 {
                    Err(std::io::Error::from_raw_os_error(-result))
                } else {
                    Ok(batch_op.process_result(
                        idx,
                        state_slab.get_mut(idx).take().unwrap(),
                        result as usize,
                    ))
                };
            }

            Ok(results.len() - results_base)
        }

        pub fn try_write_batch<'a>(
            &mut self,
            fd: &impl AsFd,
            bufs: impl IntoIterator<Item = &'a [u8]>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(TryWriteBatchOp::new(), fd, bufs, results)
        }

        pub fn try_read_buf_batch<'a, B>(
            &mut self,
            fd: &impl AsFd,
            bufs: impl IntoIterator<Item = &'a mut B>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize>
        where
            B: BufMut + 'a,
        {
            self.do_batch_op(TryReadBufBatchOp::new(), fd, bufs, results)
        }

        pub fn try_send_to_batch<'a>(
            &mut self,
            fd: &impl AsFd,
            bufs: impl IntoIterator<Item = (&'a [u8], SocketAddr)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(TrySendToBatchOp::new(), fd, bufs, results)
        }

        pub fn try_recv_buf_from_batch<'a, B>(
            &mut self,
            fd: &impl AsFd,
            bufs: impl IntoIterator<Item = &'a mut B>,
            results: &mut Vec<Result<(usize, Option<SocketAddr>)>>,
        ) -> Result<usize>
        where
            B: BufMut + 'a,
        {
            let foo = TryRecvBufFromBatchOp::new();
            self.do_batch_op(foo, fd, bufs, results)
        }
    }

    fn slice_as_iovec(buf: &[u8]) -> libc::iovec {
        libc::iovec {
            iov_base: buf.as_ptr() as *mut u8 as *mut _,
            iov_len: buf.len(),
        }
    }

    fn buf_mut_as_iovec(buf: &mut impl BufMut) -> libc::iovec {
        let chunk = buf.chunk_mut();
        libc::iovec {
            iov_base: chunk.as_mut_ptr() as *mut _,
            iov_len: chunk.len(),
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
mod posix_unbatched {
    //! Unbatched implementation using POSIX primitives.

    use super::sockaddr_to_socket_addr;
    use bytes::BufMut;
    use nix::sys::socket::{self, MsgFlags, SockaddrStorage};
    use nix::unistd;
    use std::io::{Error, Result};
    use std::net::SocketAddr;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
    use zpr_ext::std::mem::slice_assume_init_mut;

    #[allow(dead_code)]
    pub const MAX_ENTRIES: usize = 1024;

    pub struct BatchIo {}

    fn errno_to_error(errno: nix::errno::Errno) -> Error {
        Error::from_raw_os_error(errno as i32)
    }

    impl BatchIo {
        pub fn new(_entries: usize) -> Result<Self> {
            Ok(Self {})
        }

        fn do_batch_op<'a, Item, Res>(
            &mut self,
            op: impl Fn(BorrowedFd<'a>, Item) -> Result<Res>,
            fd: &'a impl AsFd,
            items: impl IntoIterator<Item = Item>,
            results: &'a mut Vec<Result<Res>>,
        ) -> Result<usize> {
            let fd = fd.as_fd();
            let mut completed = 0;
            for item in items {
                let res = op(fd, item);
                if let Err(err) = res {
                    if completed == 0 {
                        return Err(err);
                    }

                    break;
                }
                results.push(res);
                completed += 1;
            }

            Ok(completed)
        }

        pub fn try_write_batch<'a>(
            &'a mut self,
            fd: &'a impl AsFd,
            bufs: impl IntoIterator<Item = &'a [u8]>,
            results: &'a mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(
                |fd, buf| unistd::write(fd, buf).map_err(errno_to_error),
                fd,
                bufs,
                results,
            )
        }

        pub fn try_read_buf_batch<'a, B>(
            &'a mut self,
            fd: &'a impl AsFd,
            bufs: impl IntoIterator<Item = &'a mut B>,
            results: &'a mut Vec<Result<usize>>,
        ) -> Result<usize>
        where
            B: BufMut + 'a,
        {
            self.do_batch_op(
                |fd, buf| {
                    // SAFETY: We will only be writing to the chunk.
                    let chunk =
                        unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                    let amt = unistd::read(fd.as_raw_fd(), chunk).map_err(errno_to_error)?;
                    // SAFETY: We know we've written the given number of bytes in the BufMut.
                    unsafe { buf.advance_mut(amt as usize) };
                    Ok(amt)
                },
                fd,
                bufs,
                results,
            )
        }

        pub fn try_send_to_batch<'a>(
            &'a mut self,
            fd: &'a impl AsFd,
            bufs: impl IntoIterator<Item = (&'a [u8], SocketAddr)>,
            results: &'a mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(
                |fd, (buf, addr)| {
                    socket::sendto(
                        fd.as_raw_fd(),
                        buf,
                        &SockaddrStorage::from(addr),
                        MsgFlags::empty(),
                    )
                    .map_err(errno_to_error)
                },
                fd,
                bufs,
                results,
            )
        }

        pub fn try_recv_buf_from_batch<'a, B>(
            &'a mut self,
            fd: &'a impl AsFd,
            bufs: impl IntoIterator<Item = &'a mut B>,
            results: &'a mut Vec<Result<(usize, Option<SocketAddr>)>>,
        ) -> Result<usize>
        where
            B: BufMut + 'a,
        {
            self.do_batch_op(
                |fd, buf| {
                    // SAFETY: We will only be writing to the chunk.
                    let chunk =
                        unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                    let (amt, addr) =
                        socket::recvfrom(fd.as_raw_fd(), chunk).map_err(errno_to_error)?;
                    // SAFETY: We know we've written the given number of bytes in the BufMut.
                    unsafe { buf.advance_mut(amt as usize) };
                    Ok((amt, addr.and_then(sockaddr_to_socket_addr)))
                },
                fd,
                bufs,
                results,
            )
        }
    }
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use io_uring::*;
#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
pub use posix_unbatched::*;

fn sockaddr_to_socket_addr(sa: SockaddrStorage) -> Option<SocketAddr> {
    match sa.family() {
        Some(AddressFamily::Inet) => Some(SocketAddr::V4((*sa.as_sockaddr_in().unwrap()).into())),
        Some(AddressFamily::Inet6) => Some(SocketAddr::V6((*sa.as_sockaddr_in6().unwrap()).into())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::BatchIo;
    use std::io::Result;
    use std::net::UdpSocket;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn write_test() {
        // FIXME: we need to test EAGAIN behavior... possibly by first filling queue, then draining a few

        let (inq, outq) = UnixDatagram::pair().unwrap();
        inq.set_nonblocking(true).unwrap();
        outq.set_nonblocking(true).unwrap();

        let nmsgs = 16;

        let mut bio = BatchIo::new(2 * nmsgs).unwrap();

        let mut msgs = Vec::new();

        for i in 0..nmsgs {
            msgs.push(format!("This is message {i}"));
        }

        let mut results = Vec::new();

        let n = bio.try_write_batch(&inq, msgs.iter().map(|msg| msg.as_bytes()), &mut results);
        assert!(n.unwrap() >= nmsgs);

        for i in 0..nmsgs {
            assert_eq!(*results[i].as_ref().unwrap(), msgs[i].len());
        }

        let mut buf = [0u8; 256];
        for i in 0..nmsgs {
            let msg_size = outq.recv(&mut buf).unwrap();
            assert_eq!(msgs[i].as_bytes(), &buf[..msg_size]);
        }
    }

    #[test]
    fn read_test() {
        let (inq, outq) = UnixDatagram::pair().unwrap();
        inq.set_nonblocking(true).unwrap();
        outq.set_nonblocking(true).unwrap();

        let nmsgs = 16;

        let mut bio = BatchIo::new(2 * nmsgs).unwrap();

        let mut msgs = Vec::new();

        for i in 0..nmsgs {
            msgs.push(format!("This is message {i}"));
        }

        for msg in &msgs {
            let _ = inq.send(msg.as_bytes()).unwrap();
        }

        let mut bufs = vec![Vec::with_capacity(64); 2 * nmsgs];
        let mut results = Vec::new();

        let n = bio.try_read_buf_batch(&outq, bufs.iter_mut(), &mut results);
        assert!(n.unwrap() >= nmsgs);

        for i in 0..nmsgs {
            assert_eq!(*results[i].as_ref().unwrap(), msgs[i].len());
            assert_eq!(bufs[i].as_slice(), msgs[i].as_bytes());
        }
    }

    #[test]
    fn send_test() {
        // FIXME: we need to test EAGAIN behavior... possibly by first filling queue, then draining a few

        let inq = udp_socket().unwrap();
        let outq = udp_socket().unwrap();
        inq.set_nonblocking(true).unwrap();
        outq.set_nonblocking(true).unwrap();

        let nmsgs = 16;

        let mut bio = BatchIo::new(2 * nmsgs).unwrap();

        let mut msgs = Vec::new();

        for i in 0..nmsgs {
            msgs.push(format!("This is message {i}"));
        }

        let mut results = Vec::new();

        let dest = outq.local_addr().unwrap();

        let n = bio.try_send_to_batch(
            &inq,
            msgs.iter().map(|msg| (msg.as_bytes(), dest)),
            &mut results,
        );
        assert!(n.unwrap() >= nmsgs);

        for i in 0..nmsgs {
            assert_eq!(*results[i].as_ref().unwrap(), msgs[i].len());
        }

        let mut buf = [0u8; 256];
        for i in 0..nmsgs {
            let msg_size = outq.recv(&mut buf).unwrap();
            assert_eq!(msgs[i].as_bytes(), &buf[..msg_size]);
        }
    }

    #[test]
    fn recv_test() {
        let inq = udp_socket().unwrap();
        let outq = udp_socket().unwrap();
        inq.set_nonblocking(true).unwrap();
        outq.set_nonblocking(true).unwrap();
        inq.connect(outq.local_addr().unwrap()).unwrap();

        let nmsgs = 16;

        let mut bio = BatchIo::new(2 * nmsgs).unwrap();

        let mut msgs = Vec::new();

        for i in 0..nmsgs {
            msgs.push(format!("This is message {i}"));
        }

        for msg in &msgs {
            let _ = inq.send(msg.as_bytes()).unwrap();
        }

        let mut bufs = vec![Vec::with_capacity(64); 2 * nmsgs];
        let mut results = Vec::new();

        let n = bio.try_recv_buf_from_batch(&outq, bufs.iter_mut(), &mut results);
        assert!(n.unwrap() >= nmsgs);

        let sender = inq.local_addr().unwrap();

        for i in 0..nmsgs {
            let res = results[i].as_ref().unwrap();
            assert_eq!(res.0, msgs[i].len());
            assert_eq!(res.1, Some(sender));
            assert_eq!(bufs[i].as_slice(), msgs[i].as_bytes());
        }
    }

    fn udp_socket() -> Result<UdpSocket> {
        UdpSocket::bind(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))
    }
}
