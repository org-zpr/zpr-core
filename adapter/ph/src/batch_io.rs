//! Batch I/O operations.
//!
//! These vary both by operating system and feature set.
//!
//! All these operations assume a file descriptor which has been set
//! non-blocking, and they perform non-blocking I/O operations.

use crate::net_defs::{ScopedIpAddr, ScopedIpv6Addr};
use bytes::BufMut;
use libc;
use nix::sys::socket::{self, AddressFamily, SockaddrLike, SockaddrStorage};
use std::io::Result;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

pub struct ReceivedPacket {
    #[allow(dead_code)]
    pub size: usize,
    pub truncated: bool,
    pub source: Option<SocketAddr>,
    pub destination: Option<ScopedIpAddr>,
}

fn sockaddr_to_socket_addr(sa: SockaddrStorage) -> Option<SocketAddr> {
    match sa.family()? {
        AddressFamily::Inet => Some(SocketAddr::V4((*sa.as_sockaddr_in().unwrap()).into())),
        AddressFamily::Inet6 => Some(SocketAddr::V6((*sa.as_sockaddr_in6().unwrap()).into())),
        _ => None,
    }
}

fn errno_to_error(errno: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno as i32)
}

fn pktinfo_from_ipv4addr(addr: &Ipv4Addr) -> libc::in_pktinfo {
    libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr {
            s_addr: addr.to_bits().to_be(),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
    }
}

fn pktinfo_from_scoped_ipv6addr(addr: &ScopedIpv6Addr) -> libc::in6_pktinfo {
    libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: addr.ip().octets(),
        },
        ipi6_ifindex: addr.scope_id(),
    }
}

/// Enable the reception of packet info on a socket.  Required for
/// `try_recv_buf_from_to_batch()` to return the destination address.
pub fn set_recv_packet_info(fd: &impl AsFd, enable: bool) -> std::io::Result<()> {
    match socket::getsockname::<SockaddrStorage>(fd.as_fd().as_raw_fd())?.family() {
        Some(AddressFamily::Inet) => {
            socket::setsockopt(fd, socket::sockopt::Ipv4PacketInfo, &enable).map_err(errno_to_error)
        }
        Some(AddressFamily::Inet6) => {
            socket::setsockopt(fd, socket::sockopt::Ipv6RecvPacketInfo, &enable)
                .map_err(errno_to_error)
        }
        _ => Ok(()),
    }
}

trait BatchIoImpl {
    fn engine_name(&self) -> &'static str;

    fn try_write_batch<'a>(
        &mut self,
        fd: BorrowedFd<'_>,
        bufs: &mut dyn Iterator<Item = &'a [u8]>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_read_buf_batch<'a>(
        &mut self,
        fd: BorrowedFd<'_>,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_send_to_batch<'a>(
        &mut self,
        fd: BorrowedFd<'_>,
        bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_send_to_from_batch<'a>(
        &mut self,
        fd: BorrowedFd<'_>,
        bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_recv_buf_from_batch<'a>(
        &mut self,
        fd: BorrowedFd<'_>,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>;

    fn try_recv_buf_from_to_batch<'a>(
        &mut self,
        fd: BorrowedFd<'_>,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>;
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod io_uring {
    //! io_uring(7)-based implementation.  Only available for Linux.

    use super::{sockaddr_to_socket_addr, BatchIoImpl, ReceivedPacket};
    use crate::net_defs::{ScopedIpAddr, ScopedIpv6Addr};
    use bytes::BufMut;
    use io_uring::{cqueue, opcode, squeue, types, IoUring, Probe};
    use libc;
    use nix::sys::socket::{SockaddrLike, SockaddrStorage};
    use std::io::Result;
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::ptr::NonNull;

    const MAX_ENTRIES: usize = 1024;

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

    // std::cmp::max() is not const
    const fn const_u32_max(x: u32, y: u32) -> u32 {
        if x > y {
            x
        } else {
            y
        }
    }

    const PKTINFO_CMSG_SPACE_NEEDED: usize = const_u32_max(
        // SAFETY: these const functions are erroneously marked unsafe
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) },
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) },
    ) as usize;

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

    struct TryReadBufBatchOp<'a> {
        phantom: std::marker::PhantomData<&'a mut dyn BufMut>,
    }

    impl<'a> BatchOp<&'a mut dyn BufMut, &'a mut dyn BufMut, usize> for TryReadBufBatchOp<'a> {
        fn new() -> Self {
            Self {
                phantom: std::marker::PhantomData,
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            buf: &'a mut dyn BufMut,
            _idx: usize,
        ) -> (squeue::Entry, &'a mut dyn BufMut) {
            let chunk = buf.chunk_mut();
            (
                opcode::Read::new(fd, chunk.as_mut_ptr(), chunk.len() as u32).build(),
                buf,
            )
        }

        fn process_result(&self, _idx: usize, buf: &'a mut dyn BufMut, amt: usize) -> usize {
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

    struct TrySendToFromBatchOp {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: Slab<SockaddrStorage>,
        cmsg_slab: Slab<[u8; PKTINFO_CMSG_SPACE_NEEDED]>,
        msghdr_slab: Slab<libc::msghdr>,
    }

    impl BatchOp<(&[u8], SocketAddr, Option<ScopedIpAddr>), (), usize> for TrySendToFromBatchOp {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: Slab::new(),
                cmsg_slab: Slab::new(),
                msghdr_slab: Slab::new(),
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            (buf, dst_addr, src_addr): (&[u8], SocketAddr, Option<ScopedIpAddr>),
            _idx: usize,
        ) -> (squeue::Entry, ()) {
            let iovec_ref = self.iovec_slab.push(slice_as_iovec(buf));
            let sockaddr_ref = self.sockaddr_slab.push(SockaddrStorage::from(dst_addr));

            let cmsg_ref = self.cmsg_slab.push([0u8; PKTINFO_CMSG_SPACE_NEEDED]);

            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref as *mut _ as *mut libc::c_void,
                msg_namelen: sockaddr_ref.len(),
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: cmsg_ref as *mut _ as *mut libc::c_void,
                msg_controllen: std::mem::size_of_val(cmsg_ref),
                msg_flags: 0,
            });

            match src_addr {
                None => {
                    msghdr_ref.msg_controllen = 0;
                }

                Some(src_addr) => {
                    // SAFETY: we have enough space in cmsg_ref for a cmsg header
                    let cmsg_ptr =
                        unsafe { NonNull::new(libc::CMSG_FIRSTHDR(msghdr_ref)).unwrap_unchecked() };
                    // SAFETY: we have enough space in cmsg_ref for our cmsg
                    let cmsg_len = unsafe { scoped_ip_addr_to_cmsg(cmsg_ptr, src_addr) };
                    msghdr_ref.msg_controllen = cmsg_len;
                }
            }

            (opcode::SendMsg::new(fd, msghdr_ref as *const _).build(), ())
        }

        fn process_result(&self, _idx: usize, (): (), amt: usize) -> usize {
            amt
        }
    }

    struct TryRecvBufFromBatchOp<'a> {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: [MaybeUninit<SockaddrStorage>; MAX_ENTRIES],
        msghdr_slab: Slab<libc::msghdr>,
        phantom: std::marker::PhantomData<&'a mut dyn BufMut>,
    }

    impl<'a> BatchOp<&'a mut dyn BufMut, &'a mut dyn BufMut, ReceivedPacket>
        for TryRecvBufFromBatchOp<'a>
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
            buf: &'a mut dyn BufMut,
            idx: usize,
        ) -> (squeue::Entry, &'a mut dyn BufMut) {
            let iovec_ref = self.iovec_slab.push(buf_mut_as_iovec(buf));
            let sockaddr_ref = &mut self.sockaddr_slab[idx];
            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref.as_mut_ptr() as *mut libc::c_void,
                msg_namelen: std::mem::size_of_val(sockaddr_ref) as u32,
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            });

            (opcode::RecvMsg::new(fd, msghdr_ref as *mut _).build(), buf)
        }

        fn process_result(
            &self,
            idx: usize,
            buf: &'a mut dyn BufMut,
            size: usize,
        ) -> ReceivedPacket {
            // SAFETY: We know we've written the given number of bytes in the BufMut.
            unsafe {
                buf.advance_mut(size);
            }
            let truncated = (self.msghdr_slab.get(idx).msg_flags & libc::MSG_TRUNC) != 0;
            // SAFETY: We know the sockaddr is now filled.
            let source = sockaddr_to_socket_addr(unsafe { self.sockaddr_slab[idx].assume_init() });
            ReceivedPacket {
                size,
                truncated,
                source,
                destination: None,
            }
        }
    }

    struct TryRecvBufFromToBatchOp<'a> {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: [MaybeUninit<SockaddrStorage>; MAX_ENTRIES],
        cmsg_slab: [[u8; PKTINFO_CMSG_SPACE_NEEDED]; MAX_ENTRIES],
        msghdr_slab: Slab<libc::msghdr>,
        phantom: std::marker::PhantomData<&'a mut dyn BufMut>,
    }

    impl<'a> BatchOp<&'a mut dyn BufMut, &'a mut dyn BufMut, ReceivedPacket>
        for TryRecvBufFromToBatchOp<'a>
    {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: [MaybeUninit::uninit(); MAX_ENTRIES],
                cmsg_slab: [[0u8; PKTINFO_CMSG_SPACE_NEEDED]; MAX_ENTRIES],
                msghdr_slab: Slab::new(),
                phantom: std::marker::PhantomData,
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            buf: &'a mut dyn BufMut,
            idx: usize,
        ) -> (squeue::Entry, &'a mut dyn BufMut) {
            let iovec_ref = self.iovec_slab.push(buf_mut_as_iovec(buf));
            let sockaddr_ref = &mut self.sockaddr_slab[idx];
            let cmsg_ref = &mut self.cmsg_slab[idx];
            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref.as_mut_ptr() as *mut libc::c_void,
                msg_namelen: std::mem::size_of_val(sockaddr_ref) as u32,
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: cmsg_ref.as_mut_ptr() as *mut libc::c_void,
                msg_controllen: std::mem::size_of_val(cmsg_ref),
                msg_flags: 0,
            });

            (opcode::RecvMsg::new(fd, msghdr_ref as *mut _).build(), buf)
        }

        fn process_result(
            &self,
            idx: usize,
            buf: &'a mut dyn BufMut,
            size: usize,
        ) -> ReceivedPacket {
            // SAFETY: We know we've written the given number of bytes in the BufMut.
            unsafe {
                buf.advance_mut(size);
            }
            let truncated = (self.msghdr_slab.get(idx).msg_flags & libc::MSG_TRUNC) != 0;
            // SAFETY: We know the sockaddr is now filled.
            let source = sockaddr_to_socket_addr(unsafe { self.sockaddr_slab[idx].assume_init() });
            // SAFETY: We know the cmsgs are valid.
            let destination = unsafe { cmsg_iter(self.msghdr_slab.get(idx)) }
                .find_map(|cmsg| unsafe { cmsg_to_scoped_ip_addr(cmsg.as_ptr()) });
            ReceivedPacket {
                size,
                truncated,
                source,
                destination,
            }
        }
    }

    pub struct BatchIo {
        io_uring: IoUring<squeue::Entry, cqueue::Entry>,
    }

    // NOTE: Limit io_uring features used to those available in 5.10 or later.
    // (= oldest LTS release with EOL > end of 2025)

    impl BatchIo {
        pub const ENGINE_NAME: &'static str = "io_uring";

        pub const MAX_ENTRIES: usize = MAX_ENTRIES;

        const REQUIRED_OPCODES: &[u8] = &[
            opcode::AsyncCancel::CODE,
            opcode::Write::CODE,
            opcode::Read::CODE,
            opcode::SendMsg::CODE,
            opcode::RecvMsg::CODE,
        ];

        pub fn detect_support() -> bool {
            let Ok(io_uring) = IoUring::new(1) else {
                return false;
            };

            let mut probe = Probe::new();
            if io_uring.submitter().register_probe(&mut probe).is_err() {
                return false;
            }

            Self::REQUIRED_OPCODES
                .iter()
                .all(|&op| probe.is_supported(op))
        }

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
            fd: BorrowedFd<'_>,
            items: &mut dyn Iterator<Item = Item>,
            results: &mut Vec<Result<Res>>,
        ) -> Result<usize> {
            let fd = types::Fd(fd.as_raw_fd());

            let mut submitted = 0;

            let mut squeue = self.io_uring.submission();

            // Each operation consumes two entries (one for the operation, one for the cancel request).
            let max_to_submit = (squeue.capacity() - squeue.len()) / 2;

            let mut state_slab = Slab::new();

            // Enter the operations into the submission queue.
            while let Some(item) = items.next() {
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
    }

    impl BatchIoImpl for BatchIo {
        fn engine_name(&self) -> &'static str {
            Self::ENGINE_NAME
        }

        fn try_write_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = &'a [u8]>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(TryWriteBatchOp::new(), fd, bufs, results)
        }

        fn try_read_buf_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(TryReadBufBatchOp::new(), fd, bufs, results)
        }

        fn try_send_to_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(TrySendToBatchOp::new(), fd, bufs, results)
        }

        fn try_send_to_from_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(TrySendToFromBatchOp::new(), fd, bufs, results)
        }

        fn try_recv_buf_from_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            self.do_batch_op(TryRecvBufFromBatchOp::new(), fd, bufs, results)
        }

        fn try_recv_buf_from_to_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            self.do_batch_op(TryRecvBufFromToBatchOp::new(), fd, bufs, results)
        }
    }

    fn slice_as_iovec(buf: &[u8]) -> libc::iovec {
        libc::iovec {
            iov_base: buf.as_ptr() as *mut u8 as *mut _,
            iov_len: buf.len(),
        }
    }

    fn buf_mut_as_iovec(buf: &mut dyn BufMut) -> libc::iovec {
        let chunk = buf.chunk_mut();
        libc::iovec {
            iov_base: chunk.as_mut_ptr() as *mut _,
            iov_len: chunk.len(),
        }
    }

    /// SAFETY: `msg` be initialized, and its cmsgs must outlive the returned iterator
    unsafe fn cmsg_iter(msg: &libc::msghdr) -> CmsgIterator<'_> {
        CmsgIterator(msg, std::ptr::null())
    }

    struct CmsgIterator<'a>(&'a libc::msghdr, *const libc::cmsghdr);

    impl Iterator for CmsgIterator<'_> {
        type Item = NonNull<libc::cmsghdr>;

        fn next(&mut self) -> Option<Self::Item> {
            let next;
            if self.1.is_null() {
                // SAFETY: we were constructed with a valid `msghdr`
                next = unsafe { libc::CMSG_FIRSTHDR(self.0) };
            } else {
                // SAFETY: we were constructed with a valid `msghdr`, and the `cmsghdr` is nonnull and came from a previous call
                next = unsafe { libc::CMSG_NXTHDR(self.0, self.1) };
            }

            self.1 = next;

            NonNull::new(next)
        }
    }

    /// SAFETY: `cmsg` has enough space for an `in_pktinfo` or `in6_pktinfo` message
    unsafe fn scoped_ip_addr_to_cmsg(cmsg: NonNull<libc::cmsghdr>, addr: ScopedIpAddr) -> usize {
        let in_pktinfo;
        let in6_pktinfo;
        let pktinfo_ptr;
        let pktinfo_len;

        match &addr {
            ScopedIpAddr::V4(addr) => {
                in_pktinfo = super::pktinfo_from_ipv4addr(addr);
                pktinfo_ptr = &in_pktinfo as *const _ as *const u8;
                pktinfo_len = std::mem::size_of_val(&in_pktinfo);
            }

            ScopedIpAddr::V6(addr) => {
                in6_pktinfo = super::pktinfo_from_scoped_ipv6addr(addr);
                pktinfo_ptr = &in6_pktinfo as *const _ as *const u8;
                pktinfo_len = std::mem::size_of_val(&in6_pktinfo);
            }
        }

        // SAFETY: we were called with a valid `cmsg` with enough space
        unsafe {
            cmsg.write(libc::cmsghdr {
                cmsg_len: libc::CMSG_LEN(pktinfo_len as u32) as usize,
                cmsg_level: libc::IPPROTO_IP,
                cmsg_type: libc::IP_PKTINFO,
            });
            libc::CMSG_DATA(cmsg.as_ptr()).copy_from(pktinfo_ptr, pktinfo_len); // note unaligned (*u8) copy!
            return libc::CMSG_SPACE(pktinfo_len as u32) as usize;
        }
    }

    /// SAFETY: `cmsg` must point to a valid `cmsghdr`
    unsafe fn cmsg_to_scoped_ip_addr(cmsg: *const libc::cmsghdr) -> Option<ScopedIpAddr> {
        // SAFETY: `cmsg` points to a valid cmsg
        let cmsg_ref = unsafe { cmsg.as_ref()? };
        match (cmsg_ref.cmsg_level, cmsg_ref.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                // SAFETY: we know the pointed-to cmsg is valid and of the correct type
                let info = unsafe {
                    (libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo)
                        .as_ref()
                        .unwrap_unchecked()
                };
                Some(ScopedIpAddr::V4(Ipv4Addr::from(u32::from_be(
                    info.ipi_addr.s_addr,
                ))))
            }

            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                // SAFETY: we know the pointed-to cmsg is valid and of the correct type
                let info = unsafe {
                    (libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo)
                        .as_ref()
                        .unwrap_unchecked()
                };
                Some(ScopedIpAddr::V6(ScopedIpv6Addr::new(
                    Ipv6Addr::from(info.ipi6_addr.s6_addr),
                    info.ipi6_ifindex,
                )))
            }

            _ => None,
        }
    }
}

mod posix_unbatched {
    //! Unbatched implementation using POSIX primitives.

    use super::*;
    use crate::net_defs::{ScopedIpAddr, ScopedIpv6Addr};
    use bytes::BufMut;
    use nix::cmsg_space;
    use nix::sys::socket::{
        self, sockaddr_storage, ControlMessageOwned, MsgFlags, SockaddrStorage,
    };
    use nix::unistd;
    use std::io::{IoSlice, IoSliceMut, Result};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::{AsRawFd, BorrowedFd};
    use zpr_ext::std::mem::slice_assume_init_mut;

    pub struct BatchIo {
        cmsg_buffer: Vec<u8>,
    }

    macro_rules! scoped_ip_addr_to_cmsg (
        ($cmsg_id:ident : $addr:expr) => {
            let in_pktinfo;
            let in6_pktinfo;
            let $cmsg_id;
            match $addr {
                $crate::net_defs::ScopedIpAddr::V4(addr) => {
                    in_pktinfo = super::pktinfo_from_ipv4addr(addr);
                    $cmsg_id = nix::sys::socket::ControlMessage::Ipv4PacketInfo(&in_pktinfo);
                },

                $crate::net_defs::ScopedIpAddr::V6(addr) => {
                    in6_pktinfo = super::pktinfo_from_scoped_ipv6addr(addr);
                    $cmsg_id = nix::sys::socket::ControlMessage::Ipv6PacketInfo(&in6_pktinfo);
                },
            }
        }
    );

    impl BatchIo {
        pub const ENGINE_NAME: &'static str = "posix_unbatched";

        pub const MAX_ENTRIES: usize = 1024;

        pub fn detect_support() -> bool {
            // theoretically always available
            true
        }

        pub fn new(_entries: usize) -> Result<Self> {
            Ok(Self {
                cmsg_buffer: cmsg_space!(sockaddr_storage),
            })
        }

        fn do_batch_op<'a, Item, Res>(
            mut op: impl FnMut(BorrowedFd<'a>, Item) -> Result<Res>,
            fd: BorrowedFd<'a>,
            items: &mut dyn Iterator<Item = Item>,
            results: &'a mut Vec<Result<Res>>,
        ) -> Result<usize> {
            let mut completed = 0;
            while let Some(item) = items.next() {
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
    }

    impl BatchIoImpl for BatchIo {
        fn engine_name(&self) -> &'static str {
            Self::ENGINE_NAME
        }

        fn try_write_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = &'a [u8]>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| unistd::write(fd, buf).map_err(errno_to_error),
                fd,
                bufs,
                results,
            )
        }

        fn try_read_buf_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
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

        fn try_send_to_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
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

        fn try_send_to_from_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, (buf, dst, src)| match src {
                    Some(src) => {
                        scoped_ip_addr_to_cmsg!(cmsg: &src);
                        socket::sendmsg(
                            fd.as_raw_fd(),
                            &[IoSlice::new(buf)],
                            &[cmsg],
                            MsgFlags::empty(),
                            Some(&SockaddrStorage::from(dst)),
                        )
                        .map_err(errno_to_error)
                    }

                    None => socket::sendto(
                        fd.as_raw_fd(),
                        buf,
                        &SockaddrStorage::from(dst),
                        MsgFlags::empty(),
                    )
                    .map_err(errno_to_error),
                },
                fd,
                bufs,
                results,
            )
        }

        fn try_recv_buf_from_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| {
                    // SAFETY: We will only be writing to the chunk.
                    let chunk =
                        unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                    let mut io_slice = IoSliceMut::new(chunk);
                    // NOTE: nix's `recvfrom` weirdly is missing the `flags` argument,
                    // so we're forced to use `recvmsg` here
                    let recvmsg = socket::recvmsg(
                        fd.as_raw_fd(),
                        std::slice::from_mut(&mut io_slice),
                        None,
                        MsgFlags::empty(),
                    )
                    .map_err(errno_to_error)?;
                    let size = recvmsg.bytes;
                    let truncated = recvmsg.flags.contains(socket::MsgFlags::MSG_TRUNC);
                    let source = recvmsg.address.and_then(sockaddr_to_socket_addr);
                    // SAFETY: We know we've written the given number of bytes in the BufMut.
                    unsafe { buf.advance_mut(size) };
                    Ok(ReceivedPacket {
                        size,
                        truncated,
                        source,
                        destination: None,
                    })
                },
                fd,
                bufs,
                results,
            )
        }

        fn try_recv_buf_from_to_batch<'a>(
            &mut self,
            fd: BorrowedFd<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| {
                    // SAFETY: We will only be writing to the chunk.
                    let chunk =
                        unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                    let mut io_slice = IoSliceMut::new(chunk);
                    let recvmsg = socket::recvmsg(
                        fd.as_raw_fd(),
                        std::slice::from_mut(&mut io_slice),
                        Some(&mut self.cmsg_buffer),
                        MsgFlags::empty(),
                    )
                    .map_err(errno_to_error)?;
                    let size = recvmsg.bytes;
                    let truncated = recvmsg.flags.contains(socket::MsgFlags::MSG_TRUNC);
                    let source = recvmsg.address.and_then(sockaddr_to_socket_addr);
                    let destination = recvmsg
                        .cmsgs()
                        .expect("cmsgs sizing error")
                        .find_map(cmsg_to_scoped_ip_addr);
                    // SAFETY: We know we've written the given number of bytes in the BufMut.
                    unsafe { buf.advance_mut(size) };
                    Ok(ReceivedPacket {
                        size,
                        truncated,
                        source,
                        destination,
                    })
                },
                fd,
                bufs,
                results,
            )
        }
    }

    fn cmsg_to_scoped_ip_addr(cmsg: ControlMessageOwned) -> Option<ScopedIpAddr> {
        match cmsg {
            ControlMessageOwned::Ipv4PacketInfo(info) => Some(ScopedIpAddr::V4(Ipv4Addr::from(
                u32::from_be(info.ipi_addr.s_addr),
            ))),

            ControlMessageOwned::Ipv6PacketInfo(info) => Some(ScopedIpAddr::V6(
                ScopedIpv6Addr::new(Ipv6Addr::from(info.ipi6_addr.s6_addr), info.ipi6_ifindex),
            )),

            _ => None,
        }
    }
}

macro_rules! bio {
    ($m:tt) => {
        BatchIoEngine {
            engine_name: $m::BatchIo::ENGINE_NAME,
            max_entries: $m::BatchIo::MAX_ENTRIES,
            factory: |e| $m::BatchIo::new(e).map(|bio| Box::new(bio) as Box<dyn BatchIoImpl>),
            detect_support: $m::BatchIo::detect_support,
        }
    };
}

const ENGINES: &[BatchIoEngine] = &[
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    bio!(io_uring),
    bio!(posix_unbatched),
];

/// List of available engine names.  Does not include automatic selection.
pub fn engine_names() -> impl Iterator<Item = &'static str> {
    ENGINES.iter().map(|e| e.engine_name)
}

/// "Engine" name which indicates an engine should be selected automatically
/// (as by `auto_select_engine()`).
pub const AUTO_ENGINE_NAME: &'static str = "auto";

/// Select an engine by name (as listed by `engine_names()`).
/// Supplying `AUTO_ENGINE_NAME` will use automatic selection
/// (as by `auto_select_engine()`).
pub fn select_engine_by_name(name: &str) -> Option<&'static BatchIoEngine> {
    if name == AUTO_ENGINE_NAME {
        Some(auto_select_engine())
    } else {
        ENGINES.iter().find(|e| e.engine_name == name)
    }
}

/// Select the best engine which is available on the current system.
pub fn auto_select_engine() -> &'static BatchIoEngine {
    ENGINES
        .iter()
        .find(|e| e.detect_support())
        .expect("no supported I/O engines!")
}

/// Represents an available batch I/O engine which may be instantiated.
pub struct BatchIoEngine {
    engine_name: &'static str,
    max_entries: usize,
    factory: fn(usize) -> Result<Box<dyn BatchIoImpl>>,
    detect_support: fn() -> bool,
}

impl BatchIoEngine {
    /// The name of this I/O engine.
    pub fn engine_name(&self) -> &'static str {
        self.engine_name
    }

    /// The maximum number of entries per batch this I/O engine supports.
    #[allow(dead_code)]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Instantiate this batch I/O engine,
    /// supporting the supplied number of entries per batch.
    pub fn instantiate(&self, entries: usize) -> Result<BatchIo> {
        Ok(BatchIo((self.factory)(entries)?))
    }

    /// Detect whether this engine is supported by the host environment.
    pub fn detect_support(&self) -> bool {
        (self.detect_support)()
    }
}

pub struct BatchIo(Box<dyn BatchIoImpl>);

impl BatchIo {
    #[allow(dead_code)]
    pub fn engine_name(&self) -> &'static str {
        self.0.engine_name()
    }

    pub fn try_write_batch<'a>(
        &mut self,
        fd: impl AsFd,
        bufs: impl IntoIterator<Item = &'a [u8]>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        self.0
            .try_write_batch(fd.as_fd(), &mut bufs.into_iter(), results)
    }

    pub fn try_read_buf_batch<'a, B>(
        &mut self,
        fd: impl AsFd,
        bufs: impl IntoIterator<Item = &'a mut B>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>
    where
        B: BufMut + 'a,
    {
        self.0.try_read_buf_batch(
            fd.as_fd(),
            &mut bufs.into_iter().map(|b| b as &mut dyn BufMut),
            results,
        )
    }

    #[allow(dead_code)]
    pub fn try_send_to_batch<'a>(
        &mut self,
        fd: impl AsFd,
        bufs: impl IntoIterator<Item = (&'a [u8], SocketAddr)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        self.0
            .try_send_to_batch(fd.as_fd(), &mut bufs.into_iter(), results)
    }

    pub fn try_send_to_from_batch<'a>(
        &mut self,
        fd: impl AsFd,
        bufs: impl IntoIterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        self.0
            .try_send_to_from_batch(fd.as_fd(), &mut bufs.into_iter(), results)
    }

    #[allow(dead_code)]
    pub fn try_recv_buf_from_batch<'a, B>(
        &mut self,
        fd: impl AsFd,
        bufs: impl IntoIterator<Item = &'a mut B>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>
    where
        B: BufMut + 'a,
    {
        self.0.try_recv_buf_from_batch(
            fd.as_fd(),
            &mut bufs.into_iter().map(|b| b as &mut dyn BufMut),
            results,
        )
    }

    pub fn try_recv_buf_from_to_batch<'a, B>(
        &mut self,
        fd: impl AsFd,
        bufs: impl IntoIterator<Item = &'a mut B>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>
    where
        B: BufMut + 'a,
    {
        self.0.try_recv_buf_from_to_batch(
            fd.as_fd(),
            &mut bufs.into_iter().map(|b| b as &mut dyn BufMut),
            results,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use std::io::Result;
    use std::net::UdpSocket;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    #[test]
    fn test_write() {
        for engine in ENGINES {
            // FIXME: we need to test EAGAIN behavior... possibly by first filling queue, then draining a few

            let (inq, outq) = UnixDatagram::pair().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

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
    }

    #[test]
    fn test_read() {
        for engine in ENGINES {
            let (inq, outq) = UnixDatagram::pair().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

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
    }

    #[test]
    fn test_send() {
        for engine in ENGINES {
            // FIXME: we need to test EAGAIN behavior... possibly by first filling queue, then draining a few

            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

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
    }

    #[test]
    fn test_recv() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

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
                assert_eq!(res.size, msgs[i].len());
                assert!(!res.truncated);
                assert_eq!(res.source, Some(sender));
                assert_eq!(bufs[i].as_slice(), msgs[i].as_bytes());
            }
        }
    }

    #[test]
    fn test_oversize_recv() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let mut bio = engine.instantiate(1).unwrap();

            let msg = [123u8; 128];

            let _ = inq.send(&[123u8; 128]).unwrap();

            let limit = 64;
            let mut buf = Vec::with_capacity(64).limit(limit);
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_batch(&outq, std::iter::once(&mut buf), &mut results);
            assert!(n.unwrap() == 1);

            let res = results[0].as_ref().unwrap();
            assert_eq!(res.size, limit);
            assert!(res.truncated);
            assert_eq!(buf.get_ref().len(), limit);
            assert_eq!(buf.get_ref().as_slice(), &msg[..limit]);
        }
    }

    #[test]
    fn test_recv_to() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            set_recv_packet_info(&outq, true).unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let mut bio = engine.instantiate(1).unwrap();

            let msg = "Hello".as_bytes();

            let _ = inq.send(msg).unwrap();

            let mut buf = Vec::with_capacity(64);
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_to_batch(&outq, std::iter::once(&mut buf), &mut results);
            assert!(n.unwrap() == 1);

            let res = results[0].as_ref().unwrap();
            assert_eq!(res.size, msg.len());
            assert!(!res.truncated);
            assert_eq!(res.source, Some(inq.local_addr().unwrap()));
            // NOTE: we don't have any way of testing the scope ID functionality as a unit test
            assert_eq!(
                res.destination.map(|sa| sa.ip()),
                Some(outq.local_addr().unwrap().ip())
            );
            assert_eq!(buf.as_slice(), msg);
        }
    }

    #[test]
    fn test_oversize_recv_to() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let mut bio = engine.instantiate(1).unwrap();

            let msg = [123u8; 128];

            let _ = inq.send(&[123u8; 128]).unwrap();

            let limit = 64;
            let mut buf = Vec::with_capacity(64).limit(limit);
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_to_batch(&outq, std::iter::once(&mut buf), &mut results);
            assert!(n.unwrap() == 1);

            let res = results[0].as_ref().unwrap();
            assert_eq!(res.size, limit);
            assert!(res.truncated);
            assert_eq!(buf.get_ref().len(), limit);
            assert_eq!(buf.get_ref().as_slice(), &msg[..limit]);
        }
    }

    // NOTE: we don't have any way of really testing the "send_from" functionality as a unit test

    fn udp_socket() -> Result<UdpSocket> {
        UdpSocket::bind(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))
    }
}
