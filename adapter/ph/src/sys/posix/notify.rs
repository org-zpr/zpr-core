//! Notification of events via a file descriptor.
//!
//! Useful to signal events to a thread which is using `poll(2)`.

use nix::{errno, fcntl, ioctl_read_bad, libc, poll, unistd};
use std::io::Result;
use std::mem::MaybeUninit;
use std::os::fd::*;

ioctl_read_bad!(ioctl_fionread, libc::FIONREAD, libc::c_int);

/// A synchronization object used to post notifications.
///
/// A `Notify` object either has an notification, or does not.
/// Posting a notification causes the `Notify` to have a notification.
/// Consuming the notification causes the `Notify` to have no notification.
///
/// The primary benefit of a `Notify` (over e.g. an `AtomicBool`) is that
/// the presence of notifications can be monitored via a file descriptor.
pub struct Notify {
    reader: OwnedFd,
    writer: OwnedFd,
}

fn map_nix_err(errno: errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno as i32)
}

fn set_nonblocking(fd: impl AsFd) -> Result<()> {
    let _ = fcntl::fcntl(
        fd.as_fd().as_raw_fd(),
        fcntl::FcntlArg::F_SETFL(fcntl::OFlag::O_NONBLOCK),
    )
    .map_err(map_nix_err)?;
    Ok(())
}

fn fionread(fd: impl AsFd) -> Result<usize> {
    let mut n = MaybeUninit::uninit();
    // SAFETY: we've declared `ioctl_fionread` correctly.  The pointer is an output parameter.
    unsafe { ioctl_fionread(fd.as_fd().as_raw_fd(), n.as_mut_ptr()) }.map_err(map_nix_err)?;
    // SAFETY: a successful return above indicates that `n` is now filled in.
    Ok(unsafe { n.assume_init() } as usize)
}

impl Notify {
    pub fn new() -> Result<Self> {
        let (reader, writer) = unistd::pipe().map_err(map_nix_err)?;

        set_nonblocking(&reader)?;
        set_nonblocking(&writer)?;

        Ok(Self { reader, writer })
    }

    /// Returns a reference to an FD which can be used to poll for events (using POLLIN).
    ///
    /// If an event is reported, `consume()` must be used to check for and consume
    /// notifications.  (Else the notifications will stay put and re-trigger the poll event.)
    pub fn poll_fd(&self) -> BorrowedFd<'_> {
        self.reader.as_fd()
    }

    /// Post a notification.
    ///
    /// This is a memory synchronization operation.
    pub fn post(&self) {
        let buf = [0u8; 1];

        match unistd::write(&self.writer, &buf) {
            Ok(_) => (),
            // this is fine; means there's already a notification!
            Err(errno::Errno::EAGAIN) => (),
            Err(err) => panic!("Unexpected error: {err}"),
        }
    }

    /// Consume any outstanding notification.
    ///
    /// This is a memory synchronization operation.
    ///
    /// Returns `true` if there was a notification, `false` otherwise.
    pub fn consume(&self) -> bool {
        let mut buf = [0u8; 4096];

        match unistd::read(self.reader.as_raw_fd(), &mut buf) {
            Ok(0) => panic!("Unexpected end of file"),
            Ok(n) if n < buf.len() => return true,
            Ok(_) => (),
            Err(errno::Errno::EAGAIN) => return false,
            Err(err) => panic!("Unexpected error: {err}"),
        }

        // At this point, we know we've read a full buffer's worth
        // of notifications, but there might be more.
        // We want to both (a) ensure we've read all notifications posted
        // prior to this function being called, but also (b) ensure
        // that we terminate, in the event that someone is concurrently
        // posting notifications faster than we can retrieve them.
        // So, use `ioctl(FIONREAD)` to see how many are still outstanding,
        // and read at least that many, then return.  It's possible also
        // we find fewer notifications because someone else raced us;
        // that's OK.

        let mut remaining = fionread(&self.reader).unwrap() as isize;

        while remaining > 0 {
            match unistd::read(self.reader.as_raw_fd(), &mut buf) {
                Ok(0) => panic!("Unexpected end of file"),
                Ok(n) if n < buf.len() => break,
                Ok(n) => remaining -= n as isize,
                Err(errno::Errno::EAGAIN) => break,
                Err(err) => panic!("Unexpected error: {err}"),
            }
        }

        true
    }

    /// Wait for a notification to be present, and consume it.
    #[allow(dead_code)]
    pub fn wait_and_consume(&self) {
        let mut pollfd = poll::PollFd::new(self.poll_fd(), poll::PollFlags::POLLIN);

        loop {
            match poll::poll(std::slice::from_mut(&mut pollfd), poll::PollTimeout::NONE) {
                Ok(_) => {
                    if pollfd.any().unwrap() && self.consume() {
                        break;
                    }
                }

                Err(errno::Errno::EINTR) => (),

                Err(err) => panic!("Unexpected error: {err}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::poll;
    use std::sync::Arc;

    #[test]
    fn basic_test() {
        let notify = Notify::new().unwrap();

        assert!(!notify.consume());

        notify.post();
        assert!(notify.consume());
        assert!(!notify.consume());

        notify.post();
        assert!(notify.consume());
        assert!(!notify.consume());

        notify.post();
        notify.post();
        assert!(notify.consume());
        assert!(!notify.consume());
        assert!(!notify.consume());
    }

    #[test]
    fn poll_test() {
        let notify1 = Arc::new(Notify::new().unwrap());
        let notify2 = Arc::new(Notify::new().unwrap());

        let th_notify1 = notify1.clone();
        let th_notify2 = notify2.clone();

        let th = std::thread::spawn(move || {
            th_notify1.wait_and_consume();
            th_notify2.post();
        });

        notify1.post();

        let mut pollfd2 = poll::PollFd::new(notify2.poll_fd(), poll::PollFlags::POLLIN);
        assert_eq!(
            poll::poll(std::slice::from_mut(&mut pollfd2), 5000u16).unwrap(),
            1
        );

        assert!(pollfd2.any().unwrap());
        assert!(notify2.consume());
        assert!(!notify2.consume());

        assert_eq!(
            poll::poll(std::slice::from_mut(&mut pollfd2), 0u16).unwrap(),
            0
        );

        th.join().unwrap();
    }

    #[test]
    fn multi_read_test() {
        let notify = Notify::new().unwrap();

        // 10000 is greater than twice the implementation's read buffer size
        // (forces 2 extra reads)
        for _ in 0..10000 {
            notify.post();
        }

        assert!(notify.consume());
        assert!(!notify.consume());
    }
}
