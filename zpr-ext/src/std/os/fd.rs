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
