pub trait SockAddrExt {
    fn new_unspec() -> Self;
}

impl SockAddrExt for socket2::SockAddr {
    fn new_unspec() -> Self {
        // SAFETY: AF_UNSPEC is compatible with any sockaddr struct
        unsafe {
            Self::try_init(|sas, sl| {
                // SAFETY: the caller has provided valid pointers to initialized storage
                (*sas).ss_family = libc::AF_UNSPEC as _;
                *sl = std::mem::size_of::<libc::sockaddr>() as _;
                Ok(())
            })
            .unwrap()
            .1
        }
    }
}
