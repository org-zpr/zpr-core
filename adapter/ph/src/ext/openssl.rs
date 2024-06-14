pub mod ssl {
    use foreign_types::ForeignTypeRef;
    use openssl::error::ErrorStack;
    use openssl::ssl::SslRef;
    use crate::ext::openssl_sys as ffi;

    pub trait SslExt {
        fn get_data_mtu(&self) -> Result<usize, ErrorStack>;
    }

    impl SslExt for SslRef {
        // wrapper for DTLS_get_data_mtu - Get maximum data payload size
        fn get_data_mtu(&self) -> Result<usize, ErrorStack> {
            let ret = unsafe { ffi::DTLS_get_data_mtu(self.as_ptr()) };
            if ret == 0 {
                Err(ErrorStack::get())
            } else {
                Ok(ret)
            }
        }
    }
}
