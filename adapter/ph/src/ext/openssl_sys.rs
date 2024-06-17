use libc::*;
use openssl_sys::*;

extern "C" {
    pub fn DTLS_get_data_mtu(ssl: *const SSL) -> size_t;
}
