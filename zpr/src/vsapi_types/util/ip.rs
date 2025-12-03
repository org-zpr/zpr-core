use crate::vsapi_types::VsapiTypeError;
use std::net::IpAddr;

/// Create an ip address from a Vector, or return an error if the vector is badly formatted
pub fn ip_addr_from_vec(v: Vec<u8>) -> Result<IpAddr, VsapiTypeError> {
    match v.len() {
        4 => Ok(IpAddr::from(
            <[u8; 4]>::try_from(v.as_slice()).expect("Bad IP length"),
        )),
        16 => Ok(IpAddr::from(
            <[u8; 16]>::try_from(v.as_slice()).expect("Bad IP length"),
        )),
        _ => Err(VsapiTypeError::DeserializationError(
            "Bad IP Address format",
        )),
    }
}
