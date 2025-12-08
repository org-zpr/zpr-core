//! ZPR concepts, excluding the ZDP protocol.

pub mod addrs;
pub mod dn;
pub mod packet_info;
pub mod rpc_commands;
#[cfg(feature = "vsapi")]
pub mod vsapi_types;
#[cfg(feature = "vsapi")]
pub mod vsapi_types_writers;

#[cfg(feature = "admin-api")]
capnp::generated_code!(pub mod cli_capnp);
#[cfg(feature = "admin-api")]
pub mod admin_api {
    pub use super::cli_capnp as v1;
}

#[cfg(feature = "policy")]
capnp::generated_code!(pub mod policy_capnp);
#[cfg(feature = "policy")]
pub mod policy {
    pub use super::policy_capnp as v1;
}

#[cfg(feature = "vsapi")]
capnp::generated_code!(pub mod vs_capnp);
#[cfg(feature = "vsapi")]
pub mod vsapi {
    pub use super::vs_capnp as v1;
}
