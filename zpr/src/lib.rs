//! ZPR concepts, excluding the ZDP protocol.

pub mod addrs;
pub mod dn;
pub mod packet_info;
pub mod rpc_commands;
pub mod vsapi_types;
pub mod vsapi_types_writers;

capnp::generated_code!(pub mod cli_capnp);
pub mod admin_api {
    pub use super::cli_capnp as v1;
}

capnp::generated_code!(pub mod policy_capnp);
pub mod policy {
    pub use super::policy_capnp as v1;
}

capnp::generated_code!(pub mod vs_capnp);
pub mod vsapi {
    pub use super::vs_capnp as v1;
}
