capnp::generated_code!(pub mod cli_capnp);

pub use cli_capnp as v1;

pub mod rpc_commands;
pub mod data_home;

pub use data_home::get_data_home;