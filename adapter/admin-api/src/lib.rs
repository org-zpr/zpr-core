capnp::generated_code!(pub mod cli_capnp);

pub use cli_capnp as v1;

pub mod data_home;
pub mod rpc_commands;

pub use data_home::get_data_home;
