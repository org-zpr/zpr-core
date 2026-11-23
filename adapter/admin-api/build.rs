#[cfg(all(unix, feature = "capnp-ancillary"))]
use capnpc_patched as capnpc;

fn main() {
    capnpc::CompilerCommand::new()
        .file("cli.capnp")
        .run()
        .expect("failed to compile admin-api capnp schema");
}
