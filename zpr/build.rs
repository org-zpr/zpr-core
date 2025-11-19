fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("zpr-admin-api")
        .file("zpr-admin-api/cli.capnp")
        .run()
        .expect("failed to compile zpr-admin-api capnp schema");

    capnpc::CompilerCommand::new()
        .src_prefix("zpr-policy")
        .file("zpr-policy/policy.capnp")
        .run()
        .expect("failed to compile zpr-policy capnp schema");

    capnpc::CompilerCommand::new()
        .src_prefix("zpr-vsapi")
        .file("zpr-vsapi/vs.capnp")
        .run()
        .expect("failed to compile zpr-vsapi capnp schema");
}
