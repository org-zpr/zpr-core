fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("zpr-vsapi")
        .file("zpr-vsapi/vs.capnp")
        .run()
        .expect("failed to compile capnp schema");
}
