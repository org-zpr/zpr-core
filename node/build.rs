use std::process::Command;

fn main() {
    check_md5_sum("../../node/src/vsapi/vs.thrift.sum");
}

fn check_md5_sum(fname: &str) {
    // Check that the thrift source files have not changed.
    let output = Command::new("md5sum")
        .args(&["--status", "-c", fname])
        .current_dir("../visaservice/thrift")
        .output()
        .expect("failed to execute md5sum");
    // Was using .status.unwrap but that did not grab the output status properly.
    if !output.status.success() {
        println!("cargo:warning=MD5 sum for thrift source files have changed");
        panic!("*** try rebuilding thrift files ***");
    }
}
