#![no_main]
use cbpf_rs::*;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|program: Vec<BpfInsn>| {
    let _ = BpfProgram::validate(&program);
});
