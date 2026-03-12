#![no_main]
use cbpf_rs::*;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|fuzz_in: FuzzIn| {
    match BpfProgram::validate(&fuzz_in.insn) {
        Ok(prog) => {
            // println!("good");
            prog.filter(&fuzz_in.pkt);
        }
        _ => (), //println!("err"),
    };
});
