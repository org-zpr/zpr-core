use std::borrow::Borrow;
use std::hint::unreachable_unchecked;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[allow(dead_code)]
fn code_class(code: u16) -> u16 {
    code & 0x07
}
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ST: u16 = 0x02;
const STX: u16 = 0x03;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const MISC: u16 = 0x07;

#[allow(dead_code)]
fn code_size(code: u16) -> u16 {
    code & 0x18
}
const W: u16 = 0x00;
const H: u16 = 0x08;
const B: u16 = 0x10;

#[allow(dead_code)]
fn code_mode(code: u16) -> u16 {
    code & 0xe0
}
const IMM: u16 = 0x00;
const ABS: u16 = 0x20;
const IND: u16 = 0x40;
const MEM: u16 = 0x60;
const LEN: u16 = 0x80;
const MSH: u16 = 0xa0;

#[allow(dead_code)]
fn code_op(code: u16) -> u16 {
    code & 0xf0
}
const ADD: u16 = 0x00;
const SUB: u16 = 0x10;
const MUL: u16 = 0x20;
const DIV: u16 = 0x30;
const OR: u16 = 0x40;
const AND: u16 = 0x50;
const LSH: u16 = 0x60;
const RSH: u16 = 0x70;
const NEG: u16 = 0x80;
const MOD: u16 = 0x90;
const XOR: u16 = 0xa0;

const JA: u16 = 0x00;
const JEQ: u16 = 0x10;
const JGT: u16 = 0x20;
const JGE: u16 = 0x30;
const JSET: u16 = 0x40;

#[allow(dead_code)]
fn code_src(code: u16) -> u16 {
    code & 0x08
}
const K: u16 = 0x00;
const X: u16 = 0x08;

#[allow(dead_code)]
fn code_rval(code: u16) -> u16 {
    code & 0x18
}
const A: u16 = 0x10;

#[allow(dead_code)]
fn code_miscop(code: u16) -> u16 {
    code & 0xf8
}
const TAX: u16 = 0x00;
const TXA: u16 = 0x80;

pub enum BpfError {
    DecodeError,
    JumpTargetError,
    MemRangeError,
    PacketRangeError,
}

struct CodeHelper<const A: u16, const B: u16, const C: u16> {}

impl<const A: u16, const B: u16, const C: u16> CodeHelper<A, B, C> {
    const X: u16 = A | B | C;
}

macro_rules! code {
    ($i:path) => {
        CodeHelper::<$i, 0, 0>::X
    };
    ($i:path, $j:path) => {
        CodeHelper::<$i, $j, 0>::X
    };
    ($i:path, $j:path, $k:path) => {
        CodeHelper::<$i, $j, $k>::X
    };
}

unsafe fn load_byte(packet: &[u8], addr: usize) -> u32 {
    *unsafe { packet.get_unchecked(addr) } as u32
}

unsafe fn load_halfword(packet: &[u8], addr: usize) -> u32 {
    ((*unsafe { packet.get_unchecked(addr) } as u32) << 8)
        | (*unsafe { packet.get_unchecked((addr) + 1) } as u32)
}

unsafe fn load_word(packet: &[u8], addr: usize) -> u32 {
    ((*unsafe { packet.get_unchecked(addr) } as u32) << 24)
        | ((*unsafe { packet.get_unchecked((addr) + 1) } as u32) << 16)
        | ((*unsafe { packet.get_unchecked((addr) + 2) } as u32) << 8)
        | (*unsafe { packet.get_unchecked((addr) + 3) } as u32)
}

pub struct BpfProgram {
    program: Box<[BpfInsn]>,
}

impl BpfProgram {
    pub fn validate<I: IntoIterator<Item = impl Borrow<BpfInsn>>>(
        insns: I,
    ) -> Result<Self, BpfError> {
        // TODO FIXME: check program! incl. switch to check backwards jumps or not
        Ok(unsafe { Self::new_unvalidated(insns) })
    }

    pub unsafe fn new_unvalidated<I: IntoIterator<Item = impl Borrow<BpfInsn>>>(insns: I) -> Self {
        Self {
            program: insns.into_iter().map(|x| *x.borrow()).collect(),
        }
    }

    fn do_jmp(pc: usize, taken: bool, insn: &BpfInsn) -> usize {
        unsafe { pc.unchecked_add(if taken { insn.jt } else { insn.jf } as usize) }
    }

    pub fn filter<P: AsRef<[u8]>>(&self, packet: P) -> u32 {
        self.filter_slice(packet.as_ref())
    }

    fn filter_slice(&self, packet: &[u8]) -> u32 {
        let mut a = 0u32;
        let mut x = 0u32;
        let mut pc = 0;
        let mut mem = [0u32; 16];

        loop {
            let insn = unsafe { self.program.get_unchecked(pc) };
            pc = unsafe { pc.unchecked_add(1) };

            match insn.code {
                code!(RET, K) => break insn.k,
                code!(RET, A) => break a,

                code!(LD, W, ABS) => {
                    let k = insn.k as usize;
                    if k > packet.len() || packet.len() - k < 4 {
                        break 0;
                    } else {
                        a = unsafe { load_word(packet, k) }
                    }
                }

                code!(LD, H, ABS) => {
                    let k = insn.k as usize;
                    if k > packet.len() || packet.len() - k < 2 {
                        break 0;
                    } else {
                        a = unsafe { load_halfword(packet, k) }
                    }
                }

                code!(LD, B, ABS) => {
                    let k = insn.k as usize;
                    if k >= packet.len() {
                        break 0;
                    } else {
                        a = unsafe { load_byte(packet, k) }
                    }
                }

                code!(LD, W, LEN) => a = packet.len() as u32,
                code!(LDX, W, LEN) => x = packet.len() as u32,

                code!(LD, W, IND) => {
                    let k = x.wrapping_add(insn.k) as usize;
                    if k > packet.len() || packet.len() - k < 4 {
                        break 0;
                    } else {
                        a = unsafe { load_word(packet, k) }
                    }
                }

                code!(LD, H, IND) => {
                    let k = x.wrapping_add(insn.k) as usize;
                    if k > packet.len() || packet.len() - k < 2 {
                        break 0;
                    } else {
                        a = unsafe { load_halfword(packet, k) }
                    }
                }

                code!(LD, B, IND) => {
                    let k = x.wrapping_add(insn.k) as usize;
                    if k >= packet.len() {
                        break 0;
                    } else {
                        a = unsafe { load_byte(packet, k) }
                    }
                }

                code!(LDX, B, MSH) => {
                    let k = insn.k as usize;
                    if k >= packet.len() {
                        break 0;
                    } else {
                        x = (unsafe { load_byte(packet, k) } & 0xf) << 2
                    }
                }

                code!(LD, IMM) => a = insn.k,
                code!(LDX, IMM) => x = insn.k,

                code!(LD, MEM) => a = *unsafe { mem.get_unchecked(insn.k as usize) },
                code!(LDX, MEM) => x = *unsafe { mem.get_unchecked(insn.k as usize) },

                code!(ST) => *unsafe { mem.get_unchecked_mut(insn.k as usize) } = a,
                code!(STX) => *unsafe { mem.get_unchecked_mut(insn.k as usize) } = x,

                code!(JMP, JA) =>
                /* deliberate wrapping for backwards jumps */
                {
                    pc = pc.wrapping_add(insn.k as usize)
                }

                code!(JMP, JGT, K) => pc = Self::do_jmp(pc, a > insn.k, insn),
                code!(JMP, JGE, K) => pc = Self::do_jmp(pc, a >= insn.k, insn),
                code!(JMP, JEQ, K) => pc = Self::do_jmp(pc, a == insn.k, insn),
                code!(JMP, JSET, K) => pc = Self::do_jmp(pc, a & insn.k != 0, insn),

                code!(JMP, JGT, X) => pc = Self::do_jmp(pc, a > x, insn),
                code!(JMP, JGE, X) => pc = Self::do_jmp(pc, a >= x, insn),
                code!(JMP, JEQ, X) => pc = Self::do_jmp(pc, a == x, insn),
                code!(JMP, JSET, X) => pc = Self::do_jmp(pc, a & x != 0, insn),

                code!(ALU, ADD, X) => a = a.wrapping_add(x),
                code!(ALU, SUB, X) => a = a.wrapping_sub(x),
                code!(ALU, MUL, X) => a = a.wrapping_mul(x),
                code!(ALU, DIV, X) => {
                    if x == 0 {
                        break 0;
                    } else {
                        a /= x
                    }
                }
                code!(ALU, MOD, X) => {
                    if x == 0 {
                        break 0;
                    } else {
                        a %= x
                    }
                }
                code!(ALU, AND, X) => a &= x,
                code!(ALU, OR, X) => a |= x,
                code!(ALU, XOR, X) => a ^= x,
                code!(ALU, LSH, X) => {
                    if x < 32 {
                        a <<= x
                    } else {
                        a = 0
                    }
                }
                code!(ALU, RSH, X) => {
                    if x < 32 {
                        a >>= x
                    } else {
                        a = 0
                    }
                }

                code!(ALU, ADD, K) => a = a.wrapping_add(insn.k),
                code!(ALU, SUB, K) => a = a.wrapping_sub(insn.k),
                code!(ALU, MUL, K) => a = a.wrapping_mul(insn.k),
                code!(ALU, DIV, K) => {
                    if insn.k == 0 {
                        break 0;
                    } else {
                        a /= insn.k
                    }
                }
                code!(ALU, MOD, K) => {
                    if insn.k == 0 {
                        break 0;
                    } else {
                        a %= insn.k
                    }
                }
                code!(ALU, AND, K) => a &= insn.k,
                code!(ALU, OR, K) => a |= insn.k,
                code!(ALU, XOR, K) => a ^= insn.k,
                code!(ALU, LSH, K) => {
                    if insn.k < 32 {
                        a <<= insn.k
                    } else {
                        a = 0
                    }
                }
                code!(ALU, RSH, K) => {
                    if insn.k < 32 {
                        a >>= insn.k
                    } else {
                        a = 0
                    }
                }

                code!(ALU, NEG) => a = a.wrapping_neg(),

                code!(MISC, TAX) => x = a,
                code!(MISC, TXA) => a = x,

                _ => unsafe { unreachable_unchecked() },
            }
        }
    }
}

#[cfg(any(feature = "pcap", test))]
impl From<pcap::BpfInstruction> for BpfInsn {
    fn from(insn: pcap::BpfInstruction) -> Self {
        // SAFETY: these have the same C layout
        unsafe { std::mem::transmute(insn) }
    }
}

#[cfg(any(feature = "pcap", test))]
impl AsRef<BpfInsn> for pcap::BpfInstruction {
    fn as_ref(&self) -> &BpfInsn {
        // SAFETY: these have the same C layout
        unsafe { std::mem::transmute(self) }
    }
}

#[cfg(any(feature = "pcap", test))]
impl From<pcap::BpfProgram> for BpfProgram {
    fn from(prog: pcap::BpfProgram) -> Self {
        // SAFETY: these have the same C layout
        let insns: &[BpfInsn] = unsafe { std::mem::transmute(prog.get_instructions()) };
        // SAFETY: the pcap crate only creates these from compilation
        unsafe { BpfProgram::new_unvalidated(insns) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap::{Capture, Linktype};

    #[test]
    fn basic_test() {
        let capture = Capture::dead(Linktype::ETHERNET).unwrap();
        let prog = BpfProgram::from(capture.compile("ip src 1.2.3.4", true).unwrap());

        #[rustfmt::skip]
        let mut packet: Vec<u8> = vec![
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0x08, 0x00, 0, 0,
            0, 0, 0, 0,

            0, 0, 0, 0, 0, 0, 1, 2, 3, 4,
        ];

        assert!(prog.filter(&packet) >= 1500);

        packet[26..30].copy_from_slice(&[5, 6, 7, 8]);
        assert_eq!(prog.filter(packet), 0);
    }
}
