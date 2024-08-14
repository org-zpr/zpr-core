use std::borrow::Borrow;
use std::hint::unreachable_unchecked;

/// BPF compatibility version
pub const VERSION: i32 = 199606;

/// a single BPF instruction
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl BpfInsn {
    /// construct a simple BPF statement
    pub fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// construct a BPF jump statement
    pub fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

pub mod bpf_code {
    pub fn code_class(code: u16) -> u16 {
        code & 0x07
    }
    pub const LD: u16 = 0x00;
    pub const LDX: u16 = 0x01;
    pub const ST: u16 = 0x02;
    pub const STX: u16 = 0x03;
    pub const ALU: u16 = 0x04;
    pub const JMP: u16 = 0x05;
    pub const RET: u16 = 0x06;
    pub const MISC: u16 = 0x07;

    pub fn code_size(code: u16) -> u16 {
        code & 0x18
    }
    pub const W: u16 = 0x00;
    pub const H: u16 = 0x08;
    pub const B: u16 = 0x10;

    pub fn code_mode(code: u16) -> u16 {
        code & 0xe0
    }
    pub const IMM: u16 = 0x00;
    pub const ABS: u16 = 0x20;
    pub const IND: u16 = 0x40;
    pub const MEM: u16 = 0x60;
    pub const LEN: u16 = 0x80;
    pub const MSH: u16 = 0xa0;

    pub fn code_op(code: u16) -> u16 {
        code & 0xf0
    }
    pub const ADD: u16 = 0x00;
    pub const SUB: u16 = 0x10;
    pub const MUL: u16 = 0x20;
    pub const DIV: u16 = 0x30;
    pub const OR: u16 = 0x40;
    pub const AND: u16 = 0x50;
    pub const LSH: u16 = 0x60;
    pub const RSH: u16 = 0x70;
    pub const NEG: u16 = 0x80;
    pub const MOD: u16 = 0x90;
    pub const XOR: u16 = 0xa0;

    pub const JA: u16 = 0x00;
    pub const JEQ: u16 = 0x10;
    pub const JGT: u16 = 0x20;
    pub const JGE: u16 = 0x30;
    pub const JSET: u16 = 0x40;

    pub fn code_src(code: u16) -> u16 {
        code & 0x08
    }
    pub const K: u16 = 0x00;
    pub const X: u16 = 0x08;

    pub fn code_rval(code: u16) -> u16 {
        code & 0x18
    }
    pub const A: u16 = 0x10;

    pub fn code_miscop(code: u16) -> u16 {
        code & 0xf8
    }
    pub const TAX: u16 = 0x00;
    pub const TXA: u16 = 0x80;
}

use bpf_code::*;

/// number of words addressable via MEM addressing mode
const MEMWORDS: usize = 16;

/// Launder a compile-time u16 value as a const symbol
/// which can be used for pattern matching.
struct U16Value<const A: u16> {}

impl<const A: u16> U16Value<A> {
    const VALUE: u16 = A;
}

/// macro helper for arithmetic expression patterns
macro_rules! u16pat {
    ($i:expr) => {
        $crate::U16Value::<{ $i }>::VALUE
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

/// error indicating why a BPF program did not validate
#[derive(Debug, PartialEq)]
pub enum BpfError {
    ProgramTooLarge,
    MissingReturn,
    InvalidInstruction,
    BadJumpTarget,
    BadMemoryAccess,
    DivideByZero,
}

/// a validated BPF program
pub struct BpfProgram {
    insns: Box<[BpfInsn]>,
}

impl BpfProgram {
    /// Allow backward jumps while validating. This means a BPF program
    /// is not guaranteed to terminate.
    pub const VALIDATE_ALLOW_BACKWARD_JUMPS: usize = 1;

    // SAFETY: all unsafe blocks in these methods assume the program has been validated.

    /// Validate the stream of BPF instructions and construct a program as proof.
    pub fn validate<'a, I: IntoIterator<Item = &'a (impl Borrow<BpfInsn> + 'a)>>(
        insns: I,
    ) -> Result<Self, BpfError> {
        Self::validate_with_flags(insns, 0)
    }

    /// Validate, with options.
    pub fn validate_with_flags<'a, I: IntoIterator<Item = &'a (impl Borrow<BpfInsn> + 'a)>>(
        insns: I,
        flags: usize,
    ) -> Result<Self, BpfError> {
        let insns: Box<_> = insns.into_iter().map(|x| *x.borrow()).collect();
        Self::do_validate(insns.as_ref(), flags)?;
        Ok(Self { insns })
    }

    /// Create a BPF program from a series of instructions without validating.
    pub unsafe fn new_unvalidated<'a, I: IntoIterator<Item = &'a (impl Borrow<BpfInsn> + 'a)>>(
        insns: I,
    ) -> Self {
        Self {
            insns: insns.into_iter().map(|x| *x.borrow()).collect(),
        }
    }

    fn do_jmp(pc: u32, taken: bool, insn: &BpfInsn) -> u32 {
        unsafe { pc.unchecked_add(if taken { insn.jt } else { insn.jf } as u32) }
    }

    /// Execute the BPF program on the given packet data.
    pub fn filter<P: AsRef<[u8]>>(&self, packet: P) -> u32 {
        self.filter_slice(packet.as_ref())
    }

    fn filter_slice(&self, packet: &[u8]) -> u32 {
        let mut a = 0u32;
        let mut x = 0u32;
        let mut pc = 0u32;
        let mut mem = [0u32; MEMWORDS];

        loop {
            let insn = unsafe { self.insns.get_unchecked(pc as usize) };
            pc = unsafe { pc.unchecked_add(1) };

            match insn.code {
                u16pat!(RET | K) => break insn.k,
                u16pat!(RET | A) => break a,

                u16pat!(LD | W | ABS) => {
                    let k = insn.k as usize;
                    if k > packet.len() || packet.len() - k < 4 {
                        break 0;
                    } else {
                        a = unsafe { load_word(packet, k) }
                    }
                }

                u16pat!(LD | H | ABS) => {
                    let k = insn.k as usize;
                    if k > packet.len() || packet.len() - k < 2 {
                        break 0;
                    } else {
                        a = unsafe { load_halfword(packet, k) }
                    }
                }

                u16pat!(LD | B | ABS) => {
                    let k = insn.k as usize;
                    if k >= packet.len() {
                        break 0;
                    } else {
                        a = unsafe { load_byte(packet, k) }
                    }
                }

                u16pat!(LD | W | LEN) => a = packet.len() as u32,
                u16pat!(LDX | W | LEN) => x = packet.len() as u32,

                u16pat!(LD | W | IND) => {
                    let k = x.wrapping_add(insn.k) as usize;
                    if k > packet.len() || packet.len() - k < 4 {
                        break 0;
                    } else {
                        a = unsafe { load_word(packet, k) }
                    }
                }

                u16pat!(LD | H | IND) => {
                    let k = x.wrapping_add(insn.k) as usize;
                    if k > packet.len() || packet.len() - k < 2 {
                        break 0;
                    } else {
                        a = unsafe { load_halfword(packet, k) }
                    }
                }

                u16pat!(LD | B | IND) => {
                    let k = x.wrapping_add(insn.k) as usize;
                    if k >= packet.len() {
                        break 0;
                    } else {
                        a = unsafe { load_byte(packet, k) }
                    }
                }

                u16pat!(LDX | B | MSH) => {
                    let k = insn.k as usize;
                    if k >= packet.len() {
                        break 0;
                    } else {
                        x = (unsafe { load_byte(packet, k) } & 0xf) << 2
                    }
                }

                u16pat!(LD | IMM) => a = insn.k,
                u16pat!(LDX | IMM) => x = insn.k,

                u16pat!(LD | MEM) => a = *unsafe { mem.get_unchecked(insn.k as usize) },
                u16pat!(LDX | MEM) => x = *unsafe { mem.get_unchecked(insn.k as usize) },

                u16pat!(ST) => *unsafe { mem.get_unchecked_mut(insn.k as usize) } = a,
                u16pat!(STX) => *unsafe { mem.get_unchecked_mut(insn.k as usize) } = x,

                u16pat!(JMP | JA) => {
                    /* deliberate wrapping for backwards jumps */
                    pc = pc.wrapping_add(insn.k)
                }

                u16pat!(JMP | JGT | K) => pc = Self::do_jmp(pc, a > insn.k, insn),
                u16pat!(JMP | JGE | K) => pc = Self::do_jmp(pc, a >= insn.k, insn),
                u16pat!(JMP | JEQ | K) => pc = Self::do_jmp(pc, a == insn.k, insn),
                u16pat!(JMP | JSET | K) => pc = Self::do_jmp(pc, a & insn.k != 0, insn),

                u16pat!(JMP | JGT | X) => pc = Self::do_jmp(pc, a > x, insn),
                u16pat!(JMP | JGE | X) => pc = Self::do_jmp(pc, a >= x, insn),
                u16pat!(JMP | JEQ | X) => pc = Self::do_jmp(pc, a == x, insn),
                u16pat!(JMP | JSET | X) => pc = Self::do_jmp(pc, a & x != 0, insn),

                u16pat!(ALU | ADD | X) => a = a.wrapping_add(x),
                u16pat!(ALU | SUB | X) => a = a.wrapping_sub(x),
                u16pat!(ALU | MUL | X) => a = a.wrapping_mul(x),
                u16pat!(ALU | DIV | X) => {
                    if x == 0 {
                        break 0;
                    } else {
                        a /= x
                    }
                }
                u16pat!(ALU | MOD | X) => {
                    if x == 0 {
                        break 0;
                    } else {
                        a %= x
                    }
                }
                u16pat!(ALU | AND | X) => a &= x,
                u16pat!(ALU | OR | X) => a |= x,
                u16pat!(ALU | XOR | X) => a ^= x,
                u16pat!(ALU | LSH | X) => {
                    if x < 32 {
                        a <<= x
                    } else {
                        a = 0
                    }
                }
                u16pat!(ALU | RSH | X) => {
                    if x < 32 {
                        a >>= x
                    } else {
                        a = 0
                    }
                }

                u16pat!(ALU | ADD | K) => a = a.wrapping_add(insn.k),
                u16pat!(ALU | SUB | K) => a = a.wrapping_sub(insn.k),
                u16pat!(ALU | MUL | K) => a = a.wrapping_mul(insn.k),
                u16pat!(ALU | DIV | K) => {
                    if insn.k == 0 {
                        break 0;
                    } else {
                        a /= insn.k
                    }
                }
                u16pat!(ALU | MOD | K) => {
                    if insn.k == 0 {
                        break 0;
                    } else {
                        a %= insn.k
                    }
                }
                u16pat!(ALU | AND | K) => a &= insn.k,
                u16pat!(ALU | OR | K) => a |= insn.k,
                u16pat!(ALU | XOR | K) => a ^= insn.k,
                u16pat!(ALU | LSH | K) => {
                    if insn.k < 32 {
                        a <<= insn.k
                    } else {
                        a = 0
                    }
                }
                u16pat!(ALU | RSH | K) => {
                    if insn.k < 32 {
                        a >>= insn.k
                    } else {
                        a = 0
                    }
                }

                u16pat!(ALU | NEG) => a = a.wrapping_neg(),

                u16pat!(MISC | TAX) => x = a,
                u16pat!(MISC | TXA) => a = x,

                _ => unsafe { unreachable_unchecked() },
            }
        }
    }

    fn do_validate(insns: &[BpfInsn], flags: usize) -> Result<(), BpfError> {
        if insns.len() > u32::MAX as usize {
            return Err(BpfError::ProgramTooLarge);
        }

        for i in 0..(insns.len() as u32) {
            let insn = &insns[i as usize];

            if insn.code & 0xff00 != 0 {
                return Err(BpfError::InvalidInstruction);
            }

            match code_class(insn.code) {
                LD | LDX => match code_mode(insn.code) {
                    IMM | LEN => {
                        if code_size(insn.code) != W {
                            return Err(BpfError::InvalidInstruction);
                        }
                    }

                    ABS | IND => (),

                    MSH => {
                        if code_size(insn.code) != B {
                            return Err(BpfError::InvalidInstruction);
                        }
                    }

                    MEM => {
                        if code_size(insn.code) != W {
                            return Err(BpfError::InvalidInstruction);
                        }

                        if insn.k as usize >= MEMWORDS {
                            return Err(BpfError::BadMemoryAccess);
                        }
                    }

                    _ => return Err(BpfError::InvalidInstruction),
                },

                ST | STX => {
                    if code_mode(insn.code) != MEM || code_size(insn.code) != W {
                        return Err(BpfError::InvalidInstruction);
                    }

                    if insn.k as usize >= MEMWORDS {
                        return Err(BpfError::BadMemoryAccess);
                    }
                }

                ALU => match code_op(insn.code) {
                    ADD | SUB | MUL | OR | AND | XOR | LSH | RSH => (),

                    NEG => {
                        if code_src(insn.code) != 0 {
                            return Err(BpfError::InvalidInstruction);
                        }
                    }

                    DIV | MOD => {
                        if code_src(insn.code) == K && insn.k == 0 {
                            return Err(BpfError::DivideByZero);
                        }
                    }

                    _ => return Err(BpfError::InvalidInstruction),
                },

                JMP => {
                    let from = i + 1;
                    match code_op(insn.code) {
                        JA => {
                            if code_src(insn.code) != 0 {
                                return Err(BpfError::InvalidInstruction);
                            }

                            if flags & Self::VALIDATE_ALLOW_BACKWARD_JUMPS != 0 {
                                if from.wrapping_add(insn.k) >= insns.len() as u32 {
                                    return Err(BpfError::BadJumpTarget);
                                }
                            } else {
                                if insn.k >= (insns.len() as u32) - from {
                                    return Err(BpfError::BadJumpTarget);
                                }
                            }
                        }

                        JEQ | JGT | JGE | JSET => {
                            if insn.jt as u32 >= (insns.len() as u32) - from
                                || insn.jf as u32 >= (insns.len() as u32) - from
                            {
                                return Err(BpfError::BadJumpTarget);
                            }
                        }

                        _ => return Err(BpfError::InvalidInstruction),
                    }
                }

                RET => {
                    match code_rval(insn.code) {
                        A | K => (),
                        _ => return Err(BpfError::InvalidInstruction),
                    }

                    if insn.code & 0xe0 != 0 {
                        return Err(BpfError::InvalidInstruction);
                    }
                }

                MISC => match code_miscop(insn.code) {
                    TAX | TXA => (),
                    _ => return Err(BpfError::InvalidInstruction),
                },

                _ => return Err(BpfError::InvalidInstruction),
            }
        }

        if !insns.last().is_some_and(|insn| insn.code == RET) {
            return Err(BpfError::MissingReturn);
        }

        Ok(())
    }
}

#[cfg(any(feature = "pcap", test))]
impl Borrow<BpfInsn> for pcap::BpfInstruction {
    fn borrow(&self) -> &BpfInsn {
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

    #[test]
    fn borrow_test() {
        let capture = Capture::dead(Linktype::ETHERNET).unwrap();
        let prog = capture.compile("ip src 1.2.3.4", true).unwrap();
        let my_insn: &BpfInsn = prog.get_instructions()[0].borrow();
        assert_eq!(*my_insn, BpfInsn::stmt(LD | H | ABS, 12));
    }

    #[test]
    fn validate_test() -> Result<(), BpfError> {
        let capture = Capture::dead(Linktype::ETHERNET).unwrap();
        let prog = capture.compile("ip src 1.2.3.4", true).unwrap();
        let _ = BpfProgram::validate(prog.get_instructions())?;
        Ok(())
    }

    #[test]
    fn invalid_test() {
        match BpfProgram::validate(&[BpfInsn::stmt(RET | LEN, 0)]) {
            Ok(_) => panic!("program should not compile"),
            Err(err) => assert_eq!(err, BpfError::InvalidInstruction),
        }
    }
}
