//! The RandomX program VM as an interpreter, in light mode: each dataset
//! item the program reads is computed from the cache when it is needed
//! (RandomX specification, sections 4 and 5).

use super::superscalar::reciprocal;
use super::{float, Cache, CACHE_LINE_SIZE};

const PROGRAM_SIZE: usize = 256;
const PROGRAM_ITERATIONS: usize = 2048;
const SCRATCHPAD_L3: usize = 2_097_152;
const SCRATCHPAD_L2: usize = 262_144;
const SCRATCHPAD_L1: usize = 16_384;
const L1_MASK: u64 = (SCRATCHPAD_L1 as u64 / 8 - 1) * 8;
const L2_MASK: u64 = (SCRATCHPAD_L2 as u64 / 8 - 1) * 8;
const L3_MASK: u64 = (SCRATCHPAD_L3 as u64 / 8 - 1) * 8;
const L3_MASK64: u64 = (SCRATCHPAD_L3 as u64 / 64 - 1) * 64;
const DATASET_BASE_SIZE: u64 = 2_147_483_648;
const DATASET_EXTRA_ITEMS: u64 = 33_554_368 / CACHE_LINE_SIZE as u64;
const CACHE_LINE_ALIGN_MASK: u64 = (DATASET_BASE_SIZE - 1) & !(CACHE_LINE_SIZE as u64 - 1);
const JUMP_BITS: u32 = 8;
const JUMP_OFFSET: u32 = 8;
const STORE_L3_CONDITION: u8 = 14;
const REGISTER_NEEDS_DISPLACEMENT: usize = 5;
const FSCAL_MASK: u64 = 0x80f0_0000_0000_0000;
const DYNAMIC_MANTISSA_MASK: u64 = (1 << 56) - 1;

/// The bytes the AES generator writes for one program: 128 bytes of
/// configuration entropy and 256 instructions of 8 bytes.
pub const PROGRAM_BYTES: usize = 128 + 8 * PROGRAM_SIZE;
pub const SCRATCHPAD_BYTES: usize = SCRATCHPAD_L3;

/// Instruction frequencies (out of 256) in opcode order.
const FREQUENCIES: [(Kind, u32); 29] = [
    (Kind::IAddRs, 16),
    (Kind::IAddM, 7),
    (Kind::ISubR, 16),
    (Kind::ISubM, 7),
    (Kind::IMulR, 16),
    (Kind::IMulM, 4),
    (Kind::IMulhR, 4),
    (Kind::IMulhM, 1),
    (Kind::ISmulhR, 4),
    (Kind::ISmulhM, 1),
    (Kind::IMulRcp, 8),
    (Kind::INegR, 2),
    (Kind::IXorR, 15),
    (Kind::IXorM, 5),
    (Kind::IRorR, 8),
    (Kind::IRolR, 2),
    (Kind::ISwapR, 4),
    (Kind::FSwapR, 4),
    (Kind::FAddR, 16),
    (Kind::FAddM, 5),
    (Kind::FSubR, 16),
    (Kind::FSubM, 5),
    (Kind::FScalR, 6),
    (Kind::FMulR, 32),
    (Kind::FDivM, 4),
    (Kind::FSqrtR, 6),
    (Kind::CBranch, 25),
    (Kind::CFround, 1),
    (Kind::IStore, 16),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    IAddRs,
    IAddM,
    ISubR,
    ISubM,
    IMulR,
    IMulM,
    IMulhR,
    IMulhM,
    ISmulhR,
    ISmulhM,
    IMulRcp,
    INegR,
    IXorR,
    IXorM,
    IRorR,
    IRolR,
    ISwapR,
    FSwapR,
    FAddR,
    FAddM,
    FSubR,
    FSubM,
    FScalR,
    FMulR,
    FDivM,
    FSqrtR,
    CBranch,
    CFround,
    IStore,
    Nop,
}

fn kind_of(opcode: u8) -> Kind {
    let mut limit = 0u32;
    for (kind, frequency) in FREQUENCIES {
        limit += frequency;
        if u32::from(opcode) < limit {
            return kind;
        }
    }
    Kind::Nop
}

/// The second operand of an integer instruction: a register or a constant.
#[derive(Clone, Copy)]
enum Operand {
    Reg(usize),
    Imm(u64),
}

/// A scratchpad address: `(register or zero) + imm`, masked.
#[derive(Clone, Copy)]
struct Address {
    base: Option<usize>,
    imm: u64,
    mask: u64,
}

impl Address {
    fn resolve(&self, r: &[u64; 8]) -> usize {
        let base = self.base.map_or(0, |reg| r[reg]);
        (base.wrapping_add(self.imm) & self.mask) as usize
    }
}

#[derive(Clone, Copy)]
enum Op {
    IAddRs { dst: usize, src: usize, shift: u32, imm: u64 },
    IAddM { dst: usize, mem: Address },
    ISubR { dst: usize, src: Operand },
    ISubM { dst: usize, mem: Address },
    IMulR { dst: usize, src: Operand },
    IMulM { dst: usize, mem: Address },
    IMulhR { dst: usize, src: usize },
    IMulhM { dst: usize, mem: Address },
    ISmulhR { dst: usize, src: usize },
    ISmulhM { dst: usize, mem: Address },
    INegR { dst: usize },
    IXorR { dst: usize, src: Operand },
    IXorM { dst: usize, mem: Address },
    IRorR { dst: usize, src: Operand },
    IRolR { dst: usize, src: Operand },
    ISwapR { dst: usize, src: usize },
    FSwapR { reg: usize },
    FAddR { dst: usize, src: usize },
    FAddM { dst: usize, mem: Address },
    FSubR { dst: usize, src: usize },
    FSubM { dst: usize, mem: Address },
    FScalR { dst: usize },
    FMulR { dst: usize, src: usize },
    FDivM { dst: usize, mem: Address },
    FSqrtR { dst: usize },
    CBranch { reg: usize, imm: u64, mask: u64, target: isize },
    CFround { src: usize, rotate: u32 },
    IStore { mem: Address, src: usize },
    Nop,
}

fn sign_extend(imm32: u32) -> u64 {
    imm32 as i32 as i64 as u64
}

/// Translates the program's instructions, resolving the operand choices and
/// the branch targets as the reference's bytecode compiler does.
fn compile(bytes: &[u8]) -> Vec<Op> {
    let mut register_usage = [-1isize; 8];
    let mut ops = Vec::with_capacity(PROGRAM_SIZE);
    for (i, word) in bytes.chunks_exact(8).enumerate() {
        let opcode = word[0];
        let dst = usize::from(word[1]) % 8;
        let src = usize::from(word[2]) % 8;
        let modifier = word[3];
        let imm32 = u32::from_le_bytes(word[4..8].try_into().unwrap());
        let mod_mem = modifier % 4;
        let mod_shift = u32::from((modifier >> 2) % 4);
        let mod_cond = modifier >> 4;
        let imm = sign_extend(imm32);
        let fdst = dst % 4;
        let fsrc = src % 4;
        let lower = if mod_mem != 0 { L1_MASK } else { L2_MASK };
        // Integer loads read L3 at a constant address when src == dst.
        let int_mem = if src != dst {
            Address { base: Some(src), imm, mask: lower }
        } else {
            Address { base: None, imm, mask: L3_MASK }
        };
        let float_mem = Address { base: Some(src), imm, mask: lower };
        let reg_or_imm = if src != dst { Operand::Reg(src) } else { Operand::Imm(imm) };
        let op = match kind_of(opcode) {
            Kind::IAddRs => Op::IAddRs {
                dst,
                src,
                shift: mod_shift,
                imm: if dst == REGISTER_NEEDS_DISPLACEMENT { imm } else { 0 },
            },
            Kind::IAddM => Op::IAddM { dst, mem: int_mem },
            Kind::ISubR => Op::ISubR { dst, src: reg_or_imm },
            Kind::ISubM => Op::ISubM { dst, mem: int_mem },
            Kind::IMulR => Op::IMulR { dst, src: reg_or_imm },
            Kind::IMulM => Op::IMulM { dst, mem: int_mem },
            Kind::IMulhR => Op::IMulhR { dst, src },
            Kind::IMulhM => Op::IMulhM { dst, mem: int_mem },
            Kind::ISmulhR => Op::ISmulhR { dst, src },
            Kind::ISmulhM => Op::ISmulhM { dst, mem: int_mem },
            Kind::IMulRcp => {
                let divisor = u64::from(imm32);
                if divisor & divisor.wrapping_sub(1) != 0 {
                    Op::IMulR { dst, src: Operand::Imm(reciprocal(divisor)) }
                } else {
                    Op::Nop
                }
            }
            Kind::INegR => Op::INegR { dst },
            Kind::IXorR => Op::IXorR { dst, src: reg_or_imm },
            Kind::IXorM => Op::IXorM { dst, mem: int_mem },
            Kind::IRorR => Op::IRorR {
                dst,
                src: if src != dst { Operand::Reg(src) } else { Operand::Imm(u64::from(imm32)) },
            },
            Kind::IRolR => Op::IRolR {
                dst,
                src: if src != dst { Operand::Reg(src) } else { Operand::Imm(u64::from(imm32)) },
            },
            Kind::ISwapR => {
                if src != dst {
                    Op::ISwapR { dst, src }
                } else {
                    Op::Nop
                }
            }
            Kind::FSwapR => Op::FSwapR { reg: dst },
            Kind::FAddR => Op::FAddR { dst: fdst, src: fsrc },
            Kind::FAddM => Op::FAddM { dst: fdst, mem: float_mem },
            Kind::FSubR => Op::FSubR { dst: fdst, src: fsrc },
            Kind::FSubM => Op::FSubM { dst: fdst, mem: float_mem },
            Kind::FScalR => Op::FScalR { dst: fdst },
            Kind::FMulR => Op::FMulR { dst: fdst, src: fsrc },
            Kind::FDivM => Op::FDivM { dst: fdst, mem: float_mem },
            Kind::FSqrtR => Op::FSqrtR { dst: fdst },
            Kind::CBranch => {
                let shift = u32::from(mod_cond) + JUMP_OFFSET;
                let imm = (imm | (1u64 << shift)) & !(1u64 << (shift - 1));
                let mask = ((1u64 << JUMP_BITS) - 1) << shift;
                let target = register_usage[dst];
                Op::CBranch { reg: dst, imm, mask, target }
            }
            Kind::CFround => Op::CFround { src, rotate: imm32 & 63 },
            Kind::IStore => {
                let mask = if mod_cond < STORE_L3_CONDITION { lower } else { L3_MASK };
                Op::IStore { mem: Address { base: Some(dst), imm, mask }, src }
            }
            Kind::Nop => Op::Nop,
        };
        // Registers an instruction writes, for the branch targets.
        match op {
            Op::IAddRs { dst, .. }
            | Op::IAddM { dst, .. }
            | Op::ISubR { dst, .. }
            | Op::ISubM { dst, .. }
            | Op::IMulR { dst, .. }
            | Op::IMulM { dst, .. }
            | Op::IMulhR { dst, .. }
            | Op::IMulhM { dst, .. }
            | Op::ISmulhR { dst, .. }
            | Op::ISmulhM { dst, .. }
            | Op::INegR { dst }
            | Op::IXorR { dst, .. }
            | Op::IXorM { dst, .. }
            | Op::IRorR { dst, .. }
            | Op::IRolR { dst, .. } => register_usage[dst] = i as isize,
            Op::ISwapR { dst, src } => {
                register_usage[dst] = i as isize;
                register_usage[src] = i as isize;
            }
            Op::CBranch { .. } => register_usage = [i as isize; 8],
            _ => {}
        }
        ops.push(op);
    }
    ops
}

/// A 128-bit floating-point register: two doubles, as bit patterns.
type Pair = [u64; 2];

fn small_positive_float(entropy: u64) -> u64 {
    let exponent = (entropy >> 59) + 1023;
    (exponent << 52) | (entropy & ((1 << 52) - 1))
}

fn float_mask(entropy: u64) -> u64 {
    let exponent = 0x300 | ((entropy >> 60) << 4);
    (entropy & ((1 << 22) - 1)) | (exponent << 52)
}

fn load64(scratchpad: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(scratchpad[at..at + 8].try_into().unwrap())
}

fn store64(scratchpad: &mut [u8], at: usize, value: u64) {
    scratchpad[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Two 32-bit signed integers at `at`, converted to doubles (exact).
fn load_pair(scratchpad: &[u8], at: usize) -> Pair {
    let word = |offset: usize| {
        let value = i32::from_le_bytes(scratchpad[at + offset..at + offset + 4].try_into().unwrap());
        f64::from(value).to_bits()
    };
    [word(0), word(4)]
}

/// The VM state that lives across the programs of one hash.
pub struct Vm<'a> {
    cache: &'a Cache,
    pub scratchpad: Vec<u8>,
    r: [u64; 8],
    f: [Pair; 4],
    e: [Pair; 4],
    a: [Pair; 4],
    rounding: u8,
}

impl<'a> Vm<'a> {
    pub fn new(cache: &'a Cache, scratchpad: Vec<u8>) -> Self {
        Self { cache, scratchpad, r: [0; 8], f: [[0; 2]; 4], e: [[0; 2]; 4], a: [[0; 2]; 4], rounding: float::NEAREST }
    }

    /// The register file as the reference lays it out in memory: r0 to r7,
    /// then f0 to f3, e0 to e3 and a0 to a3, each double little-endian.
    pub fn register_file(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        let words = self.r.iter().chain(self.f.iter().chain(&self.e).chain(&self.a).flatten());
        for (chunk, word) in out.chunks_exact_mut(8).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Replaces the `a` registers with the 64 bytes of `bytes`.
    pub fn set_a(&mut self, bytes: &[u8; 64]) {
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            self.a[i / 2][i % 2] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
    }

    /// Generates a program from `seed` with AesGenerator4R and runs it.
    pub fn run(&mut self, seed: &[u8; 64]) {
        let mut program = vec![0u8; PROGRAM_BYTES];
        super::aes::fill_4r(seed, &mut program);
        let entropy: Vec<u64> =
            program[..128].chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();

        for i in 0..4 {
            self.a[i] = [small_positive_float(entropy[2 * i]), small_positive_float(entropy[2 * i + 1])];
        }
        let mut ma = (entropy[8] & CACHE_LINE_ALIGN_MASK) as u32;
        let mut mx = entropy[10] as u32;
        let address_registers = entropy[12];
        let read_reg = [
            (address_registers & 1) as usize,
            2 + ((address_registers >> 1) & 1) as usize,
            4 + ((address_registers >> 2) & 1) as usize,
            6 + ((address_registers >> 3) & 1) as usize,
        ];
        let dataset_offset = (entropy[13] % (DATASET_EXTRA_ITEMS + 1)) * CACHE_LINE_SIZE as u64;
        let e_mask = [float_mask(entropy[14]), float_mask(entropy[15])];

        let ops = compile(&program[128..]);
        self.r = [0; 8];
        let mut sp_addr0 = mx;
        let mut sp_addr1 = ma;

        for _ in 0..PROGRAM_ITERATIONS {
            let sp_mix = self.r[read_reg[0]] ^ self.r[read_reg[1]];
            sp_addr0 = ((u64::from(sp_addr0) ^ sp_mix) & L3_MASK64) as u32;
            sp_addr1 = ((u64::from(sp_addr1) ^ (sp_mix >> 32)) & L3_MASK64) as u32;
            let (at0, at1) = (sp_addr0 as usize, sp_addr1 as usize);

            for i in 0..8 {
                self.r[i] ^= load64(&self.scratchpad, at0 + 8 * i);
            }
            for i in 0..4 {
                self.f[i] = load_pair(&self.scratchpad, at1 + 8 * i);
            }
            for i in 0..4 {
                let pair = load_pair(&self.scratchpad, at1 + 8 * (4 + i));
                self.e[i] = [
                    (pair[0] & DYNAMIC_MANTISSA_MASK) | e_mask[0],
                    (pair[1] & DYNAMIC_MANTISSA_MASK) | e_mask[1],
                ];
            }

            self.execute(&ops, &e_mask);

            mx ^= (self.r[read_reg[2]] ^ self.r[read_reg[3]]) as u32;
            mx &= CACHE_LINE_ALIGN_MASK as u32;
            let item = (dataset_offset + u64::from(ma)) / CACHE_LINE_SIZE as u64;
            let line = self.cache.dataset_item(item);
            for i in 0..8 {
                self.r[i] ^= line[i];
            }
            core::mem::swap(&mut mx, &mut ma);

            for i in 0..8 {
                store64(&mut self.scratchpad, at1 + 8 * i, self.r[i]);
            }
            for i in 0..4 {
                self.f[i] = [self.f[i][0] ^ self.e[i][0], self.f[i][1] ^ self.e[i][1]];
                store64(&mut self.scratchpad, at0 + 16 * i, self.f[i][0]);
                store64(&mut self.scratchpad, at0 + 16 * i + 8, self.f[i][1]);
            }
            sp_addr0 = 0;
            sp_addr1 = 0;
        }
    }

    fn execute(&mut self, ops: &[Op], e_mask: &[u64; 2]) {
        let mut pc = 0isize;
        while (pc as usize) < ops.len() {
            let mode = self.rounding;
            let r = &mut self.r;
            match ops[pc as usize] {
                Op::IAddRs { dst, src, shift, imm } => {
                    r[dst] = r[dst].wrapping_add(r[src] << shift).wrapping_add(imm);
                }
                Op::IAddM { dst, mem } => {
                    r[dst] = r[dst].wrapping_add(load64(&self.scratchpad, mem.resolve(r)));
                }
                Op::ISubR { dst, src } => r[dst] = r[dst].wrapping_sub(operand(r, src)),
                Op::ISubM { dst, mem } => {
                    r[dst] = r[dst].wrapping_sub(load64(&self.scratchpad, mem.resolve(r)));
                }
                Op::IMulR { dst, src } => r[dst] = r[dst].wrapping_mul(operand(r, src)),
                Op::IMulM { dst, mem } => {
                    r[dst] = r[dst].wrapping_mul(load64(&self.scratchpad, mem.resolve(r)));
                }
                Op::IMulhR { dst, src } => r[dst] = mulh(r[dst], r[src]),
                Op::IMulhM { dst, mem } => r[dst] = mulh(r[dst], load64(&self.scratchpad, mem.resolve(r))),
                Op::ISmulhR { dst, src } => r[dst] = smulh(r[dst], r[src]),
                Op::ISmulhM { dst, mem } => r[dst] = smulh(r[dst], load64(&self.scratchpad, mem.resolve(r))),
                Op::INegR { dst } => r[dst] = r[dst].wrapping_neg(),
                Op::IXorR { dst, src } => r[dst] ^= operand(r, src),
                Op::IXorM { dst, mem } => r[dst] ^= load64(&self.scratchpad, mem.resolve(r)),
                Op::IRorR { dst, src } => r[dst] = r[dst].rotate_right((operand(r, src) & 63) as u32),
                Op::IRolR { dst, src } => r[dst] = r[dst].rotate_left((operand(r, src) & 63) as u32),
                Op::ISwapR { dst, src } => r.swap(dst, src),
                Op::FSwapR { reg } => {
                    let pair = if reg < 4 { &mut self.f[reg] } else { &mut self.e[reg - 4] };
                    pair.swap(0, 1);
                }
                Op::FAddR { dst, src } => {
                    let a = self.a[src];
                    let f = &mut self.f[dst];
                    *f = [float::add(f[0], a[0], mode), float::add(f[1], a[1], mode)];
                }
                Op::FAddM { dst, mem } => {
                    let x = load_pair(&self.scratchpad, mem.resolve(r));
                    let f = &mut self.f[dst];
                    *f = [float::add(f[0], x[0], mode), float::add(f[1], x[1], mode)];
                }
                Op::FSubR { dst, src } => {
                    let a = self.a[src];
                    let f = &mut self.f[dst];
                    *f = [float::sub(f[0], a[0], mode), float::sub(f[1], a[1], mode)];
                }
                Op::FSubM { dst, mem } => {
                    let x = load_pair(&self.scratchpad, mem.resolve(r));
                    let f = &mut self.f[dst];
                    *f = [float::sub(f[0], x[0], mode), float::sub(f[1], x[1], mode)];
                }
                Op::FScalR { dst } => {
                    let f = &mut self.f[dst];
                    *f = [f[0] ^ FSCAL_MASK, f[1] ^ FSCAL_MASK];
                }
                Op::FMulR { dst, src } => {
                    let a = self.a[src];
                    let e = &mut self.e[dst];
                    *e = [float::mul(e[0], a[0], mode), float::mul(e[1], a[1], mode)];
                }
                Op::FDivM { dst, mem } => {
                    let x = load_pair(&self.scratchpad, mem.resolve(r));
                    let divisor = [
                        (x[0] & DYNAMIC_MANTISSA_MASK) | e_mask[0],
                        (x[1] & DYNAMIC_MANTISSA_MASK) | e_mask[1],
                    ];
                    let e = &mut self.e[dst];
                    *e = [float::div(e[0], divisor[0], mode), float::div(e[1], divisor[1], mode)];
                }
                Op::FSqrtR { dst } => {
                    let e = &mut self.e[dst];
                    *e = [float::sqrt(e[0], mode), float::sqrt(e[1], mode)];
                }
                Op::CBranch { reg, imm, mask, target } => {
                    r[reg] = r[reg].wrapping_add(imm);
                    if r[reg] & mask == 0 {
                        pc = target;
                    }
                }
                Op::CFround { src, rotate } => self.rounding = (r[src].rotate_right(rotate) % 4) as u8,
                Op::IStore { mem, src } => {
                    let at = mem.resolve(r);
                    let value = r[src];
                    store64(&mut self.scratchpad, at, value);
                }
                Op::Nop => {}
            }
            pc += 1;
        }
    }
}

fn operand(r: &[u64; 8], operand: Operand) -> u64 {
    match operand {
        Operand::Reg(reg) => r[reg],
        Operand::Imm(imm) => imm,
    }
}

fn mulh(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) >> 64) as u64
}

fn smulh(a: u64, b: u64) -> u64 {
    ((i128::from(a as i64) * i128::from(b as i64)) >> 64) as u64
}
