//! SuperscalarHash (RandomX specification, section 6): the Blake2 generator,
//! the program generator with its model of a superscalar x86 core, and the
//! program execution used to compute dataset items in light mode.

use super::blake2b::hash512;

/// The Blake2 generator: a stream of bytes from repeated Blake2b-512 of a
/// 64-byte buffer that starts as the key (at most 60 bytes, zero padded)
/// followed by a 32-bit nonce, here always 0.
pub struct Blake2Generator {
    data: [u8; 64],
    index: usize,
}

impl Blake2Generator {
    pub fn new(seed: &[u8]) -> Self {
        let mut data = [0u8; 64];
        let len = seed.len().min(60);
        data[..len].copy_from_slice(&seed[..len]);
        Self { data, index: 64 }
    }

    fn check(&mut self, needed: usize) {
        if self.index + needed > 64 {
            self.data = hash512(&[&self.data]);
            self.index = 0;
        }
    }

    pub fn byte(&mut self) -> u8 {
        self.check(1);
        let value = self.data[self.index];
        self.index += 1;
        value
    }

    pub fn u32(&mut self) -> u32 {
        self.check(4);
        let value = u32::from_le_bytes(self.data[self.index..self.index + 4].try_into().unwrap());
        self.index += 4;
        value
    }
}

// Instruction types, in the reference's numbering.
const ISUB_R: i32 = 0;
const IXOR_R: i32 = 1;
const IADD_RS: i32 = 2;
const IMUL_R: i32 = 3;
const IROR_C: i32 = 4;
const IADD_C7: i32 = 5;
const IXOR_C7: i32 = 6;
const IADD_C8: i32 = 7;
const IXOR_C8: i32 = 8;
const IADD_C9: i32 = 9;
const IXOR_C9: i32 = 10;
const IMULH_R: i32 = 11;
const ISMULH_R: i32 = 12;
const IMUL_RCP: i32 = 13;
const INVALID: i32 = -1;

// Execution ports.
const P0: u8 = 1;
const P1: u8 = 2;
const P5: u8 = 4;
const P01: u8 = P0 | P1;
const P05: u8 = P0 | P5;
const P015: u8 = P0 | P1 | P5;

/// One x86 macro-operation of the model: its latency, its micro-operations'
/// ports (0 = none) and whether it depends on the previous macro-operation.
#[derive(Clone, Copy)]
struct MacroOp {
    latency: i32,
    uop1: u8,
    uop2: u8,
    dependent: bool,
}

const fn mop(latency: i32, uop1: u8, uop2: u8) -> MacroOp {
    MacroOp { latency, uop1, uop2, dependent: false }
}

const SUB_RR: MacroOp = mop(1, P015, 0);
const XOR_RR: MacroOp = mop(1, P015, 0);
const IMUL_R_OP: MacroOp = mop(4, P1, P5);
const MUL_R: MacroOp = mop(4, P1, P5);
const MOV_RR: MacroOp = mop(0, 0, 0);
const LEA_SIB: MacroOp = mop(1, P01, 0);
const IMUL_RR: MacroOp = mop(3, P1, 0);
const ROR_RI: MacroOp = mop(1, P05, 0);
const ADD_RI: MacroOp = mop(1, P015, 0);
const XOR_RI: MacroOp = mop(1, P015, 0);
const MOV_RI64: MacroOp = mop(1, P015, 0);
const IMUL_RR_DEPENDENT: MacroOp = MacroOp { dependent: true, ..IMUL_RR };

/// What the generator knows about one instruction type.
struct Info {
    kind: i32,
    ops: &'static [MacroOp],
    result_op: i32,
    dst_op: i32,
    src_op: i32,
}

const fn single(kind: i32, op: &'static [MacroOp], src_op: i32) -> Info {
    Info { kind, ops: op, result_op: 0, dst_op: 0, src_op }
}

static INFO_ISUB_R: Info = single(ISUB_R, &[SUB_RR], 0);
static INFO_IXOR_R: Info = single(IXOR_R, &[XOR_RR], 0);
static INFO_IADD_RS: Info = single(IADD_RS, &[LEA_SIB], 0);
static INFO_IMUL_R: Info = single(IMUL_R, &[IMUL_RR], 0);
static INFO_IROR_C: Info = single(IROR_C, &[ROR_RI], -1);
static INFO_IADD_C7: Info = single(IADD_C7, &[ADD_RI], -1);
static INFO_IXOR_C7: Info = single(IXOR_C7, &[XOR_RI], -1);
static INFO_IADD_C8: Info = single(IADD_C8, &[ADD_RI], -1);
static INFO_IXOR_C8: Info = single(IXOR_C8, &[XOR_RI], -1);
static INFO_IADD_C9: Info = single(IADD_C9, &[ADD_RI], -1);
static INFO_IXOR_C9: Info = single(IXOR_C9, &[XOR_RI], -1);
static INFO_IMULH_R: Info =
    Info { kind: IMULH_R, ops: &[MOV_RR, MUL_R, MOV_RR], result_op: 1, dst_op: 0, src_op: 1 };
static INFO_ISMULH_R: Info =
    Info { kind: ISMULH_R, ops: &[MOV_RR, IMUL_R_OP, MOV_RR], result_op: 1, dst_op: 0, src_op: 1 };
static INFO_IMUL_RCP: Info =
    Info { kind: IMUL_RCP, ops: &[MOV_RI64, IMUL_RR_DEPENDENT], result_op: 1, dst_op: 1, src_op: -1 };
static INFO_NOP: Info = Info { kind: INVALID, ops: &[], result_op: 0, dst_op: 0, src_op: 0 };

static SLOT_3: [&Info; 2] = [&INFO_ISUB_R, &INFO_IXOR_R];
static SLOT_3L: [&Info; 4] = [&INFO_ISUB_R, &INFO_IXOR_R, &INFO_IMULH_R, &INFO_ISMULH_R];
static SLOT_4: [&Info; 2] = [&INFO_IROR_C, &INFO_IADD_RS];
static SLOT_7: [&Info; 2] = [&INFO_IXOR_C7, &INFO_IADD_C7];
static SLOT_8: [&Info; 2] = [&INFO_IXOR_C8, &INFO_IADD_C8];
static SLOT_9: [&Info; 2] = [&INFO_IXOR_C9, &INFO_IADD_C9];

/// A decoder configuration: the sizes of its instruction slots.
struct DecodeBuffer {
    index: i32,
    counts: &'static [u32],
}

static BUFFER_484: DecodeBuffer = DecodeBuffer { index: 0, counts: &[4, 8, 4] };
static BUFFER_7333: DecodeBuffer = DecodeBuffer { index: 1, counts: &[7, 3, 3, 3] };
static BUFFER_3733: DecodeBuffer = DecodeBuffer { index: 2, counts: &[3, 7, 3, 3] };
static BUFFER_493: DecodeBuffer = DecodeBuffer { index: 3, counts: &[4, 9, 3] };
static BUFFER_4444: DecodeBuffer = DecodeBuffer { index: 4, counts: &[4, 4, 4, 4] };
static BUFFER_3310: DecodeBuffer = DecodeBuffer { index: 5, counts: &[3, 3, 10] };
static BUFFERS: [&DecodeBuffer; 4] = [&BUFFER_484, &BUFFER_7333, &BUFFER_3733, &BUFFER_493];

fn fetch_next(kind: i32, cycle: i32, mul_count: i32, rng: &mut Blake2Generator) -> &'static DecodeBuffer {
    if kind == IMULH_R || kind == ISMULH_R {
        return &BUFFER_3310;
    }
    if mul_count < cycle + 1 {
        return &BUFFER_4444;
    }
    if kind == IMUL_RCP {
        return if rng.byte() & 1 != 0 { &BUFFER_484 } else { &BUFFER_493 };
    }
    BUFFERS[(rng.byte() & 3) as usize]
}

const LATENCY: i32 = 170;
const CYCLE_MAP_SIZE: usize = LATENCY as usize + 4;
const LOOK_FORWARD_CYCLES: i32 = 4;
const MAX_THROWAWAY_COUNT: i32 = 256;
const MAX_SIZE: usize = 3 * LATENCY as usize + 2;
const REGISTER_NEEDS_DISPLACEMENT: i32 = 5;

#[derive(Clone, Copy)]
struct RegisterInfo {
    latency: i32,
    last_op_group: i32,
    last_op_par: i32,
}

/// The instruction being generated.
struct Candidate {
    info: &'static Info,
    modifier: u8,
    imm32: u32,
    src: i32,
    dst: i32,
    op_group: i32,
    op_group_par: i32,
    can_reuse: bool,
    group_par_is_source: bool,
}

fn select_register(available: &[i32], rng: &mut Blake2Generator) -> Option<i32> {
    match available.len() {
        0 => None,
        1 => Some(available[0]),
        n => Some(available[(rng.u32() % n as u32) as usize]),
    }
}

impl Candidate {
    fn null() -> Self {
        Self {
            info: &INFO_NOP,
            modifier: 0,
            imm32: 0,
            src: -1,
            dst: -1,
            op_group: INVALID,
            op_group_par: -1,
            can_reuse: false,
            group_par_is_source: false,
        }
    }

    fn create_for_slot(&mut self, rng: &mut Blake2Generator, slot: u32, fetch_type: i32, is_last: bool) {
        let info = match slot {
            3 if is_last => SLOT_3L[(rng.byte() & 3) as usize],
            3 => SLOT_3[(rng.byte() & 1) as usize],
            4 if fetch_type == 4 && !is_last => &INFO_IMUL_R,
            4 => SLOT_4[(rng.byte() & 1) as usize],
            7 => SLOT_7[(rng.byte() & 1) as usize],
            8 => SLOT_8[(rng.byte() & 1) as usize],
            9 => SLOT_9[(rng.byte() & 1) as usize],
            _ => &INFO_IMUL_RCP,
        };
        self.create(info, rng);
    }

    fn create(&mut self, info: &'static Info, rng: &mut Blake2Generator) {
        self.info = info;
        self.src = -1;
        self.dst = -1;
        self.can_reuse = false;
        self.group_par_is_source = false;
        match info.kind {
            ISUB_R => {
                self.modifier = 0;
                self.imm32 = 0;
                self.op_group = IADD_RS;
                self.group_par_is_source = true;
            }
            IXOR_R => {
                self.modifier = 0;
                self.imm32 = 0;
                self.op_group = IXOR_R;
                self.group_par_is_source = true;
            }
            IADD_RS => {
                self.modifier = rng.byte();
                self.imm32 = 0;
                self.op_group = IADD_RS;
                self.group_par_is_source = true;
            }
            IMUL_R => {
                self.modifier = 0;
                self.imm32 = 0;
                self.op_group = IMUL_R;
                self.group_par_is_source = true;
            }
            IROR_C => {
                self.modifier = 0;
                loop {
                    self.imm32 = u32::from(rng.byte() & 63);
                    if self.imm32 != 0 {
                        break;
                    }
                }
                self.op_group = IROR_C;
                self.op_group_par = -1;
            }
            IADD_C7 | IADD_C8 | IADD_C9 => {
                self.modifier = 0;
                self.imm32 = rng.u32();
                self.op_group = IADD_C7;
                self.op_group_par = -1;
            }
            IXOR_C7 | IXOR_C8 | IXOR_C9 => {
                self.modifier = 0;
                self.imm32 = rng.u32();
                self.op_group = IXOR_C7;
                self.op_group_par = -1;
            }
            IMULH_R | ISMULH_R => {
                self.can_reuse = true;
                self.modifier = 0;
                self.imm32 = 0;
                self.op_group = info.kind;
                self.op_group_par = rng.u32() as i32;
            }
            IMUL_RCP => {
                self.modifier = 0;
                loop {
                    self.imm32 = rng.u32();
                    if self.imm32 & self.imm32.wrapping_sub(1) != 0 {
                        break;
                    }
                }
                self.op_group = IMUL_RCP;
                self.op_group_par = -1;
            }
            _ => {}
        }
    }

    fn select_destination(
        &mut self,
        cycle: i32,
        allow_chained_mul: bool,
        registers: &[RegisterInfo; 8],
        rng: &mut Blake2Generator,
    ) -> bool {
        let available: Vec<i32> = (0..8)
            .filter(|&i| {
                let r = &registers[i as usize];
                r.latency <= cycle
                    && (self.can_reuse || i != self.src)
                    && (allow_chained_mul || self.op_group != IMUL_R || r.last_op_group != IMUL_R)
                    && (r.last_op_group != self.op_group || r.last_op_par != self.op_group_par)
                    && (self.info.kind != IADD_RS || i != REGISTER_NEEDS_DISPLACEMENT)
            })
            .collect();
        match select_register(&available, rng) {
            Some(reg) => {
                self.dst = reg;
                true
            }
            None => false,
        }
    }

    fn select_source(&mut self, cycle: i32, registers: &[RegisterInfo; 8], rng: &mut Blake2Generator) -> bool {
        let available: Vec<i32> = (0..8).filter(|&i| registers[i as usize].latency <= cycle).collect();
        if available.len() == 2
            && self.info.kind == IADD_RS
            && (available[0] == REGISTER_NEEDS_DISPLACEMENT || available[1] == REGISTER_NEEDS_DISPLACEMENT)
        {
            self.src = REGISTER_NEEDS_DISPLACEMENT;
            self.op_group_par = REGISTER_NEEDS_DISPLACEMENT;
            return true;
        }
        match select_register(&available, rng) {
            Some(reg) => {
                self.src = reg;
                if self.group_par_is_source {
                    self.op_group_par = reg;
                }
                true
            }
            None => false,
        }
    }
}

fn schedule_uop(uop: u8, ports: &mut [[u8; 3]; CYCLE_MAP_SIZE], mut cycle: i32, commit: bool) -> i32 {
    // Ports are tried in the order P5, P0, P1, so that operations that can
    // go anywhere do not crowd the multiplication port P1.
    while (cycle as usize) < CYCLE_MAP_SIZE {
        let slot = &mut ports[cycle as usize];
        for (port, mask) in [(2, P5), (0, P0), (1, P1)] {
            if uop & mask != 0 && slot[port] == 0 {
                if commit {
                    slot[port] = uop;
                }
                return cycle;
            }
        }
        cycle += 1;
    }
    -1
}

fn schedule_mop(op: &MacroOp, ports: &mut [[u8; 3]; CYCLE_MAP_SIZE], mut cycle: i32, dep_cycle: i32, commit: bool) -> i32 {
    if op.dependent {
        cycle = cycle.max(dep_cycle);
    }
    if op.uop1 == 0 {
        return cycle;
    }
    if op.uop2 == 0 {
        return schedule_uop(op.uop1, ports, cycle, commit);
    }
    // Both micro-operations must execute in the same cycle.
    while (cycle as usize) < CYCLE_MAP_SIZE {
        let cycle1 = schedule_uop(op.uop1, ports, cycle, false);
        let cycle2 = schedule_uop(op.uop2, ports, cycle, false);
        if cycle1 >= 0 && cycle1 == cycle2 {
            if commit {
                schedule_uop(op.uop1, ports, cycle1, true);
                schedule_uop(op.uop2, ports, cycle2, true);
            }
            return cycle1;
        }
        cycle += 1;
    }
    -1
}

/// One instruction of a SuperscalarHash program.
#[derive(Clone, Copy)]
pub struct Instruction {
    kind: i32,
    dst: usize,
    src: usize,
    modifier: u8,
    imm32: u32,
    /// For `IMUL_RCP`, the reciprocal of `imm32`.
    reciprocal: u64,
}

pub struct Program {
    instructions: Vec<Instruction>,
    pub address_register: usize,
}

/// The reciprocal of `IMUL_RCP`: `floor(2^x / divisor)` for the largest `x`
/// that keeps it below 2^64. `divisor` is neither 0 nor a power of 2.
pub fn reciprocal(divisor: u64) -> u64 {
    let bits = 64 - divisor.leading_zeros();
    ((1u128 << (63 + bits)) / u128::from(divisor)) as u64
}

/// Generates one SuperscalarHash program from the generator.
pub fn generate(rng: &mut Blake2Generator) -> Program {
    let mut ports = [[0u8; 3]; CYCLE_MAP_SIZE];
    let mut registers = [RegisterInfo { latency: 0, last_op_group: INVALID, last_op_par: -1 }; 8];
    let mut current = Candidate::null();
    let mut instructions: Vec<Instruction> = Vec::new();
    let mut macro_op_index = 0usize;
    let mut cycle = 0i32;
    let mut dep_cycle = 0i32;
    let mut ports_saturated = false;
    let mut mul_count = 0i32;
    let mut throw_away_count = 0i32;

    let mut decode_cycle = 0i32;
    while decode_cycle < LATENCY && !ports_saturated && instructions.len() < MAX_SIZE {
        let buffer = fetch_next(current.info.kind, decode_cycle, mul_count, rng);
        let mut buffer_index = 0usize;
        while buffer_index < buffer.counts.len() {
            let top_cycle = cycle;
            if macro_op_index >= current.info.ops.len() {
                if ports_saturated || instructions.len() >= MAX_SIZE {
                    break;
                }
                current.create_for_slot(
                    rng,
                    buffer.counts[buffer_index],
                    buffer.index,
                    buffer.counts.len() == buffer_index + 1,
                );
                macro_op_index = 0;
            }
            let op = current.info.ops[macro_op_index];
            let mut schedule_cycle = schedule_mop(&op, &mut ports, cycle, dep_cycle, false);
            if schedule_cycle < 0 {
                ports_saturated = true;
                break;
            }

            if macro_op_index as i32 == current.info.src_op {
                let mut forward = 0;
                while forward < LOOK_FORWARD_CYCLES && !current.select_source(schedule_cycle, &registers, rng) {
                    schedule_cycle += 1;
                    cycle += 1;
                    forward += 1;
                }
                if forward == LOOK_FORWARD_CYCLES {
                    if throw_away_count < MAX_THROWAWAY_COUNT {
                        throw_away_count += 1;
                        macro_op_index = current.info.ops.len();
                        continue;
                    }
                    current = Candidate::null();
                    break;
                }
            }
            if macro_op_index as i32 == current.info.dst_op {
                let mut forward = 0;
                while forward < LOOK_FORWARD_CYCLES
                    && !current.select_destination(schedule_cycle, throw_away_count > 0, &registers, rng)
                {
                    schedule_cycle += 1;
                    cycle += 1;
                    forward += 1;
                }
                if forward == LOOK_FORWARD_CYCLES {
                    if throw_away_count < MAX_THROWAWAY_COUNT {
                        throw_away_count += 1;
                        macro_op_index = current.info.ops.len();
                        continue;
                    }
                    current = Candidate::null();
                    break;
                }
            }
            throw_away_count = 0;

            schedule_cycle = schedule_mop(&op, &mut ports, schedule_cycle, schedule_cycle, true);
            if schedule_cycle < 0 {
                ports_saturated = true;
                break;
            }
            dep_cycle = schedule_cycle + op.latency;

            if macro_op_index as i32 == current.info.result_op {
                let register = &mut registers[current.dst as usize];
                register.latency = dep_cycle;
                register.last_op_group = current.op_group;
                register.last_op_par = current.op_group_par;
            }
            buffer_index += 1;
            macro_op_index += 1;
            if schedule_cycle >= LATENCY {
                ports_saturated = true;
            }
            cycle = top_cycle;

            if macro_op_index >= current.info.ops.len() {
                let dst = current.dst as usize;
                let src = if current.src >= 0 { current.src as usize } else { dst };
                let reciprocal =
                    if current.info.kind == IMUL_RCP { reciprocal(u64::from(current.imm32)) } else { 0 };
                instructions.push(Instruction {
                    kind: current.info.kind,
                    dst,
                    src,
                    modifier: current.modifier,
                    imm32: current.imm32,
                    reciprocal,
                });
                if matches!(current.info.kind, IMUL_R | IMULH_R | ISMULH_R | IMUL_RCP) {
                    mul_count += 1;
                }
            }
        }
        cycle += 1;
        decode_cycle += 1;
    }

    // The address register is the one with the longest dependency chain
    // when every operation takes one cycle (the first such register).
    let mut asic_latencies = [0i32; 8];
    for instruction in &instructions {
        let latency_dst = asic_latencies[instruction.dst] + 1;
        let latency_src =
            if instruction.dst != instruction.src { asic_latencies[instruction.src] + 1 } else { 0 };
        asic_latencies[instruction.dst] = latency_dst.max(latency_src);
    }
    let mut address_register = 0;
    let mut max = 0;
    for (i, &latency) in asic_latencies.iter().enumerate() {
        if latency > max {
            max = latency;
            address_register = i;
        }
    }
    Program { instructions, address_register }
}

fn sign_extend(imm32: u32) -> u64 {
    imm32 as i32 as i64 as u64
}

/// Runs a program over the eight registers.
pub fn execute(program: &Program, r: &mut [u64; 8]) {
    for i in &program.instructions {
        let src = r[i.src];
        let dst = &mut r[i.dst];
        match i.kind {
            ISUB_R => *dst = dst.wrapping_sub(src),
            IXOR_R => *dst ^= src,
            IADD_RS => *dst = dst.wrapping_add(src << ((i.modifier >> 2) % 4)),
            IMUL_R => *dst = dst.wrapping_mul(src),
            IROR_C => *dst = dst.rotate_right(i.imm32),
            IADD_C7 | IADD_C8 | IADD_C9 => *dst = dst.wrapping_add(sign_extend(i.imm32)),
            IXOR_C7 | IXOR_C8 | IXOR_C9 => *dst ^= sign_extend(i.imm32),
            IMULH_R => *dst = ((u128::from(*dst) * u128::from(src)) >> 64) as u64,
            ISMULH_R => *dst = ((i128::from(*dst as i64) * i128::from(src as i64)) >> 64) as u64,
            IMUL_RCP => *dst = dst.wrapping_mul(i.reciprocal),
            _ => {}
        }
    }
}
