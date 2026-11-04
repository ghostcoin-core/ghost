//! The tables of an ML-DSA-44 chunk beside the five tables of a layer
//! circuit (wires, arithmetic, permutation, bits, packing), on the same LogUp
//! bus: every value a row reads or makes is a wire of the circuit, sent as
//! `(wire, v0, .., v7)`. `SampleInBall` also checks its memory on a bus of
//! its own, `ball`, whose messages never leave its two tables.
//!
//! A Keccak lane (eight bytes) is one extension wire whose first four
//! coefficients are its 16-bit limbs, low first, and whose upper four are
//! zero. A coefficient modulo `q` is a base wire. A packed wire carries eight
//! base values in its eight coefficients, so one message moves eight values.
//!
//! The tables are laid out for the layer that verifies a chunk proof: what
//! that verifier pays for is every column a table opens (twice for a table
//! that reads its next row), every bus column and every constraint. So no
//! wide table reads its next row: rows are linked through wires instead.
//!
//! | Table | One row | Columns read or made |
//! |---|---|---|
//! | keccak | one round of Keccak-f\[1600\] (the round of the pinned `p3_keccak_air` AIR, its columns and trace), 24 a permutation | the round's 25 input and 25 output lanes |
//! | xor | one lane XOR | `x`, `y`, `x xor y` |
//! | butterfly | one NTT butterfly with a constant twiddle `zeta` | `a`, `b`, `a + zeta b`, `a - zeta b` modulo `q` |
//! | mac | one NTT-domain check `sum_s A_s z_s - c t = w` modulo `q` | eleven coefficients |
//! | expand | eight three-byte candidates of `RejNTTPoly` | three squeezed lanes, the accepted coefficients, the running count in and out |
//! | ball step | one squeezed byte of `SampleInBall` | the byte, the sign bit it uses; reads and writes on the `ball` bus |
//! | ball position | one coefficient of the result | the coefficient modulo `q`; its first and last value on the `ball` bus |
//! | t1 | 32 coefficients of `t1` unpacked from five public-key lanes | five lanes, four packed wires of eight coefficients times `2^13` |
//! | z | one coefficient of `z` with its norm bound | the coefficient modulo `q` |
//! | hint | `UseHint` on 8 coefficients of `w'_approx`, `w1Encode` of the results | a packed wire of the 8 coefficients; three 16-bit limbs of the encoding and the hint count, packed |
//!
//! Arithmetic modulo `q` is written over BabyBear by hand: every value is
//! range checked by its bits, so each identity holds over the integers, not
//! only modulo the field's prime. See each table's comments for the bounds.

use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;

use p3_air::{AirBuilder, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakCols, NUM_ROUNDS, RC, generate_trace_rows};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

use super::native::{self, Q};
use crate::layers::circuit::{Circuit, Wire};
use crate::layers::{EF, F, coeffs, from_coeffs};

/// The bus of the layer tables.
const BUS: &str = crate::layers::tables::BUS;
/// The bus `SampleInBall` checks its memory on: `(address, value, time)`.
const BALL_BUS: &str = "ball";

/// Which ML-DSA table an AIR is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MlTable {
    Keccak,
    Xor,
    Butterfly,
    Mac,
    Expand,
    BallStep,
    BallPos,
    T1,
    Z,
    Hint,
}

pub(crate) const ML_TABLES: [MlTable; 10] = [
    MlTable::Keccak,
    MlTable::Xor,
    MlTable::Butterfly,
    MlTable::Mac,
    MlTable::Expand,
    MlTable::BallStep,
    MlTable::BallPos,
    MlTable::T1,
    MlTable::Z,
    MlTable::Hint,
];

// Keccak: the columns of one round of the pinned AIR (`KeccakCols` without
// its round flags, export flag and preimage, which only its row-to-row
// constraints read): A in limbs, C, C', A' in bits, A'' in limbs, the bits of
// A''[0, 0] and the limbs of A'''[0, 0].
const KA: usize = 0;
const KC: usize = KA + 100;
const KCP: usize = KC + 320;
const KAP: usize = KCP + 320;
const KAPP: usize = KAP + 1600;
const KB00: usize = KAPP + 100;
const KAPPP: usize = KB00 + 64;
const KECCAK_WIDTH: usize = KAPPP + 4;
/// Preprocessed: 25 input wires, 25 output wires, the enable, the round
/// constant's bits at the only positions any round constant sets.
const KP_EN: usize = 50;
const KP_RC: usize = 51;
const RC_POS: [usize; 7] = [0, 1, 3, 7, 15, 31, 63];
const KECCAK_PREP: usize = KP_RC + RC_POS.len();
/// The rotation offsets `r[x][y]` of Keccak-f\[1600\] (FIPS 202, 3.2.2), as
/// the pinned AIR indexes them.
const ROT: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

// Butterfly columns.
const BF_A: usize = 0;
const BF_B: usize = 1;
const BF_K1: usize = 25;
const BF_K2: usize = 30;
const BF_A2: usize = 35;
const BF_B2: usize = 58;
const BF_WIDTH: usize = 81;
/// Bits of a butterfly's `b`.
const BF_B_BITS: usize = 24;

// Mac columns: eleven operands of two 12-bit limbs, the quotient, two carries.
const MAC_OPS: usize = 11;
const MAC_K: usize = 24 * MAC_OPS;
const MAC_E0: usize = MAC_K + 28;
const MAC_E1: usize = MAC_E0 + 15;
const MAC_WIDTH: usize = MAC_E1 + 16;
const MAC_E0_OFFSET: u32 = 1 << 13;
const MAC_E1_OFFSET: u32 = 1 << 14;

// Expand columns: 192 bits, fifteen a candidate, the count and the done flag.
const EX_CAND: usize = 192;
const EX_PER: usize = 15;
const EX_COUNT: usize = EX_CAND + 8 * EX_PER;
const EX_DONE: usize = EX_COUNT + 1;
const EX_WIDTH: usize = EX_DONE + 1;
/// Expand rows a matrix entry: five SHAKE-128 blocks of 21 lanes, three
/// lanes a row.
pub(crate) const EXPAND_ROWS: usize = 35;
pub(crate) const EXPAND_LANES: usize = 105;
/// Expand preprocessed columns: three lanes, the coefficients' first wire,
/// first, last, enable, the count wires in and out and their enables.
const EXPAND_PREP: usize = 11;

// Ball step columns: the byte, the accepted count `k` (the position is
// `i = 217 + k`), done, accepted, the comparison's 8 bits, `j = i` and its
// inverse helper, `k = 38` and its inverse helper, the value and time read
// at `j`, the time gap's 7 bits, the sign bit.
const BS_B: usize = 0;
const BS_K: usize = 1;
const BS_DONE: usize = 2;
const BS_ACC: usize = 3;
const BS_D: usize = 4;
const BS_EQ: usize = 12;
const BS_INV_EQ: usize = 13;
const BS_IS38: usize = 14;
const BS_INV38: usize = 15;
const BS_CJ: usize = 16;
const BS_TJ: usize = 17;
const BS_DT: usize = 18;
const BS_S: usize = 25;
const BS_WIDTH: usize = 26;
/// Ball step preprocessed columns: the byte's wire, the first sign bit's
/// wire, the verification's first address, the row's time, first, proc
/// (a byte row) and fin (the closing row).
const BALL_STEP_PREP: usize = 7;
/// Ball step rows a verification: 127 squeezed bytes (8 to 134), then the
/// closing row.
pub(crate) const BALL_ROWS: usize = 128;
/// Squeezed bytes `SampleInBall` may read in its one block.
const BALL_BYTES: usize = BALL_ROWS - 1;
/// The first position `SampleInBall` sets, `256 - tau`.
const BALL_FIRST: usize = native::N - native::TAU;

// Z columns.
const Z_WIDTH: usize = 36;
/// `2 (gamma1 - beta - 1)`: the range of `z + gamma1 - beta - 1`.
const Z_SPAN: u32 = 2 * (native::GAMMA1 - native::BETA - 1);
const Z_SHIFT: u32 = native::GAMMA1 - native::BETA - 1;

// Hint columns, per coefficient.
const HI_R1: usize = 0;
const HI_R1C: usize = 6;
const HI_E44: usize = 12;
const HI_INV44: usize = 13;
const HI_U: usize = 14;
const HI_UC: usize = 32;
const HI_POS: usize = 50;
const HI_V: usize = 51;
const HI_H: usize = 68;
const HI_M: usize = 69;
const HI_W1: usize = 70;
const HI_W1C: usize = 76;
const HI_PER: usize = 82;
/// Coefficients a hint row takes: their encoding is 48 bits, three limbs.
pub(crate) const HINT_COEFFS: usize = 8;
const HI_WIDTH: usize = HINT_COEFFS * HI_PER;
const TWO_GAMMA2: u32 = 2 * native::GAMMA2;

/// Main columns of an ML-DSA table.
pub(crate) const fn main_width(t: MlTable) -> usize {
    match t {
        MlTable::Keccak => KECCAK_WIDTH,
        MlTable::Xor => 128,
        MlTable::Butterfly => BF_WIDTH,
        MlTable::Mac => MAC_WIDTH,
        MlTable::Expand => EX_WIDTH,
        MlTable::BallStep => BS_WIDTH,
        MlTable::BallPos => 2,
        MlTable::T1 => 320,
        MlTable::Z => Z_WIDTH,
        MlTable::Hint => HI_WIDTH,
    }
}

/// Preprocessed columns of an ML-DSA table: the wire numbers it reads and
/// makes, its enables and flags, the butterfly's twiddle and the Keccak
/// round's constant.
pub(crate) const fn preprocessed_width(t: MlTable) -> usize {
    match t {
        MlTable::Keccak => KECCAK_PREP,
        MlTable::Xor => 4,
        MlTable::Butterfly => 5 + BF_B_BITS,
        MlTable::Mac => MAC_OPS + 1,
        MlTable::Expand => EXPAND_PREP,
        MlTable::BallStep => BALL_STEP_PREP,
        MlTable::BallPos => 3,
        MlTable::T1 => 5 + 4 + 1,
        MlTable::Z => 2,
        MlTable::Hint => 3,
    }
}

/// Whether a table's constraints read the next row: only the narrow ball
/// step table does, for its running count.
pub(crate) const fn reads_next(t: MlTable) -> bool {
    matches!(t, MlTable::BallStep)
}

/// One Keccak-f\[1600\] permutation: the 25 lanes before each round and
/// after the last, 25 states of 25 lane wires.
#[derive(Clone, Debug)]
pub(crate) struct KeccakRow {
    pub(crate) states: Vec<[Wire; 25]>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct XorRow {
    pub(crate) x: Wire,
    pub(crate) y: Wire,
    pub(crate) z: Wire,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ButterflyRow {
    pub(crate) a: Wire,
    pub(crate) b: Wire,
    pub(crate) a2: Wire,
    pub(crate) b2: Wire,
    pub(crate) zeta: u32,
}

/// `sum_s A_s Z_s - C T = W` modulo `q`: `A0..A3, Z0..Z3, C, T, W`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MacRow {
    pub(crate) ops: [Wire; MAC_OPS],
}

/// One matrix entry: its 105 squeezed lanes, its 256 coefficient wires,
/// consecutive from `base`, and the wires carrying the running count and
/// done flag from each row to the next.
#[derive(Clone, Debug)]
pub(crate) struct ExpandPoly {
    pub(crate) lanes: Vec<Wire>,
    pub(crate) base: Wire,
    pub(crate) chain: Vec<Wire>,
}

/// One `SampleInBall`: lanes 0 to 16 of its squeezed block, the wires of
/// the bytes it may read (8 to 134), the wire of the first of the 64 sign
/// bits (consecutive wires), and the 256 coefficient wires of the result.
#[derive(Clone, Debug)]
pub(crate) struct BallBlock {
    pub(crate) lanes: [Wire; 17],
    pub(crate) bytes: Vec<Wire>,
    pub(crate) sign0: Wire,
    pub(crate) c: Vec<Wire>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct T1Row {
    pub(crate) lanes: [Wire; 5],
    pub(crate) packed: [Wire; 4],
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ZRow {
    pub(crate) z: Wire,
    /// `z + gamma1 - beta - 1`.
    pub(crate) u: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct HintRow {
    pub(crate) w: [Wire; HINT_COEFFS],
    pub(crate) h: [bool; HINT_COEFFS],
    /// The packed wire of `w`.
    pub(crate) packed: Wire,
    /// The packed wire of the three limbs and the hint count.
    pub(crate) out: Wire,
}

/// The rows of every ML-DSA table of a circuit.
#[derive(Clone, Debug, Default)]
pub(crate) struct MlRows {
    pub(crate) keccak: Vec<KeccakRow>,
    pub(crate) xor: Vec<XorRow>,
    pub(crate) butterfly: Vec<ButterflyRow>,
    pub(crate) mac: Vec<MacRow>,
    pub(crate) expand: Vec<ExpandPoly>,
    pub(crate) ball: Vec<BallBlock>,
    pub(crate) t1: Vec<T1Row>,
    pub(crate) z: Vec<ZRow>,
    pub(crate) hint: Vec<HintRow>,
}

impl MlRows {
    /// The rows a table fills.
    pub(crate) fn entries(&self, t: MlTable) -> usize {
        match t {
            MlTable::Keccak => self.keccak.len() * NUM_ROUNDS,
            MlTable::Xor => self.xor.len(),
            MlTable::Butterfly => self.butterfly.len(),
            MlTable::Mac => self.mac.len(),
            MlTable::Expand => self.expand.len() * EXPAND_ROWS,
            MlTable::BallStep => self.ball.len() * BALL_ROWS,
            MlTable::BallPos => self.ball.len() * native::N,
            MlTable::T1 => self.t1.len(),
            MlTable::Z => self.z.len(),
            MlTable::Hint => self.hint.len(),
        }
    }
}

/// The lane value of an extension wire value: its first four coefficients
/// as 16-bit limbs. `None` when it is not a lane.
pub(crate) fn lane_of(v: EF) -> Option<u64> {
    let cs = coeffs(&v);
    if cs[4..].iter().any(|&x| x != F::ZERO) {
        return None;
    }
    let mut out = 0u64;
    for (l, x) in cs[..4].iter().enumerate() {
        let x = x.as_canonical_u32();
        if x >= 1 << 16 {
            return None;
        }
        out |= u64::from(x) << (16 * l);
    }
    Some(out)
}

/// The extension value of a lane.
pub(crate) fn lane_ef(x: u64) -> EF {
    from_coeffs(|i| if i < 4 { F::from_u32((x >> (16 * i)) as u32 & 0xFFFF) } else { F::ZERO })
}

/// A wire's lane value, zero when it is not a lane (the circuit records why).
fn lane(c: &Circuit, w: Wire) -> u64 {
    lane_of(c.value(w)).unwrap_or(0)
}

fn base_u32(c: &Circuit, w: Wire) -> u32 {
    c.base_value(w).as_canonical_u32()
}

/// One round of Keccak-f\[1600\] (FIPS 202, 3.3) on lanes `s[x + 5 y]`.
fn keccak_round(s: &mut [u64; 25], round: usize) {
    let c: [u64; 5] = core::array::from_fn(|x| s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]);
    for x in 0..5 {
        let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            s[x + 5 * y] ^= d;
        }
    }
    let mut b = [0u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = s[x + 5 * y].rotate_left(ROT[x][y]);
        }
    }
    for x in 0..5 {
        for y in 0..5 {
            s[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        }
    }
    s[0] ^= RC[round];
}

/// `zeta 2^j mod q` for the bits of a butterfly's `b`.
fn twiddle_bits(zeta: u32) -> [u32; BF_B_BITS] {
    core::array::from_fn(|j| ((u64::from(zeta) << j) % u64::from(Q)) as u32)
}

/// The candidates of one matrix entry, from its lanes: the value of each
/// three-byte group with its top bit cleared, and whether it is below `q`.
fn candidates(lanes: &[u64]) -> Vec<(u32, bool)> {
    let bytes: Vec<u8> = lanes.iter().flat_map(|l| l.to_le_bytes()).collect();
    bytes
        .chunks(3)
        .map(|b| {
            let v = u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2] & 0x7F) << 16;
            (v, v < Q)
        })
        .collect()
}

/// Which candidates an entry sends: the first 256 accepted ones.
fn sent(cands: &[(u32, bool)]) -> Vec<bool> {
    let mut n = 0;
    cands
        .iter()
        .map(|&(_, ok)| {
            let s = ok && n < native::N;
            n += usize::from(s);
            s
        })
        .collect()
}

/// The running count and done flag of an entry before each of its rows,
/// and after the last: `EXPAND_ROWS + 1` pairs.
fn expand_progress(s: &[bool]) -> Vec<(usize, bool)> {
    let mut out = Vec::with_capacity(EXPAND_ROWS + 1);
    let (mut count, mut done) = (0usize, false);
    for k in 0..EXPAND_ROWS {
        out.push((count, done));
        for &send in &s[8 * k..8 * k + 8] {
            done = done || (send && count == 255);
            count += usize::from(send);
        }
    }
    out.push((count, done));
    out
}

/// The value of a running count wire: the count, then the done flag.
fn progress_ef(count: usize, done: bool) -> EF {
    from_coeffs(|i| match i {
        0 => F::from_usize(count),
        1 => F::from_bool(done),
        _ => F::ZERO,
    })
}

/// `SampleInBall` over the squeezed bytes 8 to 134 of a block: the result,
/// and whether it finished within them.
fn ball(lanes: &[u64; 17]) -> ([i8; 256], bool) {
    let steps = ball_steps(lanes);
    (steps.c, steps.done)
}

/// One byte row of `SampleInBall` as its table holds it.
#[derive(Clone, Copy, Debug, Default)]
struct BallStepRow {
    b: u32,
    k: u32,
    done: bool,
    acc: bool,
    d: u32,
    eq: bool,
    cj: i8,
    tj: u32,
    sbit: u32,
}

/// The rows of one `SampleInBall`, its result with each position's last
/// write time, and whether it finished.
struct BallSteps {
    rows: Vec<BallStepRow>,
    c: [i8; 256],
    t: [u32; 256],
    done: bool,
}

/// `SampleInBall` (FIPS 204, algorithm 29) byte by byte, as memory: at the
/// byte of row `r` (time `r + 1`), when accepted, `c[i] = c[j]` and
/// `c[j] = (-1)^h_k`, the sign `k` the count of accepted bytes before.
fn ball_steps(lanes: &[u64; 17]) -> BallSteps {
    let bytes: Vec<u8> = lanes.iter().flat_map(|l| l.to_le_bytes()).collect();
    let signs = lanes[0];
    let mut c = [0i8; 256];
    let mut t = [0u32; 256];
    let (mut k, mut done) = (0usize, false);
    let mut rows = Vec::with_capacity(BALL_BYTES);
    for r in 0..BALL_BYTES {
        let b = usize::from(bytes[8 + r]);
        let i = BALL_FIRST + k;
        let acc = !done && b <= i;
        let d = if acc {
            i - b
        } else if done {
            0
        } else {
            b - i - 1
        };
        let eq = acc && b == i;
        let (cj, tj) = if acc { (c[b], t[b]) } else { (0, 0) };
        let sbit = if acc { (signs >> k) as u32 & 1 } else { 0 };
        rows.push(BallStepRow {
            b: b as u32,
            k: k as u32,
            done,
            acc,
            d: d as u32,
            eq,
            cj,
            tj,
            sbit,
        });
        if acc {
            let now = (r + 1) as u32;
            if !eq {
                c[i] = cj;
                t[i] = now;
            }
            c[b] = if sbit == 1 { -1 } else { 1 };
            t[b] = now;
            k += 1;
            done = k == native::TAU;
        }
    }
    BallSteps { rows, c, t, done }
}

/// A coefficient in `{-1, 0, 1}` as a field element.
fn small_f(x: i8) -> F {
    if x < 0 { -F::ONE } else { F::from_u8(x as u8) }
}

fn mod_q(x: i8) -> u32 {
    if x < 0 { Q - 1 } else { x as u32 }
}

/// `(r1, r0)` of `w = r1 2 gamma2 + r0` with `r0` in `(-gamma2, gamma2]`,
/// `r1` in `[0, 44]`: `None` for a `w` outside that range.
fn split_w(w: u32) -> Option<(u32, i32)> {
    let r0 = (w % TWO_GAMMA2) as i32;
    let (r1, r0) = if r0 > native::GAMMA2 as i32 {
        (w / TWO_GAMMA2 + 1, r0 - TWO_GAMMA2 as i32)
    } else {
        (w / TWO_GAMMA2, r0)
    };
    (r1 <= 44).then_some((r1, r0))
}

/// The hint row's values for one coefficient: `(r1, r0, e44, pos, w1, m)`.
fn hint_values(w: u32, h: bool) -> Option<(u32, i32, bool, bool, u32, i32)> {
    let (r1, r0) = split_w(w)?;
    let e44 = r1 == 44;
    let r1p = if e44 { 0 } else { r1 } as i32;
    let r0p = r0 - i32::from(e44);
    let pos = r0p > 0;
    let raw = r1p + if h { if pos { 1 } else { -1 } } else { 0 };
    let (w1, m) = if raw < 0 {
        (raw + 44, 1)
    } else if raw >= 44 {
        (raw - 44, -1)
    } else {
        (raw, 0)
    };
    Some((r1, r0, e44, pos, w1 as u32, m))
}

impl Circuit {
    fn check_lane(&mut self, w: Wire) -> u64 {
        match lane_of(self.value(w)) {
            Some(x) => x,
            None => {
                let n = w.0;
                self.fail(|| alloc::format!("wire {n} read as a lane is not one"));
                0
            }
        }
    }

    /// The four limb wires of a lane wire, by a packing row.
    fn lane_limbs(&mut self, lane: Wire, value: u64) -> [Wire; 4] {
        let limbs: [Wire; 4] = core::array::from_fn(|l| self.hint_base(F::from_u32((value >> (16 * l)) as u32 & 0xFFFF)));
        let zero = self.zero();
        self.pack_into([limbs[0], limbs[1], limbs[2], limbs[3], zero, zero, zero, zero], lane);
        limbs
    }

    /// Keccak-f\[1600\] of 25 lane wires, a round a row: a wire for every
    /// lane between rounds.
    pub(crate) fn ml_keccak(&mut self, input: [Wire; 25]) -> [Wire; 25] {
        let start: [u64; 25] = core::array::from_fn(|i| self.check_lane(input[i]));
        let mut s = start;
        let mut states = Vec::with_capacity(NUM_ROUNDS + 1);
        states.push(input);
        for r in 0..NUM_ROUNDS {
            keccak_round(&mut s, r);
            states.push(core::array::from_fn(|i| self.hint(lane_ef(s[i]))));
        }
        let mut whole = start;
        native::keccak_f(&mut whole);
        assert_eq!(s, whole, "the rounds make the pinned permutation");
        let output = states[NUM_ROUNDS];
        self.ml.keccak.push(KeccakRow { states });
        output
    }

    /// The XOR of two lane wires.
    pub(crate) fn ml_xor(&mut self, x: Wire, y: Wire) -> Wire {
        let v = self.check_lane(x) ^ self.check_lane(y);
        let z = self.hint(lane_ef(v));
        self.ml.xor.push(XorRow { x, y, z });
        z
    }

    /// `(a + zeta b, a - zeta b)` modulo `q`, canonical: `a` and `b` in
    /// `[0, 2^24)`.
    pub(crate) fn ml_butterfly(&mut self, a: Wire, b: Wire, zeta: u32) -> (Wire, Wire) {
        let av = i64::from(signed(self.base_value(a)));
        let bv = i64::from(base_u32(self, b));
        if !(0..1 << 24).contains(&av) || bv >= 1 << 24 {
            self.fail(|| "a butterfly input is out of range".into());
        }
        let t = i64::from(zeta) * bv;
        let q = i64::from(Q);
        let a2 = (av + t).rem_euclid(q) as u32;
        let b2 = (av - t).rem_euclid(q) as u32;
        let a2w = self.hint_base(F::from_u32(a2));
        let b2w = self.hint_base(F::from_u32(b2));
        self.ml.butterfly.push(ButterflyRow { a, b, a2: a2w, b2: b2w, zeta });
        (a2w, b2w)
    }

    /// Constrain `sum_s A_s Z_s - C T = W` modulo `q`.
    pub(crate) fn ml_mac(&mut self, ops: [Wire; MAC_OPS]) {
        let v: [u64; MAC_OPS] = core::array::from_fn(|i| u64::from(base_u32(self, ops[i])));
        if v.iter().any(|&x| x >= 1 << 24) {
            self.fail(|| "a mac operand is out of range".into());
        }
        let q = u64::from(Q);
        let lhs = (0..4).fold(0u64, |acc, s| (acc + v[s] % q * (v[4 + s] % q)) % q);
        let rhs = (v[8] % q * (v[9] % q) + v[10]) % q;
        if lhs != rhs {
            self.fail(|| "an NTT-domain product does not hold".into());
        }
        self.ml.mac.push(MacRow { ops });
    }

    /// `RejNTTPoly` from 105 squeezed lanes: 256 coefficient wires.
    pub(crate) fn ml_expand(&mut self, lanes: Vec<Wire>) -> Vec<Wire> {
        assert_eq!(lanes.len(), EXPAND_LANES);
        let vals: Vec<u64> = lanes.iter().map(|&w| self.check_lane(w)).collect();
        let cands = candidates(&vals);
        let s = sent(&cands);
        let mut out = Vec::with_capacity(native::N);
        for (&(v, _), &sv) in cands.iter().zip(&s) {
            if sv {
                out.push(v);
            }
        }
        if out.len() < native::N {
            self.fail(|| "a matrix entry needs more than five SHAKE-128 blocks".into());
        }
        out.resize(native::N, 0);
        let wires: Vec<Wire> = out.iter().map(|&v| self.hint_base(F::from_u32(v))).collect();
        debug_assert!(wires.windows(2).all(|p| p[1].0 == p[0].0 + 1));
        let progress = expand_progress(&s);
        let chain: Vec<Wire> =
            (1..EXPAND_ROWS).map(|k| self.hint(progress_ef(progress[k].0, progress[k].1))).collect();
        self.ml.expand.push(ExpandPoly {
            lanes,
            base: wires[0],
            chain,
        });
        wires
    }

    /// `SampleInBall` from lanes 0 to 16 of its squeezed block: 256
    /// coefficient wires in `{0, 1, q - 1}`. The sign bits of lane 0 and the
    /// bytes of lanes 1 to 16 get wires from their limbs' bits rows.
    pub(crate) fn ml_ball(&mut self, lanes: [Wire; 17]) -> [Wire; 256] {
        let vals: [u64; 17] = core::array::from_fn(|i| self.check_lane(lanes[i]));
        let limbs = self.lane_limbs(lanes[0], vals[0]);
        let mut signs = Vec::with_capacity(64);
        for limb in limbs {
            signs.extend(self.bits_low(limb, 16));
        }
        assert!(signs.windows(2).all(|p| p[1].0 == p[0].0 + 1), "the sign bits are consecutive wires");
        let mut bytes = Vec::with_capacity(2 * 4 * 16);
        for l in 1..17 {
            for limb in self.lane_limbs(lanes[l], vals[l]) {
                let bits = self.bits_low(limb, 16);
                let lo = self.from_bits(&bits[..8]);
                let hi = self.from_bits(&bits[8..]);
                bytes.push(lo);
                bytes.push(hi);
            }
        }
        bytes.truncate(BALL_BYTES);
        let (cv, done) = ball(&vals);
        if !done {
            self.fail(|| "SampleInBall needs more than one SHAKE-256 block".into());
        }
        let c: [Wire; 256] = core::array::from_fn(|k| self.hint_base(F::from_u32(mod_q(cv[k]))));
        self.ml.ball.push(BallBlock {
            lanes,
            bytes,
            sign0: signs[0],
            c: c.to_vec(),
        });
        c
    }

    /// 32 coefficients of `t1`, times `2^13`, from five public-key lanes,
    /// sent as four packed wires.
    pub(crate) fn ml_t1(&mut self, lanes: [Wire; 5]) -> [Wire; 32] {
        let vals: [u64; 5] = core::array::from_fn(|i| self.check_lane(lanes[i]));
        let coeffs: [Wire; 32] = core::array::from_fn(|k| {
            let bit = 10 * k;
            let t = (0..10).fold(0u32, |acc, b| {
                let at = bit + b;
                acc | ((vals[at / 64] >> (at % 64)) as u32 & 1) << b
            });
            self.hint_base(F::from_u32(t << native::D))
        });
        let packed: [Wire; 4] = core::array::from_fn(|g| self.from_coefficients(&coeffs[8 * g..8 * g + 8]));
        self.ml.t1.push(T1Row { lanes, packed });
        coeffs
    }

    /// A coefficient of `z`, which must satisfy `|z| < gamma1 - beta`, as
    /// `z + q`.
    pub(crate) fn ml_z(&mut self, z: i32) -> Wire {
        let u = i64::from(z) + i64::from(Z_SHIFT);
        if !(0..=i64::from(Z_SPAN)).contains(&u) {
            self.fail(|| "a coefficient of z is out of its bound".into());
        }
        let u = u.clamp(0, i64::from(Z_SPAN)) as u32;
        let w = self.hint_base(F::from_u32(u + Q - Z_SHIFT));
        self.ml.z.push(ZRow { z: w, u });
        w
    }

    /// `UseHint` on 8 coefficient wires with their hint bits, and
    /// `w1Encode` of the results: three 16-bit limb wires, and the number of
    /// hint bits set.
    pub(crate) fn ml_hint(&mut self, w: [Wire; HINT_COEFFS], h: [bool; HINT_COEFFS]) -> ([Wire; 3], Wire) {
        let mut bits = 0u64;
        for k in 0..HINT_COEFFS {
            let v = base_u32(self, w[k]);
            let w1 = match hint_values(v, h[k]) {
                Some(x) => x.4,
                None => {
                    self.fail(|| "a coefficient of w'_approx is out of range".into());
                    0
                }
            };
            bits |= u64::from(w1) << (6 * k);
        }
        let limbs: [u32; 3] = core::array::from_fn(|l| (bits >> (16 * l)) as u32 & 0xFFFF);
        let count = h.iter().filter(|&&b| b).count() as u32;
        let packed = self.from_coefficients(&w);
        let out = self.hint(from_coeffs(|i| match i {
            0..3 => F::from_u32(limbs[i]),
            3 => F::from_u32(count),
            _ => F::ZERO,
        }));
        let lw: [Wire; 3] = core::array::from_fn(|l| self.hint_base(F::from_u32(limbs[l])));
        let hw = self.hint_base(F::from_u32(count));
        let zero = self.zero();
        self.pack_into([lw[0], lw[1], lw[2], hw, zero, zero, zero, zero], out);
        self.ml.hint.push(HintRow { w, h, packed, out });
        (lw, hw)
    }
}

/// A field value as a signed integer, small negatives below zero.
fn signed(x: F) -> i32 {
    let v = x.as_canonical_u32();
    if v > F::ORDER_U32 / 2 { v as i32 - F::ORDER_U32 as i32 } else { v as i32 }
}

/// Count every wire the ML-DSA rows read, the way their tables send them.
pub(crate) fn count_reads(c: &Circuit, reads: &mut [u32]) {
    let rows = &c.ml;
    let mut read = |w: Wire| reads[w.0 as usize] += 1;
    for r in &rows.keccak {
        // Round `r` reads the lanes before it and makes those after it.
        for pair in r.states.windows(2) {
            pair[0].iter().chain(&pair[1]).for_each(|&w| read(w));
        }
    }
    for r in &rows.xor {
        [r.x, r.y, r.z].into_iter().for_each(&mut read);
    }
    for r in &rows.butterfly {
        [r.a, r.b, r.a2, r.b2].into_iter().for_each(&mut read);
    }
    for r in &rows.mac {
        r.ops.into_iter().for_each(&mut read);
    }
    for p in &rows.expand {
        p.lanes.iter().for_each(|&w| read(w));
        let vals: Vec<u64> = p.lanes.iter().map(|&w| lane(c, w)).collect();
        let s = sent(&candidates(&vals));
        for i in 0..s.iter().filter(|&&x| x).count() {
            read(Wire(p.base.0 + i as u32));
        }
        // Each count wire is made by one row and read by the next.
        for &w in &p.chain {
            read(w);
            read(w);
        }
    }
    for b in &rows.ball {
        b.bytes.iter().for_each(|&w| read(w));
        let vals: [u64; 17] = core::array::from_fn(|i| lane(c, b.lanes[i]));
        let accepted = ball_steps(&vals).rows.iter().filter(|r| r.acc).count();
        for k in 0..accepted {
            read(Wire(b.sign0.0 + k as u32));
        }
        b.c.iter().for_each(|&w| read(w));
    }
    for r in &rows.t1 {
        r.lanes.iter().chain(&r.packed).for_each(|&w| read(w));
    }
    for r in &rows.z {
        read(r.z);
    }
    for r in &rows.hint {
        read(r.packed);
        read(r.out);
    }
}

fn wid(w: Wire) -> F {
    F::from_u32(w.0)
}

fn put_bits(row: &mut [F], at: usize, v: u64, n: usize) {
    for b in 0..n {
        row[at + b] = F::from_u32((v >> b) as u32 & 1);
    }
}

/// A table's preprocessed columns at `height` rows.
pub(crate) fn preprocessed(t: MlTable, rows: &MlRows, height: usize) -> RowMajorMatrix<F> {
    let width = preprocessed_width(t);
    let mut m = vec![F::ZERO; height * width];
    match t {
        MlTable::Keccak => {
            // Every round constant sets bits only at RC_POS.
            let mask = RC_POS.iter().fold(0u64, |acc, &z| acc | 1 << z);
            assert!(RC.iter().all(|&rc| rc & !mask == 0), "round constants set bits only at RC_POS");
            for (p, r) in rows.keccak.iter().enumerate() {
                for k in 0..NUM_ROUNDS {
                    let at = (p * NUM_ROUNDS + k) * width;
                    for lane in 0..25 {
                        m[at + lane] = wid(r.states[k][lane]);
                        m[at + 25 + lane] = wid(r.states[k + 1][lane]);
                    }
                    m[at + KP_EN] = F::ONE;
                    for (j, &z) in RC_POS.iter().enumerate() {
                        m[at + KP_RC + j] = F::from_u32((RC[k] >> z) as u32 & 1);
                    }
                }
            }
        }
        MlTable::Xor => {
            for (i, r) in rows.xor.iter().enumerate() {
                let at = i * width;
                m[at] = wid(r.x);
                m[at + 1] = wid(r.y);
                m[at + 2] = wid(r.z);
                m[at + 3] = F::ONE;
            }
        }
        MlTable::Butterfly => {
            for (i, r) in rows.butterfly.iter().enumerate() {
                let at = i * width;
                for (k, w) in [r.a, r.b, r.a2, r.b2].into_iter().enumerate() {
                    m[at + k] = wid(w);
                }
                m[at + 4] = F::ONE;
                for (j, c) in twiddle_bits(r.zeta).into_iter().enumerate() {
                    m[at + 5 + j] = F::from_u32(c);
                }
            }
        }
        MlTable::Mac => {
            for (i, r) in rows.mac.iter().enumerate() {
                let at = i * width;
                for (k, &w) in r.ops.iter().enumerate() {
                    m[at + k] = wid(w);
                }
                m[at + MAC_OPS] = F::ONE;
            }
        }
        MlTable::Expand => {
            for (p, poly) in rows.expand.iter().enumerate() {
                for k in 0..EXPAND_ROWS {
                    let at = (p * EXPAND_ROWS + k) * width;
                    for j in 0..3 {
                        m[at + j] = wid(poly.lanes[3 * k + j]);
                    }
                    m[at + 3] = wid(poly.base);
                    m[at + 4] = F::from_bool(k == 0);
                    m[at + 5] = F::from_bool(k == EXPAND_ROWS - 1);
                    m[at + 6] = F::ONE;
                    if k > 0 {
                        m[at + 7] = wid(poly.chain[k - 1]);
                        m[at + 9] = F::ONE;
                    }
                    if k < EXPAND_ROWS - 1 {
                        m[at + 8] = wid(poly.chain[k]);
                        m[at + 10] = F::ONE;
                    }
                }
            }
        }
        MlTable::BallStep => {
            for (v, b) in rows.ball.iter().enumerate() {
                for r in 0..BALL_ROWS {
                    let at = (v * BALL_ROWS + r) * width;
                    let proc = r < BALL_BYTES;
                    if proc {
                        m[at] = wid(b.bytes[r]);
                    }
                    m[at + 1] = wid(b.sign0);
                    m[at + 2] = F::from_usize(native::N * v);
                    m[at + 3] = F::from_usize(r + 1);
                    m[at + 4] = F::from_bool(r == 0);
                    m[at + 5] = F::from_bool(proc);
                    m[at + 6] = F::from_bool(!proc);
                }
            }
        }
        MlTable::BallPos => {
            for (v, b) in rows.ball.iter().enumerate() {
                for p in 0..native::N {
                    let at = (v * native::N + p) * width;
                    m[at] = F::from_usize(native::N * v + p);
                    m[at + 1] = wid(b.c[p]);
                    m[at + 2] = F::ONE;
                }
            }
        }
        MlTable::T1 => {
            for (i, r) in rows.t1.iter().enumerate() {
                let at = i * width;
                for (k, w) in r.lanes.iter().chain(&r.packed).enumerate() {
                    m[at + k] = wid(*w);
                }
                m[at + 9] = F::ONE;
            }
        }
        MlTable::Z => {
            for (i, r) in rows.z.iter().enumerate() {
                m[i * width] = wid(r.z);
                m[i * width + 1] = F::ONE;
            }
        }
        MlTable::Hint => {
            for (i, r) in rows.hint.iter().enumerate() {
                let at = i * width;
                m[at] = wid(r.packed);
                m[at + 1] = wid(r.out);
                m[at + 2] = F::ONE;
            }
        }
    }
    RowMajorMatrix::new(m, width)
}

/// A table's main trace at `height` rows, from the circuit's wire values.
pub(crate) fn trace(t: MlTable, c: &Circuit, height: usize) -> RowMajorMatrix<F> {
    let rows = &c.ml;
    let width = main_width(t);
    let mut m = vec![F::ZERO; height * width];
    match t {
        MlTable::Keccak => {
            let inputs: Vec<[u64; 25]> =
                rows.keccak.iter().map(|r| core::array::from_fn(|i| lane(c, r.states[0][i]))).collect();
            let used = inputs.len() * NUM_ROUNDS;
            if used > 0 {
                let keccak = generate_trace_rows::<F>(inputs, 0);
                let cols = keccak.width;
                for r in 0..used {
                    let k: &KeccakCols<F> = keccak.values[r * cols..(r + 1) * cols].borrow();
                    let row = &mut m[r * width..(r + 1) * width];
                    for y in 0..5 {
                        for x in 0..5 {
                            let lane = 5 * y + x;
                            for limb in 0..4 {
                                row[KA + 4 * lane + limb] = k.a[y][x][limb];
                                row[KAPP + 4 * lane + limb] = k.a_prime_prime[y][x][limb];
                            }
                            for z in 0..64 {
                                row[KAP + 64 * lane + z] = k.a_prime[y][x][z];
                            }
                        }
                    }
                    for x in 0..5 {
                        for z in 0..64 {
                            row[KC + 64 * x + z] = k.c[x][z];
                            row[KCP + 64 * x + z] = k.c_prime[x][z];
                        }
                    }
                    row[KB00..KB00 + 64].copy_from_slice(&k.a_prime_prime_0_0_bits);
                    row[KAPPP..KAPPP + 4].copy_from_slice(&k.a_prime_prime_prime_0_0_limbs);
                }
            }
        }
        MlTable::Xor => {
            for (i, r) in rows.xor.iter().enumerate() {
                let row = &mut m[i * width..(i + 1) * width];
                put_bits(row, 0, lane(c, r.x), 64);
                put_bits(row, 64, lane(c, r.y), 64);
            }
        }
        MlTable::Butterfly => {
            for (i, r) in rows.butterfly.iter().enumerate() {
                let row = &mut m[i * width..(i + 1) * width];
                let a = c.base_value(r.a);
                let b = base_u32(c, r.b);
                let a2 = base_u32(c, r.a2);
                let b2 = base_u32(c, r.b2);
                let s: i64 = twiddle_bits(r.zeta)
                    .iter()
                    .enumerate()
                    .map(|(j, &cj)| i64::from(cj) * i64::from(b >> j & 1))
                    .sum();
                let av = i64::from(signed(a));
                let q = i64::from(Q);
                let k1 = (av + s - i64::from(a2)).div_euclid(q);
                let k2 = (i64::from(b2) - av + s).div_euclid(q);
                row[BF_A] = a;
                put_bits(row, BF_B, u64::from(b), BF_B_BITS);
                put_bits(row, BF_K1, k1.clamp(0, 31) as u64, 5);
                put_bits(row, BF_K2, k2.clamp(0, 31) as u64, 5);
                put_bits(row, BF_A2, u64::from(a2), 23);
                put_bits(row, BF_B2, u64::from(b2), 23);
            }
        }
        MlTable::Mac => {
            for (i, r) in rows.mac.iter().enumerate() {
                let row = &mut m[i * width..(i + 1) * width];
                let v: [u64; MAC_OPS] = core::array::from_fn(|k| u64::from(base_u32(c, r.ops[k])));
                for (k, &x) in v.iter().enumerate() {
                    put_bits(row, 24 * k, x, 24);
                }
                let lo = |x: u64| x & 0xFFF;
                let hi = |x: u64| x >> 12;
                let q = u128::from(Q);
                let lhs: u128 = (0..4).map(|s| u128::from(v[s]) * u128::from(v[4 + s])).sum::<u128>() + (q << 25);
                let rhs = u128::from(v[8]) * u128::from(v[9]) + u128::from(v[10]);
                let kp = lhs.saturating_sub(rhs) / q;
                put_bits(row, MAC_K, kp as u64, 28);
                let (k0, k1) = (kp as i64 & 0xFFF, (kp >> 12) as i64 & 0xFFF);
                let s = |x: u64| x as i64;
                let p0: i64 = (0..4).map(|t| s(lo(v[t])) * s(lo(v[4 + t]))).sum::<i64>()
                    - s(lo(v[8])) * s(lo(v[9]))
                    - s(lo(v[10]))
                    - k0;
                let p1: i64 = (0..4)
                    .map(|t| s(lo(v[t])) * s(hi(v[4 + t])) + s(hi(v[t])) * s(lo(v[4 + t])))
                    .sum::<i64>()
                    - (s(lo(v[8])) * s(hi(v[9])) + s(hi(v[8])) * s(lo(v[9])))
                    - s(hi(v[10]))
                    - (k0 * 2046 + k1);
                let e0 = p0.div_euclid(4096);
                let e1 = (p1 + e0).div_euclid(4096);
                put_bits(row, MAC_E0, (e0 + i64::from(MAC_E0_OFFSET)).clamp(0, (1 << 15) - 1) as u64, 15);
                put_bits(row, MAC_E1, (e1 + i64::from(MAC_E1_OFFSET)).clamp(0, (1 << 16) - 1) as u64, 16);
            }
        }
        MlTable::Expand => {
            let used = rows.expand.len() * EXPAND_ROWS;
            for (p, poly) in rows.expand.iter().enumerate() {
                let vals: Vec<u64> = poly.lanes.iter().map(|&w| lane(c, w)).collect();
                let cands = candidates(&vals);
                let s = sent(&cands);
                let mut count = 0usize;
                let mut done = false;
                for k in 0..EXPAND_ROWS {
                    let row = &mut m[(p * EXPAND_ROWS + k) * width..(p * EXPAND_ROWS + k + 1) * width];
                    for j in 0..3 {
                        put_bits(row, 64 * j, vals[3 * k + j], 64);
                    }
                    row[EX_COUNT] = F::from_usize(count);
                    row[EX_DONE] = F::from_bool(done);
                    let mut idx = count;
                    for mm in 0..8 {
                        let g = 8 * k + mm;
                        expand_candidate(row, mm, cands[g].0, s[g], idx, &mut done);
                        idx += usize::from(s[g]);
                    }
                    count = idx;
                }
            }
            // Padding rows: done, so nothing is sent.
            for r in used..height {
                let row = &mut m[r * width..(r + 1) * width];
                row[EX_DONE] = F::ONE;
                let mut done = true;
                for mm in 0..8 {
                    expand_candidate(row, mm, 0, false, 0, &mut done);
                }
            }
        }
        MlTable::BallStep => {
            for (v, b) in rows.ball.iter().enumerate() {
                let vals: [u64; 17] = core::array::from_fn(|i| lane(c, b.lanes[i]));
                let steps = ball_steps(&vals);
                let last = steps.rows.last().copied().unwrap_or_default();
                for r in 0..BALL_ROWS {
                    let row = &mut m[(v * BALL_ROWS + r) * width..(v * BALL_ROWS + r + 1) * width];
                    let s = match steps.rows.get(r) {
                        Some(&s) => s,
                        // The closing row carries the count and done flag on.
                        None => {
                            let k = last.k + u32::from(last.acc);
                            BallStepRow {
                                k,
                                done: last.done || (last.acc && last.k as usize + 1 == native::TAU),
                                ..BallStepRow::default()
                            }
                        }
                    };
                    let i = BALL_FIRST as u32 + s.k;
                    row[BS_B] = F::from_u32(s.b);
                    row[BS_K] = F::from_u32(s.k);
                    row[BS_DONE] = F::from_bool(s.done);
                    row[BS_ACC] = F::from_bool(s.acc);
                    put_bits(row, BS_D, u64::from(s.d), 8);
                    row[BS_EQ] = F::from_bool(s.eq);
                    let diff = F::from_u32(i) - F::from_u32(s.b);
                    row[BS_INV_EQ] = diff.try_inverse().unwrap_or(F::ZERO);
                    let k38 = F::from_u32(s.k) - F::from_u32(38);
                    row[BS_IS38] = F::from_bool(s.k == 38);
                    row[BS_INV38] = k38.try_inverse().unwrap_or(F::ZERO);
                    row[BS_CJ] = small_f(s.cj);
                    row[BS_TJ] = F::from_u32(s.tj);
                    if s.acc {
                        put_bits(row, BS_DT, u64::from(r as u32 - s.tj), 7);
                    }
                    row[BS_S] = F::from_u32(s.sbit);
                }
            }
        }
        MlTable::BallPos => {
            for (v, b) in rows.ball.iter().enumerate() {
                let vals: [u64; 17] = core::array::from_fn(|i| lane(c, b.lanes[i]));
                let steps = ball_steps(&vals);
                for p in 0..native::N {
                    let row = &mut m[(v * native::N + p) * width..(v * native::N + p + 1) * width];
                    row[0] = small_f(steps.c[p]);
                    row[1] = F::from_u32(steps.t[p]);
                }
            }
        }
        MlTable::T1 => {
            for (i, r) in rows.t1.iter().enumerate() {
                let row = &mut m[i * width..(i + 1) * width];
                for (k, &w) in r.lanes.iter().enumerate() {
                    put_bits(row, 64 * k, lane(c, w), 64);
                }
            }
        }
        MlTable::Z => {
            for (i, r) in rows.z.iter().enumerate() {
                let row = &mut m[i * width..(i + 1) * width];
                put_bits(row, 0, u64::from(r.u), 18);
                put_bits(row, 18, u64::from(Z_SPAN - r.u), 18);
            }
        }
        MlTable::Hint => {
            for (i, r) in rows.hint.iter().enumerate() {
                let row = &mut m[i * width..(i + 1) * width];
                for k in 0..HINT_COEFFS {
                    let at = HI_PER * k;
                    let v = base_u32(c, r.w[k]);
                    let Some((r1, r0, e44, pos, w1, mm)) = hint_values(v, r.h[k]) else {
                        continue;
                    };
                    put_bits(row, at + HI_R1, u64::from(r1), 6);
                    put_bits(row, at + HI_R1C, u64::from(44 - r1), 6);
                    row[at + HI_E44] = F::from_bool(e44);
                    let d = F::from_i32(r1 as i32 - 44);
                    row[at + HI_INV44] = if e44 { F::ZERO } else { d.inverse() };
                    let u = (r0 + native::GAMMA2 as i32 - 1) as u32;
                    put_bits(row, at + HI_U, u64::from(u), 18);
                    put_bits(row, at + HI_UC, u64::from(TWO_GAMMA2 - 1 - u), 18);
                    row[at + HI_POS] = F::from_bool(pos);
                    let r0p = r0 - i32::from(e44);
                    let vv = if pos { r0p - 1 } else { -r0p };
                    put_bits(row, at + HI_V, vv as u64, 17);
                    row[at + HI_H] = F::from_bool(r.h[k]);
                    row[at + HI_M] = F::from_i32(mm);
                    put_bits(row, at + HI_W1, u64::from(w1), 6);
                    put_bits(row, at + HI_W1C, u64::from(43 - w1), 6);
                }
            }
        }
    }
    RowMajorMatrix::new(m, width)
}

/// Fill candidate `mm` of an expand row: `v` its value, `send` whether it is
/// sent, `idx` its index among the accepted ones, `done` the flag before it
/// (updated to the flag after it).
fn expand_candidate(row: &mut [F], mm: usize, v: u32, send: bool, idx: usize, done: &mut bool) {
    let at = EX_CAND + EX_PER * mm;
    let bit = |b: usize| v >> b & 1;
    let mut tp = bit(13) * bit(14);
    row[at] = F::from_u32(tp);
    for k in 1..9 {
        tp *= bit(14 + k);
        row[at + k] = F::from_u32(tp);
    }
    let low13 = v & 0x1FFF;
    row[at + 9] = F::from_bool(low13 != 0);
    row[at + 10] = if low13 != 0 { F::from_u32(low13).inverse() } else { F::ZERO };
    row[at + 11] = F::from_bool(send);
    let d = F::from_usize(idx) - F::from_u32(255);
    let is255 = idx == 255;
    row[at + 12] = F::from_bool(is255);
    row[at + 13] = if is255 { F::ZERO } else { d.inverse() };
    *done = *done || (send && is255);
    row[at + 14] = F::from_bool(*done);
}

/// `sum_i 2^i x_i`.
fn bits_sum<E: PrimeCharacteristicRing + Clone>(xs: &[E]) -> E {
    xs.iter().enumerate().fold(E::ZERO, |acc, (i, x)| acc + x.clone() * E::from_u32(1 << i))
}

/// The four limbs of a lane from its 64 bits.
fn limbs_of<E: PrimeCharacteristicRing + Clone>(bits: &[E]) -> Vec<E> {
    (0..4).map(|l| bits_sum(&bits[16 * l..16 * (l + 1)])).collect()
}

/// Send `(wire, vals..)` on the wire bus, padded to the bus's nine fields.
fn send<AB: InteractionBuilder<F = F>>(b: &mut AB, id: AB::Expr, vals: Vec<AB::Expr>, count: AB::Expr) {
    let mut fields = Vec::with_capacity(9);
    fields.push(id);
    fields.extend(vals);
    while fields.len() < 9 {
        fields.push(AB::Expr::ZERO);
    }
    b.push_interaction(BUS, fields, Count::bounded(count, 1));
}

/// `(address, value, time)` on the `ball` bus, `count` 1 to write it and -1
/// to read it.
fn ball_op<AB: InteractionBuilder<F = F>>(b: &mut AB, fields: [AB::Expr; 3], count: AB::Expr) {
    b.push_interaction(BALL_BUS, fields, Count::bounded(count, 1));
}

fn bools<AB: AirBuilder>(b: &mut AB, xs: &[AB::Expr]) {
    for x in xs {
        b.assert_zero(x.clone() * (x.clone() - AB::Expr::ONE));
    }
}

/// The constraints and bus messages of an ML-DSA table.
pub(crate) fn eval<AB: InteractionBuilder<F = F>>(t: MlTable, builder: &mut AB) {
    let prep: Vec<AB::Expr> = builder.preprocessed().current_slice().iter().map(|&v| v.into()).collect();
    let main = builder.main();
    let l: Vec<AB::Expr> = main.current_slice().iter().map(|&v| v.into()).collect();
    let n: Vec<AB::Expr> = if reads_next(t) {
        main.next_slice().iter().map(|&v| v.into()).collect()
    } else {
        Vec::new()
    };
    let k = |x: u32| AB::Expr::from(F::from_u32(x));
    let one = || AB::Expr::ONE;
    match t {
        MlTable::Keccak => eval_keccak_round(builder, &prep, &l),
        MlTable::Xor => {
            bools(builder, &l);
            let (x, y) = (&l[..64], &l[64..128]);
            let z: Vec<AB::Expr> =
                (0..64).map(|i| x[i].clone() + y[i].clone() - x[i].clone() * y[i].clone() * k(2)).collect();
            let en = prep[3].clone();
            send(builder, prep[0].clone(), limbs_of(x), en.clone());
            send(builder, prep[1].clone(), limbs_of(y), en.clone());
            send(builder, prep[2].clone(), limbs_of(&z), en);
        }
        MlTable::Butterfly => {
            bools(builder, &l[BF_B..BF_WIDTH]);
            let a = l[BF_A].clone();
            let b = bits_sum(&l[BF_B..BF_B + BF_B_BITS]);
            let s = (0..BF_B_BITS).fold(AB::Expr::ZERO, |acc, j| acc + prep[5 + j].clone() * l[BF_B + j].clone());
            let k1 = bits_sum(&l[BF_K1..BF_K1 + 5]);
            let k2 = bits_sum(&l[BF_K2..BF_K2 + 5]);
            let a2 = bits_sum(&l[BF_A2..BF_A2 + 23]);
            let b2 = bits_sum(&l[BF_B2..BF_B2 + 23]);
            // a + zeta b = a2 + k1 q and a - zeta b = b2 - k2 q, over the
            // integers: |a| < 2^25, S < 24 q, k1, k2 < 32, a2, b2 < 2^23.
            builder.assert_zero(a.clone() + s.clone() - k1 * k(Q) - a2.clone());
            builder.assert_zero(a.clone() - s + k2 * k(Q) - b2.clone());
            let en = prep[4].clone();
            send(builder, prep[0].clone(), vec![a], en.clone());
            send(builder, prep[1].clone(), vec![b], en.clone());
            send(builder, prep[2].clone(), vec![a2], en.clone());
            send(builder, prep[3].clone(), vec![b2], en);
        }
        MlTable::Mac => {
            bools(builder, &l);
            let en = prep[MAC_OPS].clone();
            let lo = |o: usize| bits_sum(&l[24 * o..24 * o + 12]);
            let hi = |o: usize| bits_sum(&l[24 * o + 12..24 * o + 24]);
            let k0 = bits_sum(&l[MAC_K..MAC_K + 12]);
            let k1 = bits_sum(&l[MAC_K + 12..MAC_K + 24]);
            let k2 = bits_sum(&l[MAC_K + 24..MAC_K + 28]);
            let e0 = bits_sum(&l[MAC_E0..MAC_E0 + 15]) - k(MAC_E0_OFFSET);
            let e1 = bits_sum(&l[MAC_E1..MAC_E1 + 16]) - k(MAC_E1_OFFSET);
            let (q0, q1) = (k(1), k(2046));
            let mut p0 = -(lo(8) * lo(9)) - lo(10) - k0.clone() * q0.clone();
            let mut p1 = -(lo(8) * hi(9) + hi(8) * lo(9)) - hi(10) - (k0 * q1.clone() + k1.clone() * q0.clone());
            let mut p2 = -(hi(8) * hi(9)) - (k1 * q1.clone() + k2.clone() * q0) + k(2);
            for s in 0..4 {
                p0 = p0 + lo(s) * lo(4 + s);
                p1 = p1 + lo(s) * hi(4 + s) + hi(s) * lo(4 + s);
                p2 = p2 + hi(s) * hi(4 + s);
            }
            // sum A Z + 2^25 q = C T + W + K q in base 2^12, column by
            // column with carries; the top column fixes the last carry.
            let b = k(4096);
            builder.assert_zero(en.clone() * (p0 - b.clone() * e0.clone()));
            builder.assert_zero(en.clone() * (p1 + e0 - b.clone() * e1.clone()));
            builder.assert_zero(en.clone() * (p2 + e1 - b * q1 * (k2 - k(2))));
            for o in 0..MAC_OPS {
                send(builder, prep[o].clone(), vec![lo(o) + hi(o) * k(4096)], en.clone());
            }
        }
        MlTable::Expand => {
            let (first, last, en) = (prep[4].clone(), prep[5].clone(), prep[6].clone());
            bools(builder, &l[..EX_CAND]);
            let count = l[EX_COUNT].clone();
            let done_in = l[EX_DONE].clone();
            let mut done = done_in.clone();
            bools(builder, core::slice::from_ref(&done));
            builder.assert_zero(first.clone() * count.clone());
            builder.assert_zero(first * done.clone());
            let mut idx = count.clone();
            for mm in 0..8 {
                let at = EX_CAND + EX_PER * mm;
                let cb = &l[24 * mm..24 * mm + 23];
                let tp = &l[at..at + 9];
                let (nz, inv, act, is255, inv255, done_next) = (
                    l[at + 9].clone(),
                    l[at + 10].clone(),
                    l[at + 11].clone(),
                    l[at + 12].clone(),
                    l[at + 13].clone(),
                    l[at + 14].clone(),
                );
                // The top ten bits all set, and the low thirteen not all clear:
                // the candidate is at least q.
                builder.assert_zero(tp[0].clone() - cb[13].clone() * cb[14].clone());
                for j in 1..9 {
                    builder.assert_zero(tp[j].clone() - tp[j - 1].clone() * cb[14 + j].clone());
                }
                let low13 = bits_sum(&cb[..13]);
                bools(builder, &[nz.clone(), done_next.clone()]);
                builder.assert_zero(low13.clone() * (one() - nz.clone()));
                builder.assert_zero(nz.clone() * (low13 * inv - one()));
                let acc = one() - tp[8].clone() * nz;
                builder.assert_zero(act.clone() - acc * (one() - done.clone()));
                let d = idx.clone() - k(255);
                builder.assert_zero(d.clone() * is255.clone());
                builder.assert_zero(is255.clone() - one() + d * inv255);
                builder.assert_zero(done_next.clone() - done.clone() - act.clone() * is255);
                let cand = bits_sum(cb);
                send(builder, prep[3].clone() + idx.clone(), vec![cand], act.clone());
                idx = idx + act;
                done = done_next;
            }
            builder.assert_zero(last * (one() - done.clone()));
            for j in 0..3 {
                send(builder, prep[j].clone(), limbs_of(&l[64 * j..64 * (j + 1)]), en.clone());
            }
            // The running count from the row before, and to the row after,
            // through the entry's count wires.
            send(builder, prep[7].clone(), vec![count, done_in], prep[9].clone());
            send(builder, prep[8].clone(), vec![idx, done], prep[10].clone());
        }
        MlTable::BallStep => {
            let (byte_id, sign_base, addr, time) = (prep[0].clone(), prep[1].clone(), prep[2].clone(), prep[3].clone());
            let (first, proc, fin) = (prep[4].clone(), prep[5].clone(), prep[6].clone());
            let b = l[BS_B].clone();
            let kk = l[BS_K].clone();
            let done = l[BS_DONE].clone();
            let acc = l[BS_ACC].clone();
            let eq = l[BS_EQ].clone();
            let is38 = l[BS_IS38].clone();
            let cj = l[BS_CJ].clone();
            let tj = l[BS_TJ].clone();
            let sbit = l[BS_S].clone();
            bools(builder, &[done.clone(), acc.clone(), eq.clone(), is38.clone()]);
            bools(builder, &l[BS_D..BS_D + 8]);
            bools(builder, &l[BS_DT..BS_DT + 7]);
            let i = kk.clone() + k(BALL_FIRST as u32);
            let d = bits_sum(&l[BS_D..BS_D + 8]);
            let dt = bits_sum(&l[BS_DT..BS_DT + 7]);
            builder.assert_zero(first.clone() * kk.clone());
            builder.assert_zero(first * done.clone());
            // Only a byte row accepts, and not once done.
            builder.assert_zero(acc.clone() * (one() - proc.clone()));
            builder.assert_zero(acc.clone() * done.clone());
            // Accepted: j = b <= i, d = i - j. Not accepted and not done:
            // b > i, d = b - i - 1. Both below 2^8, so over the integers.
            builder.assert_zero(
                proc.clone()
                    * (d - acc.clone() * (i.clone() - b.clone())
                        - (one() - acc.clone() - done.clone()) * (b.clone() - i.clone() - one())),
            );
            // eq = (j = i) where it matters, an accepted row.
            builder.assert_zero(eq.clone() * (i.clone() - b.clone()));
            builder.assert_zero(acc.clone() * ((i.clone() - b.clone()) * l[BS_INV_EQ].clone() + eq.clone() - one()));
            // is38 = (k = 38): the accepted byte that makes k = 39 finishes.
            builder.assert_zero(is38.clone() * (kk.clone() - k(38)));
            builder.assert_zero(proc.clone() * ((kk.clone() - k(38)) * l[BS_INV38].clone() + is38.clone() - one()));
            builder.assert_zero(proc.clone() * (n[BS_K].clone() - kk.clone() - acc.clone()));
            builder.assert_zero(proc * (n[BS_DONE].clone() - done.clone() - acc.clone() * is38));
            builder.assert_zero(fin * (one() - done));
            // The time read at j is before this row's.
            builder.assert_zero(acc.clone() * (time.clone() - one() - tj.clone() - dt));
            send(builder, byte_id, vec![b.clone()], prep[5].clone());
            send(builder, sign_base + kk, vec![sbit.clone()], acc.clone());
            // c[i] = c[j] (i fresh, unless j = i), then c[j] = (-1)^sign.
            let fresh = acc.clone() - acc.clone() * eq;
            let sign = one() - sbit * k(2);
            ball_op(builder, [addr.clone() + b.clone(), cj.clone(), tj], -acc.clone());
            ball_op(builder, [addr.clone() + b, sign, time.clone()], acc);
            ball_op(builder, [addr.clone() + i.clone(), AB::Expr::ZERO, AB::Expr::ZERO], -fresh.clone());
            ball_op(builder, [addr + i, cj, time], fresh);
        }
        MlTable::BallPos => {
            let (addr, cw, en) = (prep[0].clone(), prep[1].clone(), prep[2].clone());
            let (cv, tv) = (l[0].clone(), l[1].clone());
            builder.assert_zero(cv.clone() * (cv.clone() - one()) * (cv.clone() + one()));
            ball_op(builder, [addr.clone(), AB::Expr::ZERO, AB::Expr::ZERO], en.clone());
            ball_op(builder, [addr, cv.clone(), tv], -en.clone());
            // A coefficient in {-1, 0, 1} sent modulo q: c + q (c^2 - c) / 2.
            let half = AB::Expr::from(F::TWO.inverse());
            let v = cv.clone() + (cv.clone() * cv.clone() - cv) * half * k(Q);
            send(builder, cw, vec![v], en);
        }
        MlTable::T1 => {
            bools(builder, &l);
            let en = prep[9].clone();
            for j in 0..5 {
                send(builder, prep[j].clone(), limbs_of(&l[64 * j..64 * (j + 1)]), en.clone());
            }
            for g in 0..4 {
                let vals: Vec<AB::Expr> = (0..8)
                    .map(|i| {
                        let at = 10 * (8 * g + i);
                        bits_sum(&l[at..at + 10]) * k(1 << native::D)
                    })
                    .collect();
                send(builder, prep[5 + g].clone(), vals, en.clone());
            }
        }
        MlTable::Z => {
            bools(builder, &l);
            let en = prep[1].clone();
            let u = bits_sum(&l[..18]);
            let v = bits_sum(&l[18..36]);
            builder.assert_zero(en.clone() * (u.clone() + v - k(Z_SPAN)));
            send(builder, prep[0].clone(), vec![u + k(Q - Z_SHIFT)], en);
        }
        MlTable::Hint => {
            let en = prep[2].clone();
            let mut hsum = AB::Expr::ZERO;
            let mut w1bits: Vec<AB::Expr> = Vec::with_capacity(6 * HINT_COEFFS);
            let mut ws: Vec<AB::Expr> = Vec::with_capacity(HINT_COEFFS);
            for j in 0..HINT_COEFFS {
                let at = HI_PER * j;
                let col = |o: usize| l[at + o].clone();
                bools(builder, &l[at + HI_R1..at + HI_INV44]);
                bools(builder, &l[at + HI_U..at + HI_M]);
                bools(builder, &l[at + HI_W1..at + HI_PER]);
                let r1 = bits_sum(&l[at + HI_R1..at + HI_R1 + 6]);
                let r1c = bits_sum(&l[at + HI_R1C..at + HI_R1C + 6]);
                let e44 = col(HI_E44);
                builder.assert_zero(en.clone() * (r1.clone() + r1c - k(44)));
                builder.assert_zero((r1.clone() - k(44)) * e44.clone());
                builder.assert_zero(en.clone() * (e44.clone() - one() + (r1.clone() - k(44)) * col(HI_INV44)));
                let u = bits_sum(&l[at + HI_U..at + HI_U + 18]);
                let uc = bits_sum(&l[at + HI_UC..at + HI_UC + 18]);
                builder.assert_zero(en.clone() * (u.clone() + uc - k(TWO_GAMMA2 - 1)));
                // r0 = u - (gamma2 - 1) in (-gamma2, gamma2]; when r1 = 44
                // the coefficient is q - 1 + r0, decomposed as (0, r0 - 1).
                let r0 = u.clone() - k(native::GAMMA2 - 1);
                let r0p = r0 - e44.clone();
                let pos = col(HI_POS);
                let v = bits_sum(&l[at + HI_V..at + HI_V + 17]);
                builder.assert_zero(
                    en.clone() * (v - pos.clone() * (r0p.clone() - one()) - (one() - pos.clone()) * (-r0p)),
                );
                let h = col(HI_H);
                let mm = col(HI_M);
                builder.assert_zero(mm.clone() * (mm.clone() - one()) * (mm.clone() + one()));
                let r1p = r1.clone() - e44 * k(44);
                let raw = r1p + h.clone() * (pos * k(2) - one());
                let w1 = bits_sum(&l[at + HI_W1..at + HI_W1 + 6]);
                let w1c = bits_sum(&l[at + HI_W1C..at + HI_W1C + 6]);
                builder.assert_zero(en.clone() * (w1.clone() - raw - mm * k(44)));
                builder.assert_zero(en.clone() * (w1 + w1c - k(43)));
                ws.push(r1 * k(TWO_GAMMA2) + u - k(native::GAMMA2 - 1));
                hsum = hsum + h;
                w1bits.extend_from_slice(&l[at + HI_W1..at + HI_W1 + 6]);
            }
            send(builder, prep[0].clone(), ws, en.clone());
            let mut out: Vec<AB::Expr> = (0..3).map(|j| bits_sum(&w1bits[16 * j..16 * (j + 1)])).collect();
            out.push(hsum);
            send(builder, prep[1].clone(), out, en);
        }
    }
}

/// One round of Keccak-f\[1600\] on a row, as the pinned `KeccakAir`
/// constrains it (theta, rho, pi, chi, iota), without its row-to-row
/// constraints: the round's input lanes (A) and output lanes (A''') are sent
/// as wires, so the next round is linked by its wires, and the round constant
/// is preprocessed.
fn eval_keccak_round<AB: InteractionBuilder<F = F>>(builder: &mut AB, prep: &[AB::Expr], l: &[AB::Expr]) {
    let a = |y: usize, x: usize, limb: usize| l[KA + 4 * (5 * y + x) + limb].clone();
    let c = |x: usize, z: usize| l[KC + 64 * x + z].clone();
    let cp = |x: usize, z: usize| l[KCP + 64 * x + z].clone();
    let ap = |y: usize, x: usize, z: usize| l[KAP + 64 * (5 * y + x) + z].clone();
    let app = |y: usize, x: usize, limb: usize| l[KAPP + 4 * (5 * y + x) + limb].clone();
    // B[x, y] = ROT(A'[(x + 3 y) % 5, x], r[(x + 3 y) % 5][x]).
    let b = |x: usize, y: usize, z: usize| {
        let s = (x + 3 * y) % 5;
        let rot = ROT[s][x] as usize;
        ap(x, s, (z + 64 - rot) % 64)
    };
    let limb_of = |limb: usize, bit: &dyn Fn(usize) -> AB::Expr| {
        (limb * 16..(limb + 1) * 16).rev().fold(AB::Expr::ZERO, |acc, z| acc.double() + bit(z))
    };

    // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
    for x in 0..5 {
        bools(builder, &(0..64).map(|z| c(x, z)).collect::<Vec<_>>());
        for z in 0..64 {
            let xor = c(x, z).xor3(&c((x + 4) % 5, z), &c((x + 1) % 5, (z + 63) % 64));
            builder.assert_zero(cp(x, z) - xor);
        }
    }
    // A[x, y] = xor(A'[x, y], C[x], C'[x]), A' in bits.
    for x in 0..5 {
        let c_xor_c_prime: Vec<AB::Expr> = (0..64).map(|z| c(x, z).xor(&cp(x, z))).collect();
        for y in 0..5 {
            bools(builder, &(0..64).map(|z| ap(y, x, z)).collect::<Vec<_>>());
            for limb in 0..4 {
                let bit = |z: usize| ap(y, x, z).xor(&c_xor_c_prime[z]);
                builder.assert_zero(limb_of(limb, &bit) - a(y, x, limb));
            }
        }
    }
    // xor_y A'[x, y, z] = C'[x, z].
    for x in 0..5 {
        for z in 0..64 {
            let sum: AB::Expr = (0..5).map(|y| ap(y, x, z)).sum();
            let diff = sum - cp(x, z);
            builder.assert_zero(diff.clone() * (diff.clone() - AB::Expr::TWO) * (diff - AB::Expr::TWO.double()));
        }
    }
    // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..4 {
                let bit = |z: usize| b((x + 1) % 5, y, z).andn(&b((x + 2) % 5, y, z)).xor(&b(x, y, z));
                builder.assert_zero(limb_of(limb, &bit) - app(y, x, limb));
            }
        }
    }
    // A'''[0, 0] = A''[0, 0] xor RC, through the bits of A''[0, 0].
    bools(builder, &l[KB00..KB00 + 64]);
    for limb in 0..4 {
        let bit = |z: usize| l[KB00 + z].clone();
        builder.assert_zero(limb_of(limb, &bit) - app(0, 0, limb));
    }
    let rc = |z: usize| RC_POS.iter().position(|&p| p == z).map(|j| prep[KP_RC + j].clone());
    for limb in 0..4 {
        let bit = |z: usize| match rc(z) {
            Some(r) => r.xor(&l[KB00 + z]),
            None => l[KB00 + z].clone(),
        };
        builder.assert_zero(limb_of(limb, &bit) - l[KAPPP + limb].clone());
    }
    // The round's input lanes A and output lanes A'''.
    let en = prep[KP_EN].clone();
    for lane in 0..25 {
        let (y, x) = (lane / 5, lane % 5);
        send(builder, prep[lane].clone(), (0..4).map(|limb| a(y, x, limb)).collect(), en.clone());
    }
    for lane in 0..25 {
        let (y, x) = (lane / 5, lane % 5);
        let out: Vec<AB::Expr> = (0..4)
            .map(|limb| if lane == 0 { l[KAPPP + limb].clone() } else { app(y, x, limb) })
            .collect();
        send(builder, prep[25 + lane].clone(), out, en.clone());
    }
}
