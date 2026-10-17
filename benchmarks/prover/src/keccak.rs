//! Candidate B: the reveal statement with Keccak-256.
//!
//! Each permutation is Plonky3's Keccak-f circuit (`p3-keccak-air`), 24 rows
//! per permutation, in the order
//!
//! ```text
//! perm  0..=1   commitment being opened, two 136-byte blocks
//! perm  2..=33  tree nodes, levels 0..=31
//! perm  34      marker
//! perm  35..=36 remainder commitment, two blocks
//! ```
//!
//! followed by padding permutations of the zero state. The circuit holds
//! the state as 16-bit limbs, two bytes each. A digest is the full 256-bit
//! output, 16 limbs, and is never reduced into field elements.
//!
//! Byte layouts (Keccak-256 padding `0x01 .. 0x80`, a one-byte tag first):
//!
//! ```text
//! commitment  tag s(32) r(32) b(32) type(1) fingerprint(32) rule(16) v(12)  158 bytes, 2 blocks
//! tree node   tag level left(32) right(32)                                   66 bytes, 1 block
//! marker      tag r(32) b(32)                                                65 bytes, 1 block
//! ```
//!
//! `s`, `r` and `b` start at odd offsets, so their first and last bytes share
//! a limb with a neighbour; those bytes are carried separately and range
//! checked. The second commitment block is absorbed by XOR into the first
//! block's output, which the trace proves bit by bit over the limbs that
//! carry data or padding.

use alloc::borrow::Cow;
use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak::KeccakF;
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, generate_trace_rows};
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;
use p3_uni_stark::SubAirBuilder;

use crate::witness::{AMOUNT_LIMB_BITS, AMOUNT_LIMBS, TREE_DEPTH, Witness, amount_bytes, amount_limbs};
use crate::{Tag, fill_periodic};

type F = BabyBear;

pub const RATE_BYTES: usize = 136;
pub const DIGEST_LIMBS: usize = 16;
const STATE_LIMBS: usize = 100;
const RATE_LIMBS: usize = RATE_BYTES / 2;

// ---------------------------------------------------------------------------
// Permutations and rows.

const PERM_C: usize = 0;
const PERM_NODE: usize = 2;
const PERM_ROOT: usize = PERM_NODE + TREE_DEPTH - 1;
const PERM_MARKER: usize = PERM_NODE + TREE_DEPTH;
const PERM_REM: usize = PERM_MARKER + 1;
pub const STATEMENT_PERMS: usize = PERM_REM + 2;
pub const MIN_HEIGHT: usize = (STATEMENT_PERMS * NUM_ROUNDS).next_power_of_two();

const fn first_row(perm: usize) -> usize {
    perm * NUM_ROUNDS
}
const fn last_row(perm: usize) -> usize {
    perm * NUM_ROUNDS + NUM_ROUNDS - 1
}

// ---------------------------------------------------------------------------
// Statement columns, after the Keccak circuit's own.

const DIR: usize = NUM_KECCAK_COLS;
const SWAP: usize = DIR + 1;
const CARRY: usize = SWAP + DIGEST_LIMBS;
/// A 32-byte value at an odd offset: its first byte, its last byte and the
/// 15 limbs in between.
const ITEM: usize = 17;
const fn item(group: usize, which: usize) -> usize {
    CARRY + (3 * group + which) * ITEM
}
const S: usize = 0;
const R: usize = 1;
const B: usize = 2;
const C_VT: usize = CARRY + 6 * ITEM;
const C_FP: usize = C_VT + 1;
const C_RULE: usize = C_FP + 16;
const C_V: usize = C_RULE + 8;
const C_V2: usize = C_V + AMOUNT_LIMBS;
const CARRY_END: usize = C_V2 + AMOUNT_LIMBS;
/// Limbs of the first block's output that the second block changes: the
/// eleven data limbs, the `0x01` padding limb and the `0x80` padding limb.
const XOR_DATA_LIMBS: usize = 11;
const PAD_LIMB_LOW: usize = 11;
const PAD_LIMB_HIGH: usize = RATE_LIMBS - 1;
const OBITS: usize = CARRY_END;
const MBITS: usize = OBITS + 13 * 16;
const BYTEBITS: usize = MBITS + XOR_DATA_LIMBS * 16;
const CONS: usize = BYTEBITS + 12 * 8;
pub const TRACE_WIDTH: usize = CONS + 6;

const fn obit(limb: usize, bit: usize) -> usize {
    let index = if limb == PAD_LIMB_HIGH { 12 } else { limb };
    OBITS + 16 * index + bit
}
const fn mbit(limb: usize, bit: usize) -> usize {
    MBITS + 16 * limb + bit
}
/// Column holding range-checked byte `t` (0..12): opened then remainder;
/// `s`, `r`, `b`; first then last byte.
const fn checked_byte(t: usize) -> usize {
    item(t / 6, (t % 6) / 2) + t % 2
}

// ---------------------------------------------------------------------------
// Periodic selectors.

const P_C0: usize = 0;
const P_R0: usize = 1;
const P_MARKER: usize = 2;
const P_MARKER_OUT: usize = 3;
const P_NODE: usize = 4;
const P_NODE_LIMB0: usize = 5;
const P_LINK: usize = 6;
const P_ROOT: usize = 7;
const P_XOR: usize = 8;
const P_XOR_C: usize = 9;
const P_XOR_R: usize = 10;
const P_REM_OUT: usize = 11;
const NUM_PERIODIC: usize = 12;

// ---------------------------------------------------------------------------
// Public inputs: digests as 16 limbs of 16 bits.

pub const PI_ROOT: usize = 0;
pub const PI_MARKER: usize = PI_ROOT + DIGEST_LIMBS;
pub const PI_REMAINDER: usize = PI_MARKER + DIGEST_LIMBS;
pub const PI_OUT: usize = PI_REMAINDER + DIGEST_LIMBS;
pub const PI_FEE: usize = PI_OUT + AMOUNT_LIMBS;
pub const PI_BINDING: usize = PI_FEE + AMOUNT_LIMBS;
pub const PI_TYPE: usize = PI_BINDING + DIGEST_LIMBS;
pub const NUM_PUBLIC: usize = PI_TYPE + 1;

// ---------------------------------------------------------------------------
// Native Keccak-256.

/// Keccak-256 padding to whole blocks.
fn pad(msg: &[u8]) -> Vec<u8> {
    let blocks = msg.len() / RATE_BYTES + 1;
    let mut out = msg.to_vec();
    out.resize(blocks * RATE_BYTES, 0);
    out[msg.len()] ^= 0x01;
    out[blocks * RATE_BYTES - 1] ^= 0x80;
    out
}

/// Absorb `msg`, pushing each permutation's input state; returns the digest.
fn keccak256(msg: &[u8], inputs: &mut Vec<[u64; 25]>) -> [u8; 32] {
    let mut state = [0u64; 25];
    for block in pad(msg).chunks(RATE_BYTES) {
        for (lane, chunk) in block.chunks(8).enumerate() {
            state[lane] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        inputs.push(state);
        state = KeccakF.permute(state);
    }
    let mut digest = [0u8; 32];
    for (i, lane) in state[..4].iter().enumerate() {
        digest[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    digest
}

pub fn digest_limbs(digest: &[u8; 32]) -> [u32; DIGEST_LIMBS] {
    core::array::from_fn(|k| u32::from(digest[2 * k]) | u32::from(digest[2 * k + 1]) << 8)
}

fn commitment_message(w: &Witness, remainder: bool) -> Vec<u8> {
    let (s, r, b, v) = if remainder {
        (
            &w.remainder_secret,
            &w.remainder_reveal_secret,
            &w.remainder_blinding,
            w.remainder_amount,
        )
    } else {
        (&w.secret, &w.reveal_secret, &w.blinding, w.amount)
    };
    let mut msg = vec![Tag::Commitment as u8];
    msg.extend_from_slice(s);
    msg.extend_from_slice(r);
    msg.extend_from_slice(b);
    msg.push(w.type_tag as u8);
    msg.extend_from_slice(&w.fingerprint);
    msg.extend_from_slice(&w.rule);
    msg.extend_from_slice(&amount_bytes(v));
    msg
}

pub struct StatementPerms {
    pub inputs: Vec<[u64; 25]>,
    pub root: [u8; 32],
    pub marker: [u8; 32],
    pub remainder: [u8; 32],
}

pub fn statement_perms(w: &Witness) -> StatementPerms {
    let mut inputs = Vec::with_capacity(STATEMENT_PERMS);
    let mut current = keccak256(&commitment_message(w, false), &mut inputs);
    for level in 0..TREE_DEPTH {
        let (left, right) = if w.direction(level) {
            (w.siblings[level], current)
        } else {
            (current, w.siblings[level])
        };
        let mut msg = vec![Tag::TreeNode as u8, level as u8];
        msg.extend_from_slice(&left);
        msg.extend_from_slice(&right);
        current = keccak256(&msg, &mut inputs);
    }
    let root = current;
    let mut msg = vec![Tag::Marker as u8];
    msg.extend_from_slice(&w.reveal_secret);
    msg.extend_from_slice(&w.blinding);
    let marker = keccak256(&msg, &mut inputs);
    let remainder = keccak256(&commitment_message(w, true), &mut inputs);
    debug_assert_eq!(inputs.len(), STATEMENT_PERMS);
    StatementPerms {
        inputs,
        root,
        marker,
        remainder,
    }
}

/// The binding digest, computed by the verifier outside the proof.
pub fn binding_digest(w: &Witness, remainder: &[u8; 32], root: &[u8; 32]) -> [u8; 32] {
    let mut msg = vec![Tag::Binding as u8];
    msg.extend_from_slice(&w.binding.chain_id.to_le_bytes());
    msg.push(w.binding.transaction_type);
    msg.push(w.binding.transaction_version);
    msg.extend_from_slice(&w.binding.destination);
    msg.extend_from_slice(&amount_bytes(w.amount_out));
    msg.extend_from_slice(&amount_bytes(w.fee));
    msg.extend_from_slice(remainder);
    msg.extend_from_slice(root);
    keccak256(&msg, &mut Vec::new())
}

pub fn public_inputs(w: &Witness) -> Vec<F> {
    let perms = statement_perms(w);
    let mut pis: Vec<u32> = Vec::with_capacity(NUM_PUBLIC);
    pis.extend(digest_limbs(&perms.root));
    pis.extend(digest_limbs(&perms.marker));
    pis.extend(digest_limbs(&perms.remainder));
    pis.extend(amount_limbs(w.amount_out));
    pis.extend(amount_limbs(w.fee));
    pis.extend(digest_limbs(&binding_digest(w, &perms.remainder, &perms.root)));
    pis.push(w.type_tag);
    pis.into_iter().map(F::from_u32).collect()
}

/// Canonical elements, coin type, digest limbs below 2^16 and amount limbs
/// below 2^24, checked by the verifier outside the proof.
pub fn check_public_inputs(pis: &[F]) -> bool {
    let below = |range: core::ops::Range<usize>, bits: u32| {
        pis[range].iter().all(|x| x.as_canonical_u32() < 1 << bits)
    };
    pis.len() == NUM_PUBLIC
        && pis[PI_TYPE] == F::from_u32(crate::witness::COIN_TYPE_TAG)
        && below(PI_ROOT..PI_OUT, 16)
        && below(PI_BINDING..PI_TYPE, 16)
        && below(PI_OUT..PI_BINDING, AMOUNT_LIMB_BITS as u32)
}

// ---------------------------------------------------------------------------
// Trace generation.

/// Rate or capacity limb `i` of the state, as (y, x, limb) in the circuit.
const fn limb_position(i: usize) -> (usize, usize, usize) {
    let lane = i / 4;
    (lane / 5, lane % 5, i % 4)
}

fn pre<T: Copy>(cols: &KeccakCols<T>, i: usize) -> T {
    let (y, x, limb) = limb_position(i);
    cols.preimage[y][x][limb]
}

fn out<T: Copy>(cols: &KeccakCols<T>, i: usize) -> T {
    let (y, x, limb) = limb_position(i);
    cols.a_prime_prime_prime(y, x, limb)
}

/// (first byte, last byte, inner limbs) of a 32-byte value at an odd offset.
fn split_item(bytes: &[u8; 32]) -> [u32; ITEM] {
    let mut outv = [0u32; ITEM];
    outv[0] = u32::from(bytes[0]);
    outv[1] = u32::from(bytes[31]);
    for k in 1..=15 {
        outv[1 + k] = u32::from(bytes[2 * k - 1]) | u32::from(bytes[2 * k]) << 8;
    }
    outv
}

fn even_limbs<const N: usize>(bytes: &[u8]) -> [u32; N] {
    core::array::from_fn(|k| u32::from(bytes[2 * k]) | u32::from(bytes[2 * k + 1]) << 8)
}

pub fn generate_trace(w: &Witness, height: usize) -> RowMajorMatrix<F> {
    assert!(height.is_power_of_two() && height >= MIN_HEIGHT);
    let perms = statement_perms(w);
    let mut inputs = perms.inputs.clone();
    inputs.resize(height / NUM_ROUNDS, [0u64; 25]);
    let keccak: RowMajorMatrix<F> = generate_trace_rows(inputs, 0);
    assert_eq!(keccak.values.len(), height * NUM_KECCAK_COLS);

    let mut carry = vec![0u32; CARRY_END - CARRY];
    let items = [
        &w.secret,
        &w.reveal_secret,
        &w.blinding,
        &w.remainder_secret,
        &w.remainder_reveal_secret,
        &w.remainder_blinding,
    ];
    for (k, bytes) in items.iter().enumerate() {
        carry[k * ITEM..(k + 1) * ITEM].copy_from_slice(&split_item(bytes));
    }
    carry[C_VT - CARRY] = w.type_tag;
    carry[C_FP - CARRY..C_RULE - CARRY].copy_from_slice(&even_limbs::<16>(&w.fingerprint));
    carry[C_RULE - CARRY..C_V - CARRY].copy_from_slice(&even_limbs::<8>(&w.rule));
    carry[C_V - CARRY..C_V2 - CARRY].copy_from_slice(&amount_limbs(w.amount));
    carry[C_V2 - CARRY..CARRY_END - CARRY].copy_from_slice(&amount_limbs(w.remainder_amount));
    let carry: Vec<F> = carry.into_iter().map(F::from_u32).collect();

    // Second-block message limbs of each commitment.
    let block1 = |remainder: bool| -> [u32; XOR_DATA_LIMBS] {
        let padded = pad(&commitment_message(w, remainder));
        even_limbs::<XOR_DATA_LIMBS>(&padded[RATE_BYTES..])
    };
    let xor_rows = [
        (last_row(PERM_C), block1(false)),
        (last_row(PERM_REM), block1(true)),
    ];
    let carries = crate::poseidon2::conservation_carries(w);

    let mut values = F::zero_vec(height * TRACE_WIDTH);
    for (i, row) in values.chunks_exact_mut(TRACE_WIDTH).enumerate() {
        row[..NUM_KECCAK_COLS]
            .copy_from_slice(&keccak.values[i * NUM_KECCAK_COLS..(i + 1) * NUM_KECCAK_COLS]);
        let is_node = (first_row(PERM_NODE)..=first_row(PERM_ROOT)).contains(&i)
            && i % NUM_ROUNDS == 0;
        if is_node && w.direction(i / NUM_ROUNDS - PERM_NODE) {
            row[DIR] = F::ONE;
        }
        let (pre_left, pre_right): ([F; DIGEST_LIMBS], [F; DIGEST_LIMBS]) = {
            let cols: &KeccakCols<F> = row[..NUM_KECCAK_COLS].borrow();
            (
                core::array::from_fn(|k| pre(cols, 1 + k)),
                core::array::from_fn(|k| pre(cols, 1 + DIGEST_LIMBS + k)),
            )
        };
        for k in 0..DIGEST_LIMBS {
            row[SWAP + k] = row[DIR] * (pre_right[k] - pre_left[k]);
        }
        row[CARRY..CARRY_END].copy_from_slice(&carry);

        for (xor_row, message) in &xor_rows {
            if i != *xor_row {
                continue;
            }
            let outs: Vec<u32> = {
                let cols: &KeccakCols<F> = row[..NUM_KECCAK_COLS].borrow();
                (0..RATE_LIMBS).map(|j| out(cols, j).as_canonical_u32()).collect()
            };
            for j in (0..=PAD_LIMB_LOW).chain([PAD_LIMB_HIGH]) {
                for z in 0..16 {
                    row[obit(j, z)] = F::from_u32((outs[j] >> z) & 1);
                }
            }
            for (j, &m) in message.iter().enumerate() {
                for z in 0..16 {
                    row[mbit(j, z)] = F::from_u32((m >> z) & 1);
                }
            }
        }

        if i == 0 {
            for t in 0..12 {
                let byte = row[checked_byte(t)].as_canonical_u32();
                for z in 0..8 {
                    row[BYTEBITS + 8 * t + z] = F::from_u32((byte >> z) & 1);
                }
            }
            for (k, &c) in carries.iter().enumerate() {
                row[CONS + 2 * k] = F::from_u32(c & 1);
                row[CONS + 2 * k + 1] = F::from_u32(c >> 1);
            }
        }
    }
    RowMajorMatrix::new(values, TRACE_WIDTH)
}

// ---------------------------------------------------------------------------
// The AIR.

#[derive(Clone, Debug)]
pub struct RevealAir {
    height: usize,
    periodic: Vec<Vec<F>>,
}

impl RevealAir {
    pub fn new(height: usize) -> Self {
        assert!(height.is_power_of_two() && height >= MIN_HEIGHT);
        let mut periodic = vec![vec![F::ZERO; height]; NUM_PERIODIC];
        let one = |p: &mut Vec<F>, row: usize| fill_periodic(p, row..=row, F::ONE);
        one(&mut periodic[P_C0], first_row(PERM_C));
        one(&mut periodic[P_R0], first_row(PERM_REM));
        one(&mut periodic[P_MARKER], first_row(PERM_MARKER));
        one(&mut periodic[P_MARKER_OUT], last_row(PERM_MARKER));
        one(&mut periodic[P_ROOT], last_row(PERM_ROOT));
        one(&mut periodic[P_XOR], last_row(PERM_C));
        one(&mut periodic[P_XOR], last_row(PERM_REM));
        one(&mut periodic[P_XOR_C], last_row(PERM_C));
        one(&mut periodic[P_XOR_R], last_row(PERM_REM));
        one(&mut periodic[P_REM_OUT], last_row(PERM_REM + 1));
        for level in 0..TREE_DEPTH {
            let row = first_row(PERM_NODE + level);
            periodic[P_NODE][row] = F::ONE;
            periodic[P_NODE_LIMB0][row] = F::from_u32(Tag::TreeNode as u32 | (level as u32) << 8);
        }
        for perm in PERM_C + 1..PERM_ROOT {
            periodic[P_LINK][last_row(perm)] = F::ONE;
        }
        Self { height, periodic }
    }

    pub const fn height(&self) -> usize {
        self.height
    }
}

impl BaseAir<F> for RevealAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC
    }

    fn num_periodic_columns(&self) -> usize {
        NUM_PERIODIC
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        Cow::Borrowed(&self.periodic)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for RevealAir {
    fn eval(&self, builder: &mut AB) {
        // Every permutation is Plonky3's Keccak-f circuit.
        {
            let mut sub = SubAirBuilder::<AB, KeccakAir, AB::Var>::new(builder, 0..NUM_KECCAK_COLS);
            KeccakAir {}.eval(&mut sub);
        }

        let main = builder.main();
        let local: Vec<AB::Var> = main.current_slice().to_vec();
        let next: Vec<AB::Var> = main.next_slice().to_vec();
        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|&v| v.into()).collect();
        let per: Vec<AB::Expr> = builder.periodic_values().iter().map(|&v| v.into()).collect();
        let kl: &KeccakCols<AB::Var> = local[..NUM_KECCAK_COLS].borrow();
        let kn: &KeccakCols<AB::Var> = next[..NUM_KECCAK_COLS].borrow();
        let e = |v: AB::Var| -> AB::Expr { v.into() };
        let c = |x: u32| AB::Expr::from(F::from_u32(x));
        let pre_l = |i: usize| e(pre(kl, i));
        let pre_n = |i: usize| e(pre(kn, i));
        let out_l = |i: usize| e(out(kl, i));
        let gate = |builder: &mut AB, sel: &AB::Expr, a: AB::Expr, b: AB::Expr| {
            builder.assert_zero(sel.clone() * (a - b));
        };
        let byte_pair = |lo: AB::Expr, hi: AB::Expr| lo + hi * c(256);
        let first = |g: usize, which: usize| e(local[item(g, which)]);
        let last = |g: usize, which: usize| e(local[item(g, which) + 1]);
        let inner = |g: usize, which: usize, k: usize| e(local[item(g, which) + 1 + k]);

        // First commitment block, for the opened commitment and the remainder.
        for (sel, g) in [(P_C0, 0), (P_R0, 1)] {
            let sel = &per[sel];
            gate(builder, sel, pre_l(0), byte_pair(c(Tag::Commitment as u32), first(g, S)));
            for k in 1..=15 {
                gate(builder, sel, pre_l(k), inner(g, S, k));
                gate(builder, sel, pre_l(16 + k), inner(g, R, k));
                gate(builder, sel, pre_l(32 + k), inner(g, B, k));
            }
            gate(builder, sel, pre_l(16), byte_pair(last(g, S), first(g, R)));
            gate(builder, sel, pre_l(32), byte_pair(last(g, R), first(g, B)));
            gate(builder, sel, pre_l(48), byte_pair(last(g, B), e(local[C_VT])));
            for k in 0..16 {
                gate(builder, sel, pre_l(49 + k), e(local[C_FP + k]));
            }
            for k in 0..3 {
                gate(builder, sel, pre_l(65 + k), e(local[C_RULE + k]));
            }
            for k in RATE_LIMBS..STATE_LIMBS {
                gate(builder, sel, pre_l(k), AB::Expr::ZERO);
            }
        }

        // Second commitment block: input = first block's output XOR message.
        let two_pow = |z: usize| c(1 << z);
        let xor_sel = &per[P_XOR];
        for j in (0..=PAD_LIMB_LOW).chain([PAD_LIMB_HIGH]) {
            let recomposed = (0..16).fold(AB::Expr::ZERO, |acc, z| acc + two_pow(z) * e(local[obit(j, z)]));
            gate(builder, xor_sel, out_l(j), recomposed);
        }
        for j in 0..XOR_DATA_LIMBS {
            let xored = (0..16).fold(AB::Expr::ZERO, |acc, z| {
                let o = e(local[obit(j, z)]);
                let m = e(local[mbit(j, z)]);
                acc + two_pow(z) * (o.clone() + m.clone() - (o * m).double())
            });
            gate(builder, xor_sel, pre_n(j), xored);
        }
        let flip = |j: usize, flipped: usize| {
            (0..16).fold(AB::Expr::ZERO, |acc, z| {
                let o = e(local[obit(j, z)]);
                acc + two_pow(z) * if z == flipped { AB::Expr::ONE - o } else { o }
            })
        };
        gate(builder, xor_sel, pre_n(PAD_LIMB_LOW), flip(PAD_LIMB_LOW, 0));
        gate(builder, xor_sel, pre_n(PAD_LIMB_HIGH), flip(PAD_LIMB_HIGH, 15));
        for j in (PAD_LIMB_LOW + 1..PAD_LIMB_HIGH).chain(RATE_LIMBS..STATE_LIMBS) {
            gate(builder, xor_sel, pre_n(j), out_l(j));
        }
        // The message limbs are the rest of the rule and the amount.
        let mlimb = |j: usize| (0..16).fold(AB::Expr::ZERO, |acc, z| acc + two_pow(z) * e(local[mbit(j, z)]));
        for k in 0..5 {
            gate(builder, xor_sel, mlimb(k), e(local[C_RULE + 3 + k]));
        }
        // Amount byte `k` sits in message limb 5 + k / 2.
        let amount_from_bits = |i: usize| {
            (0..AMOUNT_LIMB_BITS).fold(AB::Expr::ZERO, |acc, t| {
                let byte = 3 * i + t / 8;
                let bit = mbit(5 + byte / 2, 8 * (byte % 2) + t % 8);
                acc + two_pow(t) * e(local[bit])
            })
        };
        for i in 0..AMOUNT_LIMBS {
            gate(builder, &per[P_XOR_C], amount_from_bits(i), e(local[C_V + i]));
            gate(builder, &per[P_XOR_R], amount_from_bits(i), e(local[C_V2 + i]));
        }
        for k in OBITS..BYTEBITS {
            builder.assert_bool(local[k]);
        }

        // Remainder commitment output is public.
        for k in 0..DIGEST_LIMBS {
            gate(builder, &per[P_REM_OUT], out_l(k), pv[PI_REMAINDER + k].clone());
        }

        // Tree nodes.
        let dir = e(local[DIR]);
        builder.assert_bool(dir.clone());
        builder.assert_zero(dir.clone() - per[P_NODE].clone() * dir.clone());
        for k in 0..DIGEST_LIMBS {
            builder.assert_zero(
                e(local[SWAP + k]) - dir.clone() * (pre_l(1 + DIGEST_LIMBS + k) - pre_l(1 + k)),
            );
        }
        builder.assert_zero(per[P_NODE].clone() * pre_l(0) - per[P_NODE_LIMB0].clone());
        let node_pad = 1 + 2 * DIGEST_LIMBS;
        gate(builder, &per[P_NODE], pre_l(node_pad), c(0x01));
        gate(builder, &per[P_NODE], pre_l(PAD_LIMB_HIGH), c(0x8000));
        for k in (node_pad + 1..PAD_LIMB_HIGH).chain(RATE_LIMBS..STATE_LIMBS) {
            gate(builder, &per[P_NODE], pre_l(k), AB::Expr::ZERO);
        }
        for k in 0..DIGEST_LIMBS {
            builder.assert_zero(
                per[P_LINK].clone() * (pre_n(1 + k) + e(next[SWAP + k]) - out_l(k)),
            );
            gate(builder, &per[P_ROOT], out_l(k), pv[PI_ROOT + k].clone());
        }

        // Marker: tagged hash of (r, b).
        let sel = &per[P_MARKER];
        gate(builder, sel, pre_l(0), byte_pair(c(Tag::Marker as u32), first(0, R)));
        for k in 1..=15 {
            gate(builder, sel, pre_l(k), inner(0, R, k));
            gate(builder, sel, pre_l(16 + k), inner(0, B, k));
        }
        gate(builder, sel, pre_l(16), byte_pair(last(0, R), first(0, B)));
        gate(builder, sel, pre_l(32), byte_pair(last(0, B), c(0x01)));
        gate(builder, sel, pre_l(PAD_LIMB_HIGH), c(0x8000));
        for k in (33..PAD_LIMB_HIGH).chain(RATE_LIMBS..STATE_LIMBS) {
            gate(builder, sel, pre_l(k), AB::Expr::ZERO);
        }
        for k in 0..DIGEST_LIMBS {
            gate(builder, &per[P_MARKER_OUT], out_l(k), pv[PI_MARKER + k].clone());
        }

        // Carried witness values never change.
        for k in CARRY..CARRY_END {
            builder.when_transition().assert_eq(next[k], local[k]);
        }

        // The bytes that share a limb with a neighbour are bytes.
        for t in 0..12 {
            for z in 0..8 {
                builder.assert_bool(local[BYTEBITS + 8 * t + z]);
            }
            let recomposed = (0..8).fold(AB::Expr::ZERO, |acc, z| {
                acc + two_pow(z) * e(local[BYTEBITS + 8 * t + z])
            });
            gate(builder, &per[P_C0], e(local[checked_byte(t)]), recomposed);
        }

        // Type: the coin type.
        gate(builder, &per[P_C0], e(local[C_VT]), pv[PI_TYPE].clone());
        gate(builder, &per[P_C0], pv[PI_TYPE].clone(), c(crate::witness::COIN_TYPE_TAG));

        // Conservation: out + v' + fee = v, limb by limb with carries. The
        // limbs of v and v' come from message bits, so they are below 2^24.
        for k in 0..6 {
            builder.assert_bool(local[CONS + k]);
        }
        let carry = |i: usize| -> AB::Expr {
            if i == 0 || i == AMOUNT_LIMBS {
                AB::Expr::ZERO
            } else {
                e(local[CONS + 2 * (i - 1)]) + e(local[CONS + 2 * (i - 1) + 1]).double()
            }
        };
        for i in 0..AMOUNT_LIMBS {
            gate(
                builder,
                &per[P_C0],
                pv[PI_OUT + i].clone() + e(local[C_V2 + i]) + pv[PI_FEE + i].clone() + carry(i),
                e(local[C_V + i]) + c(1 << AMOUNT_LIMB_BITS) * carry(i + 1),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_air::check_all_constraints;
    use p3_keccak::Keccak256Hash;
    use p3_symmetric::CryptographicHasher;

    use super::*;

    #[test]
    fn native_sponge_is_keccak_256() {
        for len in [0, 65, 66, 135, 136, 158, 300] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let expected = Keccak256Hash {}.hash_iter(msg.iter().copied());
            assert_eq!(keccak256(&msg, &mut Vec::new()), expected, "length {len}");
        }
    }

    #[test]
    fn layouts_have_the_planned_lengths_and_block_counts() {
        let w = Witness::primary(5, false);
        assert_eq!(commitment_message(&w, false).len(), 158);
        assert_eq!(pad(&commitment_message(&w, false)).len(), 2 * RATE_BYTES);
        assert_eq!(statement_perms(&w).inputs.len(), 37);
    }

    #[test]
    fn honest_trace_satisfies_every_constraint() {
        let w = Witness::primary(21, false);
        let air = RevealAir::new(MIN_HEIGHT);
        let trace = generate_trace(&w, MIN_HEIGHT);
        let report = check_all_constraints(&air, &trace, &public_inputs(&w), Some(4));
        assert!(report.is_ok(), "{report:?}");
    }

    /// Every public input except the binding digest is tied to the trace by a
    /// constraint. The binding digest is bound through the transcript only.
    #[test]
    fn every_public_input_is_bound_by_a_constraint() {
        let w = Witness::primary(22, true);
        let air = RevealAir::new(MIN_HEIGHT);
        let trace = generate_trace(&w, MIN_HEIGHT);
        let honest = public_inputs(&w);
        for (name, range) in crate::HashCandidate::Keccak256.public_input_groups() {
            if name == "binding digest" {
                continue;
            }
            for i in range {
                let mut pis = honest.clone();
                pis[i] += F::ONE;
                assert!(
                    !check_all_constraints(&air, &trace, &pis, Some(1)).is_ok(),
                    "{name}, element {i}, is not constrained"
                );
            }
        }
    }

    /// The bytes that straddle two limbs are range checked: moving a carry
    /// out of a straddled byte into its neighbour keeps the limb but breaks
    /// the byte.
    #[test]
    fn a_straddled_byte_outside_0_255_is_rejected() {
        let w = Witness::primary(23, true);
        let air = RevealAir::new(MIN_HEIGHT);
        let mut trace = generate_trace(&w, MIN_HEIGHT);
        let pis = public_inputs(&w);
        // Limb 16 of the remainder commitment is s'[31] + 256 * r'[0], and
        // neither byte is used anywhere else. Raise s'[31] by 256 and lower
        // r'[0] by one: the limb, and so the hash, is unchanged; only the
        // byte range check can notice.
        let s_last = item(1, S) + 1;
        let r_first = item(1, R);
        for row in trace.values.chunks_exact_mut(TRACE_WIDTH) {
            row[s_last] += F::from_u32(256);
            row[r_first] -= F::ONE;
        }
        assert!(!check_all_constraints(&air, &trace, &pis, Some(1)).is_ok());
    }
}
