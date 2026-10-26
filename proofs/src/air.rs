//! The AIR of a statement, built from its [`Schedule`].
//!
//! Every permutation is Plonky3's Keccak-f circuit (`p3-keccak-air`), 24 rows
//! each, in schedule order. The circuit holds the state as 16-bit limbs, two
//! bytes each, little-endian. Beside it, each row carries:
//!
//! - `BITS`: 136 bytes as 1,088 bits. On the first row of a permutation they
//!   are the message block it absorbs; on the last row of a permutation that a
//!   continuation block follows, they are the rate of its output, so the XOR
//!   of the two can be checked bit by bit across the row boundary. Every bit
//!   is boolean on every row, so every byte read from them is in `[0, 255]`.
//! - `DIR`: on the first row of a tree-node permutation, whether the child is
//!   the right half.
//! - `CARRY`: witness values constant over the whole trace (the bytes of `r`
//!   and `b`, the amount limbs of `v` and `v'`, the conservation carries), so
//!   that permutations far apart read the same value.
//!
//! The constraints, with periodic selectors marking the rows they apply to:
//!
//! 1. Keccak-f on every permutation.
//! 2. First block of a hash: the input state is the block, capacity zero.
//! 3. Continuation block: the output bits recompose the output limbs, the
//!    input rate is their XOR with the block, the capacity carries over.
//! 4. Every block byte matches its source: a constant, a public value, a
//!    carried column, a limb of a carried amount, or the digest of the
//!    permutation just before (for a tree node, on the side `DIR` names).
//!    Tree-node blocks with their pair at different offsets (25 for a
//!    commitment tree node, 31 for a data marker-set node) each have their
//!    own selector, and every node block is checked.
//! 5. A digest with a public destination equals those public bytes.
//! 6. Carried columns never change; conservation holds on their limbs.
//! 7. The ordering test of an absence witness (S3 only), on the last row of
//!    the marker's permutation, whose `BITS` nothing else reads: the marker
//!    (that row's digest) against the low leaf's `value` and `nextValue` (the
//!    next row's block bytes). The witness of the two subtractions sits in
//!    that row's `BITS`, so the test adds no column and no row.

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, generate_trace_rows};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SubAirBuilder;

use crate::amount::{AMOUNT_LIMBS, limb_bytes};
use crate::hash::RATE_BYTES;
use crate::schedule::{Assignment, Execution, Ordering, PermSpec, Schedule, Src};

pub(crate) type F = BabyBear;

// The ordering witness in the `BITS` of the marker row, as bit offsets. The
// marker's 32 digest bytes come first, in the byte layout of a block, so
// limb `j` of the digest is bytes `2j` (low) and `2j + 1` (high) of them.
// Then, for `value < marker` and for `marker < nextValue`, 32 difference
// bytes and 32 borrow bits each, and last the `zero_next` flag: 833 of the
// 1,088 bits.
const ORD_MARKER: usize = 0;
const ORD_LOW_DIFF: usize = ORD_MARKER + 256;
const ORD_LOW_BORROW: usize = ORD_LOW_DIFF + 256;
const ORD_HIGH_DIFF: usize = ORD_LOW_BORROW + 32;
const ORD_HIGH_BORROW: usize = ORD_HIGH_DIFF + 256;
const ORD_ZERO_NEXT: usize = ORD_HIGH_BORROW + 32;
const _: () = assert!(ORD_ZERO_NEXT < NUM_BITS && ORD_LOW_DIFF % 8 == 0 && ORD_HIGH_DIFF % 8 == 0);

/// `a - b` over 32-byte big-endian integers, byte 31 first: the difference
/// bytes and the borrow out of each byte. The borrow out of byte 0 is 1
/// exactly when `a < b`.
fn subtract(a: &[u8], b: &[u8]) -> ([u8; 32], [bool; 32]) {
    let mut diff = [0u8; 32];
    let mut borrow = [false; 32];
    let mut borrow_in = 0i32;
    for i in (0..32).rev() {
        let d = i32::from(a[i]) - i32::from(b[i]) - borrow_in;
        borrow[i] = d < 0;
        diff[i] = d.rem_euclid(256) as u8;
        borrow_in = i32::from(borrow[i]);
    }
    (diff, borrow)
}

/// The constraints of `a - b` over 32 big-endian bytes under `sel`:
/// `a_i - b_i - borrow_in(i) + 256 * borrow_out(i) = d_i` from byte 31 up,
/// `borrow_in(31) = 0` and `borrow_in(i) = borrow_out(i + 1)`. The borrows
/// and the bits of each `d_i` are `BITS` cells, boolean on every row, so
/// every `d_i` is in `[0, 255]` and every term is far below the field size:
/// the equations hold over the integers and fix the borrows. Returns the
/// borrow out of byte 0, which is 1 exactly when `a < b`.
fn assert_subtraction<AB: AirBuilder<F = F>>(
    builder: &mut AB,
    sel: &AB::Expr,
    a: &[AB::Expr],
    b: &[AB::Expr],
    diff: &[AB::Expr],
    borrow: &[AB::Var],
) -> AB::Expr {
    let radix = AB::Expr::from(F::from_u32(256));
    for i in (0..32).rev() {
        let borrow_in = if i == 31 { AB::Expr::ZERO } else { borrow[i + 1].into() };
        let lhs = a[i].clone() - b[i].clone() - borrow_in + radix.clone() * borrow[i].into();
        builder.assert_zero(sel.clone() * (lhs - diff[i].clone()));
    }
    borrow[0].into()
}

/// Rate limbs of the state (136 bytes).
const RATE_LIMBS: usize = RATE_BYTES / 2;
/// All limbs of the state.
const STATE_LIMBS: usize = 100;
/// Limbs of a digest.
const DIGEST_LIMBS: usize = 16;

const BITS: usize = NUM_KECCAK_COLS;
const NUM_BITS: usize = RATE_BYTES * 8;
const DIR: usize = BITS + NUM_BITS;
const CARRY: usize = DIR + 1;

const fn first_row(perm: usize) -> usize {
    perm * NUM_ROUNDS
}

const fn last_row(perm: usize) -> usize {
    perm * NUM_ROUNDS + NUM_ROUNDS - 1
}

/// State limb `i` as `(y, x, limb)` in the Keccak circuit. Limb `i` holds
/// bytes `2i` and `2i + 1` of the state.
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

/// What a byte of a block is checked against, besides constants.
#[derive(Clone, Copy, Debug)]
enum Target {
    Public(usize),
    Carried(usize),
}

/// The per-permutation checks under one first-row selector.
#[derive(Clone, Debug)]
struct PermCheck {
    selector: usize,
    bytes: Vec<(usize, Target)>,
    limb_ties: Vec<(usize, usize, usize)>,
}

/// The AIR of one statement at one trace height.
#[derive(Clone, Debug)]
pub(crate) struct StatementAir {
    schedule: Schedule,
    perms: Vec<PermSpec>,
    height: usize,
    periodic: Vec<Vec<F>>,
    // Periodic column indices.
    const_sel: usize,
    const_val: usize,
    first: usize,
    cont: usize,
    /// One `(selector, offset)` per offset of a tree-node pair, in the order
    /// the schedule first has them.
    nodes: Vec<(usize, usize)>,
    links: Vec<(usize, usize)>,
    outputs: Vec<(usize, usize)>,
    checks: Vec<PermCheck>,
    /// The ordering test: its selector, the marker's last permutation, and
    /// the offsets of `value` and `nextValue` in the next block.
    ordering: Option<(usize, usize, Ordering)>,
}

impl StatementAir {
    /// Rows the schedule needs, rounded up to a power of two and to at least
    /// `min_height`.
    pub(crate) fn height_for(schedule: &Schedule, min_height: usize) -> usize {
        (schedule.expand().len() * NUM_ROUNDS)
            .next_power_of_two()
            .max(min_height.next_power_of_two())
    }

    pub(crate) fn new(schedule: Schedule, height: usize) -> Self {
        let perms = schedule.expand();
        assert!(height.is_power_of_two());
        assert!(perms.len() * NUM_ROUNDS <= height, "the trace is too short");

        let mut periodic: Vec<Vec<F>> = Vec::new();
        let column = |periodic: &mut Vec<Vec<F>>| {
            periodic.push(vec![F::ZERO; height]);
            periodic.len() - 1
        };

        // Constants, one selector and one value column per byte position.
        let const_sel = periodic.len();
        for _ in 0..RATE_BYTES {
            column(&mut periodic);
        }
        let const_val = periodic.len();
        for _ in 0..RATE_BYTES {
            column(&mut periodic);
        }
        let first = column(&mut periodic);
        let cont = column(&mut periodic);

        let mut nodes: Vec<(usize, usize)> = Vec::new();
        let mut link_cols: BTreeMap<usize, usize> = BTreeMap::new();
        let mut outputs = Vec::new();
        let mut checks = Vec::new();

        for (p, perm) in perms.iter().enumerate() {
            let row = first_row(p);
            if perm.first {
                periodic[first][row] = F::ONE;
            } else {
                assert!(p > 0);
                periodic[cont][last_row(p - 1)] = F::ONE;
            }
            let mut bytes = Vec::new();
            for (i, src) in perm.bytes.iter().enumerate() {
                match *src {
                    Src::Const(c) => {
                        periodic[const_sel + i][row] = F::ONE;
                        periodic[const_val + i][row] = F::from_u8(c);
                    }
                    Src::Public(k) => bytes.push((i, Target::Public(k))),
                    Src::Carried(c) => bytes.push((i, Target::Carried(c))),
                    Src::Free | Src::Prev(_) | Src::Node(_) => {}
                }
            }
            if !bytes.is_empty() || !perm.limb_ties.is_empty() {
                let selector = column(&mut periodic);
                periodic[selector][row] = F::ONE;
                checks.push(PermCheck {
                    selector,
                    bytes,
                    limb_ties: perm.limb_ties.clone(),
                });
            }
            if let Some(at) = perm.prev_at {
                let selector = *link_cols.entry(at).or_insert_with(|| column(&mut periodic));
                periodic[selector][last_row(p - 1)] = F::ONE;
            }
            if let Some(at) = perm.node_at {
                let selector = match nodes.iter().find(|&&(_, node_at)| node_at == at) {
                    Some(&(selector, _)) => selector,
                    None => {
                        let selector = column(&mut periodic);
                        nodes.push((selector, at));
                        selector
                    }
                };
                periodic[selector][last_row(p - 1)] = F::ONE;
            }
            if let Some(offset) = perm.output {
                let selector = column(&mut periodic);
                periodic[selector][last_row(p)] = F::ONE;
                outputs.push((selector, offset));
            }
        }
        let links = link_cols.into_iter().map(|(at, col)| (col, at)).collect();

        // 7. The ordering test reads the marker row's `BITS` and the next
        // row's block, so that row must be one no other check uses: the last
        // row of the marker's hash, with no public output, followed by the
        // first block of the low leaf, which links nothing to it.
        let ordering = schedule.ordering.map(|ord| {
            let next = schedule.first_perm(ord.marker + 1);
            assert!(next > 0 && next < perms.len(), "the low leaf follows the marker");
            let (marker, leaf) = (&perms[next - 1], &perms[next]);
            assert!(leaf.first && marker.output.is_none(), "the marker row is free");
            assert!(leaf.prev_at.is_none() && leaf.node_at.is_none(), "the marker row is free");
            for at in [ord.value_at, ord.next_at] {
                assert!(at + 32 <= RATE_BYTES, "the low leaf's values lie in its first block");
                assert!(leaf.bytes[at..at + 32].iter().all(|src| *src == Src::Free));
            }
            let selector = column(&mut periodic);
            periodic[selector][last_row(next - 1)] = F::ONE;
            (selector, next - 1, ord)
        });

        Self {
            schedule,
            perms,
            height,
            periodic,
            const_sel,
            const_val,
            first,
            cont,
            nodes,
            links,
            outputs,
            checks,
            ordering,
        }
    }

    pub(crate) const fn height(&self) -> usize {
        self.height
    }

    /// The trace for an assignment and its execution.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn generate_trace(&self, ex: &Execution, a: &Assignment) -> RowMajorMatrix<F> {
        self.generate_trace_with(ex, a, None)
    }

    /// [`Self::generate_trace`], with the ordering test's `zero_next` flag
    /// set to `zero_next` when given instead of derived from `nextValue`, so
    /// tests can show a forged flag is caught.
    pub(crate) fn generate_trace_with(
        &self,
        ex: &Execution,
        a: &Assignment,
        zero_next: Option<bool>,
    ) -> RowMajorMatrix<F> {
        assert_eq!(ex.inputs.len(), self.perms.len());
        let width = self.width();
        let mut inputs = ex.inputs.clone();
        inputs.resize(self.height / NUM_ROUNDS, [0u64; 25]);
        let keccak: RowMajorMatrix<F> = generate_trace_rows(inputs, 0);
        assert_eq!(keccak.values.len(), self.height * NUM_KECCAK_COLS);

        let carried: Vec<F> = a.carried.iter().map(|&x| F::from_u32(x)).collect();
        let mut values = F::zero_vec(self.height * width);
        for (i, row) in values.chunks_exact_mut(width).enumerate() {
            row[..NUM_KECCAK_COLS].copy_from_slice(&keccak.values[i * NUM_KECCAK_COLS..(i + 1) * NUM_KECCAK_COLS]);
            row[CARRY..].copy_from_slice(&carried);
        }
        let mut set_bits = |row: usize, bytes: &[u8; RATE_BYTES]| {
            let cells = &mut values[row * width + BITS..row * width + BITS + NUM_BITS];
            for (i, &byte) in bytes.iter().enumerate() {
                for z in 0..8 {
                    cells[8 * i + z] = F::from_u8(byte >> z & 1);
                }
            }
        };
        for (p, perm) in self.perms.iter().enumerate() {
            set_bits(first_row(p), &ex.blocks[p]);
            if !perm.first {
                set_bits(last_row(p - 1), &ex.prev_rate[p]);
            }
        }
        if let Some((_, perm, ord)) = self.ordering {
            let marker = &ex.digests[ord.marker];
            let leaf = &ex.blocks[perm + 1];
            let value = &leaf[ord.value_at..ord.value_at + 32];
            let next = &leaf[ord.next_at..ord.next_at + 32];
            let (low_diff, low_borrow) = subtract(value, marker);
            let (high_diff, high_borrow) = subtract(marker, next);
            let mut bytes = [0u8; RATE_BYTES];
            bytes[ORD_MARKER / 8..ORD_MARKER / 8 + 32].copy_from_slice(marker);
            bytes[ORD_LOW_DIFF / 8..ORD_LOW_DIFF / 8 + 32].copy_from_slice(&low_diff);
            bytes[ORD_HIGH_DIFF / 8..ORD_HIGH_DIFF / 8 + 32].copy_from_slice(&high_diff);
            let mut set_bit = |bit: usize, on: bool| bytes[bit / 8] |= u8::from(on) << (bit % 8);
            for i in 0..32 {
                set_bit(ORD_LOW_BORROW + i, low_borrow[i]);
                set_bit(ORD_HIGH_BORROW + i, high_borrow[i]);
            }
            set_bit(ORD_ZERO_NEXT, zero_next.unwrap_or(next.iter().all(|&b| b == 0)));
            set_bits(last_row(perm), &bytes);
        }
        for (p, perm) in self.perms.iter().enumerate() {
            if perm.node_at.is_some() && ex.dirs[p] {
                values[first_row(p) * width + DIR] = F::ONE;
            }
        }
        RowMajorMatrix::new(values, width)
    }
}

impl BaseAir<F> for StatementAir {
    fn width(&self) -> usize {
        CARRY + self.schedule.carried
    }

    fn num_public_values(&self) -> usize {
        self.schedule.num_public
    }

    fn num_periodic_columns(&self) -> usize {
        self.periodic.len()
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        Cow::Borrowed(&self.periodic)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for StatementAir {
    fn eval(&self, builder: &mut AB) {
        // 1. Keccak-f on every permutation.
        {
            let mut sub = SubAirBuilder::<AB, KeccakAir, AB::Var>::new(builder, 0..NUM_KECCAK_COLS);
            KeccakAir {}.eval(&mut sub);
        }

        // The rows are read in place: the window outlives the builder's
        // borrow, so no row is copied per evaluation.
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pv: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let per: Vec<AB::PeriodicVar> = builder.periodic_values().to_vec();
        let kl: &KeccakCols<AB::Var> = local[..NUM_KECCAK_COLS].borrow();
        let kn: &KeccakCols<AB::Var> = next[..NUM_KECCAK_COLS].borrow();
        let e = |v: AB::Var| -> AB::Expr { v.into() };
        let c = |x: u32| AB::Expr::from(F::from_u32(x));
        let p = |k: usize| -> AB::Expr { pv[k].into() };
        let s = |k: usize| -> AB::Expr { per[k].into() };

        let bits_l = &local[BITS..BITS + NUM_BITS];
        let bits_n = &next[BITS..BITS + NUM_BITS];
        let byte = |bits: &[AB::Var], i: usize| -> AB::Expr {
            (0..8).rev().fold(AB::Expr::ZERO, |acc, z| acc.double() + bits[8 * i + z].into())
        };
        // Every byte of this row's bits; the next row's are read only where a
        // link or a tree node needs them.
        let bytes_l: Vec<AB::Expr> = (0..RATE_BYTES).map(|i| byte(bits_l, i)).collect();
        // Limb `j` of a byte run starting at `at`: two bytes, low first.
        let limb = |bytes: &[AB::Expr], at: usize, j: usize| -> AB::Expr {
            bytes[at + 2 * j].clone() + bytes[at + 2 * j + 1].clone() * c(256)
        };
        let limb_n =
            |at: usize, j: usize| -> AB::Expr { byte(bits_n, at + 2 * j) + byte(bits_n, at + 2 * j + 1) * c(256) };
        let pv_limb = |at: usize, j: usize| -> AB::Expr { p(at + 2 * j) + p(at + 2 * j + 1) * c(256) };

        for bit in bits_l {
            builder.assert_bool(*bit);
        }
        builder.assert_bool(local[DIR]);

        // 2. First block of a hash: input = block, capacity zero.
        let first = s(self.first);
        for j in 0..RATE_LIMBS {
            builder.assert_zero(first.clone() * (e(pre(kl, j)) - limb(&bytes_l, 0, j)));
        }
        for j in RATE_LIMBS..STATE_LIMBS {
            builder.assert_zero(first.clone() * e(pre(kl, j)));
        }

        // 3. Continuation block, checked from the last row of the permutation
        // before: its output bits, then the next input as output XOR block.
        let cont = s(self.cont);
        for j in 0..RATE_LIMBS {
            builder.assert_zero(cont.clone() * (e(out(kl, j)) - limb(&bytes_l, 0, j)));
            let xored = (0..16).rev().fold(AB::Expr::ZERO, |acc, z| {
                let o = e(bits_l[16 * j + z]);
                let m = e(bits_n[16 * j + z]);
                acc.double() + o.clone() + m.clone() - (o * m).double()
            });
            builder.assert_zero(cont.clone() * (e(pre(kn, j)) - xored));
        }
        for j in RATE_LIMBS..STATE_LIMBS {
            builder.assert_zero(cont.clone() * (e(pre(kn, j)) - e(out(kl, j))));
        }

        // 4. Block bytes against their sources.
        for i in 0..RATE_BYTES {
            builder.assert_zero(s(self.const_sel + i) * bytes_l[i].clone() - s(self.const_val + i));
        }
        for check in &self.checks {
            let sel = s(check.selector);
            for &(i, target) in &check.bytes {
                let value = match target {
                    Target::Public(k) => p(k),
                    Target::Carried(col) => e(local[CARRY + col]),
                };
                builder.assert_zero(sel.clone() * (bytes_l[i].clone() - value));
            }
            for &(col, hi, lo) in &check.limb_ties {
                let recomposed = bytes_l[hi].clone() * c(256) + bytes_l[lo].clone();
                builder.assert_zero(sel.clone() * (recomposed - e(local[CARRY + col])));
            }
        }
        for &(selector, at) in &self.links {
            let sel = s(selector);
            for j in 0..DIGEST_LIMBS {
                builder.assert_zero(sel.clone() * (e(out(kl, j)) - limb_n(at, j)));
            }
        }
        for &(selector, at) in &self.nodes {
            let sel = s(selector);
            let right = e(next[DIR]);
            for j in 0..DIGEST_LIMBS {
                let left_limb = limb_n(at, j);
                let right_limb = limb_n(at + 32, j);
                let child = left_limb.clone() + right.clone() * (right_limb - left_limb);
                builder.assert_zero(sel.clone() * (e(out(kl, j)) - child));
            }
        }

        // 5. Digests with a public destination.
        for &(selector, at) in &self.outputs {
            let sel = s(selector);
            for j in 0..DIGEST_LIMBS {
                builder.assert_zero(sel.clone() * (e(out(kl, j)) - pv_limb(at, j)));
            }
        }

        // 6. Carried columns, public constants and conservation.
        for col in 0..self.schedule.carried {
            builder.when_transition().assert_eq(next[CARRY + col], local[CARRY + col]);
        }
        for &(k, value) in &self.schedule.public_consts {
            builder.when_first_row().assert_eq(p(k), c(u32::from(value)));
        }
        if let Some(cons) = self.schedule.conservation {
            let carry = |j: usize| -> AB::Expr {
                if j == 0 || j == AMOUNT_LIMBS {
                    AB::Expr::ZERO
                } else {
                    let base = CARRY + cons.carries + 2 * (j - 1);
                    e(local[base]) + e(local[base + 1]).double()
                }
            };
            for j in 1..AMOUNT_LIMBS {
                let base = CARRY + cons.carries + 2 * (j - 1);
                builder.assert_bool(local[base]);
                builder.assert_bool(local[base + 1]);
                // A carry is 0, 1 or 2, never 3.
                builder.assert_zero(e(local[base]) * e(local[base + 1]));
            }
            let word_limb = |at: usize, j: usize| -> AB::Expr {
                let (hi, lo) = limb_bytes(j);
                p(at + hi) * c(256) + p(at + lo)
            };
            for j in 0..AMOUNT_LIMBS {
                let left = word_limb(cons.out, j) + e(local[CARRY + cons.remainder + j]) + word_limb(cons.fee, j) + carry(j);
                let right = e(local[CARRY + cons.v + j]) + c(1 << 16) * carry(j + 1);
                builder.when_first_row().assert_eq(left, right);
            }
        }

        // 7. The ordering test of the absence witness, on the marker row:
        // `value < marker` and (`marker < nextValue` or `nextValue = 0`).
        if let Some((selector, _, ord)) = self.ordering {
            let sel = s(selector);
            // The marker: this row's digest, its 16 limbs decomposed into the
            // 32 bytes at `ORD_MARKER`, big-endian byte `i` the digest's byte `i`.
            let marker: Vec<AB::Expr> = (0..32).map(|i| bytes_l[ORD_MARKER / 8 + i].clone()).collect();
            for j in 0..DIGEST_LIMBS {
                builder.assert_zero(sel.clone() * (e(out(kl, j)) - limb(&bytes_l, ORD_MARKER / 8, j)));
            }
            let value: Vec<AB::Expr> = (0..32).map(|i| byte(bits_n, ord.value_at + i)).collect();
            let next_value: Vec<AB::Expr> = (0..32).map(|i| byte(bits_n, ord.next_at + i)).collect();
            let diff = |at: usize| -> Vec<AB::Expr> { (0..32).map(|i| bytes_l[at / 8 + i].clone()).collect() };

            // `value < marker`: the subtraction borrows out of byte 0. Equal
            // values give no borrow, so the test is strict.
            let low = assert_subtraction(
                builder,
                &sel,
                &value,
                &marker,
                &diff(ORD_LOW_DIFF),
                &bits_l[ORD_LOW_BORROW..ORD_LOW_BORROW + 32],
            );
            builder.assert_zero(sel.clone() * (AB::Expr::ONE - low));

            // `marker < nextValue`, unless `zero_next`. The flag is boolean
            // (a `BITS` cell) and set only if every byte of `nextValue` is
            // zero: the bytes are in `[0, 255]`, so their sum, at most 8,160,
            // is zero only when each is. So the flag needs no equality with
            // `nextValue = 0`: a prover who sets it shows `nextValue = 0`,
            // the case the spec accepts without the comparison, and one who
            // clears it must show `marker < nextValue`, which is enough on
            // its own (and impossible when `nextValue = 0`). Either way the
            // test holds.
            let high = assert_subtraction(
                builder,
                &sel,
                &marker,
                &next_value,
                &diff(ORD_HIGH_DIFF),
                &bits_l[ORD_HIGH_BORROW..ORD_HIGH_BORROW + 32],
            );
            let zero_next = e(bits_l[ORD_ZERO_NEXT]);
            let next_sum = next_value.iter().cloned().fold(AB::Expr::ZERO, |acc, x| acc + x);
            builder.assert_zero(sel.clone() * zero_next.clone() * next_sum);
            builder.assert_zero(sel * (AB::Expr::ONE - zero_next) * (AB::Expr::ONE - high));
        }
    }
}
