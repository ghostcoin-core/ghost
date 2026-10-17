//! Candidate A: the reveal statement with Poseidon2 over BabyBear, width 24.
//!
//! One trace row holds one Poseidon2 permutation, in the order
//!
//! ```text
//! row  0..=2   commitment being opened, three sponge blocks
//! row  3..=34  tree nodes, levels 0..=31
//! row  35      marker
//! row  36..=38 remainder commitment, three sponge blocks
//! row  39..    padding (permutations of the zero state)
//! ```
//!
//! The permutation circuit keeps every constraint at degree 2: each S-box
//! `x^7` commits `x^2`, `x^3` and `x^6`, and the round output is constrained
//! as `x^6 * x` inside the linear layer. That is what lets the primary blowup
//! of 2^1 carry zero-knowledge mode, whose quotient needs one degree more
//! than the constraints.
//!
//! Row roles are fixed by periodic columns of period equal to the trace
//! height, so both sides know them without a commitment.

use alloc::vec;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_24,
    BABYBEAR_POSEIDON2_RC_24_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_24_INTERNAL, BabyBear, GenericPoseidon2LinearLayersBabyBear,
    Poseidon2BabyBear, default_babybear_poseidon2_24,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;

use crate::witness::{AMOUNT_LIMB_BITS, AMOUNT_LIMBS, TREE_DEPTH, Witness, amount_limbs};
use crate::{Tag, fill_periodic};

type F = BabyBear;
type Layers = GenericPoseidon2LinearLayersBabyBear;

pub const WIDTH: usize = 24;
pub const RATE: usize = 16;
pub const DIGEST: usize = 8;
const HALF_FULL: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_24;

// ---------------------------------------------------------------------------
// Permutation columns.

/// Three registers per S-box (`x^2`, `x^3`, `x^6`) and the round output.
const FULL_ROUND_COLS: usize = 3 * WIDTH + WIDTH;
const PARTIAL_ROUND_COLS: usize = 4;
const IN: usize = 0;
const fn begin_round(r: usize) -> usize {
    WIDTH + r * FULL_ROUND_COLS
}
const fn partial_round(k: usize) -> usize {
    WIDTH + HALF_FULL * FULL_ROUND_COLS + k * PARTIAL_ROUND_COLS
}
const fn end_round(r: usize) -> usize {
    partial_round(PARTIAL) + r * FULL_ROUND_COLS
}
/// Output of the permutation: the last round's post state.
const OUT: usize = end_round(HALF_FULL - 1) + 3 * WIDTH;
const PERM_COLS: usize = end_round(HALF_FULL);

// ---------------------------------------------------------------------------
// Statement columns.

/// Direction bit of the tree level held in this row.
const DIR: usize = PERM_COLS;
/// `d * (right - left)`, which turns the left/right selection into a degree-2
/// constraint.
const SWAP: usize = DIR + 1;
/// Witness values carried, unchanged, through every row.
const CARRY: usize = SWAP + DIGEST;
const C_S: usize = CARRY;
const C_R: usize = C_S + 8;
const C_B: usize = C_R + 8;
const C_VT: usize = C_B + 8;
const C_FP: usize = C_VT + 1;
const C_RULE: usize = C_FP + 8;
const C_V: usize = C_RULE + 4;
const C_S2: usize = C_V + AMOUNT_LIMBS;
const C_R2: usize = C_S2 + 8;
const C_B2: usize = C_R2 + 8;
const C_V2: usize = C_B2 + 8;
const CARRY_END: usize = C_V2 + AMOUNT_LIMBS;
/// Range-check lanes, one per 24-bit limb of `v` and `v'`: a bit column and
/// an accumulator column, MSB first over rows 0..=23.
const RANGE: usize = CARRY_END;
const RANGE_LANES: usize = 2 * AMOUNT_LIMBS;
/// Carry bits of the conservation sum: three carries of two bits each.
const CONS: usize = RANGE + 2 * RANGE_LANES;
pub const TRACE_WIDTH: usize = CONS + 6;

// ---------------------------------------------------------------------------
// Rows and periodic selectors.

const ROW_C: usize = 0;
const ROW_NODE: usize = 3;
const ROW_ROOT: usize = ROW_NODE + TREE_DEPTH - 1;
const ROW_MARKER: usize = ROW_NODE + TREE_DEPTH;
const ROW_REM: usize = ROW_MARKER + 1;
/// Rows that carry a permutation of the statement.
pub const STATEMENT_ROWS: usize = ROW_REM + 3;
/// The smallest power-of-two trace that holds the statement.
pub const MIN_HEIGHT: usize = STATEMENT_ROWS.next_power_of_two();

const P_C0: usize = 0;
const P_C1: usize = 1;
const P_C2: usize = 2;
const P_R0: usize = 3;
const P_R1: usize = 4;
const P_R2: usize = 5;
const P_MARKER: usize = 6;
const P_NODE: usize = 7;
const P_LEVEL: usize = 8;
const P_LINK: usize = 9;
const P_ROOT: usize = 10;
const P_CHAIN: usize = 11;
const P_RANGE_STEP: usize = 12;
const P_RANGE_END: usize = 13;
const NUM_PERIODIC: usize = 14;

// ---------------------------------------------------------------------------
// Public inputs.

pub const PI_ROOT: usize = 0;
pub const PI_MARKER: usize = PI_ROOT + DIGEST;
pub const PI_REMAINDER: usize = PI_MARKER + DIGEST;
pub const PI_OUT: usize = PI_REMAINDER + DIGEST;
pub const PI_FEE: usize = PI_OUT + AMOUNT_LIMBS;
pub const PI_BINDING: usize = PI_FEE + AMOUNT_LIMBS;
pub const PI_TYPE: usize = PI_BINDING + DIGEST;
pub const NUM_PUBLIC: usize = PI_TYPE + 1;

// ---------------------------------------------------------------------------
// Native hashing.

/// Eight field elements from 32 bytes, four bytes each, reduced.
pub fn elements8(bytes: &[u8; 32]) -> [F; 8] {
    core::array::from_fn(|i| {
        F::from_u32(u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
    })
}

fn elements4(bytes: &[u8; 16]) -> [F; 4] {
    core::array::from_fn(|i| {
        F::from_u32(u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
    })
}

fn limbs_f(amount: u128) -> [F; AMOUNT_LIMBS] {
    amount_limbs(amount).map(F::from_u32)
}

/// The library's permutation, used for the native statement and for the
/// commitment scheme.
pub fn permutation() -> Poseidon2BabyBear<WIDTH> {
    default_babybear_poseidon2_24()
}

/// The commitment message: `(s, r, b, version and type, fingerprint, rule, v)`,
/// 8 + 8 + 8 + 1 + 8 + 4 + 4 = 41 elements, absorbed in three blocks of 16.
fn commitment_blocks(s: [F; 8], r: [F; 8], b: [F; 8], w: &Witness, v: u128) -> [[F; RATE]; 3] {
    let mut msg = vec![];
    msg.extend(s);
    msg.extend(r);
    msg.extend(b);
    msg.push(F::from_u32(w.type_tag));
    msg.extend(elements8(&w.fingerprint));
    msg.extend(elements4(&w.rule));
    msg.extend(limbs_f(v));
    msg.resize(3 * RATE, F::ZERO);
    core::array::from_fn(|i| msg[i * RATE..(i + 1) * RATE].try_into().unwrap())
}

/// The permutation inputs of the statement, in row order, together with the
/// public digests they produce.
pub struct StatementPerms {
    pub inputs: Vec<[F; WIDTH]>,
    pub root: [F; DIGEST],
    pub marker: [F; DIGEST],
    pub remainder: [F; DIGEST],
}

fn digest(state: &[F; WIDTH]) -> [F; DIGEST] {
    state[..DIGEST].try_into().unwrap()
}

/// Absorb a fixed-length message in overwrite mode with the tag in the
/// capacity, returning each block's permutation input and the final state.
fn sponge(
    perm: &Poseidon2BabyBear<WIDTH>,
    tag: Tag,
    blocks: &[[F; RATE]],
    inputs: &mut Vec<[F; WIDTH]>,
) -> [F; WIDTH] {
    let mut state = [F::ZERO; WIDTH];
    state[RATE] = F::from_u32(tag as u32);
    for block in blocks {
        state[..RATE].copy_from_slice(block);
        inputs.push(state);
        state = perm.permute(state);
    }
    state
}

pub fn statement_perms(w: &Witness) -> StatementPerms {
    let perm = permutation();
    let mut inputs = Vec::with_capacity(STATEMENT_ROWS);

    let (s, r, b) = (
        elements8(&w.secret),
        elements8(&w.reveal_secret),
        elements8(&w.blinding),
    );
    let opened = sponge(
        &perm,
        Tag::Commitment,
        &commitment_blocks(s, r, b, w, w.amount),
        &mut inputs,
    );

    let mut current = digest(&opened);
    for level in 0..TREE_DEPTH {
        let sibling = elements8(&w.siblings[level]);
        let (left, right) = if w.direction(level) {
            (sibling, current)
        } else {
            (current, sibling)
        };
        let mut state = [F::ZERO; WIDTH];
        state[..DIGEST].copy_from_slice(&left);
        state[DIGEST..RATE].copy_from_slice(&right);
        state[RATE] = F::from_u32(Tag::TreeNode as u32);
        state[RATE + 1] = F::from_usize(level);
        inputs.push(state);
        current = digest(&perm.permute(state));
    }
    let root = current;

    let mut block = [F::ZERO; RATE];
    block[..8].copy_from_slice(&r);
    block[8..].copy_from_slice(&b);
    let marker = digest(&sponge(&perm, Tag::Marker, &[block], &mut inputs));

    let remainder = digest(&sponge(
        &perm,
        Tag::Commitment,
        &commitment_blocks(
            elements8(&w.remainder_secret),
            elements8(&w.remainder_reveal_secret),
            elements8(&w.remainder_blinding),
            w,
            w.remainder_amount,
        ),
        &mut inputs,
    ));

    debug_assert_eq!(inputs.len(), STATEMENT_ROWS);
    StatementPerms {
        inputs,
        root,
        marker,
        remainder,
    }
}

/// The binding digest, computed by the verifier outside the proof: a tagged
/// hash of the chain identifier, transaction type and version, destination,
/// amount out, fee, remainder commitment and tree root.
pub fn binding_digest(w: &Witness, remainder: &[F; DIGEST], root: &[F; DIGEST]) -> [F; DIGEST] {
    let mut msg = vec![
        F::from_u32((w.binding.chain_id & 0xff_ffff) as u32),
        F::from_u32(((w.binding.chain_id >> 24) & 0xff_ffff) as u32),
        F::from_u32((w.binding.chain_id >> 48) as u32),
        F::from_u32(u32::from(w.binding.transaction_type) << 8 | u32::from(w.binding.transaction_version)),
    ];
    for chunk in w.binding.destination.chunks(4) {
        msg.push(F::from_u32(u32::from_le_bytes(chunk.try_into().unwrap())));
    }
    msg.extend(limbs_f(w.amount_out));
    msg.extend(limbs_f(w.fee));
    msg.extend(remainder);
    msg.extend(root);
    msg.resize(msg.len().div_ceil(RATE) * RATE, F::ZERO);
    let blocks: Vec<[F; RATE]> = msg.chunks(RATE).map(|c| c.try_into().unwrap()).collect();
    digest(&sponge(&permutation(), Tag::Binding, &blocks, &mut Vec::new()))
}

/// The honest public inputs for a witness, in the layout of `PI_*`.
pub fn public_inputs(w: &Witness) -> Vec<F> {
    let perms = statement_perms(w);
    let mut pis = Vec::with_capacity(NUM_PUBLIC);
    pis.extend(perms.root);
    pis.extend(perms.marker);
    pis.extend(perms.remainder);
    pis.extend(limbs_f(w.amount_out));
    pis.extend(limbs_f(w.fee));
    pis.extend(binding_digest(w, &perms.remainder, &perms.root));
    pis.push(F::from_u32(w.type_tag));
    pis
}

// ---------------------------------------------------------------------------
// Trace generation.

fn sbox_registers(x: F) -> ([F; 3], F) {
    let x2 = x * x;
    let x3 = x2 * x;
    let x6 = x3 * x3;
    ([x2, x3, x6], x6 * x)
}

fn fill_full_round(state: &mut [F; WIDTH], cols: &mut [F], rc: &[F; WIDTH]) {
    for i in 0..WIDTH {
        let (regs, y) = sbox_registers(state[i] + rc[i]);
        cols[3 * i..3 * i + 3].copy_from_slice(&regs);
        state[i] = y;
    }
    Layers::external_linear_layer(state);
    cols[3 * WIDTH..4 * WIDTH].copy_from_slice(state);
}

/// Write one permutation into `row` and return its output.
pub fn fill_permutation(row: &mut [F], input: [F; WIDTH]) -> [F; WIDTH] {
    row[IN..IN + WIDTH].copy_from_slice(&input);
    let mut state = input;
    Layers::external_linear_layer(&mut state);
    for r in 0..HALF_FULL {
        let at = begin_round(r);
        fill_full_round(
            &mut state,
            &mut row[at..at + FULL_ROUND_COLS],
            &BABYBEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL[r],
        );
    }
    for k in 0..PARTIAL {
        let at = partial_round(k);
        let (regs, y) = sbox_registers(state[0] + BABYBEAR_POSEIDON2_RC_24_INTERNAL[k]);
        row[at..at + 3].copy_from_slice(&regs);
        row[at + 3] = y;
        state[0] = y;
        Layers::internal_linear_layer(&mut state);
    }
    for r in 0..HALF_FULL {
        let at = end_round(r);
        fill_full_round(
            &mut state,
            &mut row[at..at + FULL_ROUND_COLS],
            &BABYBEAR_POSEIDON2_RC_24_EXTERNAL_FINAL[r],
        );
    }
    state
}

/// Integer carries of `out + v' + fee = v`, limb by limb, clamped to two
/// bits. A witness that breaks conservation still gets a trace; it simply
/// does not satisfy the constraints.
pub(crate) fn conservation_carries(w: &Witness) -> [u32; AMOUNT_LIMBS - 1] {
    let v = amount_limbs(w.amount);
    let v2 = amount_limbs(w.remainder_amount);
    let out = amount_limbs(w.amount_out);
    let fee = amount_limbs(w.fee);
    let mut carry: i64 = 0;
    let mut carries = [0u32; AMOUNT_LIMBS - 1];
    for i in 0..AMOUNT_LIMBS - 1 {
        let sum = i64::from(out[i]) + i64::from(v2[i]) + i64::from(fee[i]) + carry - i64::from(v[i]);
        carry = (sum >> AMOUNT_LIMB_BITS).clamp(0, 3);
        carries[i] = carry as u32;
    }
    carries
}

pub fn generate_trace(w: &Witness, height: usize) -> RowMajorMatrix<F> {
    assert!(height.is_power_of_two() && height >= MIN_HEIGHT);
    let perms = statement_perms(w);
    let mut values = F::zero_vec(height * TRACE_WIDTH);

    let mut carry = [F::ZERO; CARRY_END - CARRY];
    let mut put = |at: usize, xs: &[F]| carry[at - CARRY..at - CARRY + xs.len()].copy_from_slice(xs);
    put(C_S, &elements8(&w.secret));
    put(C_R, &elements8(&w.reveal_secret));
    put(C_B, &elements8(&w.blinding));
    put(C_VT, &[F::from_u32(w.type_tag)]);
    put(C_FP, &elements8(&w.fingerprint));
    put(C_RULE, &elements4(&w.rule));
    put(C_V, &limbs_f(w.amount));
    put(C_S2, &elements8(&w.remainder_secret));
    put(C_R2, &elements8(&w.remainder_reveal_secret));
    put(C_B2, &elements8(&w.remainder_blinding));
    put(C_V2, &limbs_f(w.remainder_amount));

    let lanes: Vec<u32> = amount_limbs(w.amount)
        .into_iter()
        .chain(amount_limbs(w.remainder_amount))
        .collect();
    let carries = conservation_carries(w);

    let mut padding_row = vec![F::ZERO; TRACE_WIDTH];
    let _ = fill_permutation(&mut padding_row, [F::ZERO; WIDTH]);

    for (i, row) in values.chunks_exact_mut(TRACE_WIDTH).enumerate() {
        if i < STATEMENT_ROWS {
            let _ = fill_permutation(row, perms.inputs[i]);
        } else {
            row[..PERM_COLS].copy_from_slice(&padding_row[..PERM_COLS]);
        }
        if (ROW_NODE..=ROW_ROOT).contains(&i) && w.direction(i - ROW_NODE) {
            row[DIR] = F::ONE;
        }
        for k in 0..DIGEST {
            row[SWAP + k] = row[DIR] * (row[IN + DIGEST + k] - row[IN + k]);
        }
        row[CARRY..CARRY_END].copy_from_slice(&carry);
        if i < AMOUNT_LIMB_BITS {
            let shift = AMOUNT_LIMB_BITS - 1 - i;
            for (lane, &val) in lanes.iter().enumerate() {
                row[RANGE + 2 * lane] = F::from_u32((val >> shift) & 1);
                row[RANGE + 2 * lane + 1] = F::from_u32(val >> shift);
            }
        }
        if i == ROW_C {
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
        let mut set = |col: usize, rows: core::ops::RangeInclusive<usize>| {
            fill_periodic(&mut periodic[col], rows, F::ONE);
        };
        set(P_C0, ROW_C..=ROW_C);
        set(P_C1, ROW_C + 1..=ROW_C + 1);
        set(P_C2, ROW_C + 2..=ROW_C + 2);
        set(P_R0, ROW_REM..=ROW_REM);
        set(P_R1, ROW_REM + 1..=ROW_REM + 1);
        set(P_R2, ROW_REM + 2..=ROW_REM + 2);
        set(P_MARKER, ROW_MARKER..=ROW_MARKER);
        set(P_NODE, ROW_NODE..=ROW_ROOT);
        set(P_LINK, ROW_C + 2..=ROW_ROOT - 1);
        set(P_ROOT, ROW_ROOT..=ROW_ROOT);
        set(P_CHAIN, ROW_C..=ROW_C + 1);
        set(P_CHAIN, ROW_REM..=ROW_REM + 1);
        set(P_RANGE_STEP, 0..=AMOUNT_LIMB_BITS - 2);
        set(P_RANGE_END, AMOUNT_LIMB_BITS - 1..=AMOUNT_LIMB_BITS - 1);
        for level in 0..TREE_DEPTH {
            periodic[P_LEVEL][ROW_NODE + level] = F::from_usize(level);
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

    fn periodic_columns(&self) -> alloc::borrow::Cow<'_, [Vec<F>]> {
        alloc::borrow::Cow::Borrowed(&self.periodic)
    }
}

/// Constrain one S-box and return its output expression (degree 2).
fn eval_sbox<AB: AirBuilder<F = F>>(builder: &mut AB, x: AB::Expr, regs: &[AB::Var]) -> AB::Expr {
    let (x2, x3, x6): (AB::Expr, AB::Expr, AB::Expr) = (regs[0].into(), regs[1].into(), regs[2].into());
    builder.assert_eq(x2.clone(), x.square());
    builder.assert_eq(x3.clone(), x2 * x.clone());
    builder.assert_eq(x6.clone(), x3.square());
    x6 * x
}

fn eval_full_round<AB: AirBuilder<F = F>>(
    builder: &mut AB,
    state: &mut [AB::Expr; WIDTH],
    cols: &[AB::Var],
    rc: &[F; WIDTH],
) {
    for i in 0..WIDTH {
        let x = state[i].clone() + AB::Expr::from(rc[i]);
        state[i] = eval_sbox(builder, x, &cols[3 * i..3 * i + 3]);
    }
    Layers::external_linear_layer(state);
    for i in 0..WIDTH {
        let post = cols[3 * WIDTH + i];
        builder.assert_eq(state[i].clone(), post);
        state[i] = post.into();
    }
}

/// Constrain the permutation held in `row`.
fn eval_permutation<AB: AirBuilder<F = F>>(builder: &mut AB, row: &[AB::Var]) {
    let mut state: [AB::Expr; WIDTH] = core::array::from_fn(|i| row[IN + i].into());
    Layers::external_linear_layer(&mut state);
    for r in 0..HALF_FULL {
        let at = begin_round(r);
        eval_full_round(
            builder,
            &mut state,
            &row[at..at + FULL_ROUND_COLS],
            &BABYBEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL[r],
        );
    }
    for k in 0..PARTIAL {
        let at = partial_round(k);
        let x = state[0].clone() + AB::Expr::from(BABYBEAR_POSEIDON2_RC_24_INTERNAL[k]);
        let y = eval_sbox(builder, x, &row[at..at + 3]);
        builder.assert_eq(y, row[at + 3]);
        state[0] = row[at + 3].into();
        Layers::internal_linear_layer(&mut state);
    }
    for r in 0..HALF_FULL {
        let at = end_round(r);
        eval_full_round(
            builder,
            &mut state,
            &row[at..at + FULL_ROUND_COLS],
            &BABYBEAR_POSEIDON2_RC_24_EXTERNAL_FINAL[r],
        );
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for RevealAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: Vec<AB::Var> = main.current_slice().to_vec();
        let next: Vec<AB::Var> = main.next_slice().to_vec();
        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|&v| v.into()).collect();
        let per: Vec<AB::Expr> = builder.periodic_values().iter().map(|&v| v.into()).collect();
        let e = |v: AB::Var| -> AB::Expr { v.into() };
        let c = |x: u32| AB::Expr::from(F::from_u32(x));

        // Every row is one permutation.
        eval_permutation(builder, &local);

        // Gate `sel * (a - b) = 0`.
        let gate = |builder: &mut AB, sel: &AB::Expr, a: AB::Expr, b: AB::Expr| {
            builder.assert_zero(sel.clone() * (a - b));
        };
        let input = |k: usize| e(local[IN + k]);
        let output = |k: usize| e(local[OUT + k]);

        // Commitment blocks, for the opened commitment and the remainder.
        for (p0, p1, p2, s, r, b, v) in [
            (P_C0, P_C1, P_C2, C_S, C_R, C_B, C_V),
            (P_R0, P_R1, P_R2, C_S2, C_R2, C_B2, C_V2),
        ] {
            for k in 0..8 {
                gate(builder, &per[p0], input(k), e(local[s + k]));
                gate(builder, &per[p0], input(8 + k), e(local[r + k]));
                gate(builder, &per[p1], input(k), e(local[b + k]));
            }
            gate(builder, &per[p0], input(RATE), c(Tag::Commitment as u32));
            for k in RATE + 1..WIDTH {
                gate(builder, &per[p0], input(k), AB::Expr::ZERO);
            }
            gate(builder, &per[p1], input(8), e(local[C_VT]));
            for k in 0..7 {
                gate(builder, &per[p1], input(9 + k), e(local[C_FP + k]));
            }
            gate(builder, &per[p2], input(0), e(local[C_FP + 7]));
            for k in 0..4 {
                gate(builder, &per[p2], input(1 + k), e(local[C_RULE + k]));
                gate(builder, &per[p2], input(5 + k), e(local[v + k]));
            }
            for k in 9..RATE {
                gate(builder, &per[p2], input(k), AB::Expr::ZERO);
            }
        }
        // The remainder commitment is public.
        for k in 0..DIGEST {
            gate(builder, &per[P_R2], output(k), pv[PI_REMAINDER + k].clone());
        }
        // Sponge chaining: the capacity passes from block to block.
        for k in RATE..WIDTH {
            gate(builder, &per[P_CHAIN], e(next[IN + k]), output(k));
        }

        // Tree nodes.
        let dir = e(local[DIR]);
        builder.assert_bool(dir.clone());
        builder.assert_zero(dir.clone() - per[P_NODE].clone() * dir.clone());
        for k in 0..DIGEST {
            builder.assert_zero(e(local[SWAP + k]) - dir.clone() * (input(DIGEST + k) - input(k)));
        }
        gate(builder, &per[P_NODE], input(RATE), c(Tag::TreeNode as u32));
        builder.assert_zero(per[P_NODE].clone() * input(RATE + 1) - per[P_LEVEL].clone());
        for k in RATE + 2..WIDTH {
            gate(builder, &per[P_NODE], input(k), AB::Expr::ZERO);
        }
        // The current node (the opened commitment at level 0) is the left
        // child when d = 0 and the right child when d = 1:
        // left - cur + d * (right - left) = 0.
        for k in 0..DIGEST {
            builder.assert_zero(
                per[P_LINK].clone() * (e(next[IN + k]) + e(next[SWAP + k]) - output(k)),
            );
        }
        for k in 0..DIGEST {
            gate(builder, &per[P_ROOT], output(k), pv[PI_ROOT + k].clone());
        }

        // Marker: tagged hash of (r, b).
        for k in 0..8 {
            gate(builder, &per[P_MARKER], input(k), e(local[C_R + k]));
            gate(builder, &per[P_MARKER], input(8 + k), e(local[C_B + k]));
        }
        gate(builder, &per[P_MARKER], input(RATE), c(Tag::Marker as u32));
        for k in RATE + 1..WIDTH {
            gate(builder, &per[P_MARKER], input(k), AB::Expr::ZERO);
        }
        for k in 0..DIGEST {
            gate(builder, &per[P_MARKER], output(k), pv[PI_MARKER + k].clone());
        }

        // Carried witness values never change.
        for k in CARRY..CARRY_END {
            builder.when_transition().assert_eq(next[k], local[k]);
        }

        // Type: the coin type, so a data commitment cannot satisfy this.
        gate(builder, &per[P_C0], e(local[C_VT]), pv[PI_TYPE].clone());
        gate(builder, &per[P_C0], pv[PI_TYPE].clone(), c(crate::witness::COIN_TYPE_TAG));

        // Range checks: every limb of v and v' is below 2^24.
        let lane_value = |lane: usize| {
            if lane < AMOUNT_LIMBS {
                e(local[C_V + lane])
            } else {
                e(local[C_V2 + lane - AMOUNT_LIMBS])
            }
        };
        for lane in 0..RANGE_LANES {
            let bit = RANGE + 2 * lane;
            let acc = bit + 1;
            builder.assert_bool(local[bit]);
            gate(builder, &per[P_C0], e(local[acc]), e(local[bit]));
            gate(
                builder,
                &per[P_RANGE_STEP],
                e(next[acc]),
                e(local[acc]).double() + e(next[bit]),
            );
            gate(builder, &per[P_RANGE_END], e(local[acc]), lane_value(lane));
        }

        // Conservation: out + v' + fee = v, limb by limb with carries.
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
        let base = AB::Expr::from(F::from_u32(1 << AMOUNT_LIMB_BITS));
        for i in 0..AMOUNT_LIMBS {
            gate(
                builder,
                &per[P_C0],
                pv[PI_OUT + i].clone() + e(local[C_V2 + i]) + pv[PI_FEE + i].clone() + carry(i),
                e(local[C_V + i]) + base.clone() * carry(i + 1),
            );
        }
    }
}

/// The public inputs, checked by the verifier outside the proof: canonical
/// field elements, coin type, and amount limbs below 2^24.
pub fn check_public_inputs(pis: &[F]) -> bool {
    pis.len() == NUM_PUBLIC
        && pis[PI_TYPE] == F::from_u32(crate::witness::COIN_TYPE_TAG)
        && pis[PI_OUT..PI_BINDING]
            .iter()
            .all(|x| x.as_canonical_u32() < 1 << AMOUNT_LIMB_BITS)
}

#[cfg(test)]
mod tests {
    use p3_air::check_all_constraints;

    use super::*;

    #[test]
    fn circuit_permutation_matches_the_library() {
        let perm = permutation();
        let input: [F; WIDTH] = core::array::from_fn(|i| F::from_u32(1000 + 7 * i as u32));
        let mut row = vec![F::ZERO; TRACE_WIDTH];
        let out = fill_permutation(&mut row, input);
        assert_eq!(out, perm.permute(input));
        assert_eq!(row[OUT..OUT + WIDTH], out);
    }

    #[test]
    fn honest_trace_satisfies_every_constraint() {
        let w = Witness::primary(11, false);
        let air = RevealAir::new(MIN_HEIGHT);
        let trace = generate_trace(&w, MIN_HEIGHT);
        let report = check_all_constraints(&air, &trace, &public_inputs(&w), Some(4));
        assert!(report.is_ok(), "{report:?}");
    }

    /// Every public input except the binding digest is tied to the trace by a
    /// constraint. The binding digest is bound through the transcript only,
    /// which the integration tests cover.
    #[test]
    fn every_public_input_is_bound_by_a_constraint() {
        let w = Witness::primary(13, true);
        let air = RevealAir::new(MIN_HEIGHT);
        let trace = generate_trace(&w, MIN_HEIGHT);
        let honest = public_inputs(&w);
        for (name, range) in crate::HashCandidate::Poseidon2.public_input_groups() {
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

    #[test]
    fn broken_conservation_violates_a_constraint() {
        let mut w = Witness::primary(12, true);
        let pis = public_inputs(&w);
        w.remainder_amount += 1;
        let air = RevealAir::new(MIN_HEIGHT);
        let trace = generate_trace(&w, MIN_HEIGHT);
        assert!(!check_all_constraints(&air, &trace, &pis, Some(1)).is_ok());
    }
}
