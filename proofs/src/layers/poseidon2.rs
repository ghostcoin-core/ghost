//! The width-24 Poseidon2 permutation over BabyBear as AIR columns: one
//! permutation a row.
//!
//! The permutation is the library's `default_babybear_poseidon2_24`, rebuilt
//! here from the round constants `p3_baby_bear` exports
//! (`BABYBEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL`, `_EXTERNAL_FINAL` and
//! `_INTERNAL`): 4 full rounds, 21 partial rounds, 4 full rounds, the S-box
//! `x^7`, the external layer of the `[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]`
//! blocks and the internal layer `1 + Diag(V)` of the library. A test holds the
//! two to the same output on random inputs.
//!
//! The row layout keeps every constraint at degree 3: the inputs, then for each
//! full round the cube of every S-box input and the state after the round's
//! linear layer, and for each partial round the cube of the first lane's S-box
//! input and that lane's S-box output. The state inside the partial rounds is a
//! linear expression in those columns and is never stored.

use alloc::vec::Vec;

use p3_baby_bear::{
    BABYBEAR_POSEIDON2_RC_24_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_24_INTERNAL,
};
use p3_field::{Algebra, Field, PrimeCharacteristicRing};

use super::F;

/// Lanes of the permutation.
pub(crate) const WIDTH: usize = 24;
/// Full rounds at each end.
const HALF_FULL_ROUNDS: usize = 4;
/// Partial rounds in the middle.
const PARTIAL_ROUNDS: usize = 21;
/// Columns of one full round: the cube of each S-box input, then the state
/// after the linear layer.
const FULL_ROUND_COLS: usize = 2 * WIDTH;
/// Columns of one partial round: the cube of the S-box input, then its output.
const PARTIAL_ROUND_COLS: usize = 2;
/// Columns of one permutation row.
pub(crate) const PERM_COLS: usize =
    WIDTH + 2 * HALF_FULL_ROUNDS * FULL_ROUND_COLS + PARTIAL_ROUNDS * PARTIAL_ROUND_COLS;
const _: () = assert!(PERM_COLS == 450);
/// First column of the output: the state after the last full round.
const OUTPUT_START: usize = PERM_COLS - WIDTH;

/// The diagonal `V` of the internal layer `1 + Diag(V)` for width 24, as the
/// library defines it.
fn internal_diagonal() -> [F; WIDTH] {
    let half = F::TWO.inverse();
    let inv2 = |k: u64| half.exp_u64(k);
    let n = |k: u64| -inv2(k);
    [
        -F::TWO,
        F::ONE,
        F::TWO,
        inv2(1),
        F::from_u8(3),
        F::from_u8(4),
        n(1),
        -F::from_u8(3),
        -F::from_u8(4),
        inv2(8),
        inv2(2),
        inv2(3),
        inv2(4),
        inv2(7),
        inv2(9),
        inv2(27),
        n(8),
        n(2),
        n(3),
        n(4),
        n(5),
        n(6),
        n(7),
        n(27),
    ]
}

/// The 4x4 block `[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]`.
fn mat4<R: PrimeCharacteristicRing>(x: &mut [R]) {
    let t01 = x[0].dup() + x[1].dup();
    let t23 = x[2].dup() + x[3].dup();
    let t0123 = t01.dup() + t23.dup();
    let t01123 = t0123.dup() + x[1].dup();
    let t01233 = t0123 + x[3].dup();
    x[3] = t01233.dup() + x[0].double();
    x[1] = t01123.dup() + x[2].double();
    x[0] = t01123 + t01;
    x[2] = t01233 + t23;
}

/// The external linear layer.
fn external_linear<R: PrimeCharacteristicRing>(state: &mut [R; WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        mat4(chunk);
    }
    let sums: [R; 4] = core::array::from_fn(|k| (0..WIDTH).step_by(4).map(|j| state[j + k].dup()).sum());
    for (i, x) in state.iter_mut().enumerate() {
        *x += sums[i % 4].dup();
    }
}

/// The internal linear layer: every lane becomes the sum of the lanes plus
/// `V_i` times itself.
fn internal_linear<R: Algebra<F>>(state: &mut [R; WIDTH], diagonal: &[F; WIDTH]) {
    let sum: R = state.iter().map(|x| x.dup()).sum();
    for (x, &d) in state.iter_mut().zip(diagonal) {
        *x = sum.dup() + x.dup() * d;
    }
}

/// The permutation, natively, with every column of its row.
pub(crate) fn permute_row(input: [F; WIDTH]) -> Vec<F> {
    let diagonal = internal_diagonal();
    let mut row = Vec::with_capacity(PERM_COLS);
    row.extend_from_slice(&input);
    let mut state = input;
    external_linear(&mut state);
    let full_round = |state: &mut [F; WIDTH], rc: &[F; WIDTH], row: &mut Vec<F>| {
        let mut out = [F::ZERO; WIDTH];
        for i in 0..WIDTH {
            let x = state[i] + rc[i];
            let cube = x * x * x;
            row.push(cube);
            out[i] = cube * cube * x;
        }
        external_linear(&mut out);
        row.extend_from_slice(&out);
        *state = out;
    };
    for rc in &BABYBEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL {
        full_round(&mut state, rc, &mut row);
    }
    for &rc in &BABYBEAR_POSEIDON2_RC_24_INTERNAL {
        let x = state[0] + rc;
        let cube = x * x * x;
        let y = cube * cube * x;
        row.push(cube);
        row.push(y);
        state[0] = y;
        internal_linear(&mut state, &diagonal);
    }
    for rc in &BABYBEAR_POSEIDON2_RC_24_EXTERNAL_FINAL {
        full_round(&mut state, rc, &mut row);
    }
    debug_assert_eq!(row.len(), PERM_COLS);
    row
}

/// The permutation's output.
pub(crate) fn permute(input: [F; WIDTH]) -> [F; WIDTH] {
    let row = permute_row(input);
    core::array::from_fn(|i| row[OUTPUT_START + i])
}

/// The input columns of a row.
pub(crate) fn input_columns() -> core::ops::Range<usize> {
    0..WIDTH
}

/// The output columns of a row.
pub(crate) fn output_columns() -> core::ops::Range<usize> {
    OUTPUT_START..PERM_COLS
}

/// The constraints of one row, each of degree at most 3, handed to `assert`
/// as expressions that must vanish. `cols` is the row, as expressions.
pub(crate) fn eval_row<E: Algebra<F>>(cols: &[E], mut assert: impl FnMut(E)) {
    debug_assert_eq!(cols.len(), PERM_COLS);
    let diagonal = internal_diagonal();
    let mut state: [E; WIDTH] = core::array::from_fn(|i| cols[i].dup());
    external_linear(&mut state);
    let mut at = WIDTH;
    let full_round = |state: &mut [E; WIDTH], rc: &[F; WIDTH], at: &mut usize, assert: &mut dyn FnMut(E)| {
        let mut sbox: [E; WIDTH] = core::array::from_fn(|_| E::ZERO);
        for i in 0..WIDTH {
            let x = state[i].dup() + rc[i];
            let cube = cols[*at + i].dup();
            assert(cube.dup() - x.dup() * x.dup() * x.dup());
            sbox[i] = cube.dup() * cube * x;
        }
        external_linear(&mut sbox);
        for i in 0..WIDTH {
            let post = cols[*at + WIDTH + i].dup();
            assert(post.dup() - sbox[i].dup());
            state[i] = post;
        }
        *at += FULL_ROUND_COLS;
    };
    for rc in &BABYBEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL {
        full_round(&mut state, rc, &mut at, &mut assert);
    }
    for &rc in &BABYBEAR_POSEIDON2_RC_24_INTERNAL {
        let x = state[0].dup() + rc;
        let cube = cols[at].dup();
        let y = cols[at + 1].dup();
        assert(cube.dup() - x.dup() * x.dup() * x.dup());
        assert(y.dup() - cube.dup() * cube * x);
        state[0] = y;
        internal_linear(&mut state, &diagonal);
        at += PARTIAL_ROUND_COLS;
    }
    for rc in &BABYBEAR_POSEIDON2_RC_24_EXTERNAL_FINAL {
        full_round(&mut state, rc, &mut at, &mut assert);
    }
    debug_assert_eq!(at, PERM_COLS);
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::default_babybear_poseidon2_24;
    use p3_symmetric::Permutation;

    use super::*;

    #[test]
    fn rows_match_the_library_permutation_and_satisfy_the_constraints() {
        let library = default_babybear_poseidon2_24();
        let mut seed = 24u64;
        for _ in 0..8 {
            let input: [F; WIDTH] = core::array::from_fn(|_| {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                F::from_u32((seed >> 33) as u32 % 0x7800_0001)
            });
            let row = permute_row(input);
            assert_eq!(&row[output_columns()], &library.permute(input)[..]);
            let mut failed = 0;
            eval_row(&row, |e: F| failed += usize::from(e != F::ZERO));
            assert_eq!(failed, 0);
            let mut bad = row.clone();
            bad[WIDTH + 3] += F::ONE;
            let mut failed = 0;
            eval_row(&bad, |e: F| failed += usize::from(e != F::ZERO));
            assert!(failed > 0);
        }
    }
}
