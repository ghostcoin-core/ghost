#![cfg(feature = "unsettled-points-test")]
//! Constraint 4 of the proof of holding (S3), part 2: the ordering test of
//! the `absence` witness, `low.value < marker` and (`marker < low.nextValue`
//! or `low.nextValue = 0`), in the circuit (spec 02, section 6; spec 05,
//! section 6), and the shipped [`verify_hold`] verifying.
//!
//! Honest proofs come from `prove_salted_hold` against real marker sets and
//! are checked with the shipped verifier. Each negative test builds its own
//! low leaf and takes the context's `marker_set_root` from that witness's own
//! `root()`, so the membership half holds and only the ordering is wrong.
//!
//! The S3 prover exists only under the `unsettled-points-test` feature, so
//! the file is built with it. Proving runs one test at a time to bound
//! memory.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard};

use ghost_proofs::*;

static PROVING: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only zero-knowledge randomness; a real prover draws it from a secure
/// random source.
fn zk(n: u8) -> [u8; 32] {
    let mut seed = [0x6fu8; 32];
    seed[0] = n;
    seed
}

/// Example chain constants, not Ghost's.
fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    }
}

// ---------------------------------------------------------------------------
// Two example commitments to the same content, side by side in the data
// tree at positions 6 and 7, with different salts and so different markers.

const S: [u8; 32] = [0x21; 32];
const R: [u8; 32] = [0x22; 32];
const B: [u8; 32] = [0x23; 32];
const CF: [u8; 32] = [0x24; 32];
const SALT: [u8; SALT_BYTES] = [0x3a; SALT_BYTES];
const OTHER_SALT: [u8; SALT_BYTES] = [0x3b; SALT_BYTES];
const POSITION: u32 = 6;

fn leaf(salt: &[u8; SALT_BYTES]) -> [u8; 32] {
    data_commitment_v2(&data_fingerprint_v2(&S, &R, &B, salt, &CF, &EMPTY_RULE))
}

/// The path of the leaf at `position` (6 or 7): its neighbour at level 0,
/// empty subtrees above.
fn data_path(position: u32) -> [[u8; 32]; TREE_DEPTH] {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Data, level as u8, &empty, &empty);
    }
    path[0] = leaf(if position == POSITION { &OTHER_SALT } else { &SALT });
    path
}

fn data_root() -> [u8; 32] {
    let root = merkle_root(Tree::Data, &leaf(&SALT), POSITION, &data_path(POSITION));
    assert_eq!(merkle_root(Tree::Data, &leaf(&OTHER_SALT), POSITION + 1, &data_path(POSITION + 1)), root);
    root
}

fn marker() -> [u8; 32] {
    data_marker_v2(&R, &B, &SALT)
}

fn other_marker() -> [u8; 32] {
    data_marker_v2(&R, &B, &OTHER_SALT)
}

fn opening_with(salt: [u8; SALT_BYTES], position: u32, absence: AbsenceWitness) -> SaltedHoldOpening {
    SaltedHoldOpening {
        s: S,
        r: R,
        b: B,
        salt,
        cf: CF,
        rule: EMPTY_RULE,
        position,
        path: data_path(position),
        absence,
    }
}

fn opening(absence: AbsenceWitness) -> SaltedHoldOpening {
    opening_with(SALT, POSITION, absence)
}

fn context(marker_set_root: [u8; 32]) -> HoldContext {
    HoldContext {
        type_tag: DATA_V2,
        root: data_root(),
        marker_set_root,
        verifier: [0x0a; 32],
        challenge: [0xc8; 32],
        cf: CF,
    }
}

/// A 32-byte big-endian integer plus or minus one.
fn plus_one(mut x: [u8; 32]) -> [u8; 32] {
    for byte in x.iter_mut().rev() {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            return x;
        }
    }
    panic!("2^256 - 1 has no successor");
}

fn minus_one(mut x: [u8; 32]) -> [u8; 32] {
    for byte in x.iter_mut().rev() {
        let (diff, borrow) = byte.overflowing_sub(1);
        *byte = diff;
        if !borrow {
            return x;
        }
    }
    panic!("zero has no predecessor");
}

/// A hand-made low leaf, its position and siblings arbitrary: the context
/// takes its root from the witness, so the leaf is under it whatever the
/// ordering says.
fn hand_made(low_value: [u8; 32], low_next_value: [u8; 32]) -> (AbsenceWitness, HoldContext) {
    let witness = AbsenceWitness {
        low_value,
        low_next_value,
        low_next_index: [0, 0, 0, 0, 9],
        position: 5,
        siblings: [[0x5a; 32]; MARKER_SET_DEPTH],
    };
    let root = witness.root().expect("a position below 2^40");
    (witness, context(root))
}

/// A lying prover's proof does not verify with the shipped verifier. In a
/// release build the prover makes bytes and the verifier rejects them; with
/// debug assertions on, Plonky3 checks every constraint before it proves and
/// panics on the broken one, so no proof exists at all.
fn lying_proof_fails(prove: impl FnOnce() -> Result<Proof, ProofError>, ctx: &HoldContext) {
    match catch_unwind(AssertUnwindSafe(prove)) {
        Ok(proof) => {
            let proof = proof.expect("the lying prover still produces bytes");
            assert_eq!(verify_hold(&params(), ctx, &proof), Err(ProofError::Rejected));
        }
        Err(_) => assert!(cfg!(debug_assertions), "only the debug constraint check may stop the prover"),
    }
}

/// The claiming prover on a hand-made witness: the membership holds, the
/// ordering does not, and no proof verifies.
fn ordering_fails(low_value: [u8; 32], low_next_value: [u8; 32], seed: u8) {
    let (absence, ctx) = hand_made(low_value, low_next_value);
    assert_eq!(absence.root(), Some(ctx.marker_set_root));
    lying_proof_fails(
        || prove_salted_hold_claiming(&params(), &opening(absence), &ctx, zk(seed)),
        &ctx,
    );
}

// ---------------------------------------------------------------------------
// Honest proofs.

#[test]
fn s3_proves_a_marker_between_the_low_leaf_and_its_next_value() {
    let _one = one_at_a_time();
    let m = marker();
    let (absence, root) = test_absence_witness(&[[0x01; 32], [0xff; 32]], &m);
    assert_eq!(absence.low_value, [0x01; 32]);
    assert_eq!(absence.low_next_value, [0xff; 32]);
    assert!(absence.low_value < m && m < absence.low_next_value);
    let ctx = context(root);
    let proof = prove_salted_hold(&params(), &opening(absence), &ctx, zk(1)).expect("honest proof");
    assert_eq!(verify_hold(&params(), &ctx, &proof), Ok(()));
    assert!(proof.as_bytes().len() <= PROOF_FIELD_BYTES);
}

#[test]
fn s3_proves_a_marker_above_the_last_value_through_the_zero_next_value() {
    let _one = one_at_a_time();
    let m = marker();
    let below = minus_one(m);
    let (absence, root) = test_absence_witness(&[[0x01; 32], below], &m);
    assert_eq!(absence.low_value, below, "the marker is just above the largest value");
    assert_eq!(absence.low_next_value, [0; 32]);
    let ctx = context(root);
    let proof = prove_salted_hold(&params(), &opening(absence), &ctx, zk(2)).expect("honest proof");
    assert_eq!(verify_hold(&params(), &ctx, &proof), Ok(()));

    // The flag is what carries this proof: cleared, the circuit asks for
    // `marker < 0`, and no proof verifies.
    lying_proof_fails(
        || prove_salted_hold_claiming_zero_next(&params(), &opening(absence), &ctx, false, zk(3)),
        &ctx,
    );
}

// ---------------------------------------------------------------------------
// The ordering, broken one way at a time.

#[test]
fn s3_fails_when_the_marker_equals_the_low_leaf_value() {
    let _one = one_at_a_time();
    // The marker is in the set: its own leaf, with a next value above it.
    ordering_fails(marker(), [0xff; 32], 4);
}

#[test]
fn s3_fails_when_the_marker_is_below_the_low_leaf_value() {
    let _one = one_at_a_time();
    // A zero next value, so only `value < marker` is broken.
    ordering_fails(plus_one(marker()), [0; 32], 5);
}

#[test]
fn s3_fails_when_the_marker_is_above_a_nonzero_next_value() {
    let _one = one_at_a_time();
    let m = marker();
    // `value < marker` holds; the next value is just below the marker, then
    // equal to it (the test is strict).
    ordering_fails(minus_one(minus_one(m)), minus_one(m), 6);
    ordering_fails(minus_one(m), m, 7);
}

#[test]
fn s3_fails_when_the_zero_flag_is_forged() {
    let _one = one_at_a_time();
    let m = marker();
    let next = minus_one(m);
    assert_ne!(next, [0; 32]);
    let (absence, ctx) = hand_made(minus_one(next), next);
    // The flag set over a nonzero next value would excuse `marker < next`.
    lying_proof_fails(
        || prove_salted_hold_claiming_zero_next(&params(), &opening(absence), &ctx, true, zk(8)),
        &ctx,
    );
}

/// Two commitments to the same content under the same tree: one whose marker
/// is absent from the set, one whose marker is spent. The first proves and
/// verifies; the second, borrowing the first's absence witness (the same
/// low leaf, under the same `marker_set_root`), makes no proof that
/// verifies, because its own marker is not inside that leaf's range.
#[test]
fn s3_proof_for_one_marker_does_not_verify_for_a_commitment_with_another_marker() {
    let _one = one_at_a_time();
    let (m, spent) = (marker(), other_marker());
    assert_ne!(m, spent);
    let (absence, root) = test_absence_witness(&[spent], &m);
    let ctx = context(root);
    // Whichever side of the spent marker the absent one lies, the spent one
    // is an end of the low leaf's range: its value or its next value.
    assert!(absence.low_value == spent || absence.low_next_value == spent);

    let proof = prove_salted_hold(&params(), &opening(absence), &ctx, zk(9)).expect("honest proof");
    assert_eq!(verify_hold(&params(), &ctx, &proof), Ok(()));

    let spent_opening = opening_with(OTHER_SALT, POSITION + 1, absence);
    lying_proof_fails(
        || prove_salted_hold_claiming(&params(), &spent_opening, &ctx, zk(10)),
        &ctx,
    );
}
