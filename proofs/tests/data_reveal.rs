//! The shipped data reveal verifier (S2, spec 02, section 5), built without
//! the `unsettled-points-test` feature: it settles the fee from the reserve
//! `DATA_RESERVE` (spec 04, section 6) and then checks the proof, for a
//! reveal and a revocation alike. The proof of holding stays refused.
//!
//! Proving runs one test at a time to bound memory.

use std::sync::{Mutex, MutexGuard};

use ghost_proofs::*;

static PROVING: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only zero-knowledge randomness; a real prover draws it from a secure
/// random source.
fn zk(n: u8) -> [u8; 32] {
    let mut seed = [0x3cu8; 32];
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

/// An example fee far below the reserve.
const FEE: u128 = 21_000_000_000_000;

fn path() -> [[u8; 32]; TREE_DEPTH] {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Data, level as u8, &empty, &empty);
    }
    path[0] = [9; 32];
    path
}

/// An example salted data commitment at position 3 of a data tree.
fn opening() -> SaltedDataOpening {
    SaltedDataOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        salt: [0x5e; SALT_BYTES],
        cf: [4; 32],
        position: 3,
        path: path(),
    }
}

fn root() -> [u8; 32] {
    let o = opening();
    let leaf = data_commitment_v2(&data_fingerprint_v2(&o.s, &o.r, &o.b, &o.salt, &o.cf, &EMPTY_RULE));
    merkle_root(Tree::Data, &leaf, o.position, &o.path)
}

fn request(purpose: DataPurpose, fee: u128) -> DataRevealRequest {
    DataRevealRequest {
        purpose,
        root: root(),
        party: [0x70; 32],
        fee: amount_word(fee),
        rule: EMPTY_RULE,
    }
}

fn prove(purpose: DataPurpose, fee: u128, seed: u8) -> (DataReveal, Proof) {
    prove_salted_data_reveal(&params(), &opening(), &request(purpose, fee), zk(seed)).expect("honest proof")
}

fn with_fee(tx: &DataReveal, fee: [u8; 32]) -> DataReveal {
    DataReveal { fee, ..tx.clone() }
}

#[test]
fn a_data_reveal_verifies_without_the_unsettled_points_feature() {
    let _one = one_at_a_time();
    let (tx, proof) = prove(DataPurpose::Reveal, FEE, 1);
    assert_eq!(tx.purpose, DataPurpose::Reveal);
    assert_eq!(tx.fee, amount_word(FEE));
    assert_eq!(verify_salted_data_reveal(&params(), &tx, &proof), Ok(()));
    // The same reveal claiming a fee above the reserve is refused before the
    // proof, and one claiming another fee within it fails at the proof.
    assert_eq!(
        verify_salted_data_reveal(&params(), &with_fee(&tx, amount_word(DATA_RESERVE + 1)), &proof),
        Err(ProofError::FeeAboveReserve)
    );
    assert_eq!(
        verify_salted_data_reveal(&params(), &with_fee(&tx, amount_word(FEE + 1)), &proof),
        Err(ProofError::Rejected)
    );
}

#[test]
fn a_data_revocation_verifies_without_the_unsettled_points_feature() {
    let _one = one_at_a_time();
    let (tx, proof) = prove(DataPurpose::Revoke, FEE, 2);
    assert_eq!(tx.purpose, DataPurpose::Revoke);
    assert_eq!(verify_salted_data_reveal(&params(), &tx, &proof), Ok(()));
    // The purpose is bound in the digest: the revocation is no reveal.
    let as_reveal = DataReveal {
        purpose: DataPurpose::Reveal,
        ..tx.clone()
    };
    assert_eq!(verify_salted_data_reveal(&params(), &as_reveal, &proof), Err(ProofError::Rejected));
    assert_eq!(
        verify_salted_data_reveal(&params(), &with_fee(&tx, amount_word(DATA_RESERVE + 1)), &proof),
        Err(ProofError::FeeAboveReserve)
    );
}

#[test]
fn a_data_reveal_with_a_fee_equal_to_the_reserve_verifies() {
    let _one = one_at_a_time();
    let (tx, proof) = prove(DataPurpose::Reveal, DATA_RESERVE, 3);
    assert_eq!(tx.fee, DATA_RESERVE_WORD);
    assert_eq!(verify_salted_data_reveal(&params(), &tx, &proof), Ok(()));
}

#[test]
fn a_data_reveal_with_a_fee_above_the_reserve_is_rejected() {
    let tx = DataReveal {
        purpose: DataPurpose::Reveal,
        root: root(),
        marker: data_marker_v2(&opening().r, &opening().b, &opening().salt),
        party: [0x70; 32],
        fee: amount_word(FEE),
        rule: EMPTY_RULE,
        cf: opening().cf,
    };
    // An empty proof: the fee is refused before the proof is read.
    let empty = Proof::from_bytes(Vec::new());
    assert_eq!(verify_salted_data_reveal(&params(), &tx, &empty), Err(ProofError::MalformedProof));
    for fee in [DATA_RESERVE + 1, V_MAX] {
        assert_eq!(
            verify_salted_data_reveal(&params(), &with_fee(&tx, amount_word(fee)), &empty),
            Err(ProofError::FeeAboveReserve),
            "{fee}"
        );
    }
    // A word above V_MAX is no amount at all.
    assert_eq!(
        verify_salted_data_reveal(&params(), &with_fee(&tx, amount_word(V_MAX + 1)), &empty),
        Err(ProofError::AmountOutOfRange)
    );
    assert_eq!(
        ProofError::FeeAboveReserve.to_string(),
        "the fee of a data reveal is above the fee reserve"
    );
}

#[test]
fn a_proof_of_holding_that_does_not_verify_is_refused_without_the_feature() {
    let ctx = HoldContext {
        type_tag: DATA_V2,
        root: root(),
        marker_set_root: [0x6d; 32],
        verifier: [0x0a; 32],
        challenge: [0xc1; 32],
        cf: opening().cf,
    };
    assert_eq!(ctx.check(), Ok(()));
    for proof in [Proof::from_bytes(Vec::new()), Proof::from_bytes(vec![0xa5; 4096])] {
        assert!(verify_hold(&params(), &ctx, &proof).is_err());
    }
}
