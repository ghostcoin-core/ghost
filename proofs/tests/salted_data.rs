#![cfg(feature = "unsettled-points-test")]
//! The data reveal (S2) and the proof of holding (S3) of a salted (version 2)
//! data commitment (spec 01, section 3; spec 02, PS-25 and AV-13).
//!
//! The salt is a private witness: a proof made with the commitment's salt
//! verifies, one made with another salt does not, and neither the public
//! fields, the binding digest nor the proof bytes hold the salt. A version 1
//! data commitment, made without a salt, neither opens nor can be held.
//!
//! The S2 and S3 provers exist only under the `unsettled-points-test`
//! feature. Every negative test starts from the honest proof, asserted to
//! verify, and changes one thing. Proving runs one test at a time to bound
//! memory.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard, OnceLock};

use ghost_proofs::*;

static PROVING: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only zero-knowledge randomness; a real prover draws it from a secure
/// random source.
fn zk(n: u8) -> [u8; 32] {
    let mut seed = [0x5au8; 32];
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

/// An example salt, fixed so the test repeats; a wallet draws every salt
/// fresh.
const SALT: [u8; SALT_BYTES] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

const POSITION: u32 = 5;
const FEE: [u8; 32] = {
    let mut fee = [0u8; 32];
    fee[31] = 21;
    fee
};

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

/// A salted data commitment at position 5 of a data tree.
fn salted_data() -> SaltedDataOpening {
    SaltedDataOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        salt: SALT,
        cf: [4; 32],
        position: POSITION,
        path: path(),
    }
}

fn salted_root() -> [u8; 32] {
    let o = salted_data();
    let leaf = data_commitment_v2(&data_fingerprint_v2(&o.s, &o.r, &o.b, &o.salt, &o.cf, &EMPTY_RULE));
    merkle_root(Tree::Data, &leaf, o.position, &o.path)
}

fn with_salt(o: &SaltedDataOpening, salt: [u8; SALT_BYTES]) -> SaltedDataOpening {
    SaltedDataOpening { salt, ..*o }
}

fn hold_opening(o: &SaltedDataOpening) -> SaltedHoldOpening {
    SaltedHoldOpening {
        s: o.s,
        r: o.r,
        b: o.b,
        salt: o.salt,
        cf: o.cf,
        rule: EMPTY_RULE,
        position: o.position,
        path: o.path,
    }
}

fn request(purpose: DataPurpose, root: [u8; 32]) -> DataRevealRequest {
    DataRevealRequest {
        purpose,
        root,
        party: [0x70; 32],
        fee: FEE,
        rule: EMPTY_RULE,
    }
}

fn hold_context(root: [u8; 32]) -> HoldContext {
    HoldContext {
        type_tag: DATA_V2,
        root,
        marker_set_root: [0x6d; 32],
        verifier: [0x0a; 32],
        challenge: [0xc1; 32],
        cf: salted_data().cf,
    }
}

/// The version 1 type tag of data, which no statement of this crate knows.
const DATA_V1: [u8; 2] = [1, 2];

/// A version 1 data commitment of spec 01, made without a salt, computed here
/// from its tags since the crate no longer has the functions.
fn version_1_data_commitment(o: &SaltedDataOpening) -> [u8; 32] {
    let f = tagged("ghost/data-fingerprint/v1", &[&o.s, &o.r, &o.b, &DATA_V1, &o.cf, &EMPTY_RULE]);
    tagged("ghost/data-commitment/v1", &[&DATA_V1, &f])
}

/// The root of a data tree holding the version 1 commitment of the salted
/// opening's secrets at its position.
fn version_1_root() -> [u8; 32] {
    let o = salted_data();
    merkle_root(Tree::Data, &version_1_data_commitment(&o), o.position, &o.path)
}

fn changed_salt(at: usize) -> [u8; SALT_BYTES] {
    let mut salt = SALT;
    salt[at] ^= 1;
    salt
}

/// The honest salted data reveal, made once and asserted to verify.
fn honest_reveal() -> &'static (DataReveal, Proof) {
    static HONEST: OnceLock<(DataReveal, Proof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let (tx, proof) =
            prove_salted_data_reveal(&params(), &salted_data(), &request(DataPurpose::Reveal, salted_root()), zk(1))
                .expect("honest proof");
        assert_eq!(verify_salted_data_reveal_unsettled(&params(), &tx, &proof), Ok(()));
        (tx, proof)
    })
}

/// The honest salted proof of holding, made once and asserted to verify.
fn honest_hold() -> &'static Proof {
    static HONEST: OnceLock<Proof> = OnceLock::new();
    HONEST.get_or_init(|| {
        let ctx = hold_context(salted_root());
        let proof = prove_salted_hold(&params(), &hold_opening(&salted_data()), &ctx, zk(2)).expect("honest proof");
        assert_eq!(verify_hold_unsettled(&params(), &ctx, &proof), Ok(()));
        proof
    })
}

/// Whether `haystack` holds `needle` as bytes, or as one BabyBear element
/// (four little-endian bytes) per byte, the way the proof encodes a trace
/// value.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    let as_elements: Vec<u8> = needle.iter().flat_map(|&b| u32::from(b).to_le_bytes()).collect();
    haystack.windows(needle.len()).any(|w| w == needle)
        || haystack.windows(as_elements.len()).any(|w| w == as_elements)
}

/// A lying prover's proof does not verify. In a release build the prover
/// makes bytes and the verifier rejects them; with debug assertions on,
/// Plonky3 checks every constraint before it proves and panics on the broken
/// one, so no proof exists at all.
fn lying_proof_fails(
    prove: impl FnOnce() -> Result<Proof, ProofError>,
    verify: impl FnOnce(&Proof) -> Result<(), ProofError>,
) {
    match catch_unwind(AssertUnwindSafe(prove)) {
        Ok(proof) => {
            let proof = proof.expect("the lying prover still produces bytes");
            assert_eq!(verify(&proof), Err(ProofError::Rejected));
        }
        Err(_) => assert!(cfg!(debug_assertions), "only the debug constraint check may stop the prover"),
    }
}

// ---------------------------------------------------------------------------
// S2: the data reveal.

#[test]
fn a_salted_data_reveal_verifies_with_the_salt() {
    let _one = one_at_a_time();
    let o = salted_data();
    let (tx, proof) = honest_reveal();
    assert_eq!(tx.root, salted_root());
    // The marker is the salted one of spec 01, under the v2 tag.
    assert_eq!(tx.marker, data_marker_v2(&o.r, &o.b, &o.salt));
    assert_ne!(tx.marker, tagged("ghost/data-marker/v1", &[&o.r, &o.b]));
    assert!(proof.as_bytes().len() <= PROOF_FIELD_BYTES);
    // The shipped verifier still rejects every data reveal.
    assert_eq!(verify_salted_data_reveal(&params(), tx, proof), Err(ProofError::DataFeeUnsettled));

    // A revocation of the same commitment verifies too, and not as a reveal.
    let (revoke, revoke_proof) =
        prove_salted_data_reveal(&params(), &o, &request(DataPurpose::Revoke, salted_root()), zk(3))
            .expect("honest proof");
    assert_eq!(verify_salted_data_reveal_unsettled(&params(), &revoke, &revoke_proof), Ok(()));
    let as_reveal = DataReveal {
        purpose: DataPurpose::Reveal,
        ..revoke
    };
    assert_eq!(
        verify_salted_data_reveal_unsettled(&params(), &as_reveal, &revoke_proof),
        Err(ProofError::Rejected)
    );
}

#[test]
fn the_honest_data_prover_refuses_another_salt() {
    let o = salted_data();
    for at in [0, SALT_BYTES - 1] {
        let wrong = with_salt(&o, changed_salt(at));
        let refused = prove_salted_data_reveal(&params(), &wrong, &request(DataPurpose::Reveal, salted_root()), zk(4));
        assert_eq!(refused.err(), Some(ProofError::NotInTree), "salt byte {at}");
    }
}

/// AV-13: the right `s`, `r` and `b` with another salt make no data reveal
/// that verifies.
#[test]
fn a_data_reveal_with_a_wrong_salt_fails() {
    let _one = one_at_a_time();
    let (tx, honest_proof) = honest_reveal();
    let wrong = with_salt(&salted_data(), changed_salt(7));
    lying_proof_fails(
        || prove_salted_data_reveal_claiming(&params(), &wrong, tx, zk(5)),
        |proof| verify_salted_data_reveal_unsettled(&params(), tx, proof),
    );
    // The honest proof does not verify for the marker another salt gives.
    let other_marker = DataReveal {
        marker: data_marker_v2(&wrong.r, &wrong.b, &wrong.salt),
        ..tx.clone()
    };
    assert_eq!(
        verify_salted_data_reveal_unsettled(&params(), &other_marker, honest_proof),
        Err(ProofError::Rejected)
    );
}

/// PS-25: the salt is never public. Neither the data reveal's public fields,
/// its binding digest nor the proof bytes hold it.
#[test]
fn the_data_reveal_public_values_and_proof_hold_no_salt() {
    let _one = one_at_a_time();
    let (tx, proof) = honest_reveal();
    let published = [
        &[tx.purpose.code()][..],
        &tx.root,
        &tx.marker,
        &tx.party,
        &tx.fee,
        &tx.rule,
        &tx.cf,
        &salted_data_reveal_binding(&params(), tx),
        &params().chain_id,
        &params().domain,
    ]
    .concat();
    assert!(!holds(&published, &SALT), "a public value holds the salt");
    assert!(!holds(proof.as_bytes(), &SALT), "the proof holds the salt");
    // The check itself finds a salt that is there.
    assert!(holds(&[&[0u8; 5][..], &SALT, &[1; 3]].concat(), &SALT));
    let as_elements: Vec<u8> = SALT.iter().flat_map(|&b| u32::from(b).to_le_bytes()).collect();
    assert!(holds(&[&[7u8; 3][..], &as_elements].concat(), &SALT));
}

/// A version 1 data commitment, made without a salt, sits in the data tree.
/// The salted S2 prover refuses to open it with any salt, and a lying
/// prover's reveal under that root, with the version 1 marker, does not
/// verify.
#[test]
fn a_version_1_data_leaf_does_not_open() {
    let _one = one_at_a_time();
    let o = salted_data();
    let v1_root = version_1_root();
    assert_ne!(v1_root, salted_root());
    for salt in [SALT, [0; SALT_BYTES]] {
        let attempt = with_salt(&o, salt);
        let refused = prove_salted_data_reveal(&params(), &attempt, &request(DataPurpose::Reveal, v1_root), zk(6));
        assert_eq!(refused.err(), Some(ProofError::NotInTree), "salt {salt:?}");
    }

    let req = request(DataPurpose::Reveal, v1_root);
    let claimed = DataReveal {
        purpose: req.purpose,
        root: v1_root,
        marker: tagged("ghost/data-marker/v1", &[&o.r, &o.b]),
        party: req.party,
        fee: req.fee,
        rule: req.rule,
        cf: o.cf,
    };
    lying_proof_fails(
        || prove_salted_data_reveal_claiming(&params(), &o, &claimed, zk(7)),
        |proof| verify_salted_data_reveal_unsettled(&params(), &claimed, proof),
    );
}

// ---------------------------------------------------------------------------
// S3: the proof of holding.

#[test]
fn a_salted_proof_of_holding_verifies_with_the_salt() {
    let _one = one_at_a_time();
    let ctx = hold_context(salted_root());
    let proof = honest_hold();
    assert_eq!(ctx.check(), Ok(()));
    assert!(proof.as_bytes().len() <= PROOF_FIELD_BYTES);
    // The binding holds the version 2 type tag.
    let binding = hold_binding(&params(), &ctx).expect("a known type");
    let mut fields = vec![0u8; Binding::Hold.fields_len()];
    for f in HOLD_LAYOUT {
        let value: &[u8] = match f.name {
            "chain_id" => &params().chain_id,
            "version" => &params().version,
            "domain" => &params().domain,
            "statement" => &[STATEMENT_HOLD],
            "statement_version" => &[STATEMENT_VERSION_1],
            "type" => &DATA_V2,
            "purpose" => &[PURPOSE_HOLD],
            "root" => &ctx.root,
            "marker_set_root" => &ctx.marker_set_root,
            "verifier" => &ctx.verifier,
            "challenge" => &ctx.challenge,
            "cf" => &ctx.cf,
            other => panic!("unexpected field {other}"),
        };
        fields[f.offset..f.offset + f.width].copy_from_slice(value);
    }
    assert_eq!(binding, tagged("ghost/hold-binding/v1", &[&fields]));
    // The shipped verifier still rejects every proof of holding.
    assert_eq!(verify_hold(&params(), &ctx, proof), Err(ProofError::HoldUnsettled));
    // The proof is bound to the verifier's choices.
    let other_verifier = HoldContext {
        verifier: [0x0b; 32],
        ..ctx.clone()
    };
    assert_eq!(verify_hold_unsettled(&params(), &other_verifier, proof), Err(ProofError::Rejected));
}

#[test]
fn the_honest_hold_prover_refuses_another_salt() {
    let ctx = hold_context(salted_root());
    for at in [0, SALT_BYTES - 1] {
        let wrong = hold_opening(&with_salt(&salted_data(), changed_salt(at)));
        let refused = prove_salted_hold(&params(), &wrong, &ctx, zk(9));
        assert_eq!(refused.err(), Some(ProofError::NotInTree), "salt byte {at}");
    }
}

/// AV-13: the right `s`, `r` and `b` with another salt make no proof of
/// holding that verifies.
#[test]
fn a_proof_of_holding_with_a_wrong_salt_fails() {
    let _one = one_at_a_time();
    let ctx = hold_context(salted_root());
    let _ = honest_hold();
    let wrong = hold_opening(&with_salt(&salted_data(), changed_salt(15)));
    lying_proof_fails(
        || prove_salted_hold_claiming(&params(), &wrong, &ctx, zk(10)),
        |proof| verify_hold_unsettled(&params(), &ctx, proof),
    );
}

/// PS-25: neither the context, the hold binding digest nor the proof bytes
/// hold the salt.
#[test]
fn the_hold_public_values_and_proof_hold_no_salt() {
    let _one = one_at_a_time();
    let ctx = hold_context(salted_root());
    let proof = honest_hold();
    let published = [
        &ctx.type_tag[..],
        &ctx.root,
        &ctx.marker_set_root,
        &ctx.verifier,
        &ctx.challenge,
        &ctx.cf,
        &hold_binding(&params(), &ctx).unwrap(),
        &params().chain_id,
        &params().domain,
    ]
    .concat();
    assert!(!holds(&published, &SALT), "a public value holds the salt");
    assert!(!holds(proof.as_bytes(), &SALT), "the proof holds the salt");
}

/// A version 1 data commitment, made without a salt, sits in the data tree.
/// The salted S3 prover refuses to hold it with any salt, a lying prover's
/// proof of holding under that root does not verify, and a context of the
/// version 1 data type is unknown.
#[test]
fn a_version_1_leaf_cannot_be_held() {
    let _one = one_at_a_time();
    let ctx = hold_context(version_1_root());
    for salt in [SALT, [0; SALT_BYTES]] {
        let attempt = hold_opening(&with_salt(&salted_data(), salt));
        let refused = prove_salted_hold(&params(), &attempt, &ctx, zk(11));
        assert_eq!(refused.err(), Some(ProofError::NotInTree), "salt {salt:?}");
    }
    let opening = hold_opening(&salted_data());
    lying_proof_fails(
        || prove_salted_hold_claiming(&params(), &opening, &ctx, zk(12)),
        |proof| verify_hold_unsettled(&params(), &ctx, proof),
    );

    let as_v1 = HoldContext {
        type_tag: DATA_V1,
        ..hold_context(salted_root())
    };
    assert_eq!(as_v1.check(), Err(ProofError::UnknownType));
    assert_eq!(hold_binding(&params(), &as_v1), Err(ProofError::UnknownType));
    assert_eq!(prove_salted_hold(&params(), &opening, &as_v1, zk(13)).err(), Some(ProofError::UnknownType));
    assert_eq!(verify_hold_unsettled(&params(), &as_v1, honest_hold()), Err(ProofError::UnknownType));
}

// ---------------------------------------------------------------------------
// The trace budget.

/// The salted data statements: the 3,786 columns of an opening without a
/// salt and 16 carried salt columns, inside the budget and the proof field.
#[test]
fn the_salt_costs_sixteen_columns_within_the_budget() {
    let config = shipped_configuration().expect("the shipped configuration builds");
    let trace = |statement: Statement| {
        config
            .statements
            .iter()
            .find(|(s, _)| *s == statement)
            .unwrap_or_else(|| panic!("{statement:?} is not in the report"))
            .1
    };
    for statement in [Statement::SaltedDataReveal, Statement::SaltedHold] {
        let v2 = trace(statement);
        assert_eq!(v2.trace_width, 3786 + SALT_BYTES);
        assert_eq!(v2.trace_width, 3802);
        assert!(v2.trace_width <= 3824 && v2.trace_width <= MAX_TRACE_WIDTH);
        assert!(v2.trace_height <= MAX_TRACE_HEIGHT);
        assert!(proof_length_bound(v2.trace_height, v2.trace_width) <= PROOF_FIELD_BYTES);
        assert!(v2.conjectured_bits_half_grinding >= TARGET_CONJECTURED_BITS, "{v2:?}");
    }
}
