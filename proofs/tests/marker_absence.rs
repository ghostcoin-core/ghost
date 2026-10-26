#![cfg(feature = "unsettled-points-test")]
//! Constraint 4 of the proof of holding (S3), part 1: the low leaf of the
//! `absence` witness is opened under the public `marker_set_root` (spec 02,
//! section 6; spec 05, section 6, "The data marker-set tree").
//!
//! The marker-set hashes are checked against the vectors of spec 05, section
//! 11, read at compile time by name. The S3 trace opens the low leaf under
//! the root: an honest proof verifies with the test-only verifier, and a
//! proof made with a changed sibling, or checked under another set's root,
//! does not. The ordering of the marker against the low leaf is not in the
//! circuit yet, so the shipped verifier still rejects every proof of holding.
//!
//! The S3 prover exists only under the `unsettled-points-test` feature, so
//! the file is built with it. Every negative test starts from the honest
//! proof, asserted to verify, and changes one thing. Proving runs one test at
//! a time to bound memory.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard, OnceLock};

use ghost_proofs::*;

const SPEC_05: &str = include_str!("../../docs/spec/05-trees-and-headers.md");

static PROVING: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only zero-knowledge randomness; a real prover draws it from a secure
/// random source.
fn zk(n: u8) -> [u8; 32] {
    let mut seed = [0x4du8; 32];
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
// Reading the specification.

/// The `[name]` block of a document, as a key-value map.
fn vector(doc: &str, name: &str) -> BTreeMap<String, String> {
    let header = format!("[{name}]");
    let mut lines = doc.lines().map(str::trim).skip_while(|line| *line != header);
    assert_eq!(lines.next(), Some(header.as_str()), "no vector {name}");
    lines
        .take_while(|line| !line.is_empty() && !line.starts_with('[') && !line.starts_with("```"))
        .map(|line| {
            let (key, value) = line.split_once('=').expect("key = value");
            (key.trim().to_string(), value.trim().to_string())
        })
        .collect()
}

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("32 bytes")
}

/// The `markers` of a `marker-set` vector, in insertion order.
fn markers_of(v: &BTreeMap<String, String>) -> Vec<[u8; 32]> {
    v["markers"].split_whitespace().map(hex32).collect()
}

/// The root over the used leaf hashes of a marker set at positions 0, 1, ...,
/// every other position empty, computed level by level from the empty
/// subtrees of spec 05, section 6.
fn root_over(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut nodes = leaves.to_vec();
    let mut empty = empty_leaf();
    for level in 0..MARKER_SET_DEPTH as u8 {
        nodes = nodes
            .chunks(2)
            .map(|pair| marker_set_node(level, &pair[0], pair.get(1).unwrap_or(&empty)))
            .collect();
        empty = marker_set_node(level, &empty, &empty);
    }
    assert_eq!(nodes.len(), 1);
    nodes[0]
}

/// An `absence` witness in the spec 05 layout: low value, low nextValue, low
/// nextIndex, position of low (5 bytes, big-endian), 40 siblings.
fn parse_absence(bytes: &[u8]) -> AbsenceWitness {
    assert_eq!(bytes.len(), 1354);
    let mut position = [0u8; 8];
    position[3..].copy_from_slice(&bytes[69..74]);
    let mut siblings = [[0u8; 32]; MARKER_SET_DEPTH];
    for (k, sibling) in siblings.iter_mut().enumerate() {
        *sibling = bytes[74 + 32 * k..106 + 32 * k].try_into().expect("32 bytes");
    }
    AbsenceWitness {
        low_value: bytes[0..32].try_into().expect("32 bytes"),
        low_next_value: bytes[32..64].try_into().expect("32 bytes"),
        low_next_index: bytes[64..69].try_into().expect("5 bytes"),
        position: u64::from_be_bytes(position),
        siblings,
    }
}

// ---------------------------------------------------------------------------
// The example commitment and its marker set.

const SALT: [u8; SALT_BYTES] = [0x3a; SALT_BYTES];
const POSITION: u32 = 6;

fn data_path() -> [[u8; 32]; TREE_DEPTH] {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Data, level as u8, &empty, &empty);
    }
    path[1] = [0x0e; 32];
    path
}

const S: [u8; 32] = [0x11; 32];
const R: [u8; 32] = [0x12; 32];
const B: [u8; 32] = [0x13; 32];
const CF: [u8; 32] = [0x14; 32];

fn data_root() -> [u8; 32] {
    let leaf = data_commitment_v2(&data_fingerprint_v2(&S, &R, &B, &SALT, &CF, &EMPTY_RULE));
    merkle_root(Tree::Data, &leaf, POSITION, &data_path())
}

fn marker() -> [u8; 32] {
    data_marker_v2(&R, &B, &SALT)
}

/// Three spent markers, inserted so the commitment's marker falls just above
/// the last one: its low leaf is at position 3, both direction bits of the
/// first two levels set.
fn three_markers() -> [[u8; 32]; 3] {
    let m = marker();
    let mut below = m;
    below[30] = 0;
    below[31] = 0;
    assert!(below < m && below > [0x01; 32] && m < [0xff; 32]);
    [[0x01; 32], [0xff; 32], below]
}

/// The absence witness of the commitment's marker in the three-marker set,
/// and that set's root.
fn three_marker_set() -> (AbsenceWitness, [u8; 32]) {
    test_absence_witness(&three_markers(), &marker())
}

fn opening(absence: AbsenceWitness) -> SaltedHoldOpening {
    SaltedHoldOpening {
        s: S,
        r: R,
        b: B,
        salt: SALT,
        cf: CF,
        rule: EMPTY_RULE,
        position: POSITION,
        path: data_path(),
        absence,
    }
}

fn context(marker_set_root: [u8; 32]) -> HoldContext {
    HoldContext {
        type_tag: DATA_V2,
        root: data_root(),
        marker_set_root,
        verifier: [0x0a; 32],
        challenge: [0xc7; 32],
        cf: CF,
    }
}

/// The honest proof of holding against the three-marker set, made once and
/// asserted to verify.
fn honest_hold() -> &'static Proof {
    static HONEST: OnceLock<Proof> = OnceLock::new();
    HONEST.get_or_init(|| {
        let (absence, root) = three_marker_set();
        let ctx = context(root);
        let proof = prove_salted_hold(&params(), &opening(absence), &ctx, zk(1)).expect("honest proof");
        assert_eq!(verify_hold_unsettled(&params(), &ctx, &proof), Ok(()));
        proof
    })
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
// The marker-set hashes.

/// The leaves and roots of `marker-set-empty`, `marker-set-one-marker` and
/// `marker-set-two-markers`, recomputed from the vectors' own leaves and by
/// inserting their markers; and the `absence` witness of
/// `marker-set-absence`, which opens under its root and is the one the test
/// helper builds.
#[test]
fn marker_set_roots_match_the_spec_05_vectors() {
    let example = [0x88u8; 32];
    for name in ["marker-set-empty", "marker-set-one-marker", "marker-set-two-markers"] {
        let v = vector(SPEC_05, name);
        assert_eq!(v["kind"], "marker-set", "{name}");
        let root = hex32(&v["root"]);
        let count: usize = v["count"].parse().expect("a count");
        let leaves: Vec<[u8; 32]> = (0..count)
            .map(|i| {
                let parts: Vec<&str> = v[&format!("leaf-{i}")].split_whitespace().collect();
                let next_index: [u8; MARKER_SET_INDEX_BYTES] = hex(parts[2]).try_into().expect("5 bytes");
                marker_set_leaf(&hex32(parts[0]), &hex32(parts[1]), &next_index)
            })
            .collect();
        assert_eq!(root_over(&leaves), root, "{name}: the root over the vector's leaves");
        let markers = markers_of(&v);
        assert_eq!(markers.len() + 1, count, "{name}");
        let (witness, built) = test_absence_witness(&markers, &example);
        assert_eq!(built, root, "{name}: the root of the inserted markers");
        assert_eq!(witness.root(), Some(root), "{name}");
    }
    let empty = vector(SPEC_05, "marker-set-empty");
    let sentinel = marker_set_leaf(&[0; 32], &[0; 32], &[0; MARKER_SET_INDEX_BYTES]);
    assert_eq!(root_over(&[sentinel]), hex32(&empty["root"]));

    let v = vector(SPEC_05, "marker-set-absence");
    assert_eq!(v["set"], "marker-set-two-markers");
    let root = hex32(&v["root"]);
    let marker = hex32(&v["marker"]);
    assert_eq!(marker, example);
    let witness = parse_absence(&hex(&v["absence"]));
    assert_eq!(witness.position, v["low-position"].parse::<u64>().expect("a position"));
    assert_eq!(witness.root(), Some(root));
    let markers = markers_of(&vector(SPEC_05, "marker-set-two-markers"));
    let (built, built_root) = test_absence_witness(&markers, &marker);
    assert_eq!(built_root, root);
    assert!(built == witness, "the helper's witness is the spec's");
    // A position with a bit above 39 set is no position of the set.
    let beyond = AbsenceWitness {
        position: witness.position | 1 << MARKER_SET_DEPTH,
        ..witness
    };
    assert_eq!(beyond.root(), None);
}

// ---------------------------------------------------------------------------
// S3 opens the low leaf under the marker-set root.

#[test]
fn s3_trace_opens_the_low_leaf_under_the_marker_set_root() {
    let _one = one_at_a_time();
    let (absence, root) = three_marker_set();
    assert_eq!(absence.position, 3, "the low leaf is the last marker inserted");
    assert_eq!(absence.low_value, three_markers()[2]);
    assert_eq!(absence.low_next_value, [0xff; 32]);
    assert_eq!(absence.low_next_index, [0, 0, 0, 0, 2]);
    assert_eq!(absence.root(), Some(root));
    let ctx = context(root);
    let proof = honest_hold();
    assert_eq!(verify_hold_unsettled(&params(), &ctx, proof), Ok(()));
    assert!(proof.as_bytes().len() <= PROOF_FIELD_BYTES);
}

#[test]
fn s3_proof_fails_when_a_sibling_of_the_low_leaf_is_changed() {
    let _one = one_at_a_time();
    let (absence, root) = three_marker_set();
    let ctx = context(root);
    assert_eq!(verify_hold_unsettled(&params(), &ctx, honest_hold()), Ok(()));
    for (level, seed) in [(0, 2), (MARKER_SET_DEPTH - 1, 3)] {
        let mut changed = absence;
        changed.siblings[level][7] ^= 1;
        assert_eq!(
            prove_salted_hold(&params(), &opening(changed), &ctx, zk(seed)).err(),
            Some(ProofError::NotInMarkerSet),
            "level {level}"
        );
        lying_proof_fails(
            || prove_salted_hold_claiming(&params(), &opening(changed), &ctx, zk(seed)),
            |proof| verify_hold_unsettled(&params(), &ctx, proof),
        );
    }
}

#[test]
fn s3_proof_fails_under_another_marker_set_root() {
    let _one = one_at_a_time();
    let (absence, root) = three_marker_set();
    assert_eq!(verify_hold_unsettled(&params(), &context(root), honest_hold()), Ok(()));
    // The set before the last marker was inserted: a real set, another root.
    let (_, earlier) = test_absence_witness(&three_markers()[..2], &marker());
    assert_ne!(earlier, root);
    let other = context(earlier);
    assert_eq!(verify_hold_unsettled(&params(), &other, honest_hold()), Err(ProofError::Rejected));
    assert_eq!(
        prove_salted_hold(&params(), &opening(absence), &other, zk(4)).err(),
        Some(ProofError::NotInMarkerSet)
    );
    lying_proof_fails(
        || prove_salted_hold_claiming(&params(), &opening(absence), &other, zk(5)),
        |proof| verify_hold_unsettled(&params(), &other, proof),
    );
}

#[test]
fn s3_prover_refuses_a_low_leaf_that_is_not_under_the_root() {
    let (absence, root) = three_marker_set();
    let ctx = context(root);
    let mut changes: Vec<(&str, AbsenceWitness)> = Vec::new();
    let mut w = absence;
    w.low_value[31] ^= 1;
    changes.push(("low value", w));
    let mut w = absence;
    w.low_next_value[0] ^= 1;
    changes.push(("low nextValue", w));
    let mut w = absence;
    w.low_next_index[4] ^= 1;
    changes.push(("low nextIndex", w));
    changes.push((
        "another position",
        AbsenceWitness {
            position: 2,
            ..absence
        },
    ));
    changes.push((
        "a position above 2^40 with the same low bits",
        AbsenceWitness {
            position: absence.position | 1 << MARKER_SET_DEPTH,
            ..absence
        },
    ));
    // The marker 1 falls just above the sentinel, whose leaf is at position 0.
    let mut one = [0u8; 32];
    one[31] = 1;
    let (sentinel_witness, _) = test_absence_witness(&three_markers(), &one);
    assert_eq!(sentinel_witness.position, 0);
    changes.push((
        "another leaf's hash on this leaf's path",
        AbsenceWitness {
            siblings: absence.siblings,
            position: absence.position,
            ..sentinel_witness
        },
    ));
    for (what, changed) in changes {
        assert!(changed != absence, "{what}");
        let refused = prove_salted_hold(&params(), &opening(changed), &ctx, zk(6));
        assert_eq!(refused.err(), Some(ProofError::NotInMarkerSet), "{what}");
    }
    assert!(ProofError::NotInMarkerSet.to_string().contains("marker-set root"));
}

#[test]
fn shipped_verify_hold_still_rejects_every_proof_until_part_two() {
    let _one = one_at_a_time();
    let (_, root) = three_marker_set();
    let ctx = context(root);
    let proof = honest_hold();
    assert_eq!(verify_hold_unsettled(&params(), &ctx, proof), Ok(()));
    assert_eq!(verify_hold(&params(), &ctx, proof), Err(ProofError::HoldUnsettled));
    for other in [Proof::from_bytes(Vec::new()), Proof::from_bytes(vec![0xa5; 4096])] {
        assert_eq!(verify_hold(&params(), &ctx, &other), Err(ProofError::HoldUnsettled));
    }
    assert!(
        ProofError::HoldUnsettled
            .to_string()
            .contains("the ordering of constraint 4 is not yet in the circuit")
    );
}
