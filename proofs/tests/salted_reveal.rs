//! The coin reveal of a salted (version 2) commitment (spec 01, section 3;
//! spec 02, PS-25 and AV-13).
//!
//! The salt is a private witness: a proof made with the commitment's salt
//! verifies, one made with another salt does not, and neither the public
//! fields, the binding digest nor the proof bytes hold a salt. A version 1
//! commitment still opens under its own statement, and a proof of one format
//! never verifies as the other.
//!
//! Every negative test starts from the honest proof, asserted to verify, and
//! changes one thing. Proving runs one test at a time to bound memory.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard, OnceLock};

use ghost_proofs::ffi::{COIN_REVEAL_BYTES, coin_reveal_to_bytes};
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

/// The example salts of spec 01, section 14: fixed so the test repeats; a
/// wallet draws every salt fresh.
const INPUT_SALT: [u8; SALT_BYTES] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const REMAINDER_SALT: [u8; SALT_BYTES] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

fn path() -> [[u8; 32]; TREE_DEPTH] {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Coin, level as u8, &empty, &empty);
    }
    path[0] = [9; 32];
    path
}

/// A salted coin of 1,000,000 at position 5, revealed for 600,000 and a fee
/// of 21 into a salted remainder.
fn salted_coin() -> (SaltedCoinOpening, SaltedCoinRemainder, RevealRequest) {
    let opening = SaltedCoinOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        salt: INPUT_SALT,
        v: amount_word(1_000_000),
        position: 5,
        path: path(),
    };
    let leaf = coin_commitment_v2(
        &coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, &EMPTY_RULE),
        &opening.v,
    );
    let request = RevealRequest {
        root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
        recipient: [0x11; 20],
        out: amount_word(600_000),
        fee: amount_word(21),
        rule: EMPTY_RULE,
        remainder_note: [0x33; NOTE_BYTES],
    };
    let remainder = SaltedCoinRemainder {
        s: [1; 32],
        r: [2; 32],
        b: [4; 32],
        salt: REMAINDER_SALT,
        v: amount_word(1_000_000 - 600_000 - 21),
    };
    (opening, remainder, request)
}

/// The honest salted reveal, made once and asserted to verify.
fn honest() -> &'static (CoinReveal, Proof) {
    static HONEST: OnceLock<(CoinReveal, Proof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let (opening, remainder, request) = salted_coin();
        let (tx, proof) =
            prove_salted_coin_reveal(&params(), &opening, &remainder, &request, zk(1)).expect("honest proof");
        assert_eq!(verify_salted_coin_reveal(&params(), &tx, &proof), Ok(()));
        (tx, proof)
    })
}

fn with_salt<const N: usize>(salt: &[u8; N], at: usize) -> [u8; N] {
    let mut changed = *salt;
    changed[at] ^= 1;
    changed
}

/// Whether `haystack` holds `needle` as bytes, or as one BabyBear element
/// (four little-endian bytes) per byte, the way the proof encodes a trace
/// value.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    let as_elements: Vec<u8> = needle.iter().flat_map(|&b| u32::from(b).to_le_bytes()).collect();
    haystack.windows(needle.len()).any(|w| w == needle)
        || haystack.windows(as_elements.len()).any(|w| w == as_elements)
}

#[test]
fn a_salted_reveal_verifies_with_the_salt() {
    let _one = one_at_a_time();
    let (opening, remainder, request) = salted_coin();
    let (tx, proof) = honest();
    assert_eq!(tx.root, request.root);
    // The marker and the remainder are the salted ones of spec 01.
    assert_eq!(tx.marker, coin_marker_v2(&opening.r, &opening.b, &opening.salt));
    assert_ne!(tx.marker, coin_marker(&opening.r, &opening.b));
    let f = coin_fingerprint_v2(&remainder.s, &remainder.r, &remainder.b, &remainder.salt, &EMPTY_RULE);
    assert_eq!(tx.remainder, coin_commitment_v2(&f, &remainder.v));
    assert!(proof.as_bytes().len() <= PROOF_FIELD_BYTES);
    // The binding holds the version 2 type tag, not version 1's.
    assert_ne!(salted_coin_reveal_binding(&params(), tx), coin_reveal_binding(&params(), tx));
}

#[test]
fn the_honest_prover_refuses_another_salt() {
    let (opening, remainder, request) = salted_coin();
    for at in [0, SALT_BYTES - 1] {
        let wrong = SaltedCoinOpening {
            salt: with_salt(&opening.salt, at),
            ..opening
        };
        let refused = prove_salted_coin_reveal(&params(), &wrong, &remainder, &request, zk(2));
        assert_eq!(refused.err(), Some(ProofError::NotInTree), "salt byte {at}");
    }
}

/// A lying prover's proof of `tx` from a witness with a wrong salt does not
/// verify. In a release build the prover makes bytes and the verifier rejects
/// them; with debug assertions on, Plonky3 checks every constraint before it
/// proves and panics on the broken one, so no proof exists at all.
fn lying_proof_fails(tx: &CoinReveal, prove: impl FnOnce() -> Result<Proof, ProofError>) {
    match catch_unwind(AssertUnwindSafe(prove)) {
        Ok(proof) => {
            let proof = proof.expect("the lying prover still produces bytes");
            assert_eq!(verify_salted_coin_reveal(&params(), tx, &proof), Err(ProofError::Rejected));
        }
        Err(_) => assert!(cfg!(debug_assertions), "only the debug constraint check may stop the prover"),
    }
}

/// AV-13: the right `s`, `r` and `b` with another salt make no proof that
/// verifies, for the input's salt or the remainder's.
#[test]
fn a_proof_with_a_wrong_salt_fails() {
    let _one = one_at_a_time();
    let (opening, remainder, _) = salted_coin();
    let (tx, honest_proof) = honest();
    let wrong_input = SaltedCoinOpening {
        salt: with_salt(&opening.salt, 7),
        ..opening
    };
    lying_proof_fails(tx, || prove_salted_coin_reveal_claiming(&params(), &wrong_input, &remainder, tx, zk(3)));

    let wrong_remainder = SaltedCoinRemainder {
        salt: with_salt(&remainder.salt, 15),
        ..remainder
    };
    lying_proof_fails(tx, || prove_salted_coin_reveal_claiming(&params(), &opening, &wrong_remainder, tx, zk(4)));

    // The honest proof, made with the right salts, does not verify for the
    // marker or the remainder another salt gives.
    let other_marker = CoinReveal {
        marker: coin_marker_v2(&opening.r, &opening.b, &wrong_input.salt),
        ..tx.clone()
    };
    assert_eq!(verify_salted_coin_reveal(&params(), &other_marker, honest_proof), Err(ProofError::Rejected));
    let f = coin_fingerprint_v2(&remainder.s, &remainder.r, &remainder.b, &wrong_remainder.salt, &EMPTY_RULE);
    let other_remainder = CoinReveal {
        remainder: coin_commitment_v2(&f, &remainder.v),
        ..tx.clone()
    };
    assert_eq!(verify_salted_coin_reveal(&params(), &other_remainder, honest_proof), Err(ProofError::Rejected));
}

/// PS-25: the salt is never public. Nothing the reveal publishes, its
/// binding digest, the statement a node passes the verifier, nor the proof
/// bytes hold either salt.
#[test]
fn the_public_values_and_the_proof_hold_no_salt() {
    let _one = one_at_a_time();
    let (tx, proof) = honest();
    let statement = coin_reveal_to_bytes(tx);
    assert_eq!(statement.len(), COIN_REVEAL_BYTES);
    let published = [
        &statement[..],
        &salted_coin_reveal_binding(&params(), tx),
        &ffi::chain_params_to_bytes(&params()),
    ]
    .concat();
    for salt in [INPUT_SALT, REMAINDER_SALT] {
        assert!(!holds(&published, &salt), "a public value holds a salt");
        assert!(!holds(proof.as_bytes(), &salt), "the proof holds a salt");
    }
    // The check itself finds a salt that is there.
    assert!(holds(&[&[0u8; 5][..], &INPUT_SALT, &[1; 3]].concat(), &INPUT_SALT));
}

/// A proof of one format never verifies as the other, and a version 1
/// commitment still opens under its own statement.
#[test]
fn the_formats_do_not_mix() {
    let _one = one_at_a_time();
    let (tx, proof) = honest();
    assert_eq!(verify_coin_reveal(&params(), tx, proof), Err(ProofError::Rejected));

    let (salted, salted_remainder, _) = salted_coin();
    let opening = CoinOpening {
        s: salted.s,
        r: salted.r,
        b: salted.b,
        v: salted.v,
        position: salted.position,
        path: salted.path,
    };
    let remainder = CoinRemainder {
        s: salted_remainder.s,
        r: salted_remainder.r,
        b: salted_remainder.b,
        v: salted_remainder.v,
    };
    let leaf = coin_commitment(&coin_fingerprint(&opening.s, &opening.r, &opening.b, &EMPTY_RULE), &opening.v);
    let request = RevealRequest {
        root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
        ..salted_coin().2
    };
    let (v1_tx, v1_proof) = prove_coin_reveal(&params(), &opening, &remainder, &request, zk(5)).expect("version 1");
    assert_eq!(verify_coin_reveal(&params(), &v1_tx, &v1_proof), Ok(()));
    assert_eq!(verify_salted_coin_reveal(&params(), &v1_tx, &v1_proof), Err(ProofError::Rejected));
    // The salted prover does not open the version 1 leaf with any salt.
    let refused = prove_salted_coin_reveal(&params(), &salted, &salted_remainder, &request, zk(6));
    assert_eq!(refused.err(), Some(ProofError::NotInTree));
}

/// The salted statement is the widest: 16 carried salt columns over the
/// version 1 reveal, inside the budget, with the same height.
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
    let (v1, v2) = (trace(Statement::CoinReveal), trace(Statement::SaltedCoinReveal));
    assert_eq!(v2.trace_width, v1.trace_width + SALT_BYTES);
    assert_eq!(v1.trace_height, v2.trace_height);
    assert_eq!((v1.trace_width, v2.trace_width), (3808, 3824));
    assert!(v2.trace_width <= MAX_TRACE_WIDTH && v2.trace_height <= MAX_TRACE_HEIGHT);
    assert!(proof_length_bound(v2.trace_height, v2.trace_width) <= PROOF_FIELD_BYTES);
    assert!(v2.conjectured_bits_half_grinding >= TARGET_CONJECTURED_BITS, "{v2:?}");
}
