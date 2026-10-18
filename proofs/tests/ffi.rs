//! Known-answer tests of the C interface to the coin reveal verifier.
//!
//! One honest proof is made by the crate's own prover and serialized in the
//! documented layout; every negative case changes one thing about it and
//! calls the `extern "C"` function, as a node would. The header's constants
//! are read from `include/ghost_proofs.h` and checked against the crate's.

use std::collections::BTreeMap;
use std::ptr;
use std::sync::OnceLock;

use ghost_proofs::ffi::*;
use ghost_proofs::*;

const HEADER: &str = include_str!("../include/ghost_proofs.h");

/// Example chain constants, not Ghost's.
fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    }
}

struct Fixture {
    params: Vec<u8>,
    statement: Vec<u8>,
    proof: Vec<u8>,
}

/// One honest reveal: a coin of 1,000,000 at position 5 of a coin tree whose
/// other leaves are empty but one, revealed for 600,000 and a fee of 21.
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut path = [[0u8; 32]; TREE_DEPTH];
        let mut empty = empty_leaf();
        for (level, sibling) in path.iter_mut().enumerate() {
            *sibling = empty;
            empty = tree_node(Tree::Coin, level as u8, &empty, &empty);
        }
        path[0] = [9; 32];
        let opening = CoinOpening {
            s: [1; 32],
            r: [2; 32],
            b: [3; 32],
            v: amount_word(1_000_000),
            position: 5,
            path,
        };
        let leaf = coin_commitment(&coin_fingerprint(&opening.s, &opening.r, &opening.b, &EMPTY_RULE), &opening.v);
        let request = RevealRequest {
            root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
            recipient: [0x11; 20],
            out: amount_word(600_000),
            fee: amount_word(21),
            rule: EMPTY_RULE,
            remainder_note: [0x33; NOTE_BYTES],
        };
        let remainder = CoinRemainder {
            s: [1; 32],
            r: [2; 32],
            b: [4; 32],
            v: amount_word(1_000_000 - 600_000 - 21),
        };
        // Test-only zero-knowledge randomness.
        let (tx, proof) = prove_coin_reveal(&params(), &opening, &remainder, &request, [0x5a; 32]).expect("honest proof");
        assert_eq!(verify_coin_reveal(&params(), &tx, &proof), Ok(()));
        Fixture {
            params: chain_params_to_bytes(&params()).to_vec(),
            statement: coin_reveal_to_bytes(&tx).to_vec(),
            proof: proof.into_bytes(),
        }
    })
}

fn call(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    let status = unsafe {
        ghost_verify_coin_reveal(
            params.as_ptr(),
            params.len(),
            statement.as_ptr(),
            statement.len(),
            proof.as_ptr(),
            proof.len(),
        )
    };
    assert_ne!(status, GHOST_PROOFS_PANICKED, "the verifier panicked");
    status
}

fn rejects(status: i32) -> bool {
    status == GHOST_PROOFS_REJECTED || status == GHOST_PROOFS_MALFORMED_INPUT
}

/// The statement fields as (name, offset, width), in the documented order.
const STATEMENT_FIELDS: [(&str, usize, usize); 8] = [
    ("root", 0, 32),
    ("marker", 32, 32),
    ("remainder", 64, 32),
    ("remainder_note", 96, 156),
    ("recipient", 252, 20),
    ("out", 272, 32),
    ("fee", 304, 32),
    ("rule", 336, 32),
];

const PARAM_FIELDS: [(&str, usize, usize); 3] = [("chain_id", 0, 8), ("version", 8, 2), ("domain", 10, 32)];

#[test]
fn the_header_agrees_with_the_crate() {
    let defines: BTreeMap<&str, i64> = HEADER
        .lines()
        .filter_map(|line| {
            let mut words = line.strip_prefix("#define ")?.split_whitespace();
            Some((words.next()?, words.next()?.parse().ok()?))
        })
        .collect();
    let expected: [(&str, i64); 8] = [
        ("GHOST_PROOFS_ACCEPTED", GHOST_PROOFS_ACCEPTED.into()),
        ("GHOST_PROOFS_REJECTED", GHOST_PROOFS_REJECTED.into()),
        ("GHOST_PROOFS_MALFORMED_INPUT", GHOST_PROOFS_MALFORMED_INPUT.into()),
        ("GHOST_PROOFS_BAD_ARGUMENT", GHOST_PROOFS_BAD_ARGUMENT.into()),
        ("GHOST_PROOFS_PANICKED", GHOST_PROOFS_PANICKED.into()),
        ("GHOST_PROOFS_CHAIN_PARAMS_BYTES", CHAIN_PARAMS_BYTES as i64),
        ("GHOST_PROOFS_COIN_REVEAL_BYTES", COIN_REVEAL_BYTES as i64),
        ("GHOST_PROOFS_PROOF_MAX_BYTES", PROOF_MAX_BYTES as i64),
    ];
    assert_eq!(defines, BTreeMap::from(expected));
    assert_eq!((CHAIN_PARAMS_BYTES, COIN_REVEAL_BYTES, PROOF_MAX_BYTES), (42, 368, 2_097_152));
    assert!(HEADER.contains("#ifndef GHOST_PROOFS_H"));
    assert!(HEADER.contains("#include <stdint.h>"));
    assert!(HEADER.contains("#include <stddef.h>"));
    assert!(HEADER.contains("int32_t ghost_verify_coin_reveal(const uint8_t *params, size_t params_len,"));
}

#[test]
fn the_layout_is_the_documented_one() {
    let tx = CoinReveal {
        root: [1; 32],
        marker: [2; 32],
        remainder: [3; 32],
        remainder_note: [4; NOTE_BYTES],
        recipient: [5; 20],
        out: [6; 32],
        fee: [7; 32],
        rule: [8; 32],
    };
    let bytes = coin_reveal_to_bytes(&tx);
    let mut end = 0;
    for (k, (name, offset, width)) in STATEMENT_FIELDS.into_iter().enumerate() {
        assert_eq!(offset, end, "{name}");
        assert!(bytes[offset..offset + width].iter().all(|&b| b == k as u8 + 1), "{name}");
        end = offset + width;
    }
    assert_eq!(end, COIN_REVEAL_BYTES);
    assert_eq!(coin_reveal_from_bytes(&bytes), tx);

    let p = params();
    let bytes = chain_params_to_bytes(&p);
    assert_eq!(&bytes[..8], &p.chain_id);
    assert_eq!(&bytes[8..10], &p.version);
    assert_eq!(&bytes[10..], &p.domain);
    assert_eq!(chain_params_from_bytes(&bytes), p);
}

#[test]
fn a_valid_proof_is_accepted() {
    let f = fixture();
    assert!(f.proof.len() <= PROOF_MAX_BYTES, "proof of {} bytes", f.proof.len());
    assert_eq!(call(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED);
    assert_eq!(verify_coin_reveal_bytes(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED);
}

#[test]
fn the_zero_padded_proof_field_is_accepted() {
    let f = fixture();
    let mut field = f.proof.clone();
    field.resize(PROOF_MAX_BYTES, 0);
    assert_eq!(call(&f.params, &f.statement, &field), GHOST_PROOFS_ACCEPTED);
}

#[test]
fn a_non_zero_padding_byte_is_malformed() {
    let f = fixture();
    let mut field = f.proof.clone();
    field.resize(PROOF_MAX_BYTES, 0);
    for at in [f.proof.len(), PROOF_MAX_BYTES - 1] {
        let mut padded = field.clone();
        padded[at] = 1;
        assert_eq!(call(&f.params, &f.statement, &padded), GHOST_PROOFS_MALFORMED_INPUT, "byte {at}");
    }
    let mut appended = f.proof.clone();
    appended.push(0xff);
    assert_eq!(call(&f.params, &f.statement, &appended), GHOST_PROOFS_MALFORMED_INPUT);
}

#[test]
fn a_flipped_proof_byte_is_rejected() {
    let f = fixture();
    let n = f.proof.len();
    for at in [0, 1, n / 3, n / 2, 2 * n / 3, n - 40, n - 2, n - 1] {
        let mut flipped = f.proof.clone();
        flipped[at] ^= 1;
        let status = call(&f.params, &f.statement, &flipped);
        assert!(rejects(status), "byte {at} gave {status}");
    }
}

#[test]
fn a_changed_statement_field_is_rejected() {
    let f = fixture();
    for (name, offset, width) in STATEMENT_FIELDS {
        // The last byte keeps an amount word in range, so the proof decides.
        let mut statement = f.statement.clone();
        statement[offset + width - 1] ^= 1;
        assert_eq!(call(&f.params, &statement, &f.proof), GHOST_PROOFS_REJECTED, "{name}");
        let mut statement = f.statement.clone();
        statement[offset] ^= 0x80;
        assert_eq!(call(&f.params, &statement, &f.proof), GHOST_PROOFS_REJECTED, "{name}");
    }
}

#[test]
fn a_non_empty_rule_or_out_of_range_amount_is_rejected() {
    let f = fixture();
    let (_, rule, _) = STATEMENT_FIELDS[7];
    for at in [rule, rule + 31] {
        let mut statement = f.statement.clone();
        statement[at] = 1;
        assert_eq!(call(&f.params, &statement, &f.proof), GHOST_PROOFS_REJECTED);
    }
    for (_, offset, _) in [STATEMENT_FIELDS[5], STATEMENT_FIELDS[6]] {
        // Byte 19 is the last high byte of an amount word: 2^96 and up.
        for at in [offset, offset + AMOUNT_HIGH_BYTES - 1] {
            let mut statement = f.statement.clone();
            statement[at] = 1;
            let tx = coin_reveal_from_bytes(statement.as_slice().try_into().unwrap());
            let proof = Proof::from_bytes(f.proof.clone());
            assert_eq!(
                verify_coin_reveal(&params(), &tx, &proof),
                Err(ProofError::AmountOutOfRange)
            );
            assert_eq!(call(&f.params, &statement, &f.proof), GHOST_PROOFS_REJECTED);
        }
    }
}

#[test]
fn a_changed_chain_parameter_is_rejected() {
    let f = fixture();
    for (name, offset, width) in PARAM_FIELDS {
        for at in [offset, offset + width - 1] {
            let mut p = f.params.clone();
            p[at] ^= 1;
            assert_eq!(call(&p, &f.statement, &f.proof), GHOST_PROOFS_REJECTED, "{name} byte {at}");
        }
    }
}

#[test]
fn a_truncated_empty_or_oversized_proof_is_malformed() {
    let f = fixture();
    let n = f.proof.len();
    for len in [n - 1, n / 2, 1] {
        assert_eq!(call(&f.params, &f.statement, &f.proof[..len]), GHOST_PROOFS_MALFORMED_INPUT, "{len} bytes");
    }
    assert_eq!(call(&f.params, &f.statement, &[]), GHOST_PROOFS_MALFORMED_INPUT);
    assert_eq!(verify_coin_reveal_bytes(&f.params, &f.statement, &[]), GHOST_PROOFS_MALFORMED_INPUT);
    let mut oversized = f.proof.clone();
    oversized.resize(PROOF_MAX_BYTES + 1, 0);
    assert_eq!(call(&f.params, &f.statement, &oversized), GHOST_PROOFS_MALFORMED_INPUT);
    assert_eq!(verify_coin_reveal_bytes(&f.params, &f.statement, &oversized), GHOST_PROOFS_MALFORMED_INPUT);
}

#[test]
fn a_null_pointer_is_a_bad_argument() {
    let f = fixture();
    let (p, s, q) = (&f.params, &f.statement, &f.proof);
    let cases = [
        (ptr::null(), p.len(), s.as_ptr(), s.len(), q.as_ptr(), q.len()),
        (p.as_ptr(), p.len(), ptr::null(), s.len(), q.as_ptr(), q.len()),
        (p.as_ptr(), p.len(), s.as_ptr(), s.len(), ptr::null(), q.len()),
        (p.as_ptr(), p.len(), s.as_ptr(), s.len(), ptr::null(), 0),
        (ptr::null(), 0, ptr::null(), 0, ptr::null(), 0),
    ];
    for (k, (a, al, b, bl, c, cl)) in cases.into_iter().enumerate() {
        let status = unsafe { ghost_verify_coin_reveal(a, al, b, bl, c, cl) };
        assert_eq!(status, GHOST_PROOFS_BAD_ARGUMENT, "case {k}");
    }
}

#[test]
fn a_buffer_of_the_wrong_length_is_a_bad_argument() {
    let f = fixture();
    let (p, s, q) = (&f.params, &f.statement, &f.proof);
    assert_eq!(call(&p[..p.len() - 1], s, q), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(call(p, &s[..s.len() - 1], q), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(call(&[], s, q), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(call(p, &[], q), GHOST_PROOFS_BAD_ARGUMENT);
    let mut longer = p.clone();
    longer.push(0);
    assert_eq!(call(&longer, s, q), GHOST_PROOFS_BAD_ARGUMENT);
    let mut longer = s.clone();
    longer.push(0);
    assert_eq!(call(p, &longer, q), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(verify_coin_reveal_bytes(&p[..41], s, q), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(verify_coin_reveal_bytes(p, &s[..367], q), GHOST_PROOFS_BAD_ARGUMENT);
}
