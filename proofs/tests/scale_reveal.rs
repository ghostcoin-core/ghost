//! The scale build's reveal prover: the version 2 coin reveal, its statement
//! and its own Keccak-256 hashes unchanged, proven with Poseidon2 commitments
//! and transcript, challenges from the degree-8 extension of BabyBear, 96
//! queries at blowup 2^3 and 16 and 16 bits of grinding.
//!
//! An honest proof verifies and is at most the modeled 2,330,908 bytes; a
//! proof of the shipped Keccak configuration, a proof with one flipped byte,
//! a proof whose digests are 8 elements and a proof with 95 queries are each
//! rejected. Proving runs one test at a time to bound memory.

use std::sync::{Mutex, MutexGuard, OnceLock};

use ghost_proofs::*;

static PROVING: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only zero-knowledge randomness; a real prover draws it from a secure
/// random source.
fn zk(n: u8) -> [u8; 32] {
    let mut seed = [0x6cu8; 32];
    seed[0] = n;
    seed
}

/// Example chain constants of protocol version 2, not Ghost's.
fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_2,
        domain: [0x47; 32],
    }
}

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

/// A plain salted coin of 1,000,000 at position 5, revealed for 600,000 and
/// a fee of 21.
fn opening() -> SaltedCoinOpening {
    SaltedCoinOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        salt: [0xa5; SALT_BYTES],
        v: amount_word(1_000_000),
        position: 5,
        path: path(),
    }
}

fn remainder() -> SaltedCoinRemainder {
    SaltedCoinRemainder {
        s: [1; 32],
        r: [2; 32],
        b: [4; 32],
        salt: [0x3c; SALT_BYTES],
        v: amount_word(1_000_000 - 600_000 - 21),
    }
}

fn request() -> CoinRevealV2Request {
    let o = opening();
    let leaf = coin_commitment_v2(&coin_fingerprint_v2(&o.s, &o.r, &o.b, &o.salt, &EMPTY_RULE), &o.v);
    CoinRevealV2Request {
        root: merkle_root(Tree::Coin, &leaf, o.position, &o.path),
        recipient: [0x11; 20],
        out: amount_word(600_000),
        fee: amount_word(21),
        remainder_note: [0x33; NOTE_V3_BYTES],
    }
}

fn prove_scale_shaped(shape: ScaleShape, seed: u8) -> (CoinRevealV2, Proof) {
    let _guard = one_at_a_time();
    prove_coin_reveal_v2_scale_shaped(
        &params(),
        &opening(),
        &InputRule::plain(),
        &remainder(),
        &EMPTY_RULE,
        &request(),
        zk(seed),
        shape,
    )
    .expect("an honest reveal proves at the given shape")
}

/// The honest reveal at the scale configuration, proved once.
fn honest() -> &'static (CoinRevealV2, Proof) {
    static HONEST: OnceLock<(CoinRevealV2, Proof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let _guard = one_at_a_time();
        prove_coin_reveal_v2_scale(
            &params(),
            &opening(),
            &InputRule::plain(),
            &remainder(),
            &EMPTY_RULE,
            &request(),
            zk(1),
        )
        .expect("an honest reveal proves at the scale configuration")
    })
}

/// The same reveal proved with the shipped Keccak configuration, proved once.
fn keccak() -> &'static (CoinRevealV2, Proof) {
    static KECCAK: OnceLock<(CoinRevealV2, Proof)> = OnceLock::new();
    KECCAK.get_or_init(|| {
        let _guard = one_at_a_time();
        prove_coin_reveal_v2(&params(), &opening(), &InputRule::plain(), &remainder(), &EMPTY_RULE, &request(), zk(2))
            .expect("an honest reveal proves at the shipped configuration")
    })
}

/// The configuration is the design's, and the gate's estimate of the
/// reveal at it reaches the floor of spec 09, section 4.1.
#[test]
fn the_configuration_is_the_designs() {
    assert_eq!((SCALE_POSEIDON2_WIDTH, SCALE_SPONGE_RATE, SCALE_SPONGE_CAPACITY), (24, 15, 9));
    assert_eq!((SCALE_DIGEST_ELEMS, SCALE_DIGEST_BITS), (9, 279));
    assert_eq!(SCALE_EXTENSION_DEGREE, 8);
    assert_eq!((SCALE_LOG_BLOWUP, SCALE_NUM_QUERIES), (3, 96));
    assert_eq!((SCALE_QUERY_POW_BITS, SCALE_BATCH_POW_BITS), (16, 16));
    assert_eq!(SCALE_MODELED_PROOF_BYTES, 2_330_908);
    let est = scale_coin_reveal_v2_estimate().expect("the gate takes the scale configuration");
    assert!(est.conjectured_bits_half_grinding >= TARGET_CONJECTURED_BITS, "{est:?}");
    assert_eq!((est.trace_height, est.trace_width), (MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH));
    // The shipped configuration is untouched.
    assert_eq!((EXTENSION_DEGREE, NUM_QUERIES, DIGEST_BITS), (5, 43, 256));
    assert_eq!(PROOF_FIELD_BYTES, 1_310_720);
}

/// An honest reveal proves and verifies with the new parameters, and the
/// transaction it publishes is the one the shipped prover publishes: the
/// statement, its public fields and their Keccak-256 hashes are unchanged.
#[test]
fn an_honest_reveal_proves_and_verifies() {
    let (tx, proof) = honest();
    assert_eq!(verify_coin_reveal_v2_scale(&params(), tx, proof), Ok(()));
    let (keccak_tx, _) = keccak();
    assert_eq!(tx, keccak_tx);
    let o = opening();
    assert_eq!(tx.marker, coin_marker_v2(&o.r, &o.b, &o.salt));
}

/// The proof is bound to the statement: another fee, another recipient or
/// other chain constants are rejected.
#[test]
fn the_proof_is_bound_to_the_public_fields() {
    let (tx, proof) = honest();
    let other_fee = CoinRevealV2 {
        fee: amount_word(22),
        ..tx.clone()
    };
    assert!(verify_coin_reveal_v2_scale(&params(), &other_fee, proof).is_err());
    let other_recipient = CoinRevealV2 {
        recipient: [0x12; 20],
        ..tx.clone()
    };
    assert!(verify_coin_reveal_v2_scale(&params(), &other_recipient, proof).is_err());
    let other_chain = ChainParams {
        domain: [0x48; 32],
        ..params()
    };
    assert!(verify_coin_reveal_v2_scale(&other_chain, tx, proof).is_err());
}

/// The proof is at most the modeled 2,330,908 bytes.
#[test]
fn the_proof_is_within_the_modeled_size() {
    let (_, proof) = honest();
    let len = proof.as_bytes().len();
    println!("scale reveal proof: {len} bytes (modeled bound {SCALE_MODELED_PROOF_BYTES})");
    assert!(len <= SCALE_MODELED_PROOF_BYTES, "{len} bytes, over the modeled {SCALE_MODELED_PROOF_BYTES}");
    // It is a real proof of this size, not an empty one: larger than the
    // shipped configuration's proof of the same reveal.
    assert!(len > keccak().1.as_bytes().len());
}

/// A proof made with the old Keccak parameters is rejected by the new
/// verifier, and a proof made with the new parameters by the old one.
#[test]
fn a_keccak_proof_is_rejected() {
    let (tx, proof) = keccak();
    assert_eq!(verify_coin_reveal_v2(&params(), tx, proof), Ok(()));
    assert!(verify_coin_reveal_v2_scale(&params(), tx, proof).is_err());

    let (scale_tx, scale_proof) = honest();
    assert!(verify_coin_reveal_v2(&params(), scale_tx, scale_proof).is_err());
}

/// A proof with one flipped byte is rejected, wherever the byte is: in the
/// commitments at the start, in the openings, in the last bytes.
#[test]
fn a_flipped_byte_is_rejected() {
    let (tx, proof) = honest();
    let bytes = proof.as_bytes();
    let len = bytes.len();
    for at in [1, 20, len / 7, len / 3, len / 2, 2 * len / 3, len - 40, len - 1] {
        let mut flipped = bytes.to_vec();
        flipped[at] ^= 0x01;
        assert!(
            verify_coin_reveal_v2_scale(&params(), tx, &Proof::from_bytes(flipped)).is_err(),
            "byte {at} of {len} flipped"
        );
    }
    // Truncated by a byte, or with a byte appended.
    assert!(verify_coin_reveal_v2_scale(&params(), tx, &Proof::from_bytes(bytes[..len - 1].to_vec())).is_err());
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(verify_coin_reveal_v2_scale(&params(), tx, &Proof::from_bytes(longer)).is_err());
}

/// A proof whose digests are 8 elements, not 9, is rejected, though it
/// verifies under its own digest length; so is the honest proof with its
/// first digest cut to 8 elements.
#[test]
fn a_wrong_digest_length_is_rejected() {
    let short = ScaleShape {
        digest_elems: SCALE_DIGEST_ELEMS - 1,
        ..ScaleShape::SHIPPED
    };
    let (tx, proof) = prove_scale_shaped(short, 3);
    assert_eq!(verify_coin_reveal_v2_scale_shaped(&params(), &tx, &proof, short), Ok(()));
    assert!(verify_coin_reveal_v2_scale(&params(), &tx, &proof).is_err());

    // The trace commitment comes first: a one-byte length prefix of the cap,
    // then its one digest of nine 4-byte elements. Drop the last element.
    let (tx, honest_proof) = honest();
    let bytes = honest_proof.as_bytes();
    assert_eq!(bytes[0], 1, "a cap of one digest");
    let mut cut = bytes[..1 + 4 * (SCALE_DIGEST_ELEMS - 1)].to_vec();
    cut.extend_from_slice(&bytes[1 + 4 * SCALE_DIGEST_ELEMS..]);
    assert!(verify_coin_reveal_v2_scale(&params(), tx, &Proof::from_bytes(cut)).is_err());
}

/// A proof with 95 queries, not 96, is rejected, though it verifies at its
/// own query count.
#[test]
fn a_wrong_query_count_is_rejected() {
    let fewer = ScaleShape {
        num_queries: SCALE_NUM_QUERIES - 1,
        ..ScaleShape::SHIPPED
    };
    let (tx, proof) = prove_scale_shaped(fewer, 4);
    assert_eq!(verify_coin_reveal_v2_scale_shaped(&params(), &tx, &proof, fewer), Ok(()));
    assert_eq!(verify_coin_reveal_v2_scale(&params(), &tx, &proof), Err(ProofError::MalformedProof));
    // And the honest 96-query proof is refused by a verifier that expects 95.
    let (tx, honest_proof) = honest();
    assert!(verify_coin_reveal_v2_scale_shaped(&params(), tx, honest_proof, fewer).is_err());
}
