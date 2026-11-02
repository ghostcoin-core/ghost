//! The policy reveal of the policy class, statement S4 (spec 10, sections 5.1
//! and 5.4): the rule opened from its five public fields and a private
//! override hash, a zero-value remainder with the empty rule, `v = out + fee`.
//!
//! Known answers: the binding's sizes and its digest against an independent
//! tagged hash over example fields; the gate's report of the new trace; the
//! proof-length bound. Properties RP-6 and RP-7 of spec 10, section 14, and
//! the empty-rule coin, each from an honest proof asserted to verify and a
//! lying prover that changes one thing. Proving runs one test at a time to
//! bound memory.

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
    let mut seed = [0x5cu8; 32];
    seed[0] = n;
    seed
}

/// Example chain constants, not Ghost's. The policy class binds
/// `POLICY_VERSION = 0x0001`.
fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    }
}

const VALUE: u128 = 1_000_000;
const FEE: u128 = 21;

/// An example rule with an override and actions.
fn policy() -> PolicyRule {
    PolicyRule {
        policy_address: [0x50; POLICY_ADDRESS_BYTES],
        policy_codehash: [0x51; 32],
        params_hash: tagged("ghost/policy-params/v1", &[]),
        override_hash: policy_override_hash(&[0x0e; 32]),
        action_tag: [0x53; 32],
        action_salt: [0x54; 32],
    }
}

/// The same rule with another action salt: what a lying sender publishes.
fn other_salt() -> PolicyRule {
    PolicyRule {
        action_salt: [0x55; 32],
        ..policy()
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

/// A salted coin of 1,000,000 at position 5.
fn opening() -> SaltedCoinOpening {
    SaltedCoinOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        salt: [0xa5; SALT_BYTES],
        v: amount_word(VALUE),
        position: 5,
        path: path(),
    }
}

/// The remainder, holding `v'`; the policy class requires `v' = 0`.
fn remainder(v: u128) -> SaltedCoinRemainder {
    SaltedCoinRemainder {
        s: [1; 32],
        r: [2; 32],
        b: [4; 32],
        salt: [0x3c; SALT_BYTES],
        v: amount_word(v),
    }
}

/// The root of a tree holding the coin whose fingerprint holds `coin_rule`.
fn root(coin_rule: &[u8; 32]) -> [u8; 32] {
    let o = opening();
    let leaf = coin_commitment_v2(&coin_fingerprint_v2(&o.s, &o.r, &o.b, &o.salt, coin_rule), &o.v);
    merkle_root(Tree::Coin, &leaf, o.position, &o.path)
}

/// The request for the coin with `coin_rule`, `out = v - v' - fee`.
fn request(coin_rule: &[u8; 32], v_rem: u128) -> PolicyRevealRequest {
    PolicyRevealRequest {
        root: root(coin_rule),
        out: amount_word(VALUE - v_rem - FEE),
        fee: amount_word(FEE),
        instr: [0x61; 32],
        remainder_note: [0x33; NOTE_V3_BYTES],
    }
}

/// The transaction for the coin with `coin_rule` publishing `rule`'s fields
/// and a remainder of `v_rem`, computed here from the hashes.
fn expected_tx(coin_rule: &[u8; 32], rule: &PolicyRule, v_rem: u128) -> PolicyReveal {
    let (o, rem, req) = (opening(), remainder(v_rem), request(coin_rule, v_rem));
    let f = coin_fingerprint_v2(&rem.s, &rem.r, &rem.b, &rem.salt, &EMPTY_RULE);
    PolicyReveal {
        root: req.root,
        marker: coin_marker_v2(&o.r, &o.b, &o.salt),
        remainder: coin_commitment_v2(&f, &rem.v),
        out: req.out,
        fee: req.fee,
        policy_address: rule.policy_address,
        policy_codehash: rule.policy_codehash,
        params_hash: rule.params_hash,
        action_tag: rule.action_tag,
        action_salt: rule.action_salt,
        instr: req.instr,
        remainder_note: req.remainder_note,
    }
}

fn prove(rule: &PolicyRule, coin_rule: &[u8; 32], v_rem: u128, seed: u8) -> Result<(PolicyReveal, Proof), ProofError> {
    prove_policy_reveal(&params(), &opening(), rule, &remainder(v_rem), &request(coin_rule, v_rem), zk(seed))
}

/// The policy coin spent through S4.
fn honest() -> &'static (PolicyReveal, Proof) {
    static HONEST: OnceLock<(PolicyReveal, Proof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let (tx, proof) = prove(&policy(), &policy().rule(), 0, 1).expect("honest policy reveal");
        assert_eq!(verify_policy_reveal(&params(), &tx, &proof), Ok(()));
        (tx, proof)
    })
}

/// A lying prover's proof of `tx` does not verify. In a release build the
/// prover makes bytes and the verifier rejects them; with debug assertions
/// on, Plonky3 checks every constraint before it proves and panics on the
/// broken one, so no proof exists at all.
fn lying_proof_fails(tx: &PolicyReveal, prove: impl FnOnce() -> Result<Proof, ProofError>) {
    match catch_unwind(AssertUnwindSafe(prove)) {
        Ok(proof) => {
            let proof = proof.expect("the lying prover still produces bytes");
            assert_eq!(verify_policy_reveal(&params(), tx, &proof), Err(ProofError::Rejected));
        }
        Err(_) => assert!(cfg!(debug_assertions), "only the debug constraint check may stop the prover"),
    }
}

/// A proof claiming `claimed`, the trace carrying `input_rule` into the
/// input fingerprint, with a remainder of `v_rem`.
fn lie(input_rule: &[u8; 32], v_rem: u128, claimed: &PolicyReveal, seed: u8) {
    lying_proof_fails(claimed, || {
        prove_policy_reveal_claiming(
            &params(),
            &opening(),
            &policy().override_hash,
            input_rule,
            &remainder(v_rem),
            claimed,
            zk(seed),
        )
    });
}

/// Whether `haystack` holds `needle` as bytes, or as one BabyBear element
/// (four little-endian bytes) per byte, the way the proof encodes a trace
/// value.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    let as_elements: Vec<u8> = needle.iter().flat_map(|&b| u32::from(b).to_le_bytes()).collect();
    haystack.windows(needle.len()).any(|w| w == needle)
        || haystack.windows(as_elements.len()).any(|w| w == as_elements)
}

/// The proof-length bound of the S4 trace.
fn bound() -> usize {
    proof_length_bound(2048, 3856)
}

// ---------------------------------------------------------------------------
// Known answers.

/// Spec 10, section 5.1: 767 bytes of fields, 798 with the 31-byte tag, six
/// permutations, 799 public values; the digest is the tagged hash of the
/// fields in the table's order.
#[test]
fn the_binding_is_the_known_answer() {
    let b = Binding::PolicyReveal;
    assert_eq!(b.tag(), "ghost/policy-reveal-binding/v1");
    assert_eq!(TAG_POLICY_REVEAL_BINDING_V1, b.tag());
    assert_eq!(tag_bytes(b.tag()).len(), 31);
    assert_eq!((b.fields_len(), b.input_len(), b.permutations()), (767, 798, 6));
    assert_eq!((STATEMENT_POLICY_REVEAL, PURPOSE_POLICY_SPEND), (0x04, 0x05));
    let layout: Vec<(&str, usize, usize)> = b.layout().iter().map(|f| (f.name, f.offset, f.width)).collect();
    assert_eq!(
        layout,
        [
            ("chain_id", 0, 8),
            ("version", 8, 2),
            ("domain", 10, 32),
            ("statement", 42, 1),
            ("statement_version", 43, 1),
            ("type", 44, 2),
            ("purpose", 46, 1),
            ("root", 47, 32),
            ("marker", 79, 32),
            ("remainder", 111, 32),
            ("out", 143, 32),
            ("fee", 175, 32),
            ("policy_address", 207, 20),
            ("policy_codehash", 227, 32),
            ("params_hash", 259, 32),
            ("action_tag", 291, 32),
            ("action_salt", 323, 32),
            ("instr", 355, 32),
            ("remainder_note", 387, 380),
        ]
    );
    assert_eq!(POLICY_REVEAL_LAYOUT, b.layout());

    let tx = PolicyReveal {
        root: [0x21; 32],
        marker: [0x22; 32],
        remainder: [0x23; 32],
        out: amount_word(600_000),
        fee: amount_word(21),
        policy_address: [0x24; 20],
        policy_codehash: [0x25; 32],
        params_hash: [0x26; 32],
        action_tag: [0x27; 32],
        action_salt: [0x28; 32],
        instr: [0x29; 32],
        remainder_note: [0x2a; NOTE_V3_BYTES],
    };
    let p = params();
    let independent = tagged(
        "ghost/policy-reveal-binding/v1",
        &[
            &p.chain_id,
            &[0x00, 0x01],
            &p.domain,
            &[0x04],
            &[0x01],
            &[0x02, 0x01],
            &[0x05],
            &tx.root,
            &tx.marker,
            &tx.remainder,
            &tx.out,
            &tx.fee,
            &tx.policy_address,
            &tx.policy_codehash,
            &tx.params_hash,
            &tx.action_tag,
            &tx.action_salt,
            &tx.instr,
            &tx.remainder_note,
        ],
    );
    assert_eq!(policy_reveal_binding(&p, &tx), independent);
    let public = policy_reveal_public_values(&p, &tx);
    assert_eq!(public.len(), 799);
    assert_eq!(&public[767..], &independent[..]);
    assert_eq!(public[8..10], [0x00, 0x01]);
    assert_eq!(public[42..47], [0x04, 0x01, 0x02, 0x01, 0x05]);
    assert_eq!(&public[207..227], &tx.policy_address[..]);
    assert_eq!(&public[387..767], &tx.remainder_note[..]);
    // The ordinary class's tag over the same fields is another digest.
    assert_ne!(independent, tagged("ghost/coin-reveal-binding/v2", &[&public[..767]]));
}

/// Spec 10, section 5.4: 47 permutations, and the gate's report of S4:
/// 2,048 rows by 3,856 columns, a bound of 1,063,507 bytes inside the field
/// and an estimate that meets the 128-bit rule. S4 comes after the version 2
/// coin reveal.
#[test]
fn the_gate_holds_the_new_trace() {
    // RIN, F, C, the 32 nodes, M, F', C', B.
    let perms = permutations(tag_bytes(TAG_REVEAL_POLICY_V2).len() + 6 * 32)
        + 2 * permutations(204)
        + 2 * permutations(91)
        + TREE_DEPTH * permutations(89)
        + permutations(101)
        + Binding::PolicyReveal.permutations();
    assert_eq!(perms, 47);
    assert_eq!((perms * 24).next_power_of_two(), 2048);

    let config = shipped_configuration().expect("the security gate takes every statement");
    assert_eq!(Statement::ALL.len(), 5);
    assert_eq!(Statement::ALL[3], Statement::CoinRevealV2);
    assert_eq!(Statement::ALL[4], Statement::PolicyReveal);
    let (statement, s4) = config.statements[4];
    assert_eq!(statement, Statement::PolicyReveal);
    let (_, v2) = config.statements[3];
    assert_eq!((s4.trace_height, s4.trace_width), (2048, 3856));
    assert_eq!(s4.trace_width, 3722 + 134);
    assert_eq!(proof_length_bound(2048, 3856), 1_063_507);
    assert_eq!(proof_length_bound(s4.trace_height, s4.trace_width), bound());
    assert!(s4.trace_width <= MAX_TRACE_WIDTH && s4.trace_height <= MAX_TRACE_HEIGHT);
    assert!(bound() <= proof_length_bound(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH));
    assert!(bound() <= PROOF_FIELD_BYTES);
    assert_eq!(PROOF_FIELD_BYTES, 1_310_720);
    assert!(s4.conjectured_bits_half_grinding >= TARGET_CONJECTURED_BITS, "{s4:?}");
    assert!(s4.conjectured_bits >= s4.conjectured_bits_half_grinding, "{s4:?}");
    assert!(s4.constraint_degree <= 1 << config.log_blowup, "{s4:?}");
    assert_eq!(s4.constraint_degree, v2.constraint_degree, "the zero limbs must not raise the degree");
}

// ---------------------------------------------------------------------------
// The honest proof.

/// The honest proof verifies, publishes the fields of the opened rule and a
/// zero-value remainder with the empty rule, fits the bound and the field,
/// and holds neither the override hash nor the rule.
#[test]
fn the_honest_proof_verifies_and_fits() {
    let _one = one_at_a_time();
    let (tx, proof) = honest();
    let p = policy();
    assert_eq!(tx, &expected_tx(&p.rule(), &p, 0));
    // `v = out + fee`, and the remainder is the zero-value commitment.
    assert_eq!(amount_value(&tx.out), Some(VALUE - FEE));
    let rem = remainder(0);
    let zero_remainder = coin_commitment_v2(
        &coin_fingerprint_v2(&rem.s, &rem.r, &rem.b, &rem.salt, &EMPTY_RULE),
        &amount_word(0),
    );
    assert_eq!(tx.remainder, zero_remainder);

    let len = proof.as_bytes().len();
    assert!(len <= bound(), "a proof of {len} bytes, over the bound {}", bound());
    assert!(len <= 1_063_507);
    assert!(len <= PROOF_FIELD_BYTES, "a proof of {len} bytes, over the field");

    let public = policy_reveal_public_values(&params(), tx);
    for secret in [&p.override_hash, &p.rule()] {
        assert!(!holds(&public, secret), "a public value holds a private rule value");
        assert!(!holds(proof.as_bytes(), secret), "the proof holds a private rule value");
    }
    // The check itself finds a value that is there.
    assert!(holds(&public, &tx.action_salt));

    // The proof is no proof of the ordinary class.
    let ordinary = CoinRevealV2 {
        root: tx.root,
        marker: tx.marker,
        remainder: tx.remainder,
        remainder_note: tx.remainder_note,
        recipient: [0x11; 20],
        out: tx.out,
        fee: tx.fee,
    };
    assert!(verify_coin_reveal_v2(&params(), &ordinary, proof).is_err());
}

/// Changing any bound field, or any chain constant, fails verification of
/// the honest proof. No re-proving: each check is the same proof against a
/// changed copy of the public fields.
#[test]
fn changing_any_bound_field_fails() {
    let _one = one_at_a_time();
    let (tx, proof) = honest();
    type Change = fn(&mut PolicyReveal);
    let changes: [(&str, Change); 12] = [
        ("policy_address", |t| t.policy_address[19] ^= 1),
        ("policy_codehash", |t| t.policy_codehash[0] ^= 1),
        ("params_hash", |t| t.params_hash[31] ^= 1),
        ("action_tag", |t| t.action_tag[0] ^= 1),
        ("instr", |t| t.instr[0] ^= 1),
        ("out", |t| t.out[31] ^= 1),
        ("fee", |t| t.fee[31] ^= 1),
        ("remainder_note", |t| t.remainder_note[379] ^= 1),
        ("action_salt", |t| t.action_salt[0] ^= 1),
        ("root", |t| t.root[0] ^= 1),
        ("marker", |t| t.marker[0] ^= 1),
        ("remainder", |t| t.remainder[0] ^= 1),
    ];
    for (name, change) in changes {
        let mut changed = tx.clone();
        change(&mut changed);
        assert_ne!(&changed, tx, "{name}");
        assert_eq!(verify_policy_reveal(&params(), &changed, proof), Err(ProofError::Rejected), "{name}");
    }
    // `out + fee` moved between the two still breaks the binding.
    let mut moved = tx.clone();
    moved.out = amount_word(VALUE - FEE - 1);
    moved.fee = amount_word(FEE + 1);
    assert_eq!(verify_policy_reveal(&params(), &moved, proof), Err(ProofError::Rejected));

    let chain = [
        ChainParams {
            chain_id: 1235u64.to_be_bytes(),
            ..params()
        },
        ChainParams {
            version: PROTOCOL_VERSION_2,
            ..params()
        },
        ChainParams {
            domain: [0x48; 32],
            ..params()
        },
    ];
    for p in chain {
        assert_eq!(verify_policy_reveal(&p, tx, proof), Err(ProofError::Rejected), "{p:?}");
    }
    // An amount word out of range is refused before the proof.
    let mut high = tx.clone();
    high.out[0] = 1;
    assert_eq!(verify_policy_reveal(&params(), &high, proof), Err(ProofError::AmountOutOfRange));
    // The honest proof still verifies.
    assert_eq!(verify_policy_reveal(&params(), tx, proof), Ok(()));
}

// ---------------------------------------------------------------------------
// The properties.

/// RP-6: a proof whose published `action_salt` differs from the one inside
/// the coin's rule does not verify, whether the lying prover carries the
/// coin's rule (the opening of the published fields fails) or the rule of
/// the published fields (the coin is not the leaf). The honest prover
/// refuses: the rule with that salt is not the coin's.
#[test]
fn a_published_action_salt_other_than_the_coins_fails() {
    let _one = one_at_a_time();
    let coin_rule = policy().rule();
    let published = other_salt();
    assert_ne!(published.rule(), coin_rule);
    assert_eq!(prove(&published, &coin_rule, 0, 2).err(), Some(ProofError::NotInTree));

    let claimed = expected_tx(&coin_rule, &published, 0);
    assert_eq!(claimed.action_salt, [0x55; 32]);
    assert_ne!(claimed.action_salt, policy().action_salt);
    lie(&coin_rule, 0, &claimed, 3);
    lie(&published.rule(), 0, &claimed, 4);
}

/// RP-7: a witness with a non-zero remainder amount fails. The honest prover
/// refuses it, and a lying prover's proof, with `out + v' + fee = v` so that
/// conservation alone would hold, does not verify.
#[test]
fn a_remainder_with_value_fails() {
    let _one = one_at_a_time();
    let coin_rule = policy().rule();
    assert_eq!(prove(&policy(), &coin_rule, 1_000, 5).err(), Some(ProofError::RemainderNotZero));
    // Even with a request whose amounts leave nothing over.
    let full = request(&coin_rule, 0);
    assert_eq!(
        prove_policy_reveal(&params(), &opening(), &policy(), &remainder(1_000), &full, zk(5)).err(),
        Some(ProofError::RemainderNotZero)
    );

    let claimed = expected_tx(&coin_rule, &policy(), 1_000);
    assert!(conservation_holds(&opening().v, &claimed.out, &amount_word(1_000), &claimed.fee));
    lie(&coin_rule, 1_000, &claimed, 6);
}

/// A coin with the empty rule cannot be spent with S4: the honest prover
/// refuses it, whatever rule it is given, and a lying prover that carries
/// the empty rule into the fingerprint, so the coin is the leaf, makes a
/// proof that does not verify.
#[test]
fn a_coin_with_the_empty_rule_cannot_be_spent() {
    let _one = one_at_a_time();
    assert_eq!(prove(&policy(), &EMPTY_RULE, 0, 7).err(), Some(ProofError::NotInTree));
    assert_eq!(prove(&PolicyRule::zero(), &EMPTY_RULE, 0, 7).err(), Some(ProofError::NotInTree));
    assert_ne!(PolicyRule::zero().rule(), EMPTY_RULE);

    let claimed = expected_tx(&EMPTY_RULE, &policy(), 0);
    lie(&EMPTY_RULE, 0, &claimed, 8);
}
