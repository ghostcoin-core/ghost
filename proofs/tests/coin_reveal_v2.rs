//! The coin reveal of the ordinary class, statement S1 version 2 (spec 10,
//! sections 4.2 to 4.4): the private override switch, the rule opening, the
//! override check and the free private remainder rule.
//!
//! Known answers: the binding's sizes and its digest against an independent
//! tagged hash over example fields; the gate's report of the new trace; the
//! proof-length bound. Properties RP-1 to RP-5 of spec 10, section 14, each
//! from honest proofs asserted to verify and lying provers that change one
//! thing. Proving runs one test at a time to bound memory.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard, OnceLock};

use ghost_proofs::ffi::{COIN_REVEAL_V2_BYTES, coin_reveal_v2_to_bytes};
use ghost_proofs::*;

static PROVING: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only zero-knowledge randomness; a real prover draws it from a secure
/// random source.
fn zk(n: u8) -> [u8; 32] {
    let mut seed = [0x5bu8; 32];
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

/// The example override secret; a wallet derives it from its seed.
const SECRET: [u8; 32] = [0x0e; 32];

/// An example rule with an override (Ghost Guard's shape: empty
/// parameters), with actions.
fn policy() -> PolicyRule {
    PolicyRule {
        policy_address: [0x50; POLICY_ADDRESS_BYTES],
        policy_codehash: [0x51; 32],
        params_hash: tagged("ghost/policy-params/v1", &[]),
        override_hash: policy_override_hash(&SECRET),
        action_tag: [0x53; 32],
        action_salt: [0x54; 32],
    }
}

/// The same rule with no override.
fn policy_without_override() -> PolicyRule {
    PolicyRule {
        override_hash: [0; 32],
        ..policy()
    }
}

/// A rotated rule for a remainder: another action salt.
fn rotated_rule() -> [u8; 32] {
    PolicyRule {
        action_salt: [0x55; 32],
        ..policy()
    }
    .rule()
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

/// A salted coin of 1,000,000 at position 5, revealed for 600,000 and a fee
/// of 21.
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

/// The request for the coin whose fingerprint holds `coin_rule`.
fn request(coin_rule: &[u8; 32]) -> CoinRevealV2Request {
    let o = opening();
    let leaf = coin_commitment_v2(&coin_fingerprint_v2(&o.s, &o.r, &o.b, &o.salt, coin_rule), &o.v);
    CoinRevealV2Request {
        root: merkle_root(Tree::Coin, &leaf, o.position, &o.path),
        recipient: [0x11; 20],
        out: amount_word(600_000),
        fee: amount_word(21),
        remainder_note: [0x33; NOTE_V3_BYTES],
    }
}

/// The transaction an honest reveal of the coin with `coin_rule` publishes,
/// computed here from the hashes.
fn expected_tx(coin_rule: &[u8; 32], remainder_rule: &[u8; 32]) -> CoinRevealV2 {
    let (o, rem, req) = (opening(), remainder(), request(coin_rule));
    let f = coin_fingerprint_v2(&rem.s, &rem.r, &rem.b, &rem.salt, remainder_rule);
    CoinRevealV2 {
        root: req.root,
        marker: coin_marker_v2(&o.r, &o.b, &o.salt),
        remainder: coin_commitment_v2(&f, &rem.v),
        remainder_note: req.remainder_note,
        recipient: req.recipient,
        out: req.out,
        fee: req.fee,
    }
}

fn prove(
    input: &InputRule,
    coin_rule: &[u8; 32],
    remainder_rule: &[u8; 32],
    seed: u8,
) -> Result<(CoinRevealV2, Proof), ProofError> {
    prove_coin_reveal_v2(&params(), &opening(), input, &remainder(), remainder_rule, &request(coin_rule), zk(seed))
}

/// A plain coin (the empty rule), its remainder plain too.
fn honest_plain() -> &'static (CoinRevealV2, Proof) {
    static HONEST: OnceLock<(CoinRevealV2, Proof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let (tx, proof) = prove(&InputRule::plain(), &EMPTY_RULE, &EMPTY_RULE, 1).expect("honest plain proof");
        assert_eq!(verify_coin_reveal_v2(&params(), &tx, &proof), Ok(()));
        (tx, proof)
    })
}

/// A policy coin spent through its override, its remainder keeping the rule.
fn honest_override() -> &'static (CoinRevealV2, Proof) {
    static HONEST: OnceLock<(CoinRevealV2, Proof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let rule = policy().rule();
        let input = InputRule::with_override(policy(), SECRET);
        let (tx, proof) = prove(&input, &rule, &rule, 2).expect("honest override proof");
        assert_eq!(verify_coin_reveal_v2(&params(), &tx, &proof), Ok(()));
        (tx, proof)
    })
}

/// A lying prover's proof of `tx` does not verify. In a release build the
/// prover makes bytes and the verifier rejects them; with debug assertions
/// on, Plonky3 checks every constraint before it proves and panics on the
/// broken one, so no proof exists at all.
fn lying_proof_fails(tx: &CoinRevealV2, prove: impl FnOnce() -> Result<Proof, ProofError>) {
    match catch_unwind(AssertUnwindSafe(prove)) {
        Ok(proof) => {
            let proof = proof.expect("the lying prover still produces bytes");
            assert_eq!(verify_coin_reveal_v2(&params(), tx, &proof), Err(ProofError::Rejected));
        }
        Err(_) => assert!(cfg!(debug_assertions), "only the debug constraint check may stop the prover"),
    }
}

fn lie(input: &InputRule, remainder_rule: &[u8; 32], claimed: &CoinRevealV2, seed: u8) {
    lying_proof_fails(claimed, || {
        prove_coin_reveal_v2_claiming(&params(), &opening(), input, &remainder(), remainder_rule, claimed, zk(seed))
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

/// Everything a version 2 reveal publishes: the statement a node passes the
/// verifier, the public values of the proof (binding digest included) and
/// the chain parameters.
fn published(tx: &CoinRevealV2) -> Vec<u8> {
    [
        &coin_reveal_v2_to_bytes(tx)[..],
        &coin_reveal_v2_public_values(&params(), tx),
        &ffi::chain_params_to_bytes(&params()),
    ]
    .concat()
}

/// The longest proof the version 2 trace can have.
fn bound() -> usize {
    proof_length_bound(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH)
}

// ---------------------------------------------------------------------------
// Known answers.

/// Spec 10, section 4.2: 607 bytes of fields, 636 with the 29-byte tag, five
/// permutations, 639 public values; the digest is the tagged hash of the
/// fields in the table's order, with `statement_version` 2 and no rule.
#[test]
fn the_binding_is_the_known_answer() {
    let b = Binding::CoinRevealV2;
    assert_eq!(b.tag(), "ghost/coin-reveal-binding/v2");
    assert_eq!(TAG_COIN_REVEAL_BINDING_V2, b.tag());
    assert_eq!(tag_bytes(b.tag()).len(), 29);
    assert_eq!((b.fields_len(), b.input_len(), b.permutations()), (607, 636, 5));
    assert_eq!(NOTE_V3_BYTES, 380);
    let names: Vec<&str> = b.layout().iter().map(|f| f.name).collect();
    assert_eq!(
        names,
        [
            "chain_id",
            "version",
            "domain",
            "statement",
            "statement_version",
            "type",
            "purpose",
            "root",
            "marker",
            "remainder",
            "recipient",
            "out",
            "fee",
            "remainder_note"
        ]
    );
    assert_eq!(COIN_REVEAL_V2_LAYOUT, b.layout());

    let tx = CoinRevealV2 {
        root: [0x21; 32],
        marker: [0x22; 32],
        remainder: [0x23; 32],
        remainder_note: [0x24; NOTE_V3_BYTES],
        recipient: [0x25; 20],
        out: amount_word(600_000),
        fee: amount_word(21),
    };
    let p = params();
    let independent = tagged(
        "ghost/coin-reveal-binding/v2",
        &[
            &p.chain_id,
            &[0x00, 0x02],
            &p.domain,
            &[0x01],
            &[0x02],
            &[0x02, 0x01],
            &[0x01],
            &tx.root,
            &tx.marker,
            &tx.remainder,
            &tx.recipient,
            &tx.out,
            &tx.fee,
            &tx.remainder_note,
        ],
    );
    assert_eq!(coin_reveal_v2_binding(&p, &tx), independent);
    let public = coin_reveal_v2_public_values(&p, &tx);
    assert_eq!(public.len(), 639);
    assert_eq!(&public[607..], &independent[..]);
    assert_eq!(public[42..47], [STATEMENT_COIN_REVEAL, STATEMENT_VERSION_2, 0x02, 0x01, PURPOSE_SPEND]);
    assert_eq!(&public[227..607], &tx.remainder_note[..]);
    // A version 1 binding over the same transaction is another digest.
    assert_ne!(independent, tagged("ghost/coin-reveal-binding/v1", &[&public[..607]]));
}

/// Spec 10, sections 3.1 and 4.4: the rule and override hashes, the 47
/// permutations, and the gate's report of the new statement: 2,048 rows by
/// 3,890 columns, the budget's widest, a bound of 1,070,715 bytes inside the
/// field and an estimate that meets the 128-bit rule. The version 1 coin
/// reveal stays the first statement, 3,824 columns wide.
#[test]
fn the_gate_holds_the_new_trace() {
    let rule = policy();
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&rule.policy_address);
    let expected = tagged(
        "ghost/reveal-policy/v2",
        &[
            &padded,
            &rule.policy_codehash,
            &rule.params_hash,
            &rule.override_hash,
            &rule.action_tag,
            &rule.action_salt,
        ],
    );
    assert_eq!(rule.rule(), expected);
    assert_eq!(policy_override_hash(&SECRET), tagged("ghost/policy-override/v1", &[&SECRET]));

    // RIN, OV, F, C, the 32 nodes, M, F', C', B.
    let perms = permutations(tag_bytes(TAG_REVEAL_POLICY_V2).len() + 6 * 32)
        + permutations(tag_bytes(TAG_POLICY_OVERRIDE_V1).len() + 32)
        + 2 * permutations(204)
        + 2 * permutations(91)
        + TREE_DEPTH * permutations(89)
        + permutations(101)
        + Binding::CoinRevealV2.permutations();
    assert_eq!(perms, 47);
    assert_eq!((perms * 24).next_power_of_two(), 2048);

    let config = shipped_configuration().expect("the security gate takes every statement");
    assert_eq!(config.statements.len(), 7);
    let (first, v1) = config.statements[0];
    assert_eq!(first, Statement::SaltedCoinReveal);
    let (last, v2) = config.statements[3];
    assert_eq!(last, Statement::CoinRevealV2);
    assert_eq!(Statement::ALL[3], Statement::CoinRevealV2);
    assert_eq!((v2.trace_height, v2.trace_width), (2048, 3890));
    assert_eq!((MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH), (2048, 3890));
    assert_eq!((v1.trace_height, v1.trace_width), (2048, 3824));
    assert_eq!(proof_length_bound(2048, 3890), 1_070_715);
    assert_eq!(proof_length_bound(v2.trace_height, v2.trace_width), bound());
    assert!(bound() <= PROOF_FIELD_BYTES);
    assert_eq!(PROOF_FIELD_BYTES, 1_310_720);
    assert!(v2.conjectured_bits_half_grinding >= TARGET_CONJECTURED_BITS, "{v2:?}");
    assert!(v2.conjectured_bits >= v2.conjectured_bits_half_grinding, "{v2:?}");
    assert!(v2.constraint_degree <= 1 << config.log_blowup, "{v2:?}");
    assert_eq!(v2.constraint_degree, v1.constraint_degree, "the switch must not raise the degree");
    for (statement, e) in config.statements {
        assert!(e.trace_width <= MAX_TRACE_WIDTH && e.trace_height <= MAX_TRACE_HEIGHT, "{statement:?}");
    }
}

// ---------------------------------------------------------------------------
// The properties.

/// RP-1: a plain-coin proof and an override proof are proofs of one
/// statement with the same public layout and length, both inside the bound
/// and the proof field; neither publishes a rule or the override secret.
#[test]
fn plain_and_override_proofs_look_alike() {
    let _one = one_at_a_time();
    let (plain, plain_proof) = honest_plain();
    let (over, over_proof) = honest_override();
    assert_eq!(plain, &expected_tx(&EMPTY_RULE, &EMPTY_RULE));
    let rule = policy().rule();
    assert_eq!(over, &expected_tx(&rule, &rule));

    let (a, b) = (coin_reveal_v2_public_values(&params(), plain), coin_reveal_v2_public_values(&params(), over));
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), Binding::CoinRevealV2.fields_len() + 32);
    // The constants of the binding are the same bytes in both.
    let header = Binding::CoinRevealV2.layout()[7].offset;
    assert_eq!(a[..header], b[..header]);
    assert_eq!(coin_reveal_v2_to_bytes(plain).len(), COIN_REVEAL_V2_BYTES);
    assert_eq!(coin_reveal_v2_to_bytes(over).len(), COIN_REVEAL_V2_BYTES);

    for proof in [plain_proof, over_proof] {
        let len = proof.as_bytes().len();
        assert!(len <= bound(), "a proof of {len} bytes, over the bound {}", bound());
        assert!(len <= PROOF_FIELD_BYTES, "a proof of {len} bytes, over the field");
    }
    // Each proof is bound to its own transaction.
    assert_eq!(verify_coin_reveal_v2(&params(), plain, over_proof), Err(ProofError::Rejected));
    assert_eq!(verify_coin_reveal_v2(&params(), over, plain_proof), Err(ProofError::Rejected));

    let p = policy();
    for secret in [&rule, &SECRET, &p.override_hash, &p.action_salt, &p.policy_codehash] {
        assert!(!holds(&published(over), secret), "a public value holds a rule field");
        assert!(!holds(over_proof.as_bytes(), secret), "the proof holds a rule field");
    }
    assert!(!holds(&published(over), &p.policy_address));
    // The check itself finds a value that is there.
    assert!(holds(&published(over), &over.remainder));
}

/// RP-2: a switch of 2 fails to prove and to verify.
#[test]
fn a_switch_of_two_fails() {
    let _one = one_at_a_time();
    let rule = policy().rule();
    let two = InputRule {
        use_override: 2,
        ..InputRule::with_override(policy(), SECRET)
    };
    assert_eq!(prove(&two, &rule, &rule, 3).err(), Some(ProofError::OverrideSwitchNotBit));
    let (tx, _) = honest_override();
    lie(&two, &rule, tx, 4);
}

/// RP-3: a coin with the empty rule cannot use the override, and a coin
/// with a rule cannot be spent with the switch off.
#[test]
fn the_switch_must_match_the_coin() {
    let _one = one_at_a_time();
    let rule = policy().rule();
    // An empty-rule coin through the override.
    let on = InputRule::with_override(policy(), SECRET);
    assert_eq!(prove(&on, &EMPTY_RULE, &EMPTY_RULE, 5).err(), Some(ProofError::NotInTree));
    let (plain, _) = honest_plain();
    lie(&on, &EMPTY_RULE, plain, 6);

    // A policy coin with the switch off, whatever rule fields come with it.
    assert_eq!(prove(&InputRule::plain(), &rule, &rule, 7).err(), Some(ProofError::NotInTree));
    let off = InputRule {
        use_override: 0,
        ..InputRule::with_override(policy(), SECRET)
    };
    assert_eq!(prove(&off, &rule, &rule, 7).err(), Some(ProofError::NotInTree));
    let (over, _) = honest_override();
    lie(&off, &rule, over, 8);
}

/// RP-4: a wrong override secret fails, and so does the override of a rule
/// whose `override_hash` is zero.
#[test]
fn a_wrong_or_missing_override_fails() {
    let _one = one_at_a_time();
    let rule = policy().rule();
    let mut wrong_secret = SECRET;
    wrong_secret[0] ^= 1;
    let wrong = InputRule::with_override(policy(), wrong_secret);
    assert_eq!(prove(&wrong, &rule, &rule, 9).err(), Some(ProofError::WrongOverrideSecret));
    let (over, _) = honest_override();
    lie(&wrong, &rule, over, 10);

    let none = policy_without_override();
    let none_rule = none.rule();
    assert_ne!(none_rule, rule);
    let zero = InputRule::with_override(policy_without_override(), SECRET);
    assert_eq!(prove(&zero, &none_rule, &EMPTY_RULE, 11).err(), Some(ProofError::OverrideNotSet));
    let claimed = expected_tx(&none_rule, &EMPTY_RULE);
    lie(&zero, &EMPTY_RULE, &claimed, 12);
}

/// RP-5: the remainder rule is the prover's choice and changes no public
/// value. With the input's rule, a rotated rule and the empty rule, every
/// proof verifies, the public layout and length are the same, every public
/// value but the remainder commitment (and the digest over it) is the same,
/// and no rule appears in any of them.
#[test]
fn the_remainder_rule_changes_no_public_value() {
    let _one = one_at_a_time();
    let rule = policy().rule();
    let rotated = rotated_rule();
    assert_ne!(rotated, rule);
    let (kept, _) = honest_override();
    let input = InputRule::with_override(policy(), SECRET);
    let mut reveals = vec![(rule, kept.clone())];
    for (remainder_rule, seed) in [(rotated, 13), (EMPTY_RULE, 14)] {
        let (tx, proof) = prove(&input, &rule, &remainder_rule, seed).expect("honest proof");
        assert_eq!(verify_coin_reveal_v2(&params(), &tx, &proof), Ok(()));
        assert!(proof.as_bytes().len() <= bound() && proof.as_bytes().len() <= PROOF_FIELD_BYTES);
        reveals.push((remainder_rule, tx));
    }

    let at = Binding::CoinRevealV2.layout()[9];
    assert_eq!(at.name, "remainder");
    let digest = Binding::CoinRevealV2.fields_len();
    let without_remainder = |tx: &CoinRevealV2| {
        let public = coin_reveal_v2_public_values(&params(), tx);
        [&public[..at.offset], &public[at.offset + at.width..digest]].concat()
    };
    let reference = without_remainder(&reveals[0].1);
    for (remainder_rule, tx) in &reveals {
        // The remainder holds the chosen rule.
        assert_eq!(tx, &expected_tx(&rule, remainder_rule));
        let public = coin_reveal_v2_public_values(&params(), tx);
        assert_eq!(public.len(), 639);
        assert_eq!(without_remainder(tx), reference);
        for r in [&rule, &rotated] {
            assert!(!holds(&published(tx), r), "a public value holds a rule");
        }
    }
    // The remainders differ, as their rules do.
    assert_ne!(reveals[0].1.remainder, reveals[1].1.remainder);
    assert_ne!(reveals[1].1.remainder, reveals[2].1.remainder);
}
