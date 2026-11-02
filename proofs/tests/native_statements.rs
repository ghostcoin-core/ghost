//! The native statements of spec 10, sections 8.2 and 9: `KNOW_ACTION_v1`
//! and `KNOW_PREIMAGE_v1`.
//!
//! Known answers: the codes, purposes and tags; each binding's sizes and its
//! digest against an independent tagged hash over example fields; the
//! calldata hash and its limit; the gate's report of both traces; the
//! proof-length bound and `ACTION_PROOF_BYTES`. Then properties RP-16 and
//! RP-17 of spec 10, section 14, and the separation of the two statements,
//! each from honest proofs asserted to verify. Proving runs one test at a
//! time to bound memory.

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
    let mut seed = [0x6du8; 32];
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

/// The owner's private `action_root`, and the slot's salt.
const ACTION_ROOT: [u8; 32] = [0x71; 32];
const SLOT_SALT: [u8; 32] = [0x72; 32];
/// The private preimage of `KNOW_PREIMAGE_v1`.
const X: [u8; 32] = [0x81; 32];

const CALLDATA: &[u8] = b"example calldata for a policy action";

/// The public inputs of an action on the example slot, as the node sets
/// them: the tag and salt are the slot's.
fn slot_action() -> KnowAction {
    KnowAction {
        policy_address: [0x50; POLICY_ADDRESS_BYTES],
        marker: [0x51; 32],
        action_nonce: 0x0102_0304_0506_0708,
        action_tag: policy_action_tag(&ACTION_ROOT, &SLOT_SALT),
        action_salt: SLOT_SALT,
        expected_remaining: amount_word(1_000_000),
        debit: amount_word(25_000),
        expiry: 0x1112_1314_1516_1718,
        calldata_hash: action_calldata_hash(CALLDATA).expect("short calldata"),
    }
}

fn preimage_statement() -> KnowPreimage {
    KnowPreimage {
        policy_address: [0x50; POLICY_ADDRESS_BYTES],
        y: policy_preimage_hash(&X),
        context: [0x82; PREIMAGE_CONTEXT_BYTES],
    }
}

/// The honest action proof on the example slot.
fn honest_action() -> &'static Proof {
    static HONEST: OnceLock<Proof> = OnceLock::new();
    HONEST.get_or_init(|| {
        let proof = prove_know_action(&params(), &slot_action(), &ACTION_ROOT, zk(1)).expect("honest action proof");
        assert_eq!(verify_know_action(&params(), &slot_action(), &proof), Ok(()));
        proof
    })
}

/// The honest preimage proof.
fn honest_preimage() -> &'static Proof {
    static HONEST: OnceLock<Proof> = OnceLock::new();
    HONEST.get_or_init(|| {
        let proof = prove_know_preimage(&params(), &preimage_statement(), &X, zk(2)).expect("honest preimage proof");
        assert_eq!(verify_know_preimage(&params(), &preimage_statement(), &proof), Ok(()));
        proof
    })
}

/// A lying prover's proof fails `verify`. In a release build the prover
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

/// Whether `haystack` holds `needle` as bytes, or as one BabyBear element
/// (four little-endian bytes) per byte, the way the proof encodes a trace
/// value.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    let as_elements: Vec<u8> = needle.iter().flat_map(|&b| u32::from(b).to_le_bytes()).collect();
    haystack.windows(needle.len()).any(|w| w == needle)
        || haystack.windows(as_elements.len()).any(|w| w == as_elements)
}

/// The proof-length bound of both native traces.
const BOUND: usize = 947_283;

// ---------------------------------------------------------------------------
// Known answers.

/// Spec 10, section 9: the codes, version, purposes and tags.
#[test]
fn the_codes_and_tags_are_the_spec_ones() {
    assert_eq!((STATEMENT_KNOW_ACTION, PURPOSE_ACTION), (0x05, 0x06));
    assert_eq!((STATEMENT_KNOW_PREIMAGE, PURPOSE_PREIMAGE), (0x06, 0x07));
    assert_eq!(STATEMENT_VERSION_1, 0x01);
    assert_eq!(Binding::Action.tag(), "ghost/action-binding/v1");
    assert_eq!(Binding::Preimage.tag(), "ghost/preimage-binding/v1");
    assert_eq!(TAG_ACTION_BINDING_V1, "ghost/action-binding/v1");
    assert_eq!(TAG_PREIMAGE_BINDING_V1, "ghost/preimage-binding/v1");
    assert_eq!(TAG_POLICY_ACTION_V1, "ghost/policy-action/v1");
    assert_eq!(TAG_POLICY_PREIMAGE_V1, "ghost/policy-preimage/v1");
    assert_eq!(TAG_ACTION_CALLDATA_V1, "ghost/action-calldata/v1");
    // Every code, purpose and tag differs from the other statements'.
    let codes = [
        STATEMENT_COIN_REVEAL,
        STATEMENT_DATA_REVEAL,
        STATEMENT_HOLD,
        STATEMENT_POLICY_REVEAL,
        STATEMENT_KNOW_ACTION,
        STATEMENT_KNOW_PREIMAGE,
    ];
    let purposes = [
        PURPOSE_SPEND,
        PURPOSE_REVEAL,
        PURPOSE_REVOKE,
        PURPOSE_HOLD,
        PURPOSE_POLICY_SPEND,
        PURPOSE_ACTION,
        PURPOSE_PREIMAGE,
    ];
    let tags = [
        Binding::CoinReveal,
        Binding::DataReveal,
        Binding::Hold,
        Binding::CoinRevealV2,
        Binding::PolicyReveal,
        Binding::Action,
        Binding::Preimage,
    ]
    .map(Binding::tag);
    for (i, a) in codes.iter().enumerate() {
        assert!(codes[i + 1..].iter().all(|b| b != a), "statement code {a}");
    }
    for (i, a) in purposes.iter().enumerate() {
        assert!(purposes[i + 1..].iter().all(|b| b != a), "purpose {a}");
    }
    for (i, a) in tags.iter().enumerate() {
        assert!(tags[i + 1..].iter().all(|b| b != a), "tag {a}");
    }
    // The preimage and action tags of A1 and Y.
    assert_eq!(
        policy_action_tag(&ACTION_ROOT, &SLOT_SALT),
        tagged("ghost/policy-action/v1", &[&ACTION_ROOT, &SLOT_SALT])
    );
    assert_eq!(policy_preimage_hash(&X), tagged("ghost/policy-preimage/v1", &[&X]));
    assert_eq!(tag_bytes(TAG_POLICY_ACTION_V1).len() + 64, 87);
    assert_eq!(permutations(87), 1);
    assert_eq!(permutations(tag_bytes(TAG_POLICY_PREIMAGE_V1).len() + 32), 1);
}

/// Spec 10, section 8.2: 273 bytes of fields, 297 with the 24-byte tag,
/// three permutations; no `type`; the integers big-endian; the digest is the
/// tagged hash of the fields in the table's order.
#[test]
fn the_action_binding_is_the_known_answer() {
    let b = Binding::Action;
    assert_eq!(tag_bytes(b.tag()).len(), 24);
    assert_eq!((b.fields_len(), b.input_len(), b.permutations()), (273, 297, 3));
    let layout: Vec<(&str, usize, usize)> = b.layout().iter().map(|f| (f.name, f.offset, f.width)).collect();
    assert_eq!(
        layout,
        [
            ("chain_id", 0, 8),
            ("version", 8, 2),
            ("domain", 10, 32),
            ("statement", 42, 1),
            ("statement_version", 43, 1),
            ("purpose", 44, 1),
            ("policy_address", 45, 20),
            ("marker", 65, 32),
            ("action_nonce", 97, 8),
            ("action_tag", 105, 32),
            ("action_salt", 137, 32),
            ("expected_remaining", 169, 32),
            ("debit", 201, 32),
            ("expiry", 233, 8),
            ("calldata_hash", 241, 32),
        ]
    );
    assert_eq!(ACTION_LAYOUT, b.layout());

    let s = KnowAction {
        policy_address: [0x24; 20],
        marker: [0x25; 32],
        action_nonce: 0x0102_0304_0506_0708,
        action_tag: [0x26; 32],
        action_salt: [0x27; 32],
        expected_remaining: amount_word(600_000),
        debit: amount_word(21),
        expiry: 0x1112_1314_1516_1718,
        calldata_hash: [0x28; 32],
    };
    let p = params();
    let independent = tagged(
        "ghost/action-binding/v1",
        &[
            &p.chain_id,
            &[0x00, 0x01],
            &p.domain,
            &[0x05],
            &[0x01],
            &[0x06],
            &s.policy_address,
            &s.marker,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &s.action_tag,
            &s.action_salt,
            &s.expected_remaining,
            &s.debit,
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
            &s.calldata_hash,
        ],
    );
    assert_eq!(know_action_binding(&p, &s), independent);
    let public = know_action_public_values(&p, &s);
    assert_eq!(public.len(), 273 + 32);
    assert_eq!(&public[273..], &independent[..]);
    assert_eq!(public[42..45], [0x05, 0x01, 0x06]);
    assert_eq!(public[97..105], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(public[233..241], [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    assert_eq!(&public[0..8], &1234u64.to_be_bytes()[..]);
    // The preimage tag over the same fields is another digest.
    assert_ne!(independent, tagged("ghost/preimage-binding/v1", &[&public[..273]]));
}

/// Spec 10, section 9.2: 161 bytes of fields, 187 with the 26-byte tag, two
/// permutations; no `type`.
#[test]
fn the_preimage_binding_is_the_known_answer() {
    let b = Binding::Preimage;
    assert_eq!(tag_bytes(b.tag()).len(), 26);
    assert_eq!((b.fields_len(), b.input_len(), b.permutations()), (161, 187, 2));
    let layout: Vec<(&str, usize, usize)> = b.layout().iter().map(|f| (f.name, f.offset, f.width)).collect();
    assert_eq!(
        layout,
        [
            ("chain_id", 0, 8),
            ("version", 8, 2),
            ("domain", 10, 32),
            ("statement", 42, 1),
            ("statement_version", 43, 1),
            ("purpose", 44, 1),
            ("policy_address", 45, 20),
            ("y", 65, 32),
            ("context", 97, 64),
        ]
    );
    assert_eq!(PREIMAGE_LAYOUT, b.layout());

    let s = KnowPreimage {
        policy_address: [0x34; 20],
        y: [0x35; 32],
        context: [0x36; 64],
    };
    let p = params();
    let independent = tagged(
        "ghost/preimage-binding/v1",
        &[
            &p.chain_id,
            &[0x00, 0x01],
            &p.domain,
            &[0x06],
            &[0x01],
            &[0x07],
            &s.policy_address,
            &s.y,
            &s.context,
        ],
    );
    assert_eq!(know_preimage_binding(&p, &s), independent);
    let public = know_preimage_public_values(&p, &s);
    assert_eq!(public.len(), 161 + 32);
    assert_eq!(&public[161..], &independent[..]);
    assert_eq!(public[42..45], [0x06, 0x01, 0x07]);
    assert_ne!(independent, tagged("ghost/action-binding/v1", &[&public[..161]]));
}

/// The calldata hash takes a two-byte big-endian length, then the bytes;
/// 1,024 bytes are accepted and 1,025 refused.
#[test]
fn the_calldata_hash_is_the_known_answer() {
    assert_eq!(ACTION_CALLDATA_MAX, 1_024);
    let len = (CALLDATA.len() as u16).to_be_bytes();
    assert_eq!(
        action_calldata_hash(CALLDATA),
        Ok(tagged("ghost/action-calldata/v1", &[&len, CALLDATA]))
    );
    assert_eq!(action_calldata_hash(&[]), Ok(tagged("ghost/action-calldata/v1", &[&[0, 0]])));
    let full = vec![0xa7u8; 1_024];
    assert_eq!(action_calldata_hash(&full), Ok(tagged("ghost/action-calldata/v1", &[&[0x04, 0x00], &full])));
    // The length is part of the hash: trailing zeros are not padding.
    assert_ne!(action_calldata_hash(b"ab"), action_calldata_hash(b"ab\0"));
    assert_eq!(action_calldata_hash(&[0; 1_025]), Err(ProofError::CalldataTooLong));
    assert_eq!(action_calldata_hash(&vec![0; 70_000]), Err(ProofError::CalldataTooLong));
}

/// Spec 10, sections 8.2 and 9.2: four and three permutations padded to 128
/// rows, 3,722 columns; a bound of 947,283 bytes; `ACTION_PROOF_BYTES` that
/// bound rounded up to a multiple of 1,024; each statement under its own
/// gate entry, after the policy reveal, meeting the 128-bit rule.
#[test]
fn the_gate_holds_both_traces() {
    let action_perms = permutations(tag_bytes(TAG_POLICY_ACTION_V1).len() + 64) + Binding::Action.permutations();
    let preimage_perms =
        permutations(tag_bytes(TAG_POLICY_PREIMAGE_V1).len() + 32) + Binding::Preimage.permutations();
    assert_eq!((action_perms, preimage_perms), (4, 3));
    assert_eq!((action_perms * 24, preimage_perms * 24), (96, 72));
    assert_eq!((action_perms * 24).next_power_of_two(), 128);
    assert_eq!((preimage_perms * 24).next_power_of_two().max(128), 128);

    assert_eq!(proof_length_bound(128, 3722), BOUND);
    assert_eq!(ACTION_PROOF_BYTES, 948_224);
    assert_eq!(ACTION_PROOF_BYTES, BOUND.div_ceil(1024) * 1024);
    assert!(ACTION_PROOF_BYTES < PROOF_FIELD_BYTES);
    // The field is sized to the 128-row trace: twice the rows would not fit.
    assert!(proof_length_bound(256, 3722) > ACTION_PROOF_BYTES);

    assert_eq!(Statement::ALL.len(), 7);
    assert_eq!(Statement::ALL[4], Statement::PolicyReveal);
    assert_eq!(Statement::ALL[5], Statement::KnowAction);
    assert_eq!(Statement::ALL[6], Statement::KnowPreimage);
    let config = shipped_configuration().expect("the security gate takes every statement");
    let (_, s4) = config.statements[4];
    for (index, statement) in [(5, Statement::KnowAction), (6, Statement::KnowPreimage)] {
        let (reported, e) = config.statements[index];
        assert_eq!(reported, statement);
        assert_eq!((e.trace_height, e.trace_width), (128, 3722), "{statement:?}");
        assert_eq!(proof_length_bound(e.trace_height, e.trace_width), BOUND);
        assert_eq!(statement.proof_field_bytes(), ACTION_PROOF_BYTES);
        assert!(e.conjectured_bits_half_grinding >= TARGET_CONJECTURED_BITS, "{statement:?}: {e:?}");
        assert!(e.conjectured_bits >= e.conjectured_bits_half_grinding, "{statement:?}: {e:?}");
        assert_eq!(e.conjectured_quantum_bits, e.conjectured_bits / 2);
        assert!(e.proven_bits > 0 && e.proven_bits <= e.conjectured_bits, "{statement:?}: {e:?}");
        assert!(e.constraint_degree <= 1 << config.log_blowup, "{statement:?}: {e:?}");
        assert!(e.constraint_degree <= s4.constraint_degree, "{statement:?}: {e:?}");
    }
    for statement in [Statement::SaltedCoinReveal, Statement::CoinRevealV2, Statement::PolicyReveal] {
        assert_eq!(statement.proof_field_bytes(), PROOF_FIELD_BYTES);
    }
}

// ---------------------------------------------------------------------------
// The honest proofs.

/// Both honest proofs verify and are no longer than the bound or
/// `ACTION_PROOF_BYTES`, and neither holds its private value.
#[test]
fn the_honest_proofs_verify_and_fit() {
    let _one = one_at_a_time();
    for (name, proof, secret) in [("action", honest_action(), ACTION_ROOT), ("preimage", honest_preimage(), X)] {
        let len = proof.as_bytes().len();
        assert!(len <= BOUND, "a {name} proof of {len} bytes, over the bound {BOUND}");
        assert!(len <= ACTION_PROOF_BYTES, "a {name} proof of {len} bytes, over the field");
        assert!(!holds(proof.as_bytes(), &secret), "the {name} proof holds its private value");
    }
    let public = know_action_public_values(&params(), &slot_action());
    assert!(!holds(&public, &ACTION_ROOT));
    // The check itself finds a value that is there.
    assert!(holds(&public, &SLOT_SALT));
    assert!(!holds(&know_preimage_public_values(&params(), &preimage_statement()), &X));

    // A proof longer than the field is refused before it is decoded.
    let mut long = honest_action().as_bytes().to_vec();
    long.resize(ACTION_PROOF_BYTES + 1, 0);
    let long = Proof::from_bytes(long);
    assert_eq!(verify_know_action(&params(), &slot_action(), &long), Err(ProofError::MalformedProof));
    assert_eq!(verify_know_preimage(&params(), &preimage_statement(), &long), Err(ProofError::MalformedProof));
    // Bytes that do not decode are refused, not a panic.
    let short = Proof::from_bytes(honest_action().as_bytes()[..1000].to_vec());
    assert_eq!(verify_know_action(&params(), &slot_action(), &short), Err(ProofError::MalformedProof));

    // The honest provers refuse a private value that does not match.
    assert_eq!(
        prove_know_action(&params(), &slot_action(), &[0x70; 32], zk(3)).err(),
        Some(ProofError::NotThePreimage)
    );
    assert_eq!(
        prove_know_preimage(&params(), &preimage_statement(), &[0x80; 32], zk(3)).err(),
        Some(ProofError::NotThePreimage)
    );
}

// ---------------------------------------------------------------------------
// The properties.

/// RP-16: changing the nonce, `expected_remaining`, `debit`, `expiry`, the
/// calldata hash, the marker, the policy address or the chain makes the
/// action proof fail. No re-proving: each check is the same proof against a
/// changed copy of the public inputs.
#[test]
fn changing_any_action_input_fails() {
    let _one = one_at_a_time();
    let proof = honest_action();
    let s = slot_action();
    type Change = fn(&mut KnowAction);
    let changes: [(&str, Change); 10] = [
        ("action_nonce", |t| t.action_nonce += 1),
        ("action_nonce high byte", |t| t.action_nonce ^= 1 << 63),
        ("expected_remaining", |t| t.expected_remaining = amount_word(1_000_001)),
        ("debit", |t| t.debit = amount_word(25_001)),
        ("expiry", |t| t.expiry += 1),
        ("calldata_hash", |t| {
            t.calldata_hash = action_calldata_hash(b"other calldata for a policy action").unwrap()
        }),
        ("calldata_hash bit", |t| t.calldata_hash[31] ^= 1),
        ("marker", |t| t.marker[0] ^= 1),
        ("policy_address", |t| t.policy_address[19] ^= 1),
        ("policy_address first byte", |t| t.policy_address[0] ^= 0x80),
    ];
    for (name, change) in changes {
        let mut changed = s.clone();
        change(&mut changed);
        assert_ne!(changed, s, "{name}");
        assert_eq!(verify_know_action(&params(), &changed, proof), Err(ProofError::Rejected), "{name}");
    }
    // The debit moved into the remaining amount still breaks the binding.
    let mut moved = s.clone();
    moved.expected_remaining = amount_word(1_000_000 - 25_000);
    moved.debit = amount_word(0);
    assert_eq!(verify_know_action(&params(), &moved, proof), Err(ProofError::Rejected));

    let chain = [
        ChainParams {
            chain_id: 1235u64.to_be_bytes(),
            ..params()
        },
        ChainParams {
            domain: [0x48; 32],
            ..params()
        },
        ChainParams {
            version: PROTOCOL_VERSION_2,
            ..params()
        },
    ];
    for p in chain {
        assert_eq!(verify_know_action(&p, &s, proof), Err(ProofError::Rejected), "{p:?}");
    }
    // The honest proof still verifies.
    assert_eq!(verify_know_action(&params(), &s, proof), Ok(()));
}

/// RP-17: an action proof made against a salt or a tag other than the
/// slot's does not verify when the verifier is given the slot's tag and
/// salt, which it reads from the slot, never from the proof or the
/// transaction.
#[test]
fn a_proof_for_another_salt_or_tag_fails() {
    let _one = one_at_a_time();
    let slot = slot_action();

    // An honest proof for another salt, with the tag that salt gives.
    let other_salt = [0x73; 32];
    let for_salt = KnowAction {
        action_salt: other_salt,
        action_tag: policy_action_tag(&ACTION_ROOT, &other_salt),
        ..slot.clone()
    };
    assert_ne!(for_salt.action_tag, slot.action_tag);
    let proof = prove_know_action(&params(), &for_salt, &ACTION_ROOT, zk(4)).expect("honest proof for another salt");
    assert_eq!(verify_know_action(&params(), &for_salt, &proof), Ok(()));
    assert_eq!(verify_know_action(&params(), &slot, &proof), Err(ProofError::Rejected));
    // Nor with only one of the two swapped back.
    let salt_only = KnowAction {
        action_salt: other_salt,
        ..slot.clone()
    };
    assert_eq!(verify_know_action(&params(), &salt_only, &proof), Err(ProofError::Rejected));

    // An honest proof for another tag: another root under the slot's salt.
    let other_root = [0x74; 32];
    let for_tag = KnowAction {
        action_tag: policy_action_tag(&other_root, &SLOT_SALT),
        ..slot.clone()
    };
    assert_ne!(for_tag.action_tag, slot.action_tag);
    let proof = prove_know_action(&params(), &for_tag, &other_root, zk(5)).expect("honest proof for another tag");
    assert_eq!(verify_know_action(&params(), &for_tag, &proof), Ok(()));
    assert_eq!(verify_know_action(&params(), &slot, &proof), Err(ProofError::Rejected));

    // The honest prover refuses a root that is not the slot's; a lying
    // prover that claims the slot's tag and salt with it makes a proof that
    // does not verify.
    assert_eq!(prove_know_action(&params(), &slot, &other_root, zk(6)).err(), Some(ProofError::NotThePreimage));
    lying_proof_fails(
        || prove_know_action_claiming(&params(), &slot, &other_root, zk(6)),
        |proof| verify_know_action(&params(), &slot, proof),
    );
}

/// Changing any public input of the preimage statement, or the chain, makes
/// the preimage proof fail, and a lying prover with another `x` fails.
#[test]
fn changing_any_preimage_input_fails() {
    let _one = one_at_a_time();
    let proof = honest_preimage();
    let s = preimage_statement();
    type Change = fn(&mut KnowPreimage);
    let changes: [(&str, Change); 4] = [
        ("y", |t| t.y[0] ^= 1),
        ("context first byte", |t| t.context[0] ^= 1),
        ("context last byte", |t| t.context[63] ^= 1),
        ("policy_address", |t| t.policy_address[19] ^= 1),
    ];
    for (name, change) in changes {
        let mut changed = s.clone();
        change(&mut changed);
        assert_eq!(verify_know_preimage(&params(), &changed, proof), Err(ProofError::Rejected), "{name}");
    }
    let other_chain = ChainParams {
        chain_id: 1235u64.to_be_bytes(),
        ..params()
    };
    assert_eq!(verify_know_preimage(&other_chain, &s, proof), Err(ProofError::Rejected));
    assert_eq!(verify_know_preimage(&params(), &s, proof), Ok(()));

    lying_proof_fails(
        || prove_know_preimage_claiming(&params(), &s, &[0x80; 32], zk(7)),
        |proof| verify_know_preimage(&params(), &s, proof),
    );
}

/// Spec 10, section 9.1: a `KNOW_PREIMAGE_v1` proof never verifies as
/// `KNOW_ACTION_v1` and the other way round. Each proof, given to the other
/// statement's verifier with plausible public inputs, returns an error
/// without panicking.
#[test]
fn neither_statement_verifies_as_the_other() {
    let _one = one_at_a_time();
    let (action, preimage) = (honest_action(), honest_preimage());

    // The preimage proof against action inputs: the example slot, and a slot
    // whose tag is the preimage's `y` with the same policy.
    let preimage_s = preimage_statement();
    let plausible_actions = [
        slot_action(),
        KnowAction {
            action_tag: preimage_s.y,
            policy_address: preimage_s.policy_address,
            ..slot_action()
        },
    ];
    for s in &plausible_actions {
        let result = catch_unwind(AssertUnwindSafe(|| verify_know_action(&params(), s, preimage)));
        let result = result.expect("the action verifier does not panic on a preimage proof");
        assert!(result.is_err(), "a preimage proof verified as an action");
    }

    // The action proof against preimage inputs: the example statement, and
    // one whose `y` is the slot's tag and whose context is the slot's salt
    // and marker.
    let slot = slot_action();
    let mut context = [0u8; PREIMAGE_CONTEXT_BYTES];
    context[..32].copy_from_slice(&slot.action_salt);
    context[32..].copy_from_slice(&slot.marker);
    let plausible_preimages = [
        preimage_statement(),
        KnowPreimage {
            policy_address: slot.policy_address,
            y: slot.action_tag,
            context,
        },
    ];
    for s in &plausible_preimages {
        let result = catch_unwind(AssertUnwindSafe(|| verify_know_preimage(&params(), s, action)));
        let result = result.expect("the preimage verifier does not panic on an action proof");
        assert!(result.is_err(), "an action proof verified as a preimage");
    }

    // The digests differ even over the same field bytes.
    let action_public = know_action_public_values(&params(), &slot);
    let preimage_public = know_preimage_public_values(&params(), &preimage_s);
    assert_ne!(action_public[42..45], preimage_public[42..45]);
    assert_ne!(action_public.len(), preimage_public.len());
    // Each still verifies as itself.
    assert_eq!(verify_know_action(&params(), &slot, action), Ok(()));
    assert_eq!(verify_know_preimage(&params(), &preimage_s, preimage), Ok(()));
}
