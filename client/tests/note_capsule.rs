//! Note version 3 and its capsule (spec 10, section 3.2): every note is 380
//! bytes, an empty-rule coin carries the all-zero version 0 capsule, and a
//! wallet restores a policy coin from its capsule (RP-29). A note whose
//! capsule is malformed, of another version, or does not open the note's rule
//! is discarded, never repaired; so is a note whose rule does not open its
//! leaf.

use ghost_client::note::{
    chacha20poly1305_seal, note_associated_data, CAPSULE_PARAMS_BYTES, CAPSULE_VERSION_1, CAPSULE_VERSION_EMPTY,
    NOTE_PLAINTEXT_BYTES, NOTE_V2_PLAINTEXT_BYTES, NOTE_VERSION_3, TAG_POLICY_PARAMS,
};
use ghost_client::{
    decrypt_note, decrypt_note_with_capsule, encrypt_note, encrypt_note_v2, restore_coins, restore_coins_at, Amount,
    Capsule, Commitment, Current, DiscardReason, NoteContents, NoteError, PhantomKey, Rule, Salt, TreeLeaf,
    CAPSULE_BYTES, NOTE_BYTES, REVEAL_NOTE_BYTES, SALT_BYTES,
};
use ghost_proofs::{policy_override_hash, reveal_policy_rule, tagged, PolicyRule};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// The example words key of spec 01, section 5, as its digit view. Example
/// only.
const DIGITS: &str = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
const CHAIN_ID: u64 = 1234;
const ADDRESS: [u8; 20] = [0x11; 20];
const CODEHASH: [u8; 32] = [0x22; 32];
const PARAMS: &[u8] = b"limit 5 per day";

fn key() -> PhantomKey {
    PhantomKey::parse(DIGITS).unwrap_or_else(|_| panic!("the example key parses"))
}

fn amount(wei: u128) -> Amount {
    Amount::new(wei).unwrap()
}

/// A policy capsule with an override and actions.
fn policy() -> Capsule {
    Capsule::policy(ADDRESS, CODEHASH, PARAMS, policy_override_hash(&[0x33; 32]), [0x44; 32], [0x55; 32]).unwrap()
}

/// The same policy under another action salt: another rule.
fn other_policy() -> Capsule {
    Capsule::policy(ADDRESS, CODEHASH, PARAMS, policy_override_hash(&[0x33; 32]), [0x44; 32], [0x56; 32]).unwrap()
}

/// `plaintext` sealed under the key's note key for `leaf` as a 380-byte note,
/// so a plaintext no wallet writes can be offered to the reader.
fn sealed(leaf: &Commitment, plaintext: &[u8; NOTE_PLAINTEXT_BYTES]) -> [u8; NOTE_BYTES] {
    let mut note = [0u8; NOTE_BYTES];
    note[..12].copy_from_slice(&[9; 12]);
    note[12..NOTE_BYTES - 16].copy_from_slice(plaintext);
    let tag = chacha20poly1305_seal(
        key().note_key().as_bytes(),
        &[9; 12],
        &note_associated_data(CHAIN_ID, leaf),
        &mut note[12..NOTE_BYTES - 16],
    );
    note[NOTE_BYTES - 16..].copy_from_slice(&tag);
    note
}

/// The version 3 plaintext of `contents` with `capsule` bytes in place of
/// the capsule, whatever they hold.
fn plaintext_with(contents: &NoteContents, capsule: &[u8; CAPSULE_BYTES]) -> [u8; NOTE_PLAINTEXT_BYTES] {
    // Written under the empty rule and capsule, which `to_plaintext` accepts,
    // then given the contents' rule at offset 64 and the capsule bytes.
    let mut plaintext = NoteContents { rule: Rule::EMPTY, ..*contents }.to_plaintext(&Capsule::empty());
    plaintext[64..96].copy_from_slice(contents.rule.as_bytes());
    plaintext[NOTE_V2_PLAINTEXT_BYTES..].copy_from_slice(capsule);
    plaintext
}

/// A coin of the key's number `number` under `rule`, as its leaf.
fn coin_leaf(number: u64, wei: u128, rule: Rule, salt: Salt) -> Commitment {
    key().coin_commit_with_rule(number, amount(wei), rule, salt).commitment
}

/// Restores `leaves` and returns the one discard reason, asserting nothing
/// was found.
fn discarded(leaves: &[TreeLeaf]) -> DiscardReason {
    let restored = restore_coins(&key(), CHAIN_ID, 0, leaves, &[]).unwrap();
    assert!(restored.found.is_empty(), "nothing is found");
    assert!(matches!(restored.current, Current::None));
    assert_eq!(restored.discarded.len(), 1, "one note is discarded");
    restored.discarded[0].reason
}

#[test]
fn capsule_layout_and_rule() {
    assert_eq!(CAPSULE_BYTES, 224);
    assert_eq!(NOTE_PLAINTEXT_BYTES, 352);
    assert_eq!(NOTE_BYTES, 12 + 352 + 16);
    assert_eq!(NOTE_BYTES, ghost_proofs::NOTE_V3_BYTES);
    assert_eq!(REVEAL_NOTE_BYTES, ghost_proofs::NOTE_BYTES);
    assert_eq!(TAG_POLICY_PARAMS, "ghost/policy-params/v1");

    // Version 0: the empty rule, all 224 bytes zero.
    let empty = Capsule::empty();
    assert_eq!(empty.version(), CAPSULE_VERSION_EMPTY);
    assert!(empty.is_empty());
    assert_eq!(empty.to_bytes(), [0; CAPSULE_BYTES]);
    assert_eq!(empty.rule(), Rule::EMPTY);
    assert!(Capsule::from_bytes(&[0; CAPSULE_BYTES]).unwrap() == empty);

    // Version 1: version, address, code hash, override hash, action tag,
    // action salt, params length, params, zero pad.
    let capsule = policy();
    let bytes = capsule.to_bytes();
    assert_eq!(capsule.version(), CAPSULE_VERSION_1);
    assert!(!capsule.is_empty());
    assert_eq!(bytes[0], 0x01);
    assert_eq!(bytes[1..21], ADDRESS);
    assert_eq!(bytes[21..53], CODEHASH);
    assert_eq!(bytes[53..85], policy_override_hash(&[0x33; 32]));
    assert_eq!(bytes[85..117], [0x44; 32]);
    assert_eq!(bytes[117..149], [0x55; 32]);
    assert_eq!(usize::from(bytes[149]), PARAMS.len());
    assert_eq!(&bytes[150..150 + PARAMS.len()], PARAMS);
    assert!(bytes[150 + PARAMS.len()..].iter().all(|&byte| byte == 0));
    assert_eq!(150 + CAPSULE_PARAMS_BYTES + 10, CAPSULE_BYTES);
    assert!(Capsule::from_bytes(&bytes).unwrap() == capsule);
    assert_eq!(capsule.params(), PARAMS);
    assert_eq!(capsule.policy_address(), &ADDRESS);

    // The rule is K("ghost/reveal-policy/v2", ...) of spec 10, section 3.1,
    // as the proofs crate computes it, and never the empty rule.
    let params_hash = tagged("ghost/policy-params/v1", &[PARAMS]);
    assert_eq!(capsule.params_hash(), params_hash);
    let expected = reveal_policy_rule(
        &ADDRESS,
        &CODEHASH,
        &params_hash,
        &policy_override_hash(&[0x33; 32]),
        &[0x44; 32],
        &[0x55; 32],
    );
    assert_eq!(capsule.rule().as_bytes(), &expected);
    let fields = PolicyRule {
        policy_address: ADDRESS,
        policy_codehash: CODEHASH,
        params_hash,
        override_hash: policy_override_hash(&[0x33; 32]),
        action_tag: [0x44; 32],
        action_salt: [0x55; 32],
    };
    assert_eq!(capsule.rule().as_bytes(), &fields.rule());
    assert!(!capsule.rule().is_empty());
    assert_ne!(capsule.rule(), other_policy().rule());

    // A version 1 capsule with every field zero is still a real rule.
    let zero = Capsule::policy([0; 20], [0; 32], &[], [0; 32], [0; 32], [0; 32]).unwrap();
    assert!(!zero.rule().is_empty());
    assert_eq!(zero.to_bytes()[0], 0x01);

    // Up to 64 bytes of params; more is refused.
    let full = Capsule::policy(ADDRESS, CODEHASH, &[7; 64], [0; 32], [0; 32], [0; 32]).unwrap();
    assert!(Capsule::from_bytes(&full.to_bytes()).unwrap() == full);
    assert_eq!(
        Capsule::policy(ADDRESS, CODEHASH, &[7; 65], [0; 32], [0; 32], [0; 32]).err(),
        Some(NoteError::BadCapsule)
    );
}

#[test]
fn malformed_capsules_are_refused() {
    let good = policy().to_bytes();
    let refuse = |bytes: [u8; CAPSULE_BYTES], what: &str| {
        assert_eq!(Capsule::from_bytes(&bytes).err(), Some(NoteError::BadCapsule), "{what}");
    };
    // Another version.
    for version in [0x02, 0x03, 0x80, 0xff] {
        let mut bad = good;
        bad[0] = version;
        refuse(bad, "another version");
    }
    // A version 0 capsule with any byte not zero.
    for offset in [1, 20, 100, 149, 150, 223] {
        let mut bad = [0u8; CAPSULE_BYTES];
        bad[offset] = 1;
        refuse(bad, "a non-zero version 0 capsule");
    }
    // A params length above 64.
    for len in [65, 74, 255] {
        let mut bad = good;
        bad[149] = len;
        refuse(bad, "params longer than 64");
    }
    // A byte after the params, inside the params field or in the pad.
    for offset in [150 + PARAMS.len(), 213, 214, 223] {
        let mut bad = good;
        bad[offset] = 1;
        refuse(bad, "a non-zero byte after the params");
    }
    // A params length of 64 leaves only the pad, which must stay zero.
    let mut full = Capsule::policy(ADDRESS, CODEHASH, &[7; 64], [0; 32], [0; 32], [0; 32]).unwrap().to_bytes();
    assert!(Capsule::from_bytes(&full).is_ok());
    full[214] = 1;
    refuse(full, "a non-zero pad");
}

#[test]
fn empty_rule_coins_carry_the_zero_capsule_and_notes_are_one_length() {
    let mut rng = StdRng::seed_from_u64(0xca9);
    let key = key();
    let salt = Salt::from_bytes([0x61; SALT_BYTES]);

    // An empty-rule coin: version 3, its capsule all zero.
    let plain = NoteContents::salted_coin(0, amount(1_000), Rule::EMPTY, salt);
    let plain_leaf = coin_leaf(0, 1_000, Rule::EMPTY, salt);
    let plaintext = plain.to_plaintext(&Capsule::empty());
    assert_eq!(plaintext[0], NOTE_VERSION_3);
    assert_eq!(plaintext[NOTE_V2_PLAINTEXT_BYTES..], [0; CAPSULE_BYTES]);
    let plain_note = encrypt_note(&key.note_key(), CHAIN_ID, &plain_leaf, &plain, &Capsule::empty(), &mut rng);
    let (read, capsule) = decrypt_note_with_capsule(&key.note_key(), CHAIN_ID, &plain_leaf, &plain_note).unwrap();
    assert!(read == plain && capsule == Capsule::empty());

    // A policy coin: the same length, coin or data, empty rule or not.
    let ruled = NoteContents::salted_coin(0, amount(1_000), policy().rule(), salt);
    let ruled_leaf = coin_leaf(0, 1_000, policy().rule(), salt);
    let ruled_note = encrypt_note(&key.note_key(), CHAIN_ID, &ruled_leaf, &ruled, &policy(), &mut rng);
    assert_eq!(plain_note.len(), NOTE_BYTES);
    assert_eq!(ruled_note.len(), plain_note.len());
    let (read, capsule) = decrypt_note_with_capsule(&key.note_key(), CHAIN_ID, &ruled_leaf, &ruled_note).unwrap();
    assert!(read == ruled && capsule == policy());
    assert_eq!(decrypt_note(&key.note_key(), CHAIN_ID, &ruled_leaf, &ruled_note).unwrap().rule, policy().rule());

    // The reveal's remainder note alone keeps the 156-byte slot.
    let short = encrypt_note_v2(&key.note_key(), CHAIN_ID, &plain_leaf, &plain, &mut rng);
    assert_eq!(short.len(), REVEAL_NOTE_BYTES);
    assert_eq!(REVEAL_NOTE_BYTES, 156);
}

#[test]
#[should_panic(expected = "the capsule does not open the note's rule")]
fn a_capsule_of_another_rule_is_never_written() {
    let mut rng = StdRng::seed_from_u64(1);
    let salt = Salt::from_bytes([1; SALT_BYTES]);
    let contents = NoteContents::salted_coin(0, amount(1), policy().rule(), salt);
    let leaf = coin_leaf(0, 1, policy().rule(), salt);
    let _ = encrypt_note(&key().note_key(), CHAIN_ID, &leaf, &contents, &other_policy(), &mut rng);
}

#[test]
#[should_panic(expected = "the capsule does not open the note's rule")]
fn an_empty_capsule_is_never_written_for_a_policy_rule() {
    let salt = Salt::from_bytes([1; SALT_BYTES]);
    let contents = NoteContents::salted_coin(0, amount(1), policy().rule(), salt);
    let _ = contents.to_plaintext(&Capsule::empty());
}

#[test]
fn a_wallet_restores_a_policy_coin_from_its_capsule() {
    // RP-29: the rule recomputed from the capsule opens the leaf.
    let mut rng = StdRng::seed_from_u64(0x29);
    let key = key();
    let other = PhantomKey::generate(ghost_client::KeyFormat::Words, &mut rng);
    let salt = Salt::from_bytes([0x29; SALT_BYTES]);
    let rule = policy().rule();
    let commit = key.coin_commit_with_rule(0, amount(5_000), rule, salt);
    let contents = NoteContents::salted_coin(0, amount(5_000), rule, salt);
    let note = encrypt_note(&key.note_key(), CHAIN_ID, &commit.commitment, &contents, &policy(), &mut rng);

    // Beside an empty-rule coin of another key.
    let other_salt = Salt::from_bytes([0x30; SALT_BYTES]);
    let other_commit = other.coin_commit_with_salt(0, amount(7_000), Rule::EMPTY, other_salt).unwrap();
    let other_note = encrypt_note(
        &other.note_key(),
        CHAIN_ID,
        &other_commit.commitment,
        &NoteContents::salted_coin(0, amount(7_000), Rule::EMPTY, other_salt),
        &Capsule::empty(),
        &mut rng,
    );
    let leaves = vec![
        TreeLeaf { commitment: other_commit.commitment, note: other_note, salt: Some(other_salt) },
        TreeLeaf { commitment: commit.commitment, note, salt: Some(salt) },
    ];

    let restored = restore_coins(&key, CHAIN_ID, 0, &leaves, &[]).unwrap();
    assert!(restored.discarded.is_empty());
    let Current::One(found) = restored.current else {
        panic!("the policy coin restores");
    };
    assert_eq!((found.number, found.amount.wei(), found.position), (0, 5_000, 1));
    assert_eq!(found.rule, rule);
    assert_eq!(found.capsule.rule(), found.rule);
    assert!(found.capsule == policy());
    assert_eq!(found.capsule.params(), PARAMS);
    assert_eq!(found.commitment, commit.commitment);
    assert_eq!(found.marker, commit.marker);

    // Restore by positions finds it the same way; spent, it is not current.
    let pairs: Vec<(u32, TreeLeaf)> = vec![(900, leaves[1].clone())];
    let at = restore_coins_at(&key, CHAIN_ID, 2, &pairs, &[commit.marker]).unwrap();
    assert_eq!(at.found.len(), 1);
    assert_eq!((at.found[0].position, at.found[0].tree_index), (900, 2));
    assert!(at.found[0].capsule == policy());
    assert!(matches!(at.current, Current::None));

    // The other key finds its empty-rule coin with the empty capsule.
    let theirs = restore_coins(&other, CHAIN_ID, 0, &leaves, &[]).unwrap();
    assert_eq!(theirs.found.len(), 1);
    assert!(theirs.found[0].capsule == Capsule::empty());
    assert_eq!(theirs.found[0].rule, Rule::EMPTY);
}

#[test]
fn a_capsule_that_does_not_open_the_rule_is_discarded() {
    let salt = Salt::from_bytes([0x31; SALT_BYTES]);
    let rule = policy().rule();
    let leaf = coin_leaf(0, 5_000, rule, salt);
    let contents = NoteContents::salted_coin(0, amount(5_000), rule, salt);
    let at = |capsule: [u8; CAPSULE_BYTES]| vec![TreeLeaf { commitment: leaf, note: sealed(&leaf, &plaintext_with(&contents, &capsule)), salt: Some(salt) }];

    // The honest note restores.
    let honest = restore_coins(&key(), CHAIN_ID, 0, &at(policy().to_bytes()), &[]).unwrap();
    assert_eq!(honest.found.len(), 1);
    assert!(honest.discarded.is_empty());

    // The rule at offset 64 opens the leaf, but the capsule is of another
    // rule, or is the empty capsule: discarded, not repaired.
    for wrong in [other_policy(), Capsule::empty()] {
        let leaves = at(wrong.to_bytes());
        assert_eq!(
            decrypt_note(&key().note_key(), CHAIN_ID, &leaf, &leaves[0].note).err(),
            Some(NoteError::BadCapsule)
        );
        assert_eq!(discarded(&leaves), DiscardReason::Malformed(NoteError::BadCapsule));
    }

    // Each field of the capsule matters: one bit flipped in any of them
    // gives another rule.
    for offset in [1, 21, 53, 85, 117, 150] {
        let mut bad = policy().to_bytes();
        bad[offset] ^= 0x01;
        assert!(Capsule::from_bytes(&bad).is_ok(), "byte {offset} still parses");
        assert_eq!(discarded(&at(bad)), DiscardReason::Malformed(NoteError::BadCapsule), "byte {offset}");
    }
    // A shorter params length is another rule too.
    let mut shorter = policy().to_bytes();
    shorter[149] -= 1;
    shorter[150 + PARAMS.len() - 1] = 0;
    assert_eq!(discarded(&at(shorter)), DiscardReason::Malformed(NoteError::BadCapsule));
}

#[test]
fn a_capsule_of_another_version_length_or_padding_is_discarded() {
    let salt = Salt::from_bytes([0x32; SALT_BYTES]);
    let rule = policy().rule();
    let leaf = coin_leaf(0, 5_000, rule, salt);
    let contents = NoteContents::salted_coin(0, amount(5_000), rule, salt);
    let at = |capsule: [u8; CAPSULE_BYTES]| vec![TreeLeaf { commitment: leaf, note: sealed(&leaf, &plaintext_with(&contents, &capsule)), salt: None }];
    let good = policy().to_bytes();

    let mut cases = Vec::new();
    for version in [0x00, 0x02, 0xff] {
        let mut bad = good;
        bad[0] = version;
        cases.push((bad, "version"));
    }
    for len in [65, 200] {
        let mut bad = good;
        bad[149] = len;
        cases.push((bad, "params length"));
    }
    for offset in [150 + PARAMS.len(), 213, 214, 223] {
        let mut bad = good;
        bad[offset] = 0x01;
        cases.push((bad, "padding"));
    }
    for (bad, what) in cases {
        let leaves = at(bad);
        assert_eq!(
            decrypt_note(&key().note_key(), CHAIN_ID, &leaf, &leaves[0].note).err(),
            Some(NoteError::BadCapsule),
            "{what}"
        );
        assert_eq!(discarded(&leaves), DiscardReason::Malformed(NoteError::BadCapsule), "{what}");
    }

    // An empty-rule coin whose capsule is not all zero is discarded too.
    let plain_leaf = coin_leaf(0, 5_000, Rule::EMPTY, salt);
    let plain = NoteContents::salted_coin(0, amount(5_000), Rule::EMPTY, salt);
    for capsule in [policy().to_bytes(), { let mut b = [0u8; CAPSULE_BYTES]; b[223] = 1; b }] {
        let note = sealed(&plain_leaf, &plaintext_with(&plain, &capsule));
        let leaves = vec![TreeLeaf { commitment: plain_leaf, note, salt: Some(salt) }];
        assert_eq!(discarded(&leaves), DiscardReason::Malformed(NoteError::BadCapsule));
    }
    let note = sealed(&plain_leaf, &plaintext_with(&plain, &[0; CAPSULE_BYTES]));
    let restored = restore_coins(&key(), CHAIN_ID, 0, &[TreeLeaf { commitment: plain_leaf, note, salt: Some(salt) }], &[]).unwrap();
    assert_eq!(restored.found.len(), 1);
}

#[test]
fn a_note_of_another_version_or_a_rule_off_the_leaf_is_discarded() {
    let salt = Salt::from_bytes([0x33; SALT_BYTES]);
    let rule = policy().rule();
    let leaf = coin_leaf(0, 5_000, rule, salt);
    let contents = NoteContents::salted_coin(0, amount(5_000), rule, salt);
    let good = plaintext_with(&contents, &policy().to_bytes());

    // Byte 0 is the note version: only 3 is read.
    for version in [0x01, 0x02, 0x04] {
        let mut bad = good;
        bad[0] = version;
        let leaves = vec![TreeLeaf { commitment: leaf, note: sealed(&leaf, &bad), salt: None }];
        assert_eq!(discarded(&leaves), DiscardReason::Malformed(NoteError::UnknownVersion), "version {version}");
    }

    // A well-formed capsule of another rule, with that rule at offset 64,
    // reads, but the rule does not open the leaf: a leaf mismatch.
    let off_leaf = NoteContents::salted_coin(0, amount(5_000), other_policy().rule(), salt);
    let note = sealed(&leaf, &plaintext_with(&off_leaf, &other_policy().to_bytes()));
    assert!(decrypt_note(&key().note_key(), CHAIN_ID, &leaf, &note).is_ok());
    let leaves = vec![TreeLeaf { commitment: leaf, note, salt: Some(salt) }];
    assert_eq!(discarded(&leaves), DiscardReason::LeafMismatch);

    // The empty rule and the empty capsule for a policy leaf: a mismatch
    // with the leaf.
    let empty = NoteContents::salted_coin(0, amount(5_000), Rule::EMPTY, salt);
    let note = sealed(&leaf, &plaintext_with(&empty, &[0; CAPSULE_BYTES]));
    assert_eq!(discarded(&[TreeLeaf { commitment: leaf, note, salt: None }]), DiscardReason::LeafMismatch);
}

#[test]
fn only_a_zero_padded_reveal_note_is_read_as_version_2() {
    let mut rng = StdRng::seed_from_u64(0x156);
    let key = key();
    let salt = Salt::from_bytes([0x34; SALT_BYTES]);
    let commit = key.coin_commit_with_salt(1, amount(800), Rule::EMPTY, salt).unwrap();
    let contents = NoteContents::salted_coin(1, amount(800), Rule::EMPTY, salt);
    let short = encrypt_note_v2(&key.note_key(), CHAIN_ID, &commit.commitment, &contents, &mut rng);

    // Zero-padded, as the node stores a reveal's remainder note: it restores.
    let mut note = [0u8; NOTE_BYTES];
    note[..REVEAL_NOTE_BYTES].copy_from_slice(&short);
    let leaf = TreeLeaf { commitment: commit.commitment, note, salt: None };
    let restored = restore_coins(&key, CHAIN_ID, 0, std::slice::from_ref(&leaf), &[]).unwrap();
    assert_eq!(restored.found.len(), 1);
    assert!(restored.found[0].capsule == Capsule::empty());
    // It is not a note version 3.
    assert_eq!(decrypt_note(&key.note_key(), CHAIN_ID, &commit.commitment, &note).err(), Some(NoteError::Unauthentic));

    // With any byte of the padding set, it is not read at all.
    for offset in [REVEAL_NOTE_BYTES, 200, NOTE_BYTES - 1] {
        let mut dirty = leaf.clone();
        dirty.note[offset] = 1;
        let restored = restore_coins(&key, CHAIN_ID, 0, &[dirty], &[]).unwrap();
        assert!(restored.found.is_empty() && restored.discarded.is_empty(), "byte {offset}");
    }

    // A note version 3 plaintext written into the 156-byte slot is the
    // wrong version for it: discarded.
    let mut v3_fields = [0u8; NOTE_V2_PLAINTEXT_BYTES];
    v3_fields.copy_from_slice(&contents.to_plaintext(&Capsule::empty())[..NOTE_V2_PLAINTEXT_BYTES]);
    let mut short_v3 = [0u8; REVEAL_NOTE_BYTES];
    short_v3[..12].copy_from_slice(&[4; 12]);
    short_v3[12..REVEAL_NOTE_BYTES - 16].copy_from_slice(&v3_fields);
    let tag = chacha20poly1305_seal(
        key.note_key().as_bytes(),
        &[4; 12],
        &note_associated_data(CHAIN_ID, &commit.commitment),
        &mut short_v3[12..REVEAL_NOTE_BYTES - 16],
    );
    short_v3[REVEAL_NOTE_BYTES - 16..].copy_from_slice(&tag);
    let mut note = [0u8; NOTE_BYTES];
    note[..REVEAL_NOTE_BYTES].copy_from_slice(&short_v3);
    let leaves = vec![TreeLeaf { commitment: commit.commitment, note, salt: None }];
    assert_eq!(discarded(&leaves), DiscardReason::Malformed(NoteError::UnknownVersion));
}
