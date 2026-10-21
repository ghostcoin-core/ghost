//! Salted (version 2) commits: the fingerprint, commitment and marker under a
//! salt, checked against the vectors of spec 01, section 14 and the proofs
//! crate's own hashes; a fresh salt from the caller's generator for every new
//! commit; and the 206-byte data of a salted commit.

use ghost_client::{
    salted_commit_data, Amount, Content, Fingerprint, NoteContents, PhantomKey, Rule, Salt,
    CommitError, COIN, COIN_V2, DATA, DATA_V2, NOTE_BYTES, SALTED_COMMIT_DATA_BYTES,
    SALTED_COMMIT_FORMAT_VERSION, SALT_BYTES,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const SPEC: &str = include_str!("../../docs/spec/01-commitments-and-keys.md");

/// One `field = value` line of a `[name]` block of spec 01, section 14.
fn spec_field(block: &str, field: &str) -> String {
    let (_, rest) = SPEC.split_once(&format!("[{block}]\n")).expect("the block exists");
    rest.lines()
        .take_while(|line| !line.is_empty() && !line.starts_with("```"))
        .find_map(|line| line.strip_prefix(&format!("{field} = ")))
        .unwrap_or_else(|| panic!("{block} has {field}"))
        .to_owned()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex32(block: &str, field: &str) -> [u8; 32] {
    hex(&spec_field(block, field)).try_into().unwrap()
}

fn vector_key(block: &str) -> PhantomKey {
    PhantomKey::parse(&spec_field(block, "key")).unwrap_or_else(|_| panic!("the example key parses"))
}

fn vector_salt(block: &str) -> Salt {
    Salt::from_bytes(hex(&spec_field(block, "salt")).try_into().unwrap())
}

fn amount(wei: u128) -> Amount {
    Amount::new(wei).unwrap()
}

#[test]
fn two_salts_give_unrelated_commitments_and_markers() {
    // Coins: the commit and the remainder, each under two salts.
    for (block, other) in [
        ("coin-commit-salted", "coin-commit-salted-other"),
        ("coin-remainder-salted", "coin-remainder-salted-other"),
    ] {
        let key = vector_key(block);
        let index: u64 = spec_field(block, "index").parse().unwrap();
        let value = amount(spec_field(block, "amount").parse().unwrap());
        let mut commits = Vec::new();
        for name in [block, other] {
            assert_eq!(hex(&spec_field(name, "type-tag")), COIN_V2.to_vec());
            let salt = vector_salt(name);
            let commit = key.coin_commit_with_salt(index, value, Rule::EMPTY, salt).unwrap();
            assert_eq!(commit.fingerprint.as_bytes(), &hex32(name, "fingerprint"), "{name}");
            assert_eq!(commit.commitment.as_bytes(), &hex32(name, "commitment"), "{name}");
            assert_eq!(commit.marker.as_bytes(), &hex32(name, "marker"), "{name}");
            assert_eq!(commit.salt, Some(salt));
            assert_eq!(commit.type_tag(), COIN_V2);

            // The proofs crate's own version 2 hashes agree.
            let bytes = key.key_bytes();
            let b = *bytes.blinding(index).as_bytes();
            let f = ghost_proofs::coin_fingerprint_v2(
                bytes.secret().as_bytes(),
                bytes.reveal_secret().as_bytes(),
                &b,
                salt.as_bytes(),
                Rule::EMPTY.as_bytes(),
            );
            assert_eq!(&f, commit.fingerprint.as_bytes());
            assert_eq!(&ghost_proofs::coin_commitment_v2(&f, &value.to_bytes()), commit.commitment.as_bytes());
            assert_eq!(
                &ghost_proofs::coin_marker_v2(bytes.reveal_secret().as_bytes(), &b, salt.as_bytes()),
                commit.marker.as_bytes()
            );
            commits.push(commit);
        }
        let (a, b) = (commits[0], commits[1]);
        assert_ne!(a.fingerprint, b.fingerprint);
        assert_ne!(a.commitment, b.commitment);
        assert_ne!(a.marker, b.marker);

        // Neither is the version 1 commitment of the same key and number.
        let v1 = key.coin_commit(index, value, Rule::EMPTY).unwrap();
        assert_eq!(v1.salt, None);
        assert_eq!(v1.type_tag(), COIN);
        for salted in [a, b] {
            assert_ne!(salted.fingerprint, v1.fingerprint);
            assert_ne!(salted.commitment, v1.commitment);
            assert_ne!(salted.marker, v1.marker);
        }
    }

    // Data, under two salts.
    let (block, other) = ("data-commit-salted", "data-commit-salted-other");
    let key = vector_key(block);
    let content = Content::new(spec_field(block, "content-ascii").into_bytes());
    let mut commits = Vec::new();
    for name in [block, other] {
        assert_eq!(hex(&spec_field(name, "type-tag")), DATA_V2.to_vec());
        let salt = vector_salt(name);
        let commit = key.data_commit_with_salt(&content, Rule::EMPTY, salt).unwrap();
        assert_eq!(commit.content_fingerprint.as_bytes(), &hex32(name, "content-fingerprint"));
        assert_eq!(commit.fingerprint.as_bytes(), &hex32(name, "fingerprint"), "{name}");
        assert_eq!(commit.commitment.as_bytes(), &hex32(name, "commitment"), "{name}");
        assert_eq!(commit.marker.as_bytes(), &hex32(name, "marker"), "{name}");
        assert_eq!(commit.salt, Some(salt));
        assert_eq!(commit.type_tag(), DATA_V2);
        commits.push(commit);
    }
    let (a, b) = (commits[0], commits[1]);
    assert_ne!(a.fingerprint, b.fingerprint);
    assert_ne!(a.commitment, b.commitment);
    assert_ne!(a.marker, b.marker);
    let v1 = key.data_commit(&content, Rule::EMPTY).unwrap();
    assert_eq!(v1.salt, None);
    assert_eq!(v1.type_tag(), DATA);
    for salted in [a, b] {
        assert_ne!(salted.fingerprint, v1.fingerprint);
        assert_ne!(salted.commitment, v1.commitment);
        assert_ne!(salted.marker, v1.marker);
    }
}

#[test]
fn new_commit_draws_a_fresh_salt_each_time() {
    let key = vector_key("coin-commit-salted");
    let value = amount(1_000_000_000);

    // The salt is the next 16 bytes of the caller's generator.
    let mut rng = StdRng::seed_from_u64(0x5a17);
    let mut expected = StdRng::seed_from_u64(0x5a17);
    let first = key.salted_coin_commit(0, value, Rule::EMPTY, &mut rng).unwrap();
    let mut drawn = [0u8; SALT_BYTES];
    expected.fill_bytes(&mut drawn);
    assert_eq!(first.salt, Some(Salt::from_bytes(drawn)));
    assert_eq!(first.type_tag(), COIN_V2);

    // The same key, number and amount again: a new salt, so a new leaf and
    // a new marker.
    let second = key.salted_coin_commit(0, value, Rule::EMPTY, &mut rng).unwrap();
    expected.fill_bytes(&mut drawn);
    assert_eq!(second.salt, Some(Salt::from_bytes(drawn)));
    assert_ne!(first.salt, second.salt);
    assert_ne!(first.fingerprint, second.fingerprint);
    assert_ne!(first.commitment, second.commitment);
    assert_ne!(first.marker, second.marker);

    // Each is the version 2 commitment under the salt it returns.
    for commit in [first, second] {
        let again = key.coin_commit_with_salt(0, value, Rule::EMPTY, commit.salt.unwrap()).unwrap();
        assert_eq!(again, commit);
    }

    // The salt comes from the generator, not the key: another key under the
    // same generator state draws the same salt.
    let other = vector_key("data-commit-salted");
    let a = key.salted_coin_commit(3, value, Rule::EMPTY, &mut StdRng::seed_from_u64(77)).unwrap();
    let b = other.salted_coin_commit(3, value, Rule::EMPTY, &mut StdRng::seed_from_u64(77)).unwrap();
    assert_eq!(a.salt, b.salt);
    assert_ne!(a.commitment, b.commitment);

    // Data commitments too.
    let content = Content::new(b"Ghost example data".to_vec());
    let d1 = key.salted_data_commit(&content, Rule::EMPTY, &mut rng).unwrap();
    let d2 = key.salted_data_commit(&content, Rule::EMPTY, &mut rng).unwrap();
    assert!(d1.salt.is_some() && d2.salt.is_some());
    assert_ne!(d1.salt, d2.salt);
    assert_ne!(d1.commitment, d2.commitment);
    assert_ne!(d1.marker, d2.marker);
    assert!(d1.content_fingerprint == d2.content_fingerprint);
    let again = key.data_commit_with_salt(&content, Rule::EMPTY, d1.salt.unwrap()).unwrap();
    assert!(again == d1);

    // Version 2 still accepts only the empty rule.
    let ruled = Rule::from_bytes([1; 32]);
    assert_eq!(key.salted_coin_commit(0, value, ruled, &mut rng).err(), Some(CommitError::RuleNotSupported));
    assert_eq!(
        key.coin_commit_with_salt(0, value, ruled, Salt::from_bytes([1; SALT_BYTES])).err(),
        Some(CommitError::RuleNotSupported)
    );
    assert!(key.salted_data_commit(&content, ruled, &mut rng).is_err());
}

#[test]
fn salted_commit_data_is_206_bytes() {
    assert_eq!(SALTED_COMMIT_DATA_BYTES, 206);
    assert_eq!(SALTED_COMMIT_FORMAT_VERSION, [0x00, 0x02]);

    let key = vector_key("coin-commit-salted");
    let mut rng = StdRng::seed_from_u64(206);
    let value = amount(1_000_000_000);
    let commit = key.salted_coin_commit(0, value, Rule::EMPTY, &mut rng).unwrap();
    let salt = commit.salt.unwrap();
    // The note of a new commit is note version 2 carrying the same salt.
    let contents = NoteContents::salted_coin(0, value, Rule::EMPTY, salt);
    let note = ghost_client::encrypt_note(&key.note_key(), 1234, &commit.commitment, &contents, &mut rng);

    let data = salted_commit_data(&commit.fingerprint, &salt, &note);
    assert_eq!(data.len(), 206);
    assert_eq!(&data[..2], &[0x00, 0x02]);
    assert_eq!(&data[2..34], commit.fingerprint.as_bytes());
    assert_eq!(&data[34..50], salt.as_bytes());
    assert_eq!(&data[50..], &note[..]);
    assert_eq!(50 + NOTE_BYTES, 206);

    let read = ghost_client::decrypt_note(&key.note_key(), 1234, &commit.commitment, &note).unwrap();
    assert_eq!(read.salt, Some(salt));
    assert_eq!(read.type_tag, COIN_V2);

    // A data commit has the same layout.
    let content = Content::new(b"Ghost example data".to_vec());
    let data_commit = key.salted_data_commit(&content, Rule::EMPTY, &mut rng).unwrap();
    let data_salt = data_commit.salt.unwrap();
    let data_note = [0x5a; NOTE_BYTES];
    let data = salted_commit_data(&data_commit.fingerprint, &data_salt, &data_note);
    assert_eq!(&data[..2], &SALTED_COMMIT_FORMAT_VERSION);
    assert_eq!(&data[2..34], data_commit.fingerprint.as_bytes());
    assert_eq!(&data[34..50], data_salt.as_bytes());
    assert_eq!(&data[50..], &data_note[..]);

    // Every field lands in its place: change one input, only its bytes move.
    let other_f = Fingerprint::from_bytes([0xff; 32]);
    let changed = salted_commit_data(&other_f, &data_salt, &data_note);
    assert_eq!(&changed[..2], &data[..2]);
    assert_eq!(&changed[2..34], &[0xff; 32]);
    assert_eq!(&changed[34..], &data[34..]);
}
