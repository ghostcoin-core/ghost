//! Note version 2, which carries the salt of a version 2 commitment (spec 01,
//! section 9): it round-trips and returns its salt, its plaintext matches the
//! salted note vectors of section 14, and a version 1 note, a type tag other
//! than the version 2 ones and non-zero padding are refused.

use ghost_client::note::{
    chacha20poly1305_seal, note_associated_data, NOTE_PLAINTEXT_BYTES, NOTE_VERSION_2,
};
use ghost_client::{
    decrypt_note, encrypt_note, Amount, Commitment, ContentFingerprint, NoteContents, NoteError,
    PhantomKey, Rule, Salt, COIN_V2, DATA_V2, NOTE_BYTES, V_MAX,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

const SPEC: &str = include_str!("../../docs/spec/01-commitments-and-keys.md");

/// The example words key of spec 01, section 5, as its digit view. Example
/// only. The note vectors of section 14 hold no key; their leaves are used
/// only as bytes of the associated data.
const DIGITS: &str = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
/// The example chain identifier of spec 01, section 14.
const CHAIN_ID: u64 = 1234;

fn key() -> PhantomKey {
    PhantomKey::parse(DIGITS).unwrap_or_else(|_| panic!("the example key parses"))
}

fn amount(wei: u128) -> Amount {
    Amount::new(wei).unwrap()
}

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

fn spec_salt(block: &str) -> Salt {
    Salt::from_bytes(hex(&spec_field(block, "salt")).try_into().unwrap())
}

fn spec_leaf(block: &str) -> Commitment {
    Commitment::from_bytes(hex(&spec_field(block, "leaf")).try_into().unwrap())
}

/// A note sealed under the example key for `leaf` with any plaintext, so that
/// a plaintext the codec would never write can be offered to the reader.
fn sealed(leaf: &Commitment, plaintext: [u8; NOTE_PLAINTEXT_BYTES]) -> [u8; NOTE_BYTES] {
    let mut note = [0u8; NOTE_BYTES];
    note[..12].copy_from_slice(&[5; 12]);
    note[12..140].copy_from_slice(&plaintext);
    let tag = chacha20poly1305_seal(
        key().note_key().as_bytes(),
        &[5; 12],
        &note_associated_data(CHAIN_ID, leaf),
        &mut note[12..140],
    );
    note[140..].copy_from_slice(&tag);
    note
}

fn read(leaf: &Commitment, plaintext: [u8; NOTE_PLAINTEXT_BYTES]) -> Result<NoteContents, NoteError> {
    decrypt_note(&key().note_key(), CHAIN_ID, leaf, &sealed(leaf, plaintext))
}

#[test]
fn salted_note_round_trips_and_returns_its_salt() {
    let mut rng = StdRng::seed_from_u64(11);
    let key = key();
    let leaf = spec_leaf("note-coin-remainder-salted");
    let salt = spec_salt("note-coin-remainder-salted");
    let contents = NoteContents::salted_coin(1, amount(700_000_000_000_000_000), Rule::EMPTY, salt);
    assert_eq!(contents.type_tag, COIN_V2);
    assert_eq!(contents.version(), NOTE_VERSION_2);

    let note = encrypt_note(&key.note_key(), CHAIN_ID, &leaf, &contents, &mut rng);
    assert_eq!(note.len(), 156);
    let read = decrypt_note(&key.note_key(), CHAIN_ID, &leaf, &note).unwrap();
    assert!(read == contents);
    assert_eq!(read.salt, salt);
    assert_eq!(read.type_tag, COIN_V2);
    assert_eq!(read.number, 1);
    assert_eq!(read.amount, amount(700_000_000_000_000_000));

    // Another salt gives another note, and reads back as that salt.
    let other = Salt::from_bytes([0xa5; 16]);
    let note = encrypt_note(
        &key.note_key(),
        CHAIN_ID,
        &leaf,
        &NoteContents { salt: other, ..contents },
        &mut rng,
    );
    assert_eq!(decrypt_note(&key.note_key(), CHAIN_ID, &leaf, &note).unwrap().salt, other);

    // The largest amount fits the 12-byte amount of version 2.
    let top = NoteContents::salted_coin(9, amount(V_MAX), Rule::EMPTY, salt);
    let plaintext = top.to_plaintext();
    assert_eq!(plaintext[12..24], [0xff; 12]);
    assert!(NoteContents::from_plaintext(&plaintext).unwrap() == top);
}

#[test]
fn salted_note_plaintext_matches_spec_vectors() {
    // [note-coin-remainder-salted]: a salted coin remainder.
    let coin = NoteContents::salted_coin(
        1,
        amount(700_000_000_000_000_000),
        Rule::EMPTY,
        spec_salt("note-coin-remainder-salted"),
    );
    let plaintext = coin.to_plaintext();
    assert_eq!(plaintext.to_vec(), hex(&spec_field("note-coin-remainder-salted", "plaintext")));
    assert_eq!(plaintext[0], 0x02);
    assert_eq!(plaintext[96..112], spec_salt("note-coin-remainder-salted").as_bytes()[..]);
    assert_eq!(
        note_associated_data(CHAIN_ID, &spec_leaf("note-coin-remainder-salted")).to_vec(),
        hex(&spec_field("note-coin-remainder-salted", "associated-data"))
    );
    assert!(NoteContents::from_plaintext(&plaintext).unwrap() == coin);

    // [note-data-commit-salted]: a salted data commit.
    let data = NoteContents {
        type_tag: DATA_V2,
        number: 0,
        amount: amount(0),
        content_fingerprint: ContentFingerprint::from_bytes(
            hex(&spec_field("note-data-commit-salted", "content-fingerprint")).try_into().unwrap(),
        ),
        content_length: 18,
        rule: Rule::EMPTY,
        salt: spec_salt("note-data-commit-salted"),
    };
    let plaintext = data.to_plaintext();
    assert_eq!(plaintext.to_vec(), hex(&spec_field("note-data-commit-salted", "plaintext")));
    assert_eq!(
        note_associated_data(CHAIN_ID, &spec_leaf("note-data-commit-salted")).to_vec(),
        hex(&spec_field("note-data-commit-salted", "associated-data"))
    );
    let read = NoteContents::from_plaintext(&plaintext).unwrap();
    assert!(read == data);
    assert_eq!(read.salt, spec_salt("note-data-commit-salted"));
    assert_eq!(read.content_length, 18);
}

/// The type tags of the unsalted version 1 format, coin and data.
const COIN_V1: [u8; 2] = [0x01, 0x01];
const DATA_V1: [u8; 2] = [0x01, 0x02];

/// A version 1 plaintext laid out as version 1 wrote it: `0x01 || 0x01 ||
/// type || i (8) || v (32) || cf (32) || content length (8) || rule (32) ||
/// 12 zero bytes`, for a coin of number 1 and 700000000000000000 wei.
fn version_1_plaintext(type_tag: [u8; 2]) -> [u8; NOTE_PLAINTEXT_BYTES] {
    let mut plaintext = [0u8; NOTE_PLAINTEXT_BYTES];
    plaintext[0] = 0x01;
    plaintext[1] = 0x01;
    plaintext[2..4].copy_from_slice(&type_tag);
    plaintext[4..12].copy_from_slice(&1u64.to_be_bytes());
    plaintext[28..44].copy_from_slice(&700_000_000_000_000_000u128.to_be_bytes());
    plaintext
}

#[test]
fn version_1_note_is_refused() {
    let leaf = spec_leaf("note-coin-remainder-salted");
    // A version 1 coin note and a version 1 data note: the version byte is
    // read first and is unknown.
    for tag in [COIN_V1, DATA_V1] {
        let plain = version_1_plaintext(tag);
        assert_eq!(plain[0], 0x01);
        assert_eq!(NoteContents::from_plaintext(&plain).err(), Some(NoteError::UnknownVersion), "{tag:?}");
        assert_eq!(read(&leaf, plain).err(), Some(NoteError::UnknownVersion), "{tag:?}");
    }

    // A version 2 note that names a version 1 type tag: an unknown type.
    let salted: [u8; NOTE_PLAINTEXT_BYTES] =
        hex(&spec_field("note-coin-remainder-salted", "plaintext")).try_into().unwrap();
    assert!(read(&leaf, salted).is_ok());
    for tag in [COIN_V1, DATA_V1] {
        let mut bad = salted;
        bad[2..4].copy_from_slice(&tag);
        assert_eq!(NoteContents::from_plaintext(&bad).err(), Some(NoteError::UnknownType), "{tag:?}");
        assert_eq!(read(&leaf, bad).err(), Some(NoteError::UnknownType), "{tag:?}");
    }

    // A salted note whose version byte alone is set back to 1 is refused too.
    let mut bad = salted;
    bad[0] = 0x01;
    assert_eq!(read(&leaf, bad).err(), Some(NoteError::UnknownVersion));
}

fn read_ok(leaf: &Commitment, plaintext: [u8; NOTE_PLAINTEXT_BYTES]) -> NoteContents {
    read(leaf, plaintext).unwrap_or_else(|error| panic!("the note reads: {error}"))
}

#[test]
fn only_version_2_and_its_type_tags_read() {
    let leaf = spec_leaf("note-coin-remainder-salted");
    let salted: [u8; NOTE_PLAINTEXT_BYTES] =
        hex(&spec_field("note-coin-remainder-salted", "plaintext")).try_into().unwrap();
    assert!(read(&leaf, salted).is_ok());

    // Both version 2 type tags read.
    for tag in [COIN_V2, DATA_V2] {
        let mut changed = salted;
        changed[2..4].copy_from_slice(&tag);
        assert_eq!(read_ok(&leaf, changed).type_tag, tag);
    }

    // A note version other than 2.
    for version in [0x00, 0x01, 0x03, 0xff] {
        let mut bad = salted;
        bad[0] = version;
        assert_eq!(read(&leaf, bad).err(), Some(NoteError::UnknownVersion), "{version}");
    }
    // A type tag other than `COIN_V2` and `DATA_V2`.
    for tag in [COIN_V1, DATA_V1, [0x03, 0x01], [0x02, 0x03], [0x00, 0x01]] {
        let mut bad = salted;
        bad[2..4].copy_from_slice(&tag);
        assert_eq!(read(&leaf, bad).err(), Some(NoteError::UnknownType), "{tag:?}");
    }
    let mut bad = salted;
    bad[1] = 0x02;
    assert_eq!(read(&leaf, bad).err(), Some(NoteError::UnknownScheme));
}

#[test]
#[should_panic(expected = "not of note version")]
fn version_1_type_tag_is_not_written() {
    let contents = NoteContents {
        type_tag: COIN_V1,
        ..NoteContents::salted_coin(1, amount(1), Rule::EMPTY, Salt::from_bytes([1; 16]))
    };
    let _ = contents.to_plaintext();
}

#[test]
fn non_zero_padding_is_refused() {
    let leaf = spec_leaf("note-coin-remainder-salted");
    let salted: [u8; NOTE_PLAINTEXT_BYTES] =
        hex(&spec_field("note-coin-remainder-salted", "plaintext")).try_into().unwrap();
    // Every byte of the 16 bytes of padding after the salt.
    for offset in 112..NOTE_PLAINTEXT_BYTES {
        let mut bad = salted;
        bad[offset] = 0x01;
        assert_eq!(read(&leaf, bad).err(), Some(NoteError::NonZeroPadding), "byte {offset}");
    }
    // Any salt byte is a salt, not padding: it reads and comes back.
    for offset in 96..112 {
        let mut changed = salted;
        changed[offset] ^= 0xff;
        let contents = read_ok(&leaf, changed);
        assert_eq!(contents.salt.as_bytes()[..], changed[96..112]);
    }
}
