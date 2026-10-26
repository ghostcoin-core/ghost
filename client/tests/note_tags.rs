//! Key-derived note lookup tags in the note nonce, the bucket rule and
//! restore by note buckets (spec 01, sections 8, 9 and 14; spec 05,
//! section 8).

use std::collections::{BTreeSet, HashMap};

use ghost_client::hash::{self, TAG_NOTE_TAG};
use ghost_client::note::{chacha20poly1305_seal, note_associated_data, NOTE_NONCE_BYTES, NOTE_PLAINTEXT_BYTES};
use ghost_client::note_tag::{
    bucket_bits, bucket_prefix, lookup_tag, note_lookup_tag, restore_coins_by_tags, BucketNote,
    LookupTag, NoteBuckets, LOOKUP_TAG_BYTES, MAX_BUCKET_BITS, MIN_BUCKET_NOTES, TAG_BATCH,
};
use ghost_client::{
    decrypt_note, encrypt_note, restore_coins, Amount, Commitment, Current, Marker, NoteContents,
    NoteError, PhantomKey, RestoreError, Rule, Salt, TreeLeaf, MAX_TREE_LEAVES, NOTE_BYTES,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// The example words key of spec 01, section 5, as its digit view: the key
/// of `[derivation-words]`. Example only.
const DIGITS: &str = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
const CHAIN_ID: u64 = 1234;
const SPEC_01: &str = include_str!("../../docs/spec/01-commitments-and-keys.md");

/// `m = 10`: 1,024 buckets of 4,096 notes.
const LARGE_TREE: u64 = 4_194_304;

fn key() -> PhantomKey {
    PhantomKey::parse(DIGITS).unwrap_or_else(|_| panic!("the example key parses"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The vectors of one kind in spec 01, section 14, as maps of their fields.
fn vectors(kind: &str) -> Vec<HashMap<String, String>> {
    let body = &SPEC_01[SPEC_01.find("## 14. Test vectors").expect("section 14")..];
    let mut out: Vec<HashMap<String, String>> = Vec::new();
    let mut current: Option<HashMap<String, String>> = None;
    for line in body.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            out.extend(current.take());
            let mut block = HashMap::new();
            block.insert("name".to_owned(), line[1..line.len() - 1].to_owned());
            current = Some(block);
        } else if let (Some(block), Some((field, value))) = (current.as_mut(), line.split_once(" = ")) {
            block.insert(field.to_owned(), value.to_owned());
        } else if line.is_empty() || line.starts_with("```") {
            out.extend(current.take());
        }
    }
    out.extend(current);
    out.retain(|block| block.get("kind").map(String::as_str) == Some(kind));
    out
}

fn random<const N: usize>(rng: &mut StdRng) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

/// The key's coins of numbers `0..hops`, each the remainder of the one
/// before, at the given positions, and the markers of every one but the last.
fn hops(key: &PhantomKey, positions: &[u32], rng: &mut StdRng) -> (Vec<BucketNote>, Vec<Marker>) {
    let note_key = key.note_key();
    let mut notes = Vec::new();
    let mut spent = Vec::new();
    for (number, &position) in positions.iter().enumerate() {
        let number = number as u64;
        let amount = Amount::new(1_000_000 - u128::from(number)).unwrap();
        let salt = Salt::from_bytes(random(rng));
        let commit = key.coin_commit_with_salt(number, amount, Rule::EMPTY, salt).unwrap();
        let contents = NoteContents::salted_coin(number, amount, Rule::EMPTY, salt);
        let note = encrypt_note(&note_key, CHAIN_ID, &commit.commitment, &contents, rng);
        notes.push(BucketNote {
            position,
            leaf: TreeLeaf {
                commitment: commit.commitment,
                note,
                // A commit publishes its salt; a remainder's is only in its note.
                salt: (number == 0).then_some(salt),
            },
        });
        if number + 1 < positions.len() as u64 {
            spent.push(commit.marker);
        }
    }
    (notes, spent)
}

/// The bucket prefixes of the key's numbers in `numbers`, each once, in
/// order of first use.
fn prefixes(key: &PhantomKey, numbers: std::ops::Range<u64>, bits: u32) -> Vec<u32> {
    let note_key = key.note_key();
    let mut seen = BTreeSet::new();
    numbers
        .map(|number| bucket_prefix(&lookup_tag(&note_key, number), bits))
        .filter(|prefix| seen.insert(*prefix))
        .collect()
}

/// A tree that builds each bucket when it is asked for: 4,096 random notes
/// whose tags start with the bucket's prefix, at positions of that bucket's
/// own, with the key's real notes in place of fillers in theirs.
struct RandomTree {
    real: Vec<BucketNote>,
    asked: Vec<(u32, u32)>,
    served: u64,
}

impl NoteBuckets for RandomTree {
    fn read_bucket(&mut self, bits: u32, prefix: u32) -> Vec<BucketNote> {
        self.asked.push((bits, prefix));
        let mut rng = StdRng::seed_from_u64(u64::from(prefix));
        let rest = MAX_BUCKET_BITS - bits;
        let mut bucket: Vec<BucketNote> = Vec::new();
        for j in 0..MIN_BUCKET_NOTES as u32 {
            let position = prefix * MIN_BUCKET_NOTES as u32 + j;
            if let Some(real) = self.real.iter().find(|note| note.position == position) {
                bucket.push(real.clone());
                continue;
            }
            let low = u32::from_be_bytes(random(&mut rng)) & ((1 << rest) - 1);
            let tag = ((prefix << rest) | low).to_be_bytes();
            let mut note: [u8; NOTE_BYTES] = random(&mut rng);
            note[..LOOKUP_TAG_BYTES].copy_from_slice(&tag[1..]);
            bucket.push(BucketNote {
                position,
                leaf: TreeLeaf {
                    commitment: Commitment::from_bytes(random(&mut rng)),
                    note,
                    salt: None,
                },
            });
        }
        self.served += bucket.len() as u64;
        bucket
    }
}

/// A tree that holds only the given notes and serves each by its own tag.
struct TaggedNotes {
    notes: Vec<BucketNote>,
    asked: Vec<(u32, u32)>,
}

impl NoteBuckets for TaggedNotes {
    fn read_bucket(&mut self, bits: u32, prefix: u32) -> Vec<BucketNote> {
        self.asked.push((bits, prefix));
        self.notes
            .iter()
            .filter(|note| bucket_prefix(&note_lookup_tag(&note.leaf.note), bits) == prefix)
            .cloned()
            .collect()
    }
}

#[test]
fn note_tag_matches_the_spec_vectors() {
    assert_eq!(TAG_NOTE_TAG, "ghost/note-tag/v1");
    // The length byte, the tag, k_note and i as 8 bytes.
    assert_eq!(1 + TAG_NOTE_TAG.len() + 32 + 8, 58);
    let key = key();
    let note_key = key.note_key();
    let derivation = &vectors("derivation")[0];
    assert_eq!(derivation["name"], "derivation-words");
    assert_eq!(derivation["note-key"], hex(note_key.as_bytes()));

    let tags = vectors("note-tag");
    let names: Vec<&str> = tags.iter().map(|v| v["name"].as_str()).collect();
    assert_eq!(names, ["note-tag-index-0", "note-tag-index-1"]);
    for (expected_index, v) in tags.iter().enumerate() {
        let index: u64 = v["index"].parse().unwrap();
        assert_eq!(index, expected_index as u64);
        assert_eq!(v["key-bytes"], derivation["key-bytes"]);
        assert_eq!(v["key-bytes"], hex(key.key_bytes().as_bytes()));
        let digest = hash::s(TAG_NOTE_TAG, &[note_key.as_bytes(), &index.to_be_bytes()]);
        assert_eq!(v["digest"], hex(&digest));
        assert_eq!(v["tag"], hex(&digest[..LOOKUP_TAG_BYTES]));
        assert_eq!(v["tag"], hex(&lookup_tag(&note_key, index)));
    }
    assert_ne!(tags[0]["tag"], tags[1]["tag"]);
    // The tag is under k_note, not the key bytes.
    let from_key_bytes = hash::s(TAG_NOTE_TAG, &[key.key_bytes().as_bytes(), &0u64.to_be_bytes()]);
    assert_ne!(tags[0]["digest"], hex(&from_key_bytes));
}

#[test]
fn a_sealed_note_carries_its_tag_in_the_nonce_and_stays_156_bytes() {
    let mut rng = StdRng::seed_from_u64(0x7a9);
    let key = key();
    let note_key = key.note_key();
    let salt = Salt::from_bytes([0x31; 16]);
    let amount = Amount::new(700).unwrap();
    let commit = key.coin_commit_with_salt(5, amount, Rule::EMPTY, salt).unwrap();
    let contents = NoteContents::salted_coin(5, amount, Rule::EMPTY, salt);
    let note = encrypt_note(&note_key, CHAIN_ID, &commit.commitment, &contents, &mut rng);
    assert_eq!(NOTE_BYTES, 156);
    assert_eq!(note.len(), 156);
    assert_eq!(note_lookup_tag(&note), lookup_tag(&note_key, 5));
    assert_eq!(&note[..3], &lookup_tag(&note_key, 5)[..]);
    assert!(decrypt_note(&note_key, CHAIN_ID, &commit.commitment, &note).unwrap() == contents);

    // Two notes of the same contents share the tag and differ in the 9
    // random bytes after it.
    let again = encrypt_note(&note_key, CHAIN_ID, &commit.commitment, &contents, &mut rng);
    assert_eq!(note[..3], again[..3]);
    assert_ne!(note[3..NOTE_NONCE_BYTES], again[3..NOTE_NONCE_BYTES]);

    // The tag follows the number, and another key's tag is another.
    let next = NoteContents::salted_coin(6, amount, Rule::EMPTY, salt);
    let other = encrypt_note(&note_key, CHAIN_ID, &commit.commitment, &next, &mut rng);
    assert_eq!(note_lookup_tag(&other), lookup_tag(&note_key, 6));
    assert_ne!(lookup_tag(&note_key, 5), lookup_tag(&note_key, 6));
    let stranger = PhantomKey::generate(ghost_client::KeyFormat::Words, &mut rng);
    assert_ne!(lookup_tag(&stranger.note_key(), 5), lookup_tag(&note_key, 5));
}

#[test]
fn a_changed_tag_fails_to_decrypt() {
    let mut rng = StdRng::seed_from_u64(0xc4a);
    let key = key();
    let note_key = key.note_key();
    let salt = Salt::from_bytes([0x44; 16]);
    let amount = Amount::new(1_000).unwrap();
    let commit = key.coin_commit_with_salt(1, amount, Rule::EMPTY, salt).unwrap();
    let contents = NoteContents::salted_coin(1, amount, Rule::EMPTY, salt);
    let note = encrypt_note(&note_key, CHAIN_ID, &commit.commitment, &contents, &mut rng);
    for byte in 0..LOOKUP_TAG_BYTES {
        let mut changed = note;
        changed[byte] ^= 0x80;
        assert_eq!(
            decrypt_note(&note_key, CHAIN_ID, &commit.commitment, &changed).err(),
            Some(NoteError::Unauthentic)
        );
    }
    // The tag of another number, put in its place, does not decrypt either.
    let mut moved = note;
    moved[..LOOKUP_TAG_BYTES].copy_from_slice(&lookup_tag(&note_key, 0));
    assert_eq!(
        decrypt_note(&note_key, CHAIN_ID, &commit.commitment, &moved).err(),
        Some(NoteError::Unauthentic)
    );
}

#[test]
fn a_note_with_a_random_nonce_still_decrypts() {
    let mut rng = StdRng::seed_from_u64(0x01d);
    let key = key();
    let note_key = key.note_key();
    let salt = Salt::from_bytes([0x52; 16]);
    let amount = Amount::new(2_000).unwrap();
    let commit = key.coin_commit_with_salt(0, amount, Rule::EMPTY, salt).unwrap();
    let contents = NoteContents::salted_coin(0, amount, Rule::EMPTY, salt);

    // A note sealed as before the tag: 12 random bytes of nonce, here with a
    // first byte unlike the key's tag of number 0.
    let mut nonce: [u8; NOTE_NONCE_BYTES] = random(&mut rng);
    nonce[0] = !lookup_tag(&note_key, 0)[0];
    let mut note = [0u8; NOTE_BYTES];
    note[..NOTE_NONCE_BYTES].copy_from_slice(&nonce);
    let body = NOTE_NONCE_BYTES..NOTE_NONCE_BYTES + NOTE_PLAINTEXT_BYTES;
    note[body.clone()].copy_from_slice(&contents.to_plaintext());
    let tag = chacha20poly1305_seal(
        note_key.as_bytes(),
        &nonce,
        &note_associated_data(CHAIN_ID, &commit.commitment),
        &mut note[body],
    );
    note[NOTE_NONCE_BYTES + NOTE_PLAINTEXT_BYTES..].copy_from_slice(&tag);
    assert!(decrypt_note(&note_key, CHAIN_ID, &commit.commitment, &note).unwrap() == contents);

    // The full scan finds it; a bucket read does not return it.
    let leaf = TreeLeaf {
        commitment: commit.commitment,
        note,
        salt: Some(salt),
    };
    let scan = restore_coins(&key, CHAIN_ID, 0, std::slice::from_ref(&leaf), &[]).unwrap();
    assert_eq!(scan.found.len(), 1);
    let mut source = TaggedNotes {
        notes: vec![BucketNote { position: 0, leaf }],
        asked: Vec::new(),
    };
    let by_tags = restore_coins_by_tags(&key, CHAIN_ID, 0, LARGE_TREE, &mut source, &[]).unwrap();
    assert!(by_tags.restored.found.is_empty());
    assert!(matches!(by_tags.restored.current, Current::None));
    assert_eq!(by_tags.notes_tried, 0);
}

#[test]
fn bucket_bits_follows_the_rule() {
    let rules = vectors("bucket-rule");
    let names: Vec<&str> = rules.iter().map(|v| v["name"].as_str()).collect();
    assert_eq!(
        names,
        ["bucket-rule-0", "bucket-rule-1", "bucket-rule-2", "bucket-rule-3", "bucket-rule-4", "bucket-rule-5"]
    );
    let mut pairs = Vec::new();
    for v in &rules {
        let notes: u64 = v["notes"].parse().unwrap();
        let bits: u32 = v["bits"].parse().unwrap();
        assert_eq!(bucket_bits(notes), bits, "[{}]", v["name"]);
        pairs.push((notes, bits));
    }
    assert_eq!(
        pairs,
        [(0, 0), (8191, 0), (8192, 1), (1_048_576, 8), (3_650_000_000, 19), (1_099_511_627_776, 24)]
    );

    // Around the edges: an expected bucket keeps at least 4,096 notes.
    for (notes, bits) in [(1, 0), (4095, 0), (4096, 0), (16_383, 1), (16_384, 2), (LARGE_TREE, 10)] {
        assert_eq!(bucket_bits(notes), bits, "{notes} notes");
    }
    assert_eq!(bucket_bits(MAX_TREE_LEAVES), 20);
    assert_eq!(bucket_bits(u64::MAX), MAX_BUCKET_BITS);
    for notes in [8192, 100_000, 3_650_000_000, 1 << 36] {
        assert!(notes >> bucket_bits(notes) >= MIN_BUCKET_NOTES);
    }

    // The prefix is the first bits of the tag, big-endian.
    let tag: LookupTag = [0xab, 0xcd, 0xef];
    assert_eq!(bucket_prefix(&tag, 0), 0);
    assert_eq!(bucket_prefix(&tag, 1), 1);
    assert_eq!(bucket_prefix(&tag, 4), 0xa);
    assert_eq!(bucket_prefix(&tag, 10), 0x2af);
    assert_eq!(bucket_prefix(&tag, 24), 0xab_cdef);
    assert_eq!(bucket_prefix(&tag, 30), 0xab_cdef);
}

#[test]
fn restore_by_tags_reads_only_the_buckets_it_asks_for() {
    let mut rng = StdRng::seed_from_u64(0xb0c);
    let key = key();
    let bits = bucket_bits(LARGE_TREE);
    assert_eq!(bits, 10);
    // Each real note sits in its own bucket's range of positions.
    let note_key = key.note_key();
    let positions: Vec<u32> = (0..3u64)
        .map(|number| {
            let prefix = bucket_prefix(&lookup_tag(&note_key, number), bits);
            prefix * MIN_BUCKET_NOTES as u32 + 100 + number as u32
        })
        .collect();
    let (real, spent) = hops(&key, &positions, &mut rng);
    let mut source = RandomTree {
        real,
        asked: Vec::new(),
        served: 0,
    };
    let result = restore_coins_by_tags(&key, CHAIN_ID, 7, LARGE_TREE, &mut source, &spent).unwrap();

    let Current::One(current) = result.restored.current else {
        panic!("the key's current coin");
    };
    assert_eq!(current.number, 2);
    assert_eq!((current.tree_index, current.position), (7, positions[2]));
    let found: Vec<(u64, u32)> = result.restored.found.iter().map(|coin| (coin.number, coin.position)).collect();
    // In position order.
    let mut expected_found = vec![(0, positions[0]), (1, positions[1]), (2, positions[2])];
    expected_found.sort_by_key(|&(_, position)| position);
    assert_eq!(found, expected_found);
    assert!(result.restored.discarded.is_empty());

    // Only m bits, only the prefixes of tags 0 to 15, each once.
    let expected = prefixes(&key, 0..TAG_BATCH, bits);
    let asked: Vec<u32> = source.asked.iter().map(|&(asked_bits, prefix)| {
        assert_eq!(asked_bits, bits);
        prefix
    }).collect();
    assert_eq!(asked, expected);
    assert_eq!(result.bucket_reads, expected.len() as u64);
    assert_eq!(result.notes_tried, source.served);
    assert_eq!(result.notes_tried, result.bucket_reads * MIN_BUCKET_NOTES);
    assert!(result.notes_tried * 50 < LARGE_TREE, "{} notes tried", result.notes_tried);
}

#[test]
fn lookups_go_in_batches_of_16_and_continue_only_after_a_found_note() {
    let mut rng = StdRng::seed_from_u64(0x16);
    let key = key();
    let bits = bucket_bits(LARGE_TREE);
    let run = |hop_count: u32, note_count: u64, rng: &mut StdRng| {
        let positions: Vec<u32> = (0..hop_count).map(|n| 1_000 + 37 * n).collect();
        let (notes, spent) = hops(&key, &positions, rng);
        let mut source = TaggedNotes {
            notes,
            asked: Vec::new(),
        };
        let result = restore_coins_by_tags(&key, CHAIN_ID, 0, note_count, &mut source, &spent).unwrap();
        let Current::One(current) = result.restored.current else {
            panic!("the key's current coin");
        };
        assert_eq!(current.number, u64::from(hop_count) - 1);
        assert_eq!(result.restored.found.len(), hop_count as usize);
        assert_eq!(result.bucket_reads, source.asked.len() as u64);
        assert_eq!(result.notes_tried, u64::from(hop_count));
        source.asked
    };
    let asked_at = |asked: &[(u32, u32)]| -> Vec<u32> {
        asked.iter().map(|&(asked_bits, prefix)| {
            assert_eq!(asked_bits, bits);
            prefix
        }).collect()
    };

    // 3 hops: one batch, all 16 tags asked though 3 are expected.
    let asked = run(3, LARGE_TREE, &mut rng);
    assert_eq!(asked_at(&asked), prefixes(&key, 0..16, bits));

    // 20 hops: number 15 is found, so a second batch; number 31 is not.
    let asked = run(20, LARGE_TREE, &mut rng);
    assert_eq!(asked_at(&asked), prefixes(&key, 0..32, bits));
    assert_ne!(prefixes(&key, 0..32, bits), prefixes(&key, 0..16, bits));

    // Exactly 16 hops: the second batch finds nothing and the lookup stops.
    let asked = run(16, LARGE_TREE, &mut rng);
    assert_eq!(asked_at(&asked), prefixes(&key, 0..32, bits));
    assert_ne!(prefixes(&key, 0..48, bits), prefixes(&key, 0..32, bits));

    // A small tree is one bucket: it is read once, however many batches.
    let positions: Vec<u32> = (0..20).collect();
    let (notes, spent) = hops(&key, &positions, &mut rng);
    let mut whole = TaggedNotes {
        notes,
        asked: Vec::new(),
    };
    let result = restore_coins_by_tags(&key, CHAIN_ID, 0, 8191, &mut whole, &spent).unwrap();
    assert_eq!(whole.asked, [(0, 0)]);
    assert_eq!(result.bucket_reads, 1);
    assert!(matches!(result.restored.current, Current::One(coin) if coin.number == 19));

    // More notes than one tree holds is refused, with nothing asked.
    let mut none = TaggedNotes {
        notes: Vec::new(),
        asked: Vec::new(),
    };
    let over = restore_coins_by_tags(&key, CHAIN_ID, 0, MAX_TREE_LEAVES + 1, &mut none, &[]);
    assert_eq!(over.err(), Some(RestoreError::TooManyLeaves));
    assert!(none.asked.is_empty());
}
