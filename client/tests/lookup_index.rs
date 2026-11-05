//! Lookup tags, the coin and data lookup indices, the coin spent-marker set
//! tree and the block lookup digest, against the golden vectors of spec 01,
//! section 14 and spec 05, section 11 (decision 0004).

use std::collections::HashMap;

use ghost_client::hash::{self, TAG_NOTE_LOOKUP};
use ghost_client::lookup::{
    check_lookup_digest, global_position, key_lookup_tag, lookup_tag, lookup_tags, position_bytes,
    verify_lookup, verify_lookup_membership, verify_marker_absence, verify_marker_membership, BlockLookupList,
    CoinMarkerLeaf, CoinMarkerSet, CoinMarkerWitness, InsertError, ListError, LookupAnswer, LookupIndex,
    LookupLeaf, LookupMembership, LookupTag, LookupTree, LookupWitness, SpentMarker, WitnessError,
    COIN_MARKER_WITNESS_BYTES, LOOKUP_TAG_BYTES, LOOKUP_WITNESS_BYTES, NO_POSITION, ZERO_TAG,
};
use ghost_client::PhantomKey;
use tiny_keccak::{Hasher, Sha3};

const SPEC_01: &str = include_str!("../../docs/spec/01-commitments-and-keys.md");
const SPEC_05: &str = include_str!("../../docs/spec/05-trees-and-headers.md");
const DECISION_0004: &str = include_str!("../../docs/decisions/0004-lookup-formats.md");

/// The key bytes of spec 01's example words key and data example key
/// (`[derivation-words]`, `[derivation-words-data]`). Examples only.
const WORDS_KEY_BYTES: &str = "20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const DATA_KEY_BYTES: &str = "207f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f";

type Block = HashMap<String, String>;

/// Every `[name]` block from `heading` to the end of `doc`, as maps of their
/// fields; an empty field (`entries =`) maps to the empty string.
fn blocks(doc: &str, heading: &str) -> Vec<Block> {
    let body = &doc[doc.find(heading).unwrap_or_else(|| panic!("{heading}"))..];
    let mut out: Vec<Block> = Vec::new();
    let mut current: Option<Block> = None;
    for line in body.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') && !line.contains(' ') {
            out.extend(current.take());
            let mut block = HashMap::new();
            block.insert("name".to_owned(), line[1..line.len() - 1].to_owned());
            current = Some(block);
        } else if line.is_empty() || line.starts_with("```") {
            out.extend(current.take());
        } else if let Some(block) = current.as_mut() {
            let field = line
                .split_once(" = ")
                .or_else(|| line.strip_suffix(" =").map(|field| (field, "")));
            if let Some((field, value)) = field {
                block.insert(field.to_owned(), value.to_owned());
            }
        }
    }
    out.extend(current);
    out
}

fn spec_05() -> Vec<Block> {
    blocks(SPEC_05, "## 11. Golden vectors")
}

fn spec_01() -> Vec<Block> {
    blocks(SPEC_01, "## 14. Test vectors")
}

fn of_kind(all: &[Block], kind: &str) -> Vec<Block> {
    all.iter().filter(|block| block["kind"] == kind).cloned().collect()
}

fn named(all: &[Block], name: &str) -> Block {
    all.iter()
        .find(|block| block["name"] == name)
        .unwrap_or_else(|| panic!("vector {name}"))
        .clone()
}

fn names(blocks: &[Block]) -> Vec<&str> {
    blocks.iter().map(|block| block["name"].as_str()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "{text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or_else(|_| panic!("hex: {text}")))
        .collect()
}

fn bytes<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().unwrap_or_else(|_| panic!("{N} bytes: {text}"))
}

fn tag(text: &str) -> LookupTag {
    bytes(text)
}

fn list(text: &str) -> Vec<&str> {
    text.split_whitespace().collect()
}

/// `tag@g` or `marker@a` entries.
fn at_entries<const N: usize>(text: &str) -> Vec<([u8; N], u64)> {
    list(text)
        .into_iter()
        .map(|entry| {
            let (value, position) = entry.split_once('@').expect("value@position");
            (bytes(value), position.parse().expect("a position"))
        })
        .collect()
}

fn lookup_leaf_text(leaf: &LookupLeaf) -> String {
    let b = leaf.to_bytes();
    format!("{} {} {} {} {}", hex(&b[..16]), hex(&b[16..21]), hex(&b[21..37]), hex(&b[37..42]), hex(&b[42..]))
}

fn marker_leaf_text(leaf: &CoinMarkerLeaf) -> String {
    let b = leaf.to_bytes();
    format!("{} {} {} {}", hex(&b[..32]), hex(&b[32..64]), hex(&b[64..69]), hex(&b[69..]))
}

fn tree(block: &Block) -> LookupTree {
    match block["tree"].as_str() {
        "coin" => LookupTree::Coin,
        "data" => LookupTree::Data,
        other => panic!("tree {other}"),
    }
}

fn index_of(block: &Block) -> LookupIndex {
    LookupIndex::from_entries(tree(block), at_entries::<16>(&block["entries"])).expect("the entries insert")
}

fn set_of(block: &Block) -> CoinMarkerSet {
    let spends = at_entries::<32>(&block["spends"]).into_iter().map(|(marker, a)| (marker, Some(a)));
    CoinMarkerSet::from_spends(spends).expect("the spends insert")
}

/// The example key of a derivation vector, parsed from its digit groups.
fn derivation_key(key_bytes: &str) -> (PhantomKey, Block) {
    let derivation = of_kind(&spec_01(), "derivation")
        .into_iter()
        .find(|block| block["key-bytes"] == key_bytes)
        .expect("a derivation vector with these key bytes");
    let key = PhantomKey::parse(&derivation["key"]).unwrap_or_else(|_| panic!("the example key parses"));
    (key, derivation)
}

/// SHA3-256 over `tagbytes("ghost/note-lookup/v1") || k_note || i`, written
/// here on `tiny_keccak` alone, without the library's tagged hash.
fn independent_digest(note_key: &[u8; 32], number: u64) -> [u8; 32] {
    let mut input = vec![20u8];
    input.extend_from_slice(b"ghost/note-lookup/v1");
    input.extend_from_slice(note_key);
    input.extend_from_slice(&number.to_be_bytes());
    assert_eq!(input.len(), 61);
    let mut hasher = Sha3::v256();
    hasher.update(&input);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Every byte of a witness changed in turn, each one rejected by `check`.
fn every_changed_byte_rejects(witness: &[u8], check: impl Fn(&[u8]) -> bool) {
    assert!(check(witness), "the witness itself is accepted");
    for i in 0..witness.len() {
        let mut changed = witness.to_vec();
        changed[i] ^= 0x01;
        assert!(!check(&changed), "a change at byte {i} is rejected");
    }
    assert!(!check(&witness[..witness.len() - 1]), "one byte short is rejected");
    let mut long = witness.to_vec();
    long.push(0);
    assert!(!check(&long), "one byte long is rejected");
}

// ---------------------------------------------------------------------------
// Lookup tags
// ---------------------------------------------------------------------------

#[test]
fn every_vector_block_of_decision_0004_is_in_the_specs_unchanged() {
    let decision = blocks(DECISION_0004, "## Worked examples");
    let specs: Vec<Block> = spec_05().into_iter().chain(spec_01()).collect();
    assert!(decision.len() >= 20);
    for block in &decision {
        let in_spec = specs
            .iter()
            .find(|spec| spec["name"] == block["name"])
            .unwrap_or_else(|| panic!("{} is in a spec", block["name"]));
        assert_eq!(in_spec, block, "{}", block["name"]);
    }
}

#[test]
fn lookup_tags_match_the_vectors_of_spec_01_and_spec_05() {
    assert_eq!(TAG_NOTE_LOOKUP, "ghost/note-lookup/v1");
    assert_eq!(1 + TAG_NOTE_LOOKUP.len() + 32 + 8, 61);
    let in_05 = of_kind(&spec_05(), "lookup-tag");
    let in_01 = of_kind(&spec_01(), "lookup-tag");
    let expected = ["lookup-tag-index-0", "lookup-tag-index-1", "lookup-tag-index-2", "lookup-tag-data-index-0"];
    assert_eq!(names(&in_05), expected);
    assert_eq!(in_01, in_05, "spec 01 carries the same blocks");
    for v in &in_05 {
        let (key, derivation) = derivation_key(&v["key-bytes"]);
        assert_eq!(hex(key.key_bytes().as_bytes()), v["key-bytes"]);
        let note_key = key.note_key();
        assert_eq!(hex(note_key.as_bytes()), v["note-key"]);
        assert_eq!(derivation["note-key"], v["note-key"]);
        let index: u64 = v["index"].parse().unwrap();
        assert_eq!(hex(&index.to_be_bytes()), v["index-bytes"]);
        let digest = hash::s(TAG_NOTE_LOOKUP, &[note_key.as_bytes(), &index.to_be_bytes()]);
        assert_eq!(hex(&digest), v["digest"]);
        assert_eq!(hex(&independent_digest(note_key.as_bytes(), index)), v["digest"]);
        assert_eq!(hex(&lookup_tag(&note_key, index)), v["tag"]);
        assert_eq!(hex(&key_lookup_tag(&key, index)), v["tag"]);
        assert_eq!(v["tag"], v["digest"][..2 * LOOKUP_TAG_BYTES]);
    }
    // The 16-byte tag is not the 3-byte nonce tag under its own domain.
    let note_tags = of_kind(&spec_01(), "note-tag");
    assert!(!note_tags.is_empty());
    for note_tag in &note_tags {
        let same = in_05.iter().find(|v| v["index"] == note_tag["index"] && v["key-bytes"] == note_tag["key-bytes"]);
        let same = same.expect("a lookup tag of the same number");
        assert_ne!(same["digest"], note_tag["digest"]);
    }
}

#[test]
fn the_same_tags_come_from_the_digits_alone_for_numbers_0_to_1023() {
    let vectors = of_kind(&spec_05(), "lookup-tag");
    for key_bytes in [WORDS_KEY_BYTES, DATA_KEY_BYTES] {
        let (key, derivation) = derivation_key(key_bytes);
        // The note key as the spec writes it, not as the library derives it.
        let spec_note_key: [u8; 32] = bytes(&derivation["note-key"]);
        let tags = lookup_tags(&key, 0..1024);
        assert_eq!(tags.len(), 1024);

        // The same digits typed again, and the same key in its words view.
        let again = PhantomKey::parse(&derivation["key"]).unwrap_or_else(|_| panic!("the digits parse"));
        let words = key.format_words().expect("an example key has a words view");
        let from_words = PhantomKey::parse(words.as_str()).unwrap_or_else(|_| panic!("the words parse"));
        let groups = key.format_groups();
        assert_eq!(groups.as_str(), derivation["key"]);

        for (number, tag) in (0u64..).zip(&tags) {
            let digest = independent_digest(&spec_note_key, number);
            assert_eq!(tag[..], digest[..LOOKUP_TAG_BYTES], "number {number}");
            assert_eq!(&key_lookup_tag(&again, number), tag, "number {number}");
            assert_eq!(&key_lookup_tag(&from_words, number), tag, "number {number}");
            assert_ne!(tag, &ZERO_TAG);
        }
        let mut distinct = tags.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 1024, "no two numbers share a tag");

        for v in vectors.iter().filter(|v| v["key-bytes"] == key_bytes) {
            let index: usize = v["index"].parse().unwrap();
            assert_eq!(hex(&tags[index]), v["tag"]);
        }
    }
    // The two keys share no tag.
    let (a, _) = derivation_key(WORDS_KEY_BYTES);
    let (b, _) = derivation_key(DATA_KEY_BYTES);
    let a = lookup_tags(&a, 0..1024);
    assert!(lookup_tags(&b, 0..1024).iter().all(|tag| !a.contains(tag)));
}

// ---------------------------------------------------------------------------
// Lookup indices
// ---------------------------------------------------------------------------

#[test]
fn lookup_index_vectors_give_the_same_leaves_counts_and_roots() {
    let all = spec_05();
    let vectors = of_kind(&all, "lookup-index");
    assert_eq!(
        names(&vectors),
        [
            "coin-lookup-empty",
            "data-lookup-empty",
            "coin-lookup-one-leaf",
            "coin-lookup-two-leaves",
            "coin-lookup-copied-tag",
            "data-lookup-one-leaf",
        ]
    );
    for v in &vectors {
        let index = index_of(v);
        let name = &v["name"];
        assert_eq!(index.len().to_string(), v["count"], "{name}");
        for (i, leaf) in index.leaves().iter().enumerate() {
            assert_eq!(lookup_leaf_text(leaf), v[&format!("leaf-{i}")], "{name} leaf {i}");
            assert_eq!(&LookupLeaf::from_bytes(&leaf.to_bytes()), leaf);
        }
        assert!(!v.contains_key(&format!("leaf-{}", index.len())), "{name}");
        assert_eq!(hex(&index.root()), v["root"], "{name}");
        // Every entry sits at index position g + 1 and its witness folds.
        for (tag, position) in at_entries::<16>(&v["entries"]) {
            let witness = index.membership_witness(&tag, position).expect("a member");
            assert_eq!(witness.index_position, position + 1);
            let accepted = verify_lookup_membership(tree(v), &index.root(), &witness.to_bytes(), &tag, position);
            assert_eq!(accepted.map(|m| m.index_position), Ok(position + 1));
        }
    }
    assert_eq!(hex(&LookupTree::Coin.genesis_root()), named(&all, "coin-lookup-empty")["root"]);
    assert_eq!(hex(&LookupTree::Data.genesis_root()), named(&all, "data-lookup-empty")["root"]);
    // The two types hash under their own tags.
    assert_ne!(LookupTree::Coin.genesis_root(), LookupTree::Data.genesis_root());
    let data_one = named(&all, "data-lookup-one-leaf");
    let as_coin = LookupIndex::from_entries(LookupTree::Coin, at_entries::<16>(&data_one["entries"])).unwrap();
    assert_ne!(hex(&as_coin.root()), data_one["root"]);
}

#[test]
fn a_copied_tag_sorts_after_the_original() {
    let v = named(&spec_05(), "coin-lookup-copied-tag");
    let index = index_of(&v);
    let original = tag("74c5d993f5f018e3174926b2c8e8fb68");
    let root = index.root();
    let witness = index.membership_witness(&original, 0).unwrap().to_bytes();
    assert_eq!(
        verify_lookup_membership(LookupTree::Coin, &root, &witness, &original, 0),
        Ok(LookupMembership {
            index_position: 1,
            next_with_same_tag: Some(2),
        })
    );
    let copy = index.membership_witness(&original, 2).unwrap().to_bytes();
    assert_eq!(
        verify_lookup_membership(LookupTree::Coin, &root, &copy, &original, 2),
        Ok(LookupMembership {
            index_position: 3,
            next_with_same_tag: None,
        })
    );
}

#[test]
fn the_absence_witness_vector_shows_its_tag_absent() {
    let all = spec_05();
    let witnesses = of_kind(&all, "lookup-witness");
    assert_eq!(names(&witnesses), ["coin-lookup-absence", "coin-lookup-first-entry"]);
    let v = named(&all, "coin-lookup-absence");
    assert_eq!(v["outcome"], "absent");
    let index = index_of(&named(&all, &v["set"]));
    let root: [u8; 32] = bytes(&v["root"]);
    assert_eq!(index.root(), root);
    let asked = tag(&v["tag"]);
    let witness = unhex(&v["witness"]);
    assert_eq!(witness.len(), LOOKUP_WITNESS_BYTES);

    let parsed = LookupWitness::from_bytes(&witness).unwrap();
    assert_eq!(lookup_leaf_text(&parsed.leaf), v["low-leaf"]);
    assert_eq!(parsed.index_position.to_string(), v["low-position"]);
    assert_eq!(parsed.to_bytes(), witness);
    assert_eq!(parsed.root(LookupTree::Coin), root);
    assert_eq!(index.lookup_witness(&asked).unwrap().to_bytes(), witness, "the rebuilt index makes the same witness");

    assert_eq!(verify_lookup(LookupTree::Coin, &root, &witness, &asked), Ok(LookupAnswer::Absent));
    for rejected in ["reject-equal", "reject-below"] {
        assert_eq!(
            verify_lookup(LookupTree::Coin, &root, &witness, &tag(&v[rejected])),
            Err(WitnessError::NotTheLowLeaf),
            "{rejected}"
        );
    }
    assert_eq!(verify_lookup(LookupTree::Coin, &root, &witness, &ZERO_TAG), Err(WitnessError::ZeroKey));
    // The data index's tags in place of the coin index's.
    assert_eq!(verify_lookup(LookupTree::Data, &root, &witness, &asked), Err(WitnessError::Root));
    every_changed_byte_rejects(&witness, |w| verify_lookup(LookupTree::Coin, &root, w, &asked).is_ok());
}

#[test]
fn the_first_entry_witness_vector_answers_the_original_not_the_copy() {
    let all = spec_05();
    let v = named(&all, "coin-lookup-first-entry");
    assert_eq!(v["outcome"], "first");
    let index = index_of(&named(&all, &v["set"]));
    let root: [u8; 32] = bytes(&v["root"]);
    assert_eq!(index.root(), root);
    let asked = tag(&v["tag"]);
    let witness = unhex(&v["witness"]);

    let parsed = LookupWitness::from_bytes(&witness).unwrap();
    assert_eq!(lookup_leaf_text(&parsed.leaf), v["low-leaf"]);
    assert_eq!(parsed.index_position.to_string(), v["low-position"]);
    assert_eq!(index.lookup_witness(&asked).unwrap().to_bytes(), witness);

    let position: u64 = v["position"].parse().unwrap();
    assert_eq!(
        verify_lookup(LookupTree::Coin, &root, &witness, &asked),
        Ok(LookupAnswer::First {
            position,
            index_position: position + 1,
        })
    );
    assert_eq!(position, 0);
    assert_eq!(verify_lookup(LookupTree::Data, &root, &witness, &asked), Err(WitnessError::Root));
    every_changed_byte_rejects(&witness, |w| verify_lookup(LookupTree::Coin, &root, w, &asked).is_ok());
}

#[test]
fn the_membership_witness_vector_is_accepted_for_its_pair_only() {
    let all = spec_05();
    assert_eq!(names(&of_kind(&all, "lookup-membership")), ["coin-lookup-membership"]);
    let v = named(&all, "coin-lookup-membership");
    let index = index_of(&named(&all, &v["set"]));
    let root: [u8; 32] = bytes(&v["root"]);
    assert_eq!(index.root(), root);
    let member = tag(&v["tag"]);
    let position: u64 = v["position"].parse().unwrap();
    let witness = unhex(&v["witness"]);

    let parsed = LookupWitness::from_bytes(&witness).unwrap();
    assert_eq!(lookup_leaf_text(&parsed.leaf), v["leaf"]);
    assert_eq!(parsed.index_position.to_string(), v["leaf-position"]);
    assert_eq!(index.membership_witness(&member, position).unwrap().to_bytes(), witness);

    assert_eq!(
        verify_lookup_membership(LookupTree::Coin, &root, &witness, &member, position),
        Ok(LookupMembership {
            index_position: v["leaf-position"].parse().unwrap(),
            next_with_same_tag: None,
        })
    );
    for other in [0, 1, 3, NO_POSITION] {
        assert_eq!(
            verify_lookup_membership(LookupTree::Coin, &root, &witness, &member, other),
            Err(WitnessError::NotTheEntry),
            "position {other}"
        );
    }
    assert_eq!(
        verify_lookup_membership(LookupTree::Coin, &root, &witness, &ZERO_TAG, position),
        Err(WitnessError::ZeroKey)
    );
    assert_eq!(
        verify_lookup_membership(LookupTree::Data, &root, &witness, &member, position),
        Err(WitnessError::Root)
    );
    every_changed_byte_rejects(&witness, |w| {
        verify_lookup_membership(LookupTree::Coin, &root, w, &member, position).is_ok()
    });
}

// ---------------------------------------------------------------------------
// Coin spent-marker set tree
// ---------------------------------------------------------------------------

#[test]
fn coin_marker_set_vectors_give_the_same_leaves_counts_and_roots() {
    let all = spec_05();
    let vectors = of_kind(&all, "coin-marker-set");
    assert_eq!(
        names(&vectors),
        ["coin-marker-set-empty", "coin-marker-set-one-marker", "coin-marker-set-two-markers"]
    );
    for v in &vectors {
        let set = set_of(v);
        let name = &v["name"];
        assert_eq!(set.len().to_string(), v["count"], "{name}");
        for (i, leaf) in set.leaves().iter().enumerate() {
            assert_eq!(marker_leaf_text(leaf), v[&format!("leaf-{i}")], "{name} leaf {i}");
            assert_eq!(&CoinMarkerLeaf::from_bytes(&leaf.to_bytes()), leaf);
        }
        assert!(!v.contains_key(&format!("leaf-{}", set.len())), "{name}");
        assert_eq!(hex(&set.root()), v["root"], "{name}");
    }
    assert_eq!(hex(&CoinMarkerSet::genesis_root()), named(&all, "coin-marker-set-empty")["root"]);
    // A rewritten leaf keeps its own `appended`: one that took the new
    // marker's instead gives another root.
    let two = named(&all, "coin-marker-set-two-markers");
    let set = set_of(&two);
    assert_eq!(set.leaves()[1].appended, Some(1));
    let mut wrong = set.leaves()[1];
    wrong.appended = Some(2);
    assert_ne!(wrong.hash(), set.leaves()[1].hash());
    // The markers spent are those of spec 01's salted coin vectors.
    for (marker, _) in at_entries::<32>(&two["spends"]) {
        assert!(SPEC_01.contains(&format!("marker = {}", hex(&marker))));
    }
}

#[test]
fn the_marker_membership_vector_leads_to_the_appended_leaf() {
    let all = spec_05();
    assert_eq!(names(&of_kind(&all, "coin-marker-set-membership")), ["coin-marker-set-membership"]);
    let v = named(&all, "coin-marker-set-membership");
    let set = set_of(&named(&all, &v["set"]));
    let root: [u8; 32] = bytes(&v["root"]);
    assert_eq!(set.root(), root);
    let marker: [u8; 32] = bytes(&v["marker"]);
    let witness = unhex(&v["witness"]);
    assert_eq!(witness.len(), COIN_MARKER_WITNESS_BYTES);

    let parsed = CoinMarkerWitness::from_bytes(&witness).unwrap();
    assert_eq!(marker_leaf_text(&parsed.leaf), v["leaf"]);
    assert_eq!(parsed.position.to_string(), v["leaf-position"]);
    assert_eq!(parsed.to_bytes(), witness);
    assert_eq!(set.membership_witness(&marker).unwrap().to_bytes(), witness);

    let appended: u64 = v["appended"].parse().unwrap();
    assert_eq!(
        verify_marker_membership(&root, &witness, &marker),
        Ok(SpentMarker {
            position: v["leaf-position"].parse().unwrap(),
            appended: Some(appended),
        })
    );
    // A spent marker has no absence witness, and this one is no absence
    // witness for it.
    assert!(set.absence_witness(&marker).is_none());
    assert_eq!(verify_marker_absence(&root, &witness, &marker), Err(WitnessError::NotTheLowLeaf));
    assert_eq!(verify_marker_membership(&root, &witness, &[0; 32]), Err(WitnessError::ZeroKey));
    let other: [u8; 32] = bytes(&named(&all, "coin-marker-set-absence")["marker"]);
    assert_eq!(verify_marker_membership(&root, &witness, &other), Err(WitnessError::NotTheEntry));
    every_changed_byte_rejects(&witness, |w| verify_marker_membership(&root, w, &marker).is_ok());
}

#[test]
fn the_marker_absence_vector_shows_its_marker_unspent() {
    let all = spec_05();
    assert_eq!(names(&of_kind(&all, "coin-marker-set-absence")), ["coin-marker-set-absence"]);
    let v = named(&all, "coin-marker-set-absence");
    assert_eq!(v["valid"], "yes");
    let set = set_of(&named(&all, &v["set"]));
    let root: [u8; 32] = bytes(&v["root"]);
    assert_eq!(set.root(), root);
    let marker: [u8; 32] = bytes(&v["marker"]);
    let witness = unhex(&v["witness"]);

    let parsed = CoinMarkerWitness::from_bytes(&witness).unwrap();
    assert_eq!(marker_leaf_text(&parsed.leaf), v["low-leaf"]);
    assert_eq!(parsed.position.to_string(), v["low-position"]);
    assert_eq!(parsed.leaf.appended, None, "the sentinel's appended is none");
    assert_eq!(set.absence_witness(&marker).unwrap().to_bytes(), witness);

    assert_eq!(verify_marker_absence(&root, &witness, &marker), Ok(()));
    let spent: [u8; 32] = bytes(&v["reject-spent"]);
    assert_eq!(verify_marker_absence(&root, &witness, &spent), Err(WitnessError::NotTheLowLeaf));
    assert_eq!(verify_marker_absence(&root, &witness, &[0; 32]), Err(WitnessError::ZeroKey));
    assert_eq!(verify_marker_membership(&root, &witness, &marker), Err(WitnessError::NotTheEntry));
    every_changed_byte_rejects(&witness, |w| verify_marker_absence(&root, w, &marker).is_ok());
}

// ---------------------------------------------------------------------------
// Rejection: a wrong root, a wrong tag, a swapped neighbour
// ---------------------------------------------------------------------------

#[test]
fn a_witness_against_a_wrong_root_a_wrong_tag_or_a_swapped_neighbour_is_rejected() {
    let all = spec_05();
    let two = index_of(&named(&all, "coin-lookup-two-leaves"));
    let root = two.root();
    let number_0 = tag("74c5d993f5f018e3174926b2c8e8fb68");
    let number_1 = tag("98f00763f51d9e982a7814297473729f");
    let number_2 = tag("b3e8df15fdd3d0f3ac8c7562c50ba57e");
    let absence = two.lookup_witness(&number_2).unwrap().to_bytes();
    let member = two.membership_witness(&number_1, 1).unwrap().to_bytes();
    assert_eq!(verify_lookup(LookupTree::Coin, &root, &absence, &number_2), Ok(LookupAnswer::Absent));
    assert!(verify_lookup_membership(LookupTree::Coin, &root, &member, &number_1, 1).is_ok());

    // A wrong root: every other root of the vectors.
    for name in ["coin-lookup-empty", "coin-lookup-one-leaf", "coin-lookup-copied-tag", "data-lookup-one-leaf"] {
        let other: [u8; 32] = bytes(&named(&all, name)["root"]);
        assert_eq!(verify_lookup(LookupTree::Coin, &other, &absence, &number_2), Err(WitnessError::Root), "{name}");
        assert_eq!(
            verify_lookup_membership(LookupTree::Coin, &other, &member, &number_1, 1),
            Err(WitnessError::Root),
            "{name}"
        );
    }

    // A wrong tag.
    assert_eq!(
        verify_lookup_membership(LookupTree::Coin, &root, &member, &number_0, 1),
        Err(WitnessError::NotTheEntry)
    );
    assert_eq!(
        verify_lookup_membership(LookupTree::Coin, &root, &member, &number_2, 1),
        Err(WitnessError::NotTheEntry)
    );
    // Number 0's tag is in the index: the absence witness of number 2 says
    // nothing about it.
    assert_eq!(verify_lookup(LookupTree::Coin, &root, &absence, &number_0), Err(WitnessError::NotTheLowLeaf));
    assert_eq!(verify_lookup(LookupTree::Coin, &root, &absence, &number_1), Err(WitnessError::NotTheLowLeaf));

    // A swapped neighbour, 1: the witness of a neighbouring leaf, which folds
    // to the root but is not the low leaf: it would hide number 1's entry.
    let neighbour = two.witness_at(1).unwrap().to_bytes();
    assert!(LookupWitness::from_bytes(&neighbour).unwrap().root(LookupTree::Coin) == root);
    assert_eq!(verify_lookup(LookupTree::Coin, &root, &neighbour, &number_2), Err(WitnessError::NotTheLowLeaf));
    let sentinel = two.witness_at(0).unwrap().to_bytes();
    assert_eq!(verify_lookup(LookupTree::Coin, &root, &sentinel, &number_2), Err(WitnessError::NotTheLowLeaf));
    assert_eq!(verify_lookup(LookupTree::Coin, &root, &sentinel, &number_1), Err(WitnessError::NotTheLowLeaf));
    // 2: the low leaf with its next entry swapped for another one, here
    // "none" in place of number 1, which would make number 1 look absent.
    let mut forged = LookupWitness::from_bytes(&neighbour).unwrap();
    forged.leaf.next_tag = ZERO_TAG;
    forged.leaf.next_position = 0;
    forged.leaf.next_index = 0;
    assert_eq!(
        verify_lookup(LookupTree::Coin, &root, &forged.to_bytes(), &number_1),
        Err(WitnessError::Root)
    );
    let mut forged = LookupWitness::from_bytes(&sentinel).unwrap();
    forged.leaf.next_tag = number_1;
    forged.leaf.next_position = 1;
    forged.leaf.next_index = 2;
    assert_eq!(
        verify_lookup(LookupTree::Coin, &root, &forged.to_bytes(), &number_1),
        Err(WitnessError::Root)
    );
    // 3: two siblings swapped, and the leaf moved to its neighbour's side.
    let mut swapped = LookupWitness::from_bytes(&member).unwrap();
    swapped.siblings.swap(0, 1);
    assert_eq!(
        verify_lookup_membership(LookupTree::Coin, &root, &swapped.to_bytes(), &number_1, 1),
        Err(WitnessError::Root)
    );
    let mut moved = LookupWitness::from_bytes(&member).unwrap();
    moved.index_position ^= 1;
    assert_eq!(
        verify_lookup_membership(LookupTree::Coin, &root, &moved.to_bytes(), &number_1, 1),
        Err(WitnessError::Root)
    );

    // The same for the coin marker set.
    let set = set_of(&named(&all, "coin-marker-set-two-markers"));
    let marker_root = set.root();
    let first: [u8; 32] = bytes("d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78");
    let second: [u8; 32] = bytes("f7476caa827fa1478d8f2a561e2638a7d4817793176eaced88798bf7d28fa806");
    let unspent = [0x88u8; 32];
    let absent = set.absence_witness(&unspent).unwrap().to_bytes();
    let spent = set.membership_witness(&first).unwrap().to_bytes();
    for name in ["coin-marker-set-empty", "coin-marker-set-one-marker", "coin-lookup-two-leaves"] {
        let other: [u8; 32] = bytes(&named(&all, name)["root"]);
        assert_eq!(verify_marker_absence(&other, &absent, &unspent), Err(WitnessError::Root), "{name}");
        assert_eq!(verify_marker_membership(&other, &spent, &first), Err(WitnessError::Root), "{name}");
    }
    assert_eq!(verify_marker_membership(&marker_root, &spent, &second), Err(WitnessError::NotTheEntry));
    assert_eq!(verify_marker_absence(&marker_root, &absent, &first), Err(WitnessError::NotTheLowLeaf));
    // The neighbouring leaf of the low leaf, which folds but is above 88..88.
    assert_eq!(verify_marker_absence(&marker_root, &spent, &unspent), Err(WitnessError::NotTheLowLeaf));
    let mut skipped = CoinMarkerWitness::from_bytes(&absent).unwrap();
    skipped.leaf.next_value = second;
    skipped.leaf.next_index = 2;
    assert_eq!(
        verify_marker_absence(&marker_root, &skipped.to_bytes(), &first),
        Err(WitnessError::Root),
        "skipping the spent marker in the linked list"
    );
    let mut swapped = CoinMarkerWitness::from_bytes(&spent).unwrap();
    swapped.siblings.swap(0, 1);
    assert_eq!(verify_marker_membership(&marker_root, &swapped.to_bytes(), &first), Err(WitnessError::Root));
    let mut moved = CoinMarkerWitness::from_bytes(&spent).unwrap();
    moved.position ^= 1;
    assert_eq!(verify_marker_membership(&marker_root, &moved.to_bytes(), &first), Err(WitnessError::Root));
    // A lookup witness is no marker-set witness, nor the other way round.
    assert!(matches!(
        verify_marker_absence(&marker_root, &absence, &unspent),
        Err(WitnessError::Length { .. })
    ));
    assert!(matches!(
        verify_lookup(LookupTree::Coin, &root, &absent, &number_2),
        Err(WitnessError::Length { .. })
    ));
}

#[test]
fn rebuilt_trees_refuse_what_the_chain_refuses() {
    let mut index = LookupIndex::new(LookupTree::Coin);
    let t = tag("74c5d993f5f018e3174926b2c8e8fb68");
    assert_eq!(index.insert(ZERO_TAG, 0), Err(InsertError::ZeroKey));
    assert_eq!(index.insert(t, NO_POSITION), Err(InsertError::PositionOutOfRange));
    assert_eq!(index.insert(t, 0), Ok(1));
    assert_eq!(index.insert(t, 0), Err(InsertError::Duplicate));
    assert!(index.lookup_witness(&ZERO_TAG).is_none());

    let mut set = CoinMarkerSet::new();
    assert_eq!(set.insert([0; 32], Some(1)), Err(InsertError::ZeroKey));
    assert_eq!(set.insert([7; 32], Some(NO_POSITION)), Err(InsertError::PositionOutOfRange));
    assert_eq!(set.insert([7; 32], None), Ok(1));
    assert_eq!(set.insert([7; 32], Some(1)), Err(InsertError::Duplicate));
    let witness = set.membership_witness(&[7; 32]).unwrap().to_bytes();
    assert_eq!(
        verify_marker_membership(&set.root(), &witness, &[7; 32]),
        Ok(SpentMarker {
            position: 1,
            appended: None,
        })
    );
}

// ---------------------------------------------------------------------------
// Block lookup digest, genesis values and global positions
// ---------------------------------------------------------------------------

fn lookup_list(v: &Block) -> BlockLookupList {
    BlockLookupList {
        coin_start: v["coin-start"].parse().unwrap(),
        coin_tags: list(&v["coin-tags"]).into_iter().map(tag).collect(),
        data_start: v["data-start"].parse().unwrap(),
        data_tags: list(&v["data-tags"]).into_iter().map(tag).collect(),
        coin_markers: list(&v["coin-markers"]).into_iter().map(bytes).collect(),
        data_markers: list(&v["data-markers"]).into_iter().map(bytes).collect(),
    }
}

#[test]
fn lookup_digest_vectors_give_the_same_encodings_and_digests() {
    let all = spec_05();
    let vectors = of_kind(&all, "lookup-digest");
    assert_eq!(names(&vectors), ["lookup-digest-empty", "lookup-digest-example", "lookup-digest-block-one-example"]);
    for v in &vectors {
        let name = &v["name"];
        let parsed = lookup_list(v);
        let encoding = parsed.encoding().unwrap();
        assert_eq!(hex(&encoding), v["encoding"], "{name}");
        assert_eq!(hex(&parsed.digest().unwrap()), v["digest"], "{name}");
        assert_eq!(BlockLookupList::decode(&encoding), Ok(parsed.clone()), "{name}");
        let digest: [u8; 32] = bytes(&v["digest"]);
        assert!(check_lookup_digest(&parsed, &digest));
        assert_eq!(BlockLookupList::decode(&encoding[..encoding.len() - 1]), Err(ListError::Length));
        let mut long = encoding.clone();
        long.push(0);
        assert_eq!(BlockLookupList::decode(&long), Err(ListError::Length));
        if !parsed.coin_tags.is_empty() {
            let mut moved = parsed.clone();
            moved.coin_start += 1;
            assert!(!check_lookup_digest(&moved, &digest), "{name}: the start is bound");
        }
    }
    let block_one = lookup_list(&named(&all, "lookup-digest-block-one-example"));
    let entries: Vec<(LookupTag, u64)> = block_one.coin_entries().collect();
    assert_eq!(
        entries,
        [(tag("74c5d993f5f018e3174926b2c8e8fb68"), 0), (tag("98f00763f51d9e982a7814297473729f"), 1)]
    );
    // The block's coin tags rebuild the two-leaf coin index of the vectors.
    let index = LookupIndex::from_entries(LookupTree::Coin, block_one.coin_entries()).unwrap();
    assert_eq!(hex(&index.root()), named(&all, "coin-lookup-two-leaves")["root"]);
    let data = LookupIndex::from_entries(LookupTree::Data, block_one.data_entries()).unwrap();
    assert_eq!(hex(&data.root()), named(&all, "data-lookup-one-leaf")["root"]);
}

#[test]
fn genesis_values_and_global_positions_match_their_vectors() {
    let all = spec_05();
    let genesis = named(&all, "header-genesis-new-fields");
    assert_eq!(genesis["kind"], "genesis-fields");
    assert_eq!(hex(&LookupTree::Coin.genesis_root()), genesis["coinLookupRoot"]);
    assert_eq!(hex(&LookupTree::Data.genesis_root()), genesis["dataLookupRoot"]);
    assert_eq!(hex(&CoinMarkerSet::genesis_root()), genesis["coinMarkerRoot"]);
    assert_eq!(hex(&BlockLookupList::default().digest().unwrap()), genesis["lookupDigest"]);

    let positions = named(&all, "global-position-examples");
    assert_eq!(positions["kind"], "global-position");
    let at = |tree_index: u64, position: u32| global_position(tree_index, position).and_then(position_bytes);
    assert_eq!(at(0, 0).map(|b| hex(&b)).unwrap(), positions["tree-0-position-0"]);
    assert_eq!(at(0, u32::MAX).map(|b| hex(&b)).unwrap(), positions["tree-0-position-4294967295"]);
    assert_eq!(at(1, 0).map(|b| hex(&b)).unwrap(), positions["tree-1-position-0"]);
    assert_eq!(at(255, u32::MAX - 1).map(|b| hex(&b)).unwrap(), positions["tree-255-position-4294967294"]);
    assert_eq!(positions["tree-255-position-4294967295"], "rejected");
    assert_eq!(global_position(255, u32::MAX), None);
    assert_eq!(global_position(256, 0), None);
    assert_eq!(global_position(u64::MAX, 0), None);
    assert_eq!(hex(&position_bytes(NO_POSITION).unwrap()), positions["none"]);
    assert_eq!(position_bytes(NO_POSITION + 1), None);
}

// ---------------------------------------------------------------------------
// Reorganisation
// ---------------------------------------------------------------------------

/// One block as a wallet reads it: the coin entries it appends and the coin
/// spends it inserts, each with the position its reveal appended.
#[derive(Clone)]
struct ReadBlock {
    entries: Vec<(LookupTag, u64)>,
    spends: Vec<([u8; 32], Option<u64>)>,
}

/// A wallet's rebuilt trees along its best chain: the state after every
/// block, so that a reorganisation rolls back to the common ancestor.
struct Followed {
    states: Vec<(LookupIndex, CoinMarkerSet)>,
}

impl Followed {
    fn genesis() -> Self {
        Self {
            states: vec![(LookupIndex::new(LookupTree::Coin), CoinMarkerSet::new())],
        }
    }

    fn connect(&mut self, block: &ReadBlock) {
        let (mut index, mut set) = self.states.last().unwrap().clone();
        for (tag, position) in &block.entries {
            index.insert(*tag, *position).unwrap();
        }
        for (marker, appended) in &block.spends {
            set.insert(*marker, *appended).unwrap();
        }
        self.states.push((index, set));
    }

    /// Disconnects every block above `ancestor` and connects `branch`.
    fn reorganise(&mut self, ancestor: usize, branch: &[ReadBlock]) {
        self.states.truncate(ancestor + 1);
        branch.iter().for_each(|block| self.connect(block));
    }

    fn marker_root(&self, height: usize) -> [u8; 32] {
        self.states[height].1.root()
    }
}

#[test]
fn a_spend_only_on_a_disconnected_block_is_absent_from_the_new_chains_marker_root() {
    let all = spec_05();
    let number_0 = tag("74c5d993f5f018e3174926b2c8e8fb68");
    let number_1 = tag("98f00763f51d9e982a7814297473729f");
    let marker_0: [u8; 32] = bytes("d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78");
    let other_coin = [0x88u8; 32];
    let other_tag = tag("9d77715bd859976996087ca266cf37b0");

    // Block 1, the common ancestor: the commit of number 0 at coin leaf 0.
    let ancestor = ReadBlock {
        entries: vec![(number_0, 0)],
        spends: vec![],
    };
    // Old block 2: the reveal of number 0, its remainder (number 1) at coin
    // leaf 1.
    let old = ReadBlock {
        entries: vec![(number_1, 1)],
        spends: vec![(marker_0, Some(1))],
    };
    // New blocks 2 and 3: another wallet's commit takes coin leaf 1, then
    // another coin's reveal appends coin leaf 2. Number 0 is not spent.
    let new_branch = [
        ReadBlock {
            entries: vec![(other_tag, 1)],
            spends: vec![],
        },
        ReadBlock {
            entries: vec![(tag("0102030405060708090a0b0c0d0e0f10"), 2)],
            spends: vec![(other_coin, Some(2))],
        },
    ];

    let mut chain = Followed::genesis();
    chain.connect(&ancestor);
    chain.connect(&old);
    let old_root = chain.marker_root(2);
    assert_eq!(hex(&old_root), named(&all, "coin-marker-set-one-marker")["root"]);
    let old_spend = chain.states[2].1.membership_witness(&marker_0).unwrap().to_bytes();
    assert_eq!(
        verify_marker_membership(&old_root, &old_spend, &marker_0),
        Ok(SpentMarker {
            position: 1,
            appended: Some(1),
        })
    );
    let old_entry = chain.states[2].0.membership_witness(&number_1, 1).unwrap().to_bytes();
    let old_lookup_root = chain.states[2].0.root();

    chain.reorganise(1, &new_branch);
    assert_eq!(chain.states.len(), 4);
    // The new block 2 spends nothing: its root is the genesis set's, the root
    // of `coin-marker-set-empty`.
    assert_eq!(hex(&chain.marker_root(2)), named(&all, "coin-marker-set-empty")["root"]);
    for height in 1..chain.states.len() {
        let (index, set) = &chain.states[height];
        let root = set.root();
        assert_ne!(root, old_root);
        assert!(!set.contains(&marker_0), "height {height}");
        assert!(set.membership_witness(&marker_0).is_none());
        let absence = set.absence_witness(&marker_0).expect("an unspent marker has an absence witness");
        assert_eq!(verify_marker_absence(&root, &absence.to_bytes(), &marker_0), Ok(()), "height {height}");
        // The disconnected block's membership witness no longer holds.
        assert_eq!(verify_marker_membership(&root, &old_spend, &marker_0), Err(WitnessError::Root));
        // Nor does its lookup entry: coin leaf 1 is another commitment now.
        assert!(index.membership_witness(&number_1, 1).is_none());
        assert_eq!(
            verify_lookup_membership(LookupTree::Coin, &index.root(), &old_entry, &number_1, 1),
            Err(WitnessError::Root)
        );
        let lookup = index.lookup_witness(&number_1).unwrap().to_bytes();
        assert_eq!(verify_lookup(LookupTree::Coin, &index.root(), &lookup, &number_1), Ok(LookupAnswer::Absent));
    }
    assert_ne!(chain.states[3].0.root(), old_lookup_root);

    // Every root equals that of a wallet that never saw the old block.
    let mut fresh = Followed::genesis();
    fresh.connect(&ancestor);
    new_branch.iter().for_each(|block| fresh.connect(block));
    for height in 0..fresh.states.len() {
        assert_eq!(chain.marker_root(height), fresh.marker_root(height));
        assert_eq!(chain.states[height].0.root(), fresh.states[height].0.root());
    }
    // Keeping the old block's spend, as a wallet that does not roll back
    // would, gives another root, under which the coin shows spent.
    let kept = CoinMarkerSet::from_spends([(marker_0, Some(1)), (other_coin, Some(2))]).unwrap();
    assert_ne!(kept.root(), chain.marker_root(3));
    let kept_spend = kept.membership_witness(&marker_0).unwrap().to_bytes();
    assert!(verify_marker_membership(&kept.root(), &kept_spend, &marker_0).is_ok());
    assert_eq!(verify_marker_membership(&chain.marker_root(3), &kept_spend, &marker_0), Err(WitnessError::Root));

    // A spend kept on the new chain is in its set.
    let reveal_again = ReadBlock {
        entries: vec![(number_1, 3)],
        spends: vec![(marker_0, Some(3))],
    };
    chain.connect(&reveal_again);
    let root = chain.marker_root(4);
    let spent = chain.states[4].1.membership_witness(&marker_0).unwrap().to_bytes();
    assert_eq!(
        verify_marker_membership(&root, &spent, &marker_0),
        Ok(SpentMarker {
            position: 2,
            appended: Some(3),
        })
    );
}
