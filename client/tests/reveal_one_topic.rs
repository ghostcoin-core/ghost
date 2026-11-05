//! The node writes both reveal versions under the one topic
//! `K("ghost/reveal-receipt/v1")` and tells them apart by data length
//! (ghost-node `core/ghostpriv/reveal.go`, `revealLogSize` and
//! `revealLogSizeV1`): 472 bytes with the 380-byte note of a version 2
//! reveal, 248 bytes with the 156-byte note of a version 1 reveal. The
//! client's reader reads them the same way and refuses any other length.

use ghost_client::hash::k;
use ghost_client::receipts::{
    check_block_receipts, check_leaves, check_markers, receipts_root, CheckedBlock, CoinRecord, ReceiptError,
    COIN_TREE_ACCOUNT, REVEAL_LOG_BYTES, REVEAL_V2_LOG_BYTES, TAG_REVEAL_RECEIPT,
};
use ghost_client::{pad_reveal_note, Commitment, Marker, TreeLeaf, NOTE_BYTES, REVEAL_NOTE_BYTES};

fn rlp_length(out: &mut Vec<u8>, len: usize, short: u8) {
    if len < 56 {
        out.push(short + len as u8);
    } else {
        let be = len.to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        out.push(short + 55 + (be.len() - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
}

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]);
    } else {
        rlp_length(&mut out, b.len(), 0x80);
        out.extend_from_slice(b);
    }
    out
}

fn rlp_uint(v: u64) -> Vec<u8> {
    let be = v.to_be_bytes();
    let skip = be.iter().take_while(|&&b| b == 0).count();
    rlp_bytes(&be[skip..])
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = Vec::new();
    rlp_length(&mut out, payload.len(), 0xc0);
    out.extend_from_slice(&payload);
    out
}

fn log(topics: &[[u8; 32]], data: &[u8]) -> Vec<u8> {
    let topics: Vec<Vec<u8>> = topics.iter().map(|t| rlp_bytes(t)).collect();
    rlp_list(&[rlp_bytes(&COIN_TREE_ACCOUNT), rlp_list(&topics), rlp_bytes(data)])
}

fn receipt(logs: &[Vec<u8>]) -> Vec<u8> {
    let body = rlp_list(&[rlp_uint(1), rlp_uint(21_000), rlp_bytes(&[0u8; 256]), rlp_list(logs)]);
    [vec![0x50], body].concat()
}

fn check(receipts: &[Vec<u8>]) -> Result<CheckedBlock, ReceiptError> {
    check_block_receipts(receipts, &receipts_root(receipts))
}

/// The one reveal topic, as the node hashes it.
fn reveal_topic() -> [u8; 32] {
    k("ghost/reveal-receipt/v1", &[])
}

const MARKER: [u8; 32] = [0x09; 32];
const LEAF: [u8; 32] = [0x08; 32];

/// A reveal log's data: tree index 0, `position`, the remainder's leaf,
/// `note`, the recipient and the amount out.
fn reveal_data(position: u32, note: &[u8]) -> Vec<u8> {
    [&0u32.to_be_bytes()[..], &position.to_be_bytes(), &LEAF, note, &[0x22; 20], &[0x01; 32]].concat()
}

/// A synthetic 380-byte note, none of its last 224 bytes zero.
fn whole_note() -> [u8; NOTE_BYTES] {
    core::array::from_fn(|i| ((i * 7 + 1) as u8) | 1)
}

fn one_reveal(data: &[u8]) -> Result<CoinRecord, ReceiptError> {
    let block = check(&[receipt(&[log(&[reveal_topic(), MARKER], data)])])?;
    assert_eq!(block.records().len(), 1);
    Ok(block.records()[0].clone())
}

#[test]
fn the_reveal_tag_is_the_nodes_one_topic() {
    assert_eq!(TAG_REVEAL_RECEIPT, "ghost/reveal-receipt/v1");
    assert_eq!(k(TAG_REVEAL_RECEIPT, &[]), reveal_topic());
    assert_eq!(REVEAL_V2_LOG_BYTES, 472);
    assert_eq!(REVEAL_LOG_BYTES, 248);
    // The reader names no other reveal receipt tag.
    let source = include_str!("../src/receipts.rs");
    let tags: Vec<&str> = source.match_indices("\"ghost/reveal-receipt/").map(|(at, _)| &source[at..at + 25]).collect();
    assert!(!tags.is_empty());
    assert!(tags.iter().all(|tag| *tag == "\"ghost/reveal-receipt/v1\""), "{tags:?}");
}

#[test]
fn a_472_byte_reveal_log_reads_as_version_2() {
    let note = whole_note();
    let data = reveal_data(1, &note);
    assert_eq!(data.len(), 472);
    let record = one_reveal(&data).expect("a version 2 reveal log under the one reveal topic is read");
    let CoinRecord::Reveal { remainder, marker, recipient, out } = &record else {
        panic!("a reveal log is a reveal record");
    };
    assert_eq!(remainder.note, note, "the 380-byte note whole, not padded or cut");
    assert_eq!((remainder.tree_index, remainder.position), (0, 1));
    assert_eq!(remainder.leaf, Commitment::from_bytes(LEAF));
    assert_eq!(remainder.salt, None);
    assert_eq!(*marker, Marker::from_bytes(MARKER));
    assert_eq!(*recipient, [0x22; 20]);
    assert_eq!(*out, [0x01; 32]);

    // The leaf run the node serves checks against it, every note byte
    // counted, and so does the spent marker.
    let block = check(&[receipt(&[log(&[reveal_topic(), MARKER], &data)])]).unwrap();
    let run = vec![TreeLeaf { commitment: Commitment::from_bytes(LEAF), note, salt: None }];
    let blocks = [block];
    assert_eq!(check_leaves(&blocks, 0, 1, &run), Ok(()));
    assert_eq!(check_markers(&blocks, &[Marker::from_bytes(MARKER)]), Ok(()));
    for byte in [0, REVEAL_NOTE_BYTES - 1, REVEAL_NOTE_BYTES, NOTE_BYTES - 1] {
        let mut changed = run.clone();
        changed[0].note[byte] ^= 1;
        assert_eq!(check_leaves(&blocks, 0, 1, &changed), Err(ReceiptError::NoteMismatch { position: 1 }), "byte {byte}");
    }
}

#[test]
fn a_248_byte_reveal_log_still_reads_as_version_1() {
    let short: [u8; REVEAL_NOTE_BYTES] = whole_note()[..REVEAL_NOTE_BYTES].try_into().unwrap();
    let data = reveal_data(1, &short);
    assert_eq!(data.len(), 248);
    let record = one_reveal(&data).expect("a version 1 reveal log is read");
    assert_eq!(record.appended().note, pad_reveal_note(&short), "the 156-byte note zero-padded to 380");
    assert!(record.appended().note[REVEAL_NOTE_BYTES..].iter().all(|&b| b == 0));
    assert_eq!(record.marker(), Some(&Marker::from_bytes(MARKER)));
}

#[test]
fn a_reveal_log_of_any_other_length_is_refused() {
    let v2 = reveal_data(1, &whole_note());
    for length in [0, 40, 247, 249, 264, 380, 468, 471, 473, 488] {
        let mut data = v2.clone();
        data.resize(length, 0);
        assert!(
            matches!(
                one_reveal(&data),
                Err(ReceiptError::CoinLog { reason: "a reveal log's data is not its length", .. })
            ),
            "{length} bytes"
        );
    }
    // Two topics exactly, and no other first topic.
    let other_topic = k("ghost/reveal-receipt/v3", &[]);
    for topics in [vec![reveal_topic()], vec![reveal_topic(), MARKER, MARKER], vec![other_topic, MARKER]] {
        assert!(
            matches!(check(&[receipt(&[log(&topics, &v2)])]), Err(ReceiptError::CoinLog { .. })),
            "{} topics",
            topics.len()
        );
    }
}
