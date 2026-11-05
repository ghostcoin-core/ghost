//! The receipt log of the version 2 ordinary reveal (spec 10, section 4): its
//! remainder note is the 380-byte note version 3 the reveal binds, so its log
//! carries that note whole, under its own first topic
//! `K("ghost/reveal-receipt/v2")`, in 472 bytes, and its record holds the note
//! as the tree stores it, unpadded. The version 1 reveal log keeps its 248
//! bytes and its 156-byte note.

use ghost_client::hash::k;
use ghost_client::receipts::{
    check_block_receipts, check_leaves, check_markers, receipts_root, CheckedBlock, CoinRecord, ReceiptError,
    COIN_TREE_ACCOUNT, REVEAL_LOG_BYTES, REVEAL_V2_LOG_BYTES, TAG_REVEAL_RECEIPT, TAG_REVEAL_RECEIPT_V2,
};
use ghost_client::{
    encrypt_note, restore_coins, Amount, Capsule, Commitment, Current, Marker, NoteContents, PhantomKey, Rule, Salt,
    TreeLeaf, NOTE_BYTES, REVEAL_NOTE_BYTES, SALT_BYTES,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// The example words key of spec 01, section 5, as its digit view. Example
/// only.
const DIGITS: &str = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
const CHAIN_ID: u64 = 1234;

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

fn commit_data(position: u32, leaf: &Commitment, note: &[u8], salt: &Salt) -> Vec<u8> {
    [&0u32.to_be_bytes()[..], &position.to_be_bytes(), leaf.as_bytes(), &[0x05; 32], note, salt.as_bytes()].concat()
}

fn reveal_data(position: u32, leaf: &Commitment, note: &[u8]) -> Vec<u8> {
    [&0u32.to_be_bytes()[..], &position.to_be_bytes(), leaf.as_bytes(), note, &[0x22; 20], &[0x01; 32]].concat()
}

fn check(receipts: &[Vec<u8>]) -> Result<CheckedBlock, ReceiptError> {
    check_block_receipts(receipts, &receipts_root(receipts))
}

fn v2_topic() -> [u8; 32] {
    k(TAG_REVEAL_RECEIPT_V2, &[])
}

#[test]
fn a_version_2_reveal_log_carries_the_whole_note() {
    assert_eq!(TAG_REVEAL_RECEIPT_V2, "ghost/reveal-receipt/v2");
    assert_eq!(REVEAL_V2_LOG_BYTES, 4 + 4 + 32 + 380 + 20 + 32);
    assert_eq!(REVEAL_V2_LOG_BYTES, 472);
    assert_eq!(REVEAL_LOG_BYTES, 248, "the version 1 log keeps its length");

    let key = PhantomKey::parse(DIGITS).unwrap_or_else(|_| panic!("the example key parses"));
    let mut rng = StdRng::seed_from_u64(472);
    let value = Amount::new(1_000_000_000).unwrap();

    // Position 0: the key's salted commit. Position 1: the remainder a
    // version 2 reveal of it made, its note a note version 3 with the empty
    // rule's capsule, 380 bytes, and no salt beside the leaf.
    let commit = key.salted_coin_commit(0, value, Rule::EMPTY, &mut rng).unwrap();
    let note = encrypt_note(
        &key.note_key(),
        CHAIN_ID,
        &commit.commitment,
        &NoteContents::salted_coin(0, value, Rule::EMPTY, commit.salt),
        &Capsule::empty(),
        &mut rng,
    );
    let left = Amount::new(400_000_000).unwrap();
    let remainder_salt = Salt::from_bytes([0x31; SALT_BYTES]);
    let remainder = key.coin_commit_with_salt(1, left, Rule::EMPTY, remainder_salt).unwrap();
    let remainder_note = encrypt_note(
        &key.note_key(),
        CHAIN_ID,
        &remainder.commitment,
        &NoteContents::salted_coin(1, left, Rule::EMPTY, remainder_salt),
        &Capsule::empty(),
        &mut rng,
    );
    assert!(remainder_note[REVEAL_NOTE_BYTES..].iter().any(|&b| b != 0), "a whole note, not a padded one");
    let marker = *commit.marker.as_bytes();

    let reveal_log = reveal_data(1, &remainder.commitment, &remainder_note);
    assert_eq!(reveal_log.len(), REVEAL_V2_LOG_BYTES);
    let receipts = vec![
        receipt(&[log(&[k("ghost/commit-receipt/v1", &[])], &commit_data(0, &commit.commitment, &note, &commit.salt))]),
        receipt(&[log(&[v2_topic(), marker], &reveal_log)]),
    ];
    let block = check(&receipts).expect("an honest block checks");
    let records = block.records();
    assert_eq!(records.len(), 2);
    let CoinRecord::Reveal { remainder: appended, marker: spent, recipient, out } = &records[1] else {
        panic!("a version 2 reveal log is a reveal record");
    };
    assert_eq!(appended.position, 1);
    assert_eq!(appended.leaf, remainder.commitment);
    assert_eq!(appended.note, remainder_note, "the note whole, as the tree stores it");
    assert_eq!(appended.salt, None);
    assert_eq!(*spent, Marker::from_bytes(marker));
    assert_eq!(*recipient, [0x22; 20]);
    assert_eq!(*out, [0x01; 32]);

    // The run the node serves checks against the records, and the spent
    // marker against the reveal's.
    let run = vec![
        TreeLeaf { commitment: commit.commitment, note, salt: Some(commit.salt) },
        TreeLeaf { commitment: remainder.commitment, note: remainder_note, salt: None },
    ];
    let blocks = [block];
    assert_eq!(check_leaves(&blocks, 0, 0, &run), Ok(()));
    assert_eq!(check_markers(&blocks, &[commit.marker]), Ok(()));
    for byte in [0, REVEAL_NOTE_BYTES, NOTE_BYTES - 1] {
        let mut changed = run.clone();
        changed[1].note[byte] ^= 1;
        assert_eq!(check_leaves(&blocks, 0, 0, &changed), Err(ReceiptError::NoteMismatch { position: 1 }), "byte {byte}");
    }

    // Restore reads the checked run: the remainder is the current coin.
    let Current::One(found) = restore_coins(&key, CHAIN_ID, 0, &run, &[commit.marker]).unwrap().current else {
        panic!("the remainder restores");
    };
    assert_eq!((found.position, found.number, found.salt), (1, 1, remainder_salt));
    assert_eq!(found.amount, left);
    assert!(found.capsule == Capsule::empty());
}

#[test]
fn a_reveal_log_off_its_layout_is_refused() {
    let leaf = Commitment::from_bytes([0x40; 32]);
    let note = [0x44; NOTE_BYTES];
    let v2 = reveal_data(3, &leaf, &note);
    let v1 = reveal_data(3, &leaf, &note[..REVEAL_NOTE_BYTES]);
    assert!(check(&[receipt(&[log(&[v2_topic(), [9; 32]], &v2)])]).is_ok());
    assert!(check(&[receipt(&[log(&[k(TAG_REVEAL_RECEIPT, &[]), [9; 32]], &v1)])]).is_ok());

    let refused = [
        // The 156-byte note under the version 2 topic.
        log(&[v2_topic(), [9; 32]], &v1),
        // The 380-byte note under the version 1 topic.
        log(&[k(TAG_REVEAL_RECEIPT, &[]), [9; 32]], &v2),
        // A byte short or over, a salt after it.
        log(&[v2_topic(), [9; 32]], &v2[1..]),
        log(&[v2_topic(), [9; 32]], &[&v2[..], &[0]].concat()),
        log(&[v2_topic(), [9; 32]], &[&v2[..], &[0x45; SALT_BYTES]].concat()),
        // No marker, or a third topic.
        log(&[v2_topic()], &v2),
        log(&[v2_topic(), [9; 32], [9; 32]], &v2),
    ];
    for (i, bad) in refused.iter().enumerate() {
        assert!(
            matches!(check(&[receipt(&[bad.clone()])]), Err(ReceiptError::CoinLog { .. })),
            "case {i} is refused"
        );
    }
}
