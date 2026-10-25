//! The commit log of a salted (version 2) commit: 244 bytes, the salt after
//! the note. The salt is read into the record and the run's salt beside each
//! leaf is checked against it.

use ghost_client::hash::k;
use ghost_client::receipts::{
    check_block_receipts, check_leaves, receipts_root, CheckedBlock, CoinRecord, ReceiptError,
    COIN_TREE_ACCOUNT, REVEAL_LOG_BYTES, SALTED_COMMIT_LOG_BYTES,
};
use ghost_client::{
    encrypt_note, restore_coins, Amount, Commitment, Current, NoteContents, PhantomKey, Rule, Salt,
    TreeLeaf, NOTE_BYTES, SALT_BYTES,
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

fn commit_topic() -> [u8; 32] {
    k("ghost/commit-receipt/v1", &[])
}

fn commit_data(position: u32, leaf: &Commitment, note: &[u8; NOTE_BYTES], salt: Option<&Salt>) -> Vec<u8> {
    let mut data = [&0u32.to_be_bytes()[..], &position.to_be_bytes(), leaf.as_bytes(), &[0x05; 32], note].concat();
    if let Some(salt) = salt {
        data.extend_from_slice(salt.as_bytes());
    }
    data
}

fn reveal_data(position: u32, leaf: &Commitment, note: &[u8; NOTE_BYTES]) -> Vec<u8> {
    [&0u32.to_be_bytes()[..], &position.to_be_bytes(), leaf.as_bytes(), note, &[0x22; 20], &[0x01; 32]].concat()
}

fn check(receipts: &[Vec<u8>]) -> Result<CheckedBlock, ReceiptError> {
    check_block_receipts(receipts, &receipts_root(receipts))
}

#[test]
fn salted_commit_log_carries_the_salt() {
    assert_eq!(SALTED_COMMIT_LOG_BYTES, 244);

    let key = PhantomKey::parse(DIGITS).unwrap_or_else(|_| panic!("the example key parses"));
    let mut rng = StdRng::seed_from_u64(244);
    let value = Amount::new(1_000_000_000).unwrap();

    // Position 0: another wallet's salted commit. Position 1: the key's
    // salted commit. Position 2: a reveal's remainder.
    let old_leaf = Commitment::from_bytes([0x10; 32]);
    let old_note = [0x11; NOTE_BYTES];
    let old_salt = Salt::from_bytes([0x12; SALT_BYTES]);
    let commit = key.salted_coin_commit(0, value, Rule::EMPTY, &mut rng).unwrap();
    let salt = commit.salt;
    let note = encrypt_note(
        &key.note_key(),
        CHAIN_ID,
        &commit.commitment,
        &NoteContents::salted_coin(0, value, Rule::EMPTY, salt),
        &mut rng,
    );
    let remainder_leaf = Commitment::from_bytes([0x30; 32]);
    let remainder_note = [0x33; NOTE_BYTES];

    let salted = commit_data(1, &commit.commitment, &note, Some(&salt));
    assert_eq!(salted.len(), SALTED_COMMIT_LOG_BYTES);
    assert_eq!(&salted[SALTED_COMMIT_LOG_BYTES - SALT_BYTES..], salt.as_bytes());
    let receipts = vec![
        receipt(&[log(&[commit_topic()], &commit_data(0, &old_leaf, &old_note, Some(&old_salt)))]),
        receipt(&[
            log(&[commit_topic()], &salted),
            log(&[k("ghost/reveal-receipt/v1", &[]), [9; 32]], &reveal_data(2, &remainder_leaf, &remainder_note)),
        ]),
    ];
    let block = check(&receipts).expect("an honest block checks");
    let records = block.records();
    assert_eq!(records.len(), 3);
    assert!(matches!(&records[0], CoinRecord::Commit { .. }));
    assert_eq!(records[0].appended().salt, Some(old_salt));
    let CoinRecord::Commit { appended, v } = &records[1] else {
        panic!("a salted commit is a commit record");
    };
    assert_eq!(appended.salt, Some(salt));
    assert_eq!(appended.leaf, commit.commitment);
    assert_eq!(appended.note, note);
    assert_eq!(*v, [0x05; 32]);
    assert!(matches!(&records[2], CoinRecord::Reveal { .. }));
    assert_eq!(records[2].appended().salt, None);

    // The run of leaves the node serves, the salt beside the commit's leaf.
    let run = vec![
        TreeLeaf { commitment: old_leaf, note: old_note, salt: Some(old_salt) },
        TreeLeaf { commitment: commit.commitment, note, salt: Some(salt) },
        TreeLeaf { commitment: remainder_leaf, note: remainder_note, salt: None },
    ];
    let blocks = [block];
    assert_eq!(check_leaves(&blocks, 0, 0, &run), Ok(()));

    // Restore reads the checked run and finds the salted coin.
    let Current::One(found) = restore_coins(&key, CHAIN_ID, &run, &[]).current else {
        panic!("the salted commit restores");
    };
    assert_eq!((found.position, found.salt), (1, salt));

    // A salt beside a leaf that is not the record's is refused.
    let mut other = *salt.as_bytes();
    other[SALT_BYTES - 1] ^= 1;
    let cases = [
        (1, Some(Salt::from_bytes(other))),
        (1, None),
        (0, Some(salt)),
        (0, None),
        (2, Some(salt)),
    ];
    for (position, changed) in cases {
        let mut bad = run.clone();
        bad[position].salt = changed;
        assert_eq!(
            check_leaves(&blocks, 0, 0, &bad),
            Err(ReceiptError::SaltMismatch { position: position as u32 }),
            "position {position}"
        );
    }

    // A commit log of neither length, and a reveal log with a salt, are
    // refused.
    let refused = [
        log(&[commit_topic()], &salted[..SALTED_COMMIT_LOG_BYTES - 1]),
        log(&[commit_topic()], &[&salted[..], &[0]].concat()),
        log(
            &[k("ghost/reveal-receipt/v1", &[]), [9; 32]],
            &[&reveal_data(2, &remainder_leaf, &remainder_note)[..], salt.as_bytes()].concat(),
        ),
    ];
    assert_eq!(REVEAL_LOG_BYTES + SALT_BYTES, 264);
    for (i, bad) in refused.iter().enumerate() {
        assert!(
            matches!(check(&[receipt(&[bad.clone()])]), Err(ReceiptError::CoinLog { .. })),
            "case {i} is refused"
        );
    }
}

#[test]
fn unsalted_commit_log_is_refused() {
    let leaf = Commitment::from_bytes([0x40; 32]);
    let note = [0x44; NOTE_BYTES];
    let salt = Salt::from_bytes([0x45; SALT_BYTES]);

    // The 228-byte log an unsalted version 1 commit had: the salted log
    // without its salt.
    let unsalted = commit_data(0, &leaf, &note, None);
    assert_eq!(unsalted.len(), 228);
    let salted = commit_data(0, &leaf, &note, Some(&salt));
    assert_eq!(salted.len(), SALTED_COMMIT_LOG_BYTES);
    assert_eq!(salted[..228], unsalted[..]);

    let block = |data: &[u8]| vec![receipt(&[log(&[commit_topic()], data)])];
    let wrong_length = ReceiptError::CoinLog { receipt: 0, log: 0, reason: "a commit log's data is not its length" };
    assert_eq!(check(&block(&unsalted)).err(), Some(wrong_length));
    // The same error as any other wrong length.
    assert_eq!(check(&block(&salted[..SALTED_COMMIT_LOG_BYTES - 1])).err(), Some(wrong_length));

    // The same block with the 244-byte log checks and carries the salt.
    let checked = check(&block(&salted)).expect("the salted commit log checks");
    assert_eq!(checked.records().len(), 1);
    assert_eq!(checked.records()[0].appended().leaf, leaf);
    assert_eq!(checked.records()[0].appended().salt, Some(salt));
}
