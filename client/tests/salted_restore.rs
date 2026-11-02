//! Restore of salted (version 2) coins from the digits and the leaf records,
//! and the reveal of a restored salted coin, checked with the proofs crate's
//! own verifier. A leaf whose note is an unsalted version 1 note is
//! discarded, never restored.

use ghost_client::note::{chacha20poly1305_seal, note_associated_data, NOTE_PLAINTEXT_BYTES};
use ghost_client::reveal::{ChainParams, CoinReveal, ProofError, TREE_DEPTH};
use ghost_client::{
    decrypt_note, encrypt_note, full_reveal, partial_reveal, restore_coins, Amount, Commitment,
    Content, Current, DiscardReason, KeyFormat, Marker, NoteContents, NoteError, OwnedCoin,
    PhantomKey, RevealError, RevealTerms, Rule, Salt, TreeLeaf, COIN_V2, DATA_V2, NOTE_BYTES,
    SALT_BYTES,
};
use ghost_proofs::{empty_leaf, tree_node, verify_coin_reveal, verify_salted_coin_reveal, Tree, PROTOCOL_VERSION_1};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// The example words key of spec 01, section 5, as its digit view. Example
/// only.
const DIGITS: &str = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
const CHAIN_ID: u64 = 1234;
const COMMITTED: u128 = 1_000_000_000;
const PAID: u128 = 100_000_000;
const FEE: u128 = 21_000;

fn params() -> ChainParams {
    ChainParams {
        chain_id: CHAIN_ID.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [7; 32],
    }
}

/// A fresh instance of the example key, as the user types the digits.
fn key() -> PhantomKey {
    PhantomKey::parse(DIGITS).unwrap_or_else(|_| panic!("the example key parses"))
}

fn amount(wei: u128) -> Amount {
    Amount::new(wei).unwrap()
}

fn zk(rng: &mut StdRng) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn terms(root: [u8; 32]) -> RevealTerms {
    RevealTerms {
        root,
        recipient: [5; 20],
        fee: amount(FEE),
    }
}

/// The root over `leaves` (position order, the rest empty) and the path of
/// the leaf at `position`.
fn root_and_path(leaves: &[TreeLeaf], position: u32) -> ([u8; 32], [[u8; 32]; TREE_DEPTH]) {
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| *leaf.commitment.as_bytes()).collect();
    let mut zero = empty_leaf();
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut index = position as usize;
    for (depth, sibling) in path.iter_mut().enumerate() {
        *sibling = level.get(index ^ 1).copied().unwrap_or(zero);
        level = level
            .chunks(2)
            .map(|pair| tree_node(Tree::Coin, depth as u8, &pair[0], pair.get(1).unwrap_or(&zero)))
            .collect();
        zero = tree_node(Tree::Coin, depth as u8, &zero, &zero);
        index >>= 1;
    }
    (level[0], path)
}

/// The coin tree and the spent markers as the chain holds them.
struct Chain {
    leaves: Vec<TreeLeaf>,
    spent: Vec<Marker>,
}

impl Chain {
    fn new() -> Self {
        Self { leaves: Vec::new(), spent: Vec::new() }
    }

    fn push(&mut self, leaf: TreeLeaf) -> u32 {
        self.leaves.push(leaf);
        (self.leaves.len() - 1) as u32
    }

    /// A new salted commit of `key`'s number 0: its note is note version 2
    /// and the record carries the salt beside the leaf.
    fn salted_commit(&mut self, key: &PhantomKey, wei: u128, rng: &mut StdRng) -> (u32, Salt) {
        let commit = key.salted_coin_commit(0, amount(wei), Rule::EMPTY, rng).unwrap();
        let salt = commit.salt;
        let contents = NoteContents::salted_coin(0, amount(wei), Rule::EMPTY, salt);
        let note = encrypt_note(&key.note_key(), CHAIN_ID, &commit.commitment, &contents, rng);
        let position = self.push(TreeLeaf { commitment: commit.commitment, note, salt: Some(salt) });
        (position, salt)
    }

    /// Includes a reveal: its marker is spent, its remainder appended with
    /// no salt beside it (a remainder's salt is only in its note).
    fn include(&mut self, reveal: &CoinReveal) -> u32 {
        self.spent.push(Marker::from_bytes(reveal.marker));
        self.push(TreeLeaf {
            commitment: Commitment::from_bytes(reveal.remainder),
            note: reveal.remainder_note,
            salt: None,
        })
    }
}

#[test]
fn restored_salted_coin_reveals_with_its_salt() {
    let mut rng = StdRng::seed_from_u64(0x5a17ed);
    let other = PhantomKey::generate(KeyFormat::Words, &mut rng);
    let mut chain = Chain::new();
    chain.salted_commit(&other, 5_000, &mut rng);
    let (position, salt) = chain.salted_commit(&key(), COMMITTED, &mut rng);
    chain.salted_commit(&other, 6_000, &mut rng);

    // Restore from the digits alone finds the coin and its salt.
    let restored = restore_coins(&key(), CHAIN_ID, 0, &chain.leaves, &chain.spent).unwrap();
    assert!(restored.discarded.is_empty());
    let Current::One(found) = restored.current else {
        panic!("one unspent salted coin");
    };
    let commit = key().coin_commit_with_salt(0, amount(COMMITTED), Rule::EMPTY, salt).unwrap();
    assert_eq!((found.number, found.amount.wei(), found.position), (0, COMMITTED, position));
    assert_eq!(found.salt, salt);
    assert_eq!(found.commitment, commit.commitment);
    assert_eq!(found.marker, commit.marker);

    // The coin as a reveal takes it carries the salt.
    let (root, path) = root_and_path(&chain.leaves, position);
    let coin = found.owned(path);
    assert_eq!(coin.salt, salt);

    // With another salt the coin does not open its leaf, and the reveal is
    // refused before proving.
    for wrong in [Salt::from_bytes([0; SALT_BYTES]), Salt::from_bytes([0x42; SALT_BYTES])] {
        let coin = OwnedCoin { salt: wrong, ..found.owned(path) };
        let refused = partial_reveal(&params(), &key(), &coin, &terms(root), amount(PAID), &mut rng, [0; 32]);
        assert_eq!(refused.err(), Some(RevealError::Proof(ProofError::NotInTree)));
    }

    // With it, the reveal proves and the salted verifier accepts it.
    let zk_randomness = zk(&mut rng);
    let built = partial_reveal(&params(), &key(), &coin, &terms(root), amount(PAID), &mut rng, zk_randomness).unwrap();
    assert_eq!(verify_salted_coin_reveal(&params(), &built.reveal, &built.proof), Ok(()));
    assert!(verify_coin_reveal(&params(), &built.reveal, &built.proof).is_err());
    assert_eq!(&built.reveal.marker, commit.marker.as_bytes());

    // The remainder is salted under a fresh salt, carried in its note.
    let left = COMMITTED - PAID - FEE;
    let remainder_salt = built.remainder.salt;
    assert_ne!(remainder_salt, salt);
    let expected = key().coin_commit_with_salt(1, amount(left), Rule::EMPTY, remainder_salt).unwrap();
    assert_eq!(built.remainder.number, 1);
    assert_eq!(built.remainder.commitment, expected.commitment);
    assert_eq!(built.remainder.marker, expected.marker);
    assert_eq!(&built.reveal.remainder, expected.commitment.as_bytes());
    let note = decrypt_note(&key().note_key(), CHAIN_ID, &expected.commitment, &built.reveal.remainder_note).unwrap();
    assert_eq!(note.type_tag, COIN_V2);
    assert_eq!(note.salt, remainder_salt);
    assert_eq!((note.number, note.amount.wei()), (1, left));

    // Once included, restore finds the remainder from its note's salt alone.
    let remainder_position = chain.include(&built.reveal);
    let restored = restore_coins(&key(), CHAIN_ID, 0, &chain.leaves, &chain.spent).unwrap();
    assert_eq!(restored.found.len(), 2);
    let Current::One(current) = restored.current else {
        panic!("the remainder is the one unspent coin");
    };
    assert_eq!((current.number, current.amount.wei(), current.position), (1, left, remainder_position));
    assert_eq!(current.salt, remainder_salt);

    // And the restored remainder reveals in turn, with its salt.
    let (root, path) = root_and_path(&chain.leaves, remainder_position);
    let zk_randomness = zk(&mut rng);
    let built = full_reveal(&params(), &key(), &current.owned(path), &terms(root), &mut rng, zk_randomness).unwrap();
    assert_eq!(verify_salted_coin_reveal(&params(), &built.reveal, &built.proof), Ok(()));
    assert_eq!(&built.reveal.marker, current.marker.as_bytes());
    assert_ne!(built.remainder.salt, remainder_salt);
}

#[test]
fn leaf_without_a_salt_beside_it_restores_from_its_note() {
    // A reveal's remainder has no salt beside its leaf: restore reads the
    // salt from its note.
    let mut rng = StdRng::seed_from_u64(0x01d);
    let salt = Salt::from_bytes([9; SALT_BYTES]);
    let commit = key().coin_commit_with_salt(1, amount(COMMITTED), Rule::EMPTY, salt).unwrap();
    let contents = NoteContents::salted_coin(1, amount(COMMITTED), Rule::EMPTY, salt);
    let note = encrypt_note(&key().note_key(), CHAIN_ID, &commit.commitment, &contents, &mut rng);
    let mut chain = Chain::new();
    let position = chain.push(TreeLeaf { commitment: commit.commitment, note, salt: None });

    let restored = restore_coins(&key(), CHAIN_ID, 0, &chain.leaves, &chain.spent).unwrap();
    assert!(restored.discarded.is_empty());
    let Current::One(found) = restored.current else {
        panic!("the remainder restores");
    };
    assert_eq!((found.number, found.amount.wei(), found.position), (1, COMMITTED, position));
    assert_eq!(found.salt, salt);
    assert_eq!(found.commitment, commit.commitment);
    assert_eq!(found.marker, commit.marker);
    assert_eq!(found.owned([[0; 32]; TREE_DEPTH]).salt, salt);

    // Spent, it is not current.
    chain.spent.push(commit.marker);
    let restored = restore_coins(&key(), CHAIN_ID, 0, &chain.leaves, &chain.spent).unwrap();
    assert!(matches!(restored.current, Current::None));
    assert_eq!(restored.found.len(), 1);
}

/// A version 1 coin note's plaintext, laid out as version 1 wrote it:
/// `0x01 || 0x01 || 0x0101 || i (8) || v (32) || cf (32) || content length (8)
/// || rule (32) || 12 zero bytes`.
fn version_1_plaintext(number: u64, wei: u128) -> [u8; NOTE_PLAINTEXT_BYTES] {
    let mut plaintext = [0u8; NOTE_PLAINTEXT_BYTES];
    plaintext[..4].copy_from_slice(&[0x01, 0x01, 0x01, 0x01]);
    plaintext[4..12].copy_from_slice(&number.to_be_bytes());
    plaintext[28..44].copy_from_slice(&wei.to_be_bytes());
    plaintext
}

/// `plaintext` sealed under `key`'s note key for `leaf`, as a note on the
/// chain.
fn sealed(key: &PhantomKey, leaf: &Commitment, plaintext: [u8; NOTE_PLAINTEXT_BYTES]) -> [u8; NOTE_BYTES] {
    let mut note = [0u8; NOTE_BYTES];
    note[..12].copy_from_slice(&[3; 12]);
    note[12..140].copy_from_slice(&plaintext);
    let tag = chacha20poly1305_seal(
        key.note_key().as_bytes(),
        &[3; 12],
        &note_associated_data(CHAIN_ID, leaf),
        &mut note[12..140],
    );
    note[140..].copy_from_slice(&tag);
    note
}

#[test]
fn version_1_note_is_discarded_on_restore() {
    let mut rng = StdRng::seed_from_u64(0x01);
    let leaf = Commitment::from_bytes([0x71; 32]);
    let note = sealed(&key(), &leaf, version_1_plaintext(0, COMMITTED));
    // The note authenticates under the key: it is the key's, not another's.
    assert_eq!(decrypt_note(&key().note_key(), CHAIN_ID, &leaf, &note).err(), Some(NoteError::UnknownVersion));

    for beside in [None, Some(Salt::from_bytes([9; SALT_BYTES]))] {
        let mut chain = Chain::new();
        let position = chain.push(TreeLeaf { commitment: leaf, note, salt: beside });
        let restored = restore_coins(&key(), CHAIN_ID, 0, &chain.leaves, &chain.spent).unwrap();
        assert!(restored.found.is_empty());
        assert!(matches!(restored.current, Current::None));
        assert_eq!(restored.discarded.len(), 1);
        assert_eq!(restored.discarded[0].position, position);
        assert_eq!(restored.discarded[0].reason, DiscardReason::Malformed(NoteError::UnknownVersion));
    }

    // Beside a salted coin of the key, only the salted coin is found.
    let mut chain = Chain::new();
    chain.push(TreeLeaf { commitment: leaf, note, salt: None });
    let (position, salt) = chain.salted_commit(&key(), COMMITTED, &mut rng);
    let restored = restore_coins(&key(), CHAIN_ID, 0, &chain.leaves, &chain.spent).unwrap();
    let Current::One(found) = restored.current else {
        panic!("the salted coin restores");
    };
    assert_eq!((found.position, found.salt), (position, salt));
    assert_eq!(restored.found.len(), 1);
    assert_eq!(restored.discarded.len(), 1);
    assert_eq!(restored.discarded[0].position, 0);
    assert_eq!(restored.discarded[0].reason, DiscardReason::Malformed(NoteError::UnknownVersion));

    // Under another key the note does not authenticate and is passed over.
    let other = PhantomKey::generate(KeyFormat::Words, &mut rng);
    let restored = restore_coins(&other, CHAIN_ID, 0, &chain.leaves, &chain.spent).unwrap();
    assert!(restored.found.is_empty() && restored.discarded.is_empty());
}

#[test]
fn a_salt_beside_the_leaf_that_disagrees_is_discarded() {
    let mut rng = StdRng::seed_from_u64(0xbad);
    let mut chain = Chain::new();
    let (position, salt) = chain.salted_commit(&key(), COMMITTED, &mut rng);

    // The record's salt differs from the note's: discarded, never trusted.
    let mut changed = chain.leaves.clone();
    let mut other = *salt.as_bytes();
    other[0] ^= 1;
    changed[position as usize].salt = Some(Salt::from_bytes(other));
    let restored = restore_coins(&key(), CHAIN_ID, 0, &changed, &[]).unwrap();
    assert!(restored.found.is_empty());
    assert!(matches!(restored.current, Current::None));
    assert_eq!(restored.discarded.len(), 1);
    assert_eq!(restored.discarded[0].position, position);
    assert_eq!(restored.discarded[0].reason, DiscardReason::LeafMismatch);

    // A record without a salt beside it reads the salt from the note.
    let mut bare = chain.leaves.clone();
    bare[position as usize].salt = None;
    let restored = restore_coins(&key(), CHAIN_ID, 0, &bare, &[]).unwrap();
    assert_eq!(restored.found.len(), 1);
    assert_eq!(restored.found[0].salt, salt);

    // A note whose salt does not open the leaf is discarded.
    let leaf = chain.leaves[position as usize].commitment;
    let wrong = NoteContents::salted_coin(0, amount(COMMITTED), Rule::EMPTY, Salt::from_bytes(other));
    let note = encrypt_note(&key().note_key(), CHAIN_ID, &leaf, &wrong, &mut rng);
    let forged = vec![TreeLeaf { commitment: leaf, note, salt: None }];
    let restored = restore_coins(&key(), CHAIN_ID, 0, &forged, &[]).unwrap();
    assert!(restored.found.is_empty());
    assert_eq!(restored.discarded[0].reason, DiscardReason::LeafMismatch);

    // A salted data note in the coin tree is not a coin.
    let content = Content::new(b"Ghost example data".to_vec());
    let data = key().salted_data_commit(&content, Rule::EMPTY, &mut rng).unwrap();
    let contents = NoteContents {
        type_tag: DATA_V2,
        number: 0,
        amount: amount(0),
        content_fingerprint: data.content_fingerprint,
        content_length: content.len() as u64,
        rule: Rule::EMPTY,
        salt: data.salt,
    };
    let note = encrypt_note(&key().note_key(), CHAIN_ID, &data.commitment, &contents, &mut rng);
    let leaves = vec![TreeLeaf { commitment: data.commitment, note, salt: Some(data.salt) }];
    let restored = restore_coins(&key(), CHAIN_ID, 0, &leaves, &[]).unwrap();
    assert!(restored.found.is_empty());
    assert_eq!(restored.discarded[0].reason, DiscardReason::NotACoin);
}

#[test]
fn restore_in_a_second_tree_reports_the_tree_index() {
    // Two trees, each with a coin of the key at a different position among
    // other keys' coins, restored one tree at a time as the wallet does.
    let mut rng = StdRng::seed_from_u64(0x2_7ee5);
    let other = PhantomKey::generate(KeyFormat::Words, &mut rng);
    let mut first = Chain::new();
    let (first_position, first_salt) = first.salted_commit(&key(), COMMITTED, &mut rng);
    first.salted_commit(&other, 5_000, &mut rng);
    let mut second = Chain::new();
    second.salted_commit(&other, 6_000, &mut rng);
    second.salted_commit(&other, 7_000, &mut rng);
    let (second_position, second_salt) = second.salted_commit(&key(), PAID, &mut rng);
    assert_ne!(first_position, second_position);

    let in_first = restore_coins(&key(), CHAIN_ID, 0, &first.leaves, &first.spent).unwrap();
    let in_second = restore_coins(&key(), CHAIN_ID, 1, &second.leaves, &second.spent).unwrap();
    let Current::One(a) = in_first.current else {
        panic!("one coin in the first tree");
    };
    let Current::One(b) = in_second.current else {
        panic!("one coin in the second tree");
    };
    assert_eq!((a.tree_index, a.position, a.salt, a.amount.wei()), (0, first_position, first_salt, COMMITTED));
    assert_eq!((b.tree_index, b.position, b.salt, b.amount.wei()), (1, second_position, second_salt, PAID));
    assert_eq!(in_second.found.len(), 1);
    assert_eq!(in_second.found[0].tree_index, 1);

    // The same leaves named as another tree report that tree: the index is
    // the caller's, never guessed from the leaves.
    let renamed = restore_coins(&key(), CHAIN_ID, 7, &second.leaves, &second.spent).unwrap();
    assert_eq!(renamed.found[0].tree_index, 7);
    assert_eq!(renamed.found[0].position, second_position);

    // The coin as a reveal takes it still carries its position in its tree.
    let (_, path) = root_and_path(&second.leaves, second_position);
    let coin = b.owned(path);
    assert_eq!((coin.position, coin.salt), (second_position, second_salt));
}
