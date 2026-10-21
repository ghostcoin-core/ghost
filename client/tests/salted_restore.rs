//! Restore of salted (version 2) coins from the digits and the leaf records,
//! and the reveal of a restored salted coin, checked with the proofs crate's
//! own verifier. Leaves made before the salt (version 1) restore as before.

use ghost_client::reveal::{ChainParams, CoinReveal, ProofError, TREE_DEPTH};
use ghost_client::{
    decrypt_note, encrypt_note, full_reveal, partial_reveal, restore_coins, Amount, Commitment,
    Content, Current, DiscardReason, KeyFormat, Marker, NoteContents, OwnedCoin, PhantomKey,
    RevealError, RevealTerms, Rule, Salt, TreeLeaf, COIN_V2, DATA_V2, SALT_BYTES,
};
use ghost_proofs::{empty_leaf, tree_node, verify_coin_reveal, verify_salted_coin_reveal, Tree, PROTOCOL_VERSION_1};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// The standard example key of spec 01, section 14. Example only.
const DIGITS: &str = "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417";
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
        let salt = commit.salt.unwrap();
        let contents = NoteContents::salted_coin(0, amount(wei), Rule::EMPTY, salt);
        let note = encrypt_note(&key.note_key(), CHAIN_ID, &commit.commitment, &contents, rng);
        let position = self.push(TreeLeaf { commitment: commit.commitment, note, salt: Some(salt) });
        (position, salt)
    }

    /// A version 1 commit of `key`'s number 0, as made before the salt,
    /// with `beside` as the salt the record carries.
    fn v1_commit(&mut self, key: &PhantomKey, wei: u128, beside: Option<Salt>, rng: &mut StdRng) -> u32 {
        let commit = key.coin_commit(0, amount(wei), Rule::EMPTY).unwrap();
        let contents = NoteContents::coin(0, amount(wei), Rule::EMPTY);
        let note = encrypt_note(&key.note_key(), CHAIN_ID, &commit.commitment, &contents, rng);
        self.push(TreeLeaf { commitment: commit.commitment, note, salt: beside })
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
    let other = PhantomKey::generate(KeyFormat::Standard, &mut rng);
    let mut chain = Chain::new();
    chain.salted_commit(&other, 5_000, &mut rng);
    let (position, salt) = chain.salted_commit(&key(), COMMITTED, &mut rng);
    chain.v1_commit(&other, 6_000, None, &mut rng);

    // Restore from the digits alone finds the coin and its salt.
    let restored = restore_coins(&key(), CHAIN_ID, &chain.leaves, &chain.spent);
    assert!(restored.discarded.is_empty());
    let Current::One(found) = restored.current else {
        panic!("one unspent salted coin");
    };
    let commit = key().coin_commit_with_salt(0, amount(COMMITTED), Rule::EMPTY, salt).unwrap();
    assert_eq!((found.number, found.amount.wei(), found.position), (0, COMMITTED, position));
    assert_eq!(found.salt, Some(salt));
    assert_eq!(found.commitment, commit.commitment);
    assert_eq!(found.marker, commit.marker);

    // The coin as a reveal takes it carries the salt.
    let (root, path) = root_and_path(&chain.leaves, position);
    let coin = found.owned(path);
    assert_eq!(coin.salt, Some(salt));

    // Without its salt, or with another, the coin does not open its leaf,
    // and the reveal is refused before proving.
    for wrong in [None, Some(Salt::from_bytes([0x42; SALT_BYTES]))] {
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
    let remainder_salt = built.remainder.salt.expect("a salted coin's remainder is salted");
    assert_ne!(remainder_salt, salt);
    let expected = key().coin_commit_with_salt(1, amount(left), Rule::EMPTY, remainder_salt).unwrap();
    assert_eq!(built.remainder.number, 1);
    assert_eq!(built.remainder.commitment, expected.commitment);
    assert_eq!(built.remainder.marker, expected.marker);
    assert_eq!(&built.reveal.remainder, expected.commitment.as_bytes());
    let note = decrypt_note(&key().note_key(), CHAIN_ID, &expected.commitment, &built.reveal.remainder_note).unwrap();
    assert_eq!(note.type_tag, COIN_V2);
    assert_eq!(note.salt, Some(remainder_salt));
    assert_eq!((note.number, note.amount.wei()), (1, left));

    // Once included, restore finds the remainder from its note's salt alone.
    let remainder_position = chain.include(&built.reveal);
    let restored = restore_coins(&key(), CHAIN_ID, &chain.leaves, &chain.spent);
    assert_eq!(restored.found.len(), 2);
    let Current::One(current) = restored.current else {
        panic!("the remainder is the one unspent coin");
    };
    assert_eq!((current.number, current.amount.wei(), current.position), (1, left, remainder_position));
    assert_eq!(current.salt, Some(remainder_salt));

    // And the restored remainder reveals in turn, with its salt.
    let (root, path) = root_and_path(&chain.leaves, remainder_position);
    let zk_randomness = zk(&mut rng);
    let built = full_reveal(&params(), &key(), &current.owned(path), &terms(root), &mut rng, zk_randomness).unwrap();
    assert_eq!(verify_salted_coin_reveal(&params(), &built.reveal, &built.proof), Ok(()));
    assert_eq!(&built.reveal.marker, current.marker.as_bytes());
    assert!(built.remainder.salt.is_some());
    assert_ne!(built.remainder.salt, Some(remainder_salt));
}

#[test]
fn leaf_without_a_salt_still_restores() {
    let mut rng = StdRng::seed_from_u64(0x01d);
    let mut chain = Chain::new();
    let position = chain.v1_commit(&key(), COMMITTED, None, &mut rng);

    let restored = restore_coins(&key(), CHAIN_ID, &chain.leaves, &chain.spent);
    assert!(restored.discarded.is_empty());
    let Current::One(found) = restored.current else {
        panic!("the version 1 coin restores");
    };
    let v1 = key().coin_commit(0, amount(COMMITTED), Rule::EMPTY).unwrap();
    assert_eq!((found.number, found.amount.wei(), found.position), (0, COMMITTED, position));
    assert_eq!(found.salt, None);
    assert_eq!(found.commitment, v1.commitment);
    assert_eq!(found.marker, v1.marker);
    assert_eq!(found.owned([[0; 32]; TREE_DEPTH]).salt, None);

    // A version 1 note restores as before whatever salt the record carries.
    let mut carried = Chain::new();
    let position = carried.v1_commit(&key(), COMMITTED, Some(Salt::from_bytes([9; SALT_BYTES])), &mut rng);
    let restored = restore_coins(&key(), CHAIN_ID, &carried.leaves, &carried.spent);
    assert!(restored.discarded.is_empty());
    let Current::One(found) = restored.current else {
        panic!("the version 1 coin restores with a salt beside it");
    };
    assert_eq!((found.position, found.salt, found.commitment), (position, None, v1.commitment));

    // Spent, it is not current, as before.
    let mut spent = chain;
    spent.spent.push(v1.marker);
    let restored = restore_coins(&key(), CHAIN_ID, &spent.leaves, &spent.spent);
    assert!(matches!(restored.current, Current::None));
    assert_eq!(restored.found.len(), 1);
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
    let restored = restore_coins(&key(), CHAIN_ID, &changed, &[]);
    assert!(restored.found.is_empty());
    assert!(matches!(restored.current, Current::None));
    assert_eq!(restored.discarded.len(), 1);
    assert_eq!(restored.discarded[0].position, position);
    assert_eq!(restored.discarded[0].reason, DiscardReason::LeafMismatch);

    // A record without a salt beside it reads the salt from the note.
    let mut bare = chain.leaves.clone();
    bare[position as usize].salt = None;
    let restored = restore_coins(&key(), CHAIN_ID, &bare, &[]);
    assert_eq!(restored.found.len(), 1);
    assert_eq!(restored.found[0].salt, Some(salt));

    // A note whose salt does not open the leaf is discarded.
    let leaf = chain.leaves[position as usize].commitment;
    let wrong = NoteContents::salted_coin(0, amount(COMMITTED), Rule::EMPTY, Salt::from_bytes(other));
    let note = encrypt_note(&key().note_key(), CHAIN_ID, &leaf, &wrong, &mut rng);
    let forged = vec![TreeLeaf { commitment: leaf, note, salt: None }];
    let restored = restore_coins(&key(), CHAIN_ID, &forged, &[]);
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
    let leaves = vec![TreeLeaf { commitment: data.commitment, note, salt: data.salt }];
    let restored = restore_coins(&key(), CHAIN_ID, &leaves, &[]);
    assert!(restored.found.is_empty());
    assert_eq!(restored.discarded[0].reason, DiscardReason::NotACoin);
}
