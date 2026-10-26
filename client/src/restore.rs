//! Restoring a key's current coin from the digits alone (spec 01, section 8).
//!
//! The caller fetches the coin tree's leaves with their notes, and the coin
//! spent markers, in bulk (spec 05, section 8): every leaf and every marker,
//! whatever it expects to find, so the fetch names no commitment, position or
//! marker. [`restore_coins`] is a pure function over that data:
//!
//! 1. It tries the key's note key on every note. Only the key's own notes
//!    authenticate; every other note is passed over.
//! 2. For each note that decrypts, it recomputes `b_i`, `F` and `C` from the
//!    digits and the note's number, amount, rule and salt: every note is
//!    version 2 (`COIN_V2`) and carries the commitment's salt, which goes into
//!    `F` and the marker. A version 1 note, which has no salt, is discarded
//!    as malformed. A note whose `C` is not the leaf it sits with is discarded
//!    and reported, never trusted. So is a note whose salt is not the one the
//!    caller read beside the leaf, when the caller has one.
//! 3. It computes each found commitment's marker and looks it up in the spent
//!    markers. The current coin is the found commitment whose marker is
//!    unspent; the next number to use is one above its number.
//!
//! [`restore_coins_at`] does the same over leaves given with their positions,
//! for a wallet that read only the note buckets of its own lookup tags
//! ([`crate::note_tag`]) rather than the whole tree.
//!
//! Whether the notes and markers have been checked against the block receipts
//! is the caller's to track (spec 05, section 8, item 5): until they are, the
//! result is unchecked.

use std::collections::BTreeSet;

use core::fmt;

use crate::commit::{Amount, Commitment, Marker, Rule, Salt, COIN_V2};
use crate::key::PhantomKey;
use crate::note::{decrypt_note, NoteError, NOTE_BYTES};
use crate::reveal::{OwnedCoin, TREE_DEPTH};

/// One filled position of the coin tree: its leaf, the note stored with it
/// and the salt served beside it.
#[derive(Clone, PartialEq, Eq)]
pub struct TreeLeaf {
    /// The leaf `C`.
    pub commitment: Commitment,
    /// The 156-byte note stored with it.
    pub note: [u8; NOTE_BYTES],
    /// The salt the caller read beside the leaf: the one a commit published
    /// in the clear. `None` for a leaf without one (a reveal's remainder,
    /// whose salt is only in its note).
    pub salt: Option<Salt>,
}

/// Why a note that decrypted under the key was discarded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DiscardReason {
    /// The commitment recomputed from the note is not the leaf it sits with,
    /// or the note's salt is not the one read beside the leaf.
    LeafMismatch,
    /// The note is for a data commitment, found in the coin tree.
    NotACoin,
    /// The note authenticated but its contents are not a note version 2
    /// reads: a version 1 note gives `Malformed(NoteError::UnknownVersion)`.
    Malformed(NoteError),
}

impl fmt::Debug for DiscardReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeafMismatch => f.write_str("LeafMismatch"),
            Self::NotACoin => f.write_str("NotACoin"),
            Self::Malformed(error) => write!(f, "Malformed({error:?})"),
        }
    }
}

/// A note of the key that was discarded, and where it sat.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DiscardedNote {
    /// The position of the leaf the note sat with.
    pub position: u32,
    /// Why it was discarded.
    pub reason: DiscardReason,
}

/// A coin commitment of the key found in the tree, its note checked against
/// its leaf. It holds the number, amount and position, so it has no `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FoundCoin {
    /// The commitment number `i`.
    pub number: u64,
    /// The amount.
    pub amount: Amount,
    /// The rule.
    pub rule: Rule,
    /// Its salt.
    pub salt: Salt,
    /// The index of the coin tree its leaf is in, the one the caller named.
    pub tree_index: u32,
    /// The position of its leaf in that tree, read from the chain.
    pub position: u32,
    /// The leaf `C`.
    pub commitment: Commitment,
    /// Its marker.
    pub marker: Marker,
}

impl FoundCoin {
    /// The number the next remainder of this coin takes: one above its own.
    pub fn next_number(&self) -> Option<u64> {
        self.number.checked_add(1)
    }

    /// The coin as a reveal takes it, with the path the wallet computed from
    /// its bulk tree data.
    pub fn owned(&self, path: [[u8; 32]; TREE_DEPTH]) -> OwnedCoin {
        OwnedCoin {
            number: self.number,
            amount: self.amount,
            rule: self.rule,
            salt: self.salt,
            position: self.position,
            path,
        }
    }
}

/// The key's current coin.
pub enum Current {
    /// No found commitment is unspent: the key's value has been fully
    /// revealed or claimed away, or the key never committed.
    None,
    /// The one unspent commitment.
    One(FoundCoin),
    /// More than one unspent commitment, only possible if the key was used
    /// for two first commitments. The wallet shows each.
    Several(Vec<FoundCoin>),
}

/// What restore found.
pub struct Restored {
    /// The current coin.
    pub current: Current,
    /// Every commitment of the key found, spent or not, in position order.
    pub found: Vec<FoundCoin>,
    /// Every note of the key that was discarded, in position order.
    pub discarded: Vec<DiscardedNote>,
}

/// The most leaves one coin tree holds: one per position a `u32` names.
pub const MAX_TREE_LEAVES: u64 = 1 << 32;

/// Why restore refused its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreError {
    /// More leaves than one coin tree holds: a position past the last one
    /// cannot be named, so the input is refused whole rather than read in
    /// part.
    TooManyLeaves,
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyLeaves => f.write_str("more leaves than one coin tree holds"),
        }
    }
}

impl std::error::Error for RestoreError {}

/// Restores the key's coins from one coin tree's leaves with their notes, in
/// position order (the first is position 0), and the coin spent markers.
/// `tree_index` is the index of that tree; each coin found carries it. More
/// than [`MAX_TREE_LEAVES`] leaves is [`RestoreError::TooManyLeaves`].
pub fn restore_coins(
    key: &PhantomKey,
    chain_id: u64,
    tree_index: u32,
    leaves: &[TreeLeaf],
    spent: &[Marker],
) -> Result<Restored, RestoreError> {
    restore_limited(key, chain_id, tree_index, leaves, spent, MAX_TREE_LEAVES)
}

/// [`restore_coins`] with the leaf limit as an argument, so a test can reach
/// it with a slice it can build.
fn restore_limited(
    key: &PhantomKey,
    chain_id: u64,
    tree_index: u32,
    leaves: &[TreeLeaf],
    spent: &[Marker],
    max_leaves: u64,
) -> Result<Restored, RestoreError> {
    if !u64::try_from(leaves.len()).is_ok_and(|count| count <= max_leaves.min(MAX_TREE_LEAVES)) {
        return Err(RestoreError::TooManyLeaves);
    }
    // At most `MAX_TREE_LEAVES` leaves, so every one has a `u32` position.
    Ok(restore_pairs(key, chain_id, tree_index, (0..=u32::MAX).zip(leaves), spent))
}

/// Restores the key's coins from leaves of one coin tree, each given with its
/// position, and the coin spent markers. `tree_index` is the index of that
/// tree; each coin found carries it, and each coin found and note discarded
/// carries the position given with its leaf. Coins and discarded notes come
/// back in the order of `leaves`. More than [`MAX_TREE_LEAVES`] pairs is
/// [`RestoreError::TooManyLeaves`].
///
/// This is the restore of a wallet that read only some of the tree, such as
/// the note buckets of its own lookup tags ([`crate::note_tag`]).
pub fn restore_coins_at(
    key: &PhantomKey,
    chain_id: u64,
    tree_index: u32,
    leaves: &[(u32, TreeLeaf)],
    spent: &[Marker],
) -> Result<Restored, RestoreError> {
    if !u64::try_from(leaves.len()).is_ok_and(|count| count <= MAX_TREE_LEAVES) {
        return Err(RestoreError::TooManyLeaves);
    }
    let pairs = leaves.iter().map(|(position, leaf)| (*position, leaf));
    Ok(restore_pairs(key, chain_id, tree_index, pairs, spent))
}

/// The restore of [`restore_coins`] and [`restore_coins_at`], over leaves
/// with their positions, in the order given.
fn restore_pairs<'a>(
    key: &PhantomKey,
    chain_id: u64,
    tree_index: u32,
    leaves: impl IntoIterator<Item = (u32, &'a TreeLeaf)>,
    spent: &[Marker],
) -> Restored {
    let note_key = key.note_key();
    let spent: BTreeSet<[u8; 32]> = spent.iter().map(|marker| *marker.as_bytes()).collect();
    let mut found = Vec::new();
    let mut discarded = Vec::new();
    for (position, leaf) in leaves {
        let contents = match decrypt_note(&note_key, chain_id, &leaf.commitment, &leaf.note) {
            Ok(contents) => contents,
            Err(NoteError::Unauthentic) => continue,
            Err(error) => {
                discarded.push(DiscardedNote {
                    position,
                    reason: DiscardReason::Malformed(error),
                });
                continue;
            }
        };
        if contents.type_tag != COIN_V2 {
            discarded.push(DiscardedNote {
                position,
                reason: DiscardReason::NotACoin,
            });
            continue;
        }
        let salt = contents.salt;
        if leaf.salt.is_some_and(|beside| beside != salt) {
            discarded.push(DiscardedNote {
                position,
                reason: DiscardReason::LeafMismatch,
            });
            continue;
        }
        let commit =
            key.coin_commit_with_salt(contents.number, contents.amount, contents.rule, salt);
        match commit {
            Ok(commit) if commit.commitment == leaf.commitment => found.push(FoundCoin {
                number: contents.number,
                amount: contents.amount,
                rule: contents.rule,
                salt: commit.salt,
                tree_index,
                position,
                commitment: commit.commitment,
                marker: commit.marker,
            }),
            _ => discarded.push(DiscardedNote {
                position,
                reason: DiscardReason::LeafMismatch,
            }),
        }
    }
    let mut unspent: Vec<FoundCoin> = found
        .iter()
        .filter(|coin| !spent.contains(coin.marker.as_bytes()))
        .copied()
        .collect();
    let current = match unspent.len() {
        0 => Current::None,
        1 => Current::One(unspent.remove(0)),
        _ => Current::Several(unspent),
    };
    Restored {
        current,
        found,
        discarded,
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;
    use crate::key::KeyFormat;
    use crate::note::{encrypt_note, NoteContents};

    const CHAIN_ID: u64 = 1234;

    /// A leaf no key's note opens: passed over by every restore.
    fn filler(byte: u8) -> TreeLeaf {
        TreeLeaf {
            commitment: Commitment::from_bytes([byte; 32]),
            note: [byte; NOTE_BYTES],
            salt: None,
        }
    }

    /// A salted coin of `key`'s number 0, as a commit puts it in the tree.
    fn coin_leaf(key: &PhantomKey, wei: u128, rng: &mut StdRng) -> TreeLeaf {
        let amount = Amount::new(wei).unwrap();
        let commit = key.salted_coin_commit(0, amount, Rule::EMPTY, rng).unwrap();
        let contents = NoteContents::salted_coin(0, amount, Rule::EMPTY, commit.salt);
        let note = encrypt_note(&key.note_key(), CHAIN_ID, &commit.commitment, &contents, rng);
        TreeLeaf {
            commitment: commit.commitment,
            note,
            salt: Some(commit.salt),
        }
    }

    #[test]
    fn leaf_overflow_is_an_error() {
        let mut rng = StdRng::seed_from_u64(0x0f10);
        let key = PhantomKey::generate(KeyFormat::Words, &mut rng);
        let mut leaves = vec![coin_leaf(&key, 1_000, &mut rng), filler(1), filler(2), filler(3)];

        // Up to the limit, the key's coin is found.
        let within = restore_limited(&key, CHAIN_ID, 0, &leaves, &[], 4).unwrap();
        assert_eq!(within.found.len(), 1);
        assert!(matches!(within.current, Current::One(_)));

        // One leaf past it, the whole input is refused: no coin comes back,
        // not even the one before the limit.
        leaves.push(filler(4));
        let over = restore_limited(&key, CHAIN_ID, 0, &leaves, &[], 4);
        assert_eq!(over.err(), Some(RestoreError::TooManyLeaves));

        // The same leaves under the real limit restore.
        assert_eq!(restore_coins(&key, CHAIN_ID, 0, &leaves, &[]).unwrap().found.len(), 1);
        assert_eq!(MAX_TREE_LEAVES, 1 << 32);
        assert_eq!(RestoreError::TooManyLeaves.to_string(), "more leaves than one coin tree holds");
    }

    #[test]
    fn found_coin_carries_the_tree_index_it_was_given() {
        let mut rng = StdRng::seed_from_u64(0x7ee);
        let key = PhantomKey::generate(KeyFormat::Words, &mut rng);
        let other = PhantomKey::generate(KeyFormat::Words, &mut rng);
        let leaves = vec![
            coin_leaf(&other, 5_000, &mut rng),
            coin_leaf(&key, 1_000, &mut rng),
            filler(9),
        ];
        let restored = restore_coins(&key, CHAIN_ID, 3, &leaves, &[]).unwrap();
        let Current::One(found) = restored.current else {
            panic!("the key's one coin");
        };
        assert_eq!((found.tree_index, found.position), (3, 1));
        assert_eq!(restored.found.len(), 1);
        assert_eq!(restored.found[0].tree_index, 3);

        // The other key's coin in the same tree names the same tree, at its
        // own position.
        let theirs = restore_coins(&other, CHAIN_ID, 3, &leaves, &[]).unwrap();
        assert_eq!((theirs.found[0].tree_index, theirs.found[0].position), (3, 0));
    }

    #[test]
    fn restore_at_takes_the_position_given_with_each_leaf() {
        let mut rng = StdRng::seed_from_u64(0xa7);
        let key = PhantomKey::generate(KeyFormat::Words, &mut rng);
        let mut bad = coin_leaf(&key, 2_000, &mut rng);
        bad.salt = Some(Salt::from_bytes([9; 16]));
        let pairs: Vec<(u32, TreeLeaf)> = vec![
            (70_000, filler(1)),
            (90_001, coin_leaf(&key, 1_000, &mut rng)),
            (123_456, bad),
        ];
        let restored = restore_coins_at(&key, CHAIN_ID, 5, &pairs, &[]).unwrap();
        let Current::One(found) = restored.current else {
            panic!("the key's one coin");
        };
        assert_eq!((found.tree_index, found.position), (5, 90_001));
        assert_eq!(restored.discarded.len(), 1);
        assert_eq!(restored.discarded[0].position, 123_456);
        assert_eq!(restored.discarded[0].reason, DiscardReason::LeafMismatch);

        // The same leaves as a slice restore at positions 0 upwards.
        let leaves: Vec<TreeLeaf> = pairs.into_iter().map(|(_, leaf)| leaf).collect();
        let whole = restore_coins(&key, CHAIN_ID, 5, &leaves, &[]).unwrap();
        assert_eq!(whole.found[0].position, 1);
        assert_eq!(whole.discarded[0].position, 2);
    }
}
