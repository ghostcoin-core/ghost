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
//!    digits and the note's number, amount and rule, under the tags of the
//!    note's type tag: a version 2 (`COIN_V2`) note carries the commitment's
//!    salt, which goes into `F` and the marker; a version 1 (`COIN`) note has
//!    none and restores as before. A note whose `C` is not the leaf it sits
//!    with is discarded and reported, never trusted. So is a version 2 note
//!    whose salt is not the one the caller read beside the leaf, when the
//!    caller has one.
//! 3. It computes each found commitment's marker and looks it up in the spent
//!    markers. The current coin is the found commitment whose marker is
//!    unspent; the next number to use is one above its number.
//!
//! Whether the notes and markers have been checked against the block receipts
//! is the caller's to track (spec 05, section 8, item 5): until they are, the
//! result is unchecked.

use std::collections::BTreeSet;

use core::fmt;

use crate::commit::{Amount, Commitment, Marker, Rule, Salt, COIN, COIN_V2};
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
    /// The salt the caller read beside the leaf: the one a version 2 commit
    /// published in the clear. `None` for a leaf without one (a version 1
    /// commit, or a reveal's remainder, whose salt is only in its note).
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
    /// The note authenticated but its contents are not a note either note
    /// version reads.
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
    /// Its salt, for a version 2 commitment; `None` for version 1.
    pub salt: Option<Salt>,
    /// The position of its leaf, read from the chain.
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

/// Restores the key's coins from the coin tree's leaves with their notes, in
/// position order (the first is position 0), and the coin spent markers.
pub fn restore_coins(
    key: &PhantomKey,
    chain_id: u64,
    leaves: &[TreeLeaf],
    spent: &[Marker],
) -> Restored {
    let note_key = key.note_key();
    let spent: BTreeSet<[u8; 32]> = spent.iter().map(|marker| *marker.as_bytes()).collect();
    let mut found = Vec::new();
    let mut discarded = Vec::new();
    for (index, leaf) in leaves.iter().enumerate() {
        let Ok(position) = u32::try_from(index) else {
            break;
        };
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
        let commit = match (contents.type_tag, contents.salt) {
            (COIN, None) => key.coin_commit(contents.number, contents.amount, contents.rule),
            (COIN_V2, Some(salt)) => {
                if leaf.salt.is_some_and(|beside| beside != salt) {
                    discarded.push(DiscardedNote {
                        position,
                        reason: DiscardReason::LeafMismatch,
                    });
                    continue;
                }
                key.coin_commit_with_salt(contents.number, contents.amount, contents.rule, salt)
            }
            _ => {
                discarded.push(DiscardedNote {
                    position,
                    reason: DiscardReason::NotACoin,
                });
                continue;
            }
        };
        match commit {
            Ok(commit) if commit.commitment == leaf.commitment => found.push(FoundCoin {
                number: contents.number,
                amount: contents.amount,
                rule: contents.rule,
                salt: commit.salt,
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
