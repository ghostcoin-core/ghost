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
//!    digits and the note's number, amount and rule. A note whose `C` is not
//!    the leaf it sits with is discarded and reported, never trusted.
//! 3. It computes each found commitment's marker and looks it up in the spent
//!    markers. The current coin is the found commitment whose marker is
//!    unspent; the next number to use is one above its number.
//!
//! Whether the notes and markers have been checked against the block receipts
//! is the caller's to track (spec 05, section 8, item 5): until they are, the
//! result is unchecked.

use std::collections::BTreeSet;

use core::fmt;

use crate::commit::{Amount, Commitment, Marker, Rule, COIN};
use crate::key::PhantomKey;
use crate::note::{decrypt_note, NoteError, NOTE_BYTES};
use crate::reveal::{OwnedCoin, TREE_DEPTH};

/// One filled position of the coin tree: its leaf and the note stored with it.
#[derive(Clone, PartialEq, Eq)]
pub struct TreeLeaf {
    /// The leaf `C`.
    pub commitment: Commitment,
    /// The 156-byte note stored with it.
    pub note: [u8; NOTE_BYTES],
}

/// Why a note that decrypted under the key was discarded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DiscardReason {
    /// The commitment recomputed from the note is not the leaf it sits with.
    LeafMismatch,
    /// The note is for a data commitment, found in the coin tree.
    NotACoin,
    /// The note authenticated but its contents are not a note version 1
    /// reads.
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
        if contents.type_tag != COIN {
            discarded.push(DiscardedNote {
                position,
                reason: DiscardReason::NotACoin,
            });
            continue;
        }
        let commit = key.coin_commit(contents.number, contents.amount, contents.rule);
        match commit {
            Ok(commit) if commit.commitment == leaf.commitment => found.push(FoundCoin {
                number: contents.number,
                amount: contents.amount,
                rule: contents.rule,
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
