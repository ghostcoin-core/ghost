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
//!    digits and the note's number, amount, rule and salt: every note carries
//!    the commitment's salt (type `COIN_V2`), which goes into `F` and the
//!    marker. A note in the tree is 380 bytes, note version 3: its capsule
//!    opens its rule (spec 10, section 3.2), and a capsule that is malformed
//!    or opens another rule discards the note as malformed
//!    ([`NoteError::BadCapsule`]), never repaired. The one other note read is
//!    a reveal's 156-byte note version 2 remainder note, zero-padded to 380
//!    bytes, until the version 2 reveal carries a 380-byte one: only if the
//!    note does not decrypt as version 3 and its last 224 bytes are zero are
//!    its first 156 read as version 2, which holds the empty rule alone. A
//!    note of any other version (version 1, which has no salt, among them)
//!    is discarded as malformed. A note whose `C` is not the leaf it sits
//!    with is discarded and reported, never trusted. So is a note whose salt
//!    is not the one the caller read beside the leaf, when the caller has
//!    one.
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
//!
//! # Keep-up check
//!
//! [`check_keep_up`] re-derives a found coin's spent status from a later
//! header proof ([`ProvenChain`], checked by samples or in full) without a
//! restore (stage 2 design, "Wallet restore volume", steps 5 and 6): the
//! marker's membership or absence witness against the `coinMarkerRoot` of a
//! snapshot header in the proof's linked tail, and the bulk lookup lists of
//! every block after it up to the tip, each matched to its header's
//! `lookupDigest`. A wrong or missing item is refused, never guessed.
//!
//! A result holds only at the tip it was checked to ([`keep_up_holds`]):
//! any later tip, even one that extends it, may carry the coin's spend in a
//! block the check never read, so the wallet checks again against the later
//! proof before it reports the coin spendable.
//!
//! # Reorganisations
//!
//! [`CanonicalTrees`] follows the checked chain from one header proof to the
//! next and keeps the coin lookup index, the coin marker-set tree and the
//! coin tree rebuilt along it, every root compared with its header's. When a
//! later proof is on a heavier branch
//! ([`crate::header_sample::ChainChange::Reorganised`]), the
//! blocks above the common ancestor are disconnected, the trees are rebuilt
//! from the last state below them and the new branch's blocks are connected
//! (spec 05, section 7). A spend only on a disconnected block is then absent
//! from every root, so the coin shows unspent again; a spend kept on the new
//! branch stays spent.
//!
//! # Header roots
//!
//! The roots both read are header fields 16, 19, 21 and 22 (`coinTreeRoot`,
//! `coinLookupRoot`, `coinMarkerRoot`, `lookupDigest`) of decision 0004's
//! 23-item header. The client's header decoder ([`crate::seal`]) reads the
//! 19-item header, so the fields are read by the caller's
//! [`ReadHeaderRoots`] until it reads the 23-item one. They are always read
//! from the bytes of a header the proof checked, never taken from a server
//! beside it.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use core::fmt;

use ghost_proofs::{empty_leaf, tree_node, Tree};

use crate::commit::{Amount, Commitment, Marker, Rule, Salt, COIN_V2};
use crate::derive::NoteKey;
use crate::header_sample::{ProvenChain, TAIL_HEADERS};
use crate::key::PhantomKey;
use crate::lookup::{
    verify_marker_absence, verify_marker_membership, BlockLookupList, CoinMarkerSet, CoinMarkerWitness, InsertError,
    LookupIndex, LookupTree, WitnessError, TREE_POSITIONS,
};
use crate::note::{
    decrypt_note_v2, decrypt_note_with_capsule, unpad_reveal_note, Capsule, NoteContents, NoteError, NOTE_BYTES,
};
use crate::reveal::{OwnedCoin, TREE_DEPTH};

/// One filled position of the coin tree: its leaf, the note stored with it
/// and the salt served beside it.
#[derive(Clone, PartialEq, Eq)]
pub struct TreeLeaf {
    /// The leaf `C`.
    pub commitment: Commitment,
    /// The 380-byte note stored with it: a note version 3, or a reveal's
    /// 156-byte remainder note followed by 224 zero bytes.
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
    /// The note authenticated but its contents are not a note restore reads:
    /// a version 1 note gives `Malformed(NoteError::UnknownVersion)`, a
    /// capsule that is malformed or does not open the note's rule
    /// `Malformed(NoteError::BadCapsule)`.
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
    /// The capsule that opens the rule, read from the note: the empty
    /// capsule for the empty rule. A remainder that keeps the rule carries it
    /// again (spec 10, section 3.2).
    pub capsule: Capsule,
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
        let (contents, capsule) = match read_note(&note_key, chain_id, leaf) {
            Ok(read) => read,
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
        // A note version 3 opened its rule through its capsule, so any rule
        // is recomputed; a padded version 2 remainder note has no capsule and
        // holds the empty rule alone, as before.
        let commit = match capsule {
            Some(_) => Ok(key.coin_commit_with_rule(contents.number, contents.amount, contents.rule, salt)),
            None => key.coin_commit_with_salt(contents.number, contents.amount, contents.rule, salt),
        };
        match commit {
            Ok(commit) if commit.commitment == leaf.commitment => found.push(FoundCoin {
                number: contents.number,
                amount: contents.amount,
                rule: contents.rule,
                capsule: capsule.unwrap_or(Capsule::empty()),
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

/// Reads a leaf's 380-byte note under the note key: as a note version 3 with
/// its capsule first; if that does not authenticate and the note's last 224
/// bytes are zero, its first 156 bytes as a reveal's note version 2
/// remainder note, with no capsule. [`NoteError::Unauthentic`] means the
/// note is not the key's; any other error is a note of the key to discard.
fn read_note(
    note_key: &NoteKey,
    chain_id: u64,
    leaf: &TreeLeaf,
) -> Result<(NoteContents, Option<Capsule>), NoteError> {
    match decrypt_note_with_capsule(note_key, chain_id, &leaf.commitment, &leaf.note) {
        Ok((contents, capsule)) => Ok((contents, Some(capsule))),
        Err(NoteError::Unauthentic) => match unpad_reveal_note(&leaf.note) {
            Some(short) => decrypt_note_v2(note_key, chain_id, &leaf.commitment, &short).map(|contents| (contents, None)),
            None => Err(NoteError::Unauthentic),
        },
        Err(error) => Err(error),
    }
}

// ---------------------------------------------------------------------------
// Header roots
// ---------------------------------------------------------------------------

/// The roots of one header that a keep-up check and the canonical trees
/// read: fields 16, 19, 21 and 22 of decision 0004's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderRoots {
    /// The current coin tree's root, field 16.
    pub coin_tree_root: [u8; 32],
    /// `coinLookupRoot`, field 19.
    pub coin_lookup_root: [u8; 32],
    /// `coinMarkerRoot`, field 21.
    pub coin_marker_root: [u8; 32],
    /// `lookupDigest`, field 22.
    pub lookup_digest: [u8; 32],
}

/// Reads [`HeaderRoots`] from a header's own bytes; `None` when the header
/// does not carry them. See "Header roots" in the module documentation.
pub trait ReadHeaderRoots {
    /// The roots `header` carries.
    fn header_roots(&self, header: &[u8]) -> Option<HeaderRoots>;
}

impl<F> ReadHeaderRoots for F
where
    F: Fn(&[u8]) -> Option<HeaderRoots>,
{
    fn header_roots(&self, header: &[u8]) -> Option<HeaderRoots> {
        self(header)
    }
}

/// The roots of the tail header at `height`, read from its bytes.
fn roots_at(proof: &ProvenChain, height: u64, reader: &(impl ReadHeaderRoots + ?Sized)) -> Option<HeaderRoots> {
    proof.header_at(height).and_then(|header| reader.header_roots(header))
}

// ---------------------------------------------------------------------------
// Keep-up check
// ---------------------------------------------------------------------------

/// What a server answers for a keep-up check of one coin, unchecked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeepUpAnswer {
    /// The height of the snapshot header, which must be a tail header of the
    /// proof the check is made against.
    pub snapshot_height: u64,
    /// The coin's marker witness against the snapshot's `coinMarkerRoot`: a
    /// membership witness when spent, an absence witness when not.
    pub marker_witness: Vec<u8>,
    /// The bulk lookup list of every block after the snapshot up to the
    /// proof's tip, oldest first.
    pub later_blocks: Vec<BlockLookupList>,
}

/// Where a coin's spend was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpentAt {
    /// In the snapshot's marker set, by a membership witness.
    Snapshot {
        /// The position of the marker's leaf in the marker-set tree.
        set_position: u64,
        /// The global position of the coin leaf the spend appended, where the
        /// next commitment is read; `None` when it appended none.
        appended: Option<u64>,
    },
    /// In the lookup list of a block after the snapshot.
    LaterBlock {
        /// That block's height.
        height: u64,
    },
}

/// A coin's spent status on the chain of the proof it was checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepUpStatus {
    /// Absent from the snapshot's marker set and from every later block.
    Unspent,
    /// Spent.
    Spent(SpentAt),
}

/// The result of a keep-up check, with the chain it holds for: a later proof
/// that does not run through `tip_hash` ([`ProvenChain::compare`]) calls for
/// a new check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepUp {
    /// The coin's status.
    pub status: KeepUpStatus,
    /// The snapshot header's height.
    pub snapshot_height: u64,
    /// The tip the status was checked to.
    pub tip_height: u64,
    /// That tip's hash.
    pub tip_hash: [u8; 32],
}

/// Why a keep-up answer is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepUpError {
    /// The snapshot header is not a tail header of the proof.
    SnapshotNotInTail {
        /// The height the answer gave.
        height: u64,
    },
    /// The header at `height` carries no roots the reader can read.
    Roots {
        /// The header's height.
        height: u64,
    },
    /// The later lists are not one for every block after the snapshot.
    LaterBlocks {
        /// The blocks after the snapshot up to the tip.
        expected: u64,
        /// The lists given.
        got: usize,
    },
    /// The list of the block at `height` is not the one its header's
    /// `lookupDigest` commits to.
    LookupDigest {
        /// The block's height.
        height: u64,
    },
    /// The marker witness is neither a membership nor an absence witness of
    /// the coin's marker under the snapshot's `coinMarkerRoot`.
    Witness(WitnessError),
}

impl fmt::Display for KeepUpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SnapshotNotInTail { height } => write!(f, "snapshot header {height} is not in the proof's tail"),
            Self::Roots { height } => write!(f, "header {height} carries no readable roots"),
            Self::LaterBlocks { expected, got } => write!(f, "{got} later block lists, not {expected}"),
            Self::LookupDigest { height } => write!(f, "the list of block {height} is not its header's"),
            Self::Witness(error) => write!(f, "marker witness: {error}"),
        }
    }
}

impl std::error::Error for KeepUpError {}

/// Re-derives the spent status of the coin whose marker is `marker` from a
/// later header proof, without a restore.
///
/// The answer's snapshot header must be a tail header of `proof`; its roots
/// are read from its bytes by `reader`. The marker witness must be a
/// membership witness (spent, with the leaf the spend appended) or an
/// absence witness (unspent) of `marker` under the snapshot's
/// `coinMarkerRoot`. An unspent marker is then looked for in the list of
/// every block after the snapshot up to the tip, each matched to its own
/// header's `lookupDigest`. Anything else is refused: a witness for another
/// root, such as one from a block a reorganisation disconnected, never
/// passes.
pub fn check_keep_up(
    marker: &Marker,
    proof: &ProvenChain,
    answer: &KeepUpAnswer,
    reader: &(impl ReadHeaderRoots + ?Sized),
) -> Result<KeepUp, KeepUpError> {
    let snapshot = answer.snapshot_height;
    if proof.header_at(snapshot).is_none() {
        return Err(KeepUpError::SnapshotNotInTail { height: snapshot });
    }
    let roots = roots_at(proof, snapshot, reader).ok_or(KeepUpError::Roots { height: snapshot })?;
    let expected = proof.tip_height() - snapshot;
    if answer.later_blocks.len() as u64 != expected {
        return Err(KeepUpError::LaterBlocks {
            expected,
            got: answer.later_blocks.len(),
        });
    }
    // Every later list is checked before any is read.
    for (height, list) in (snapshot + 1..).zip(&answer.later_blocks) {
        let later = roots_at(proof, height, reader).ok_or(KeepUpError::Roots { height })?;
        if !crate::lookup::check_lookup_digest(list, &later.lookup_digest) {
            return Err(KeepUpError::LookupDigest { height });
        }
    }
    let marker = marker.as_bytes();
    let status = match verify_marker_membership(&roots.coin_marker_root, &answer.marker_witness, marker) {
        Ok(spent) => KeepUpStatus::Spent(SpentAt::Snapshot {
            set_position: spent.position,
            appended: spent.appended,
        }),
        Err(_) => {
            verify_marker_absence(&roots.coin_marker_root, &answer.marker_witness, marker)
                .map_err(KeepUpError::Witness)?;
            (snapshot + 1..)
                .zip(&answer.later_blocks)
                .find(|(_, list)| list.coin_markers.contains(marker))
                .map_or(KeepUpStatus::Unspent, |(height, _)| {
                    KeepUpStatus::Spent(SpentAt::LaterBlock { height })
                })
        }
    };
    Ok(KeepUp {
        status,
        snapshot_height: snapshot,
        tip_height: proof.tip_height(),
        tip_hash: proof.tip_hash(),
    })
}

// ---------------------------------------------------------------------------
// The coin tree, rebuilt
// ---------------------------------------------------------------------------

/// The empty subtrees of the coin tree, `Z_0 = E` up to `Z_32`.
fn coin_zeros() -> &'static [[u8; 32]; TREE_DEPTH + 1] {
    static ZEROS: OnceLock<[[u8; 32]; TREE_DEPTH + 1]> = OnceLock::new();
    ZEROS.get_or_init(|| {
        let mut zeros = [[0u8; 32]; TREE_DEPTH + 1];
        zeros[0] = empty_leaf();
        for level in 0..TREE_DEPTH {
            zeros[level + 1] = tree_node(Tree::Coin, level as u8, &zeros[level], &zeros[level]);
        }
        zeros
    })
}

/// The right edge of the current coin tree (spec 05, section 3): the leaves
/// appended so far and the root of every full left subtree, enough to append
/// a leaf and give the root without holding the leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CoinFrontier {
    tree_index: u64,
    count: u64,
    left: [[u8; 32]; TREE_DEPTH],
    /// The root of a full tree, once its last position is filled.
    full_root: Option<[u8; 32]>,
}

impl CoinFrontier {
    fn new() -> Self {
        Self {
            tree_index: 0,
            count: 0,
            left: [[0u8; 32]; TREE_DEPTH],
            full_root: None,
        }
    }

    /// The global position the next leaf takes.
    fn next_position(&self) -> u64 {
        self.tree_index * TREE_POSITIONS + self.count
    }

    /// Appends `leaf` at the next position; a full tree is followed by the
    /// next tree index.
    fn append(&mut self, leaf: &[u8; 32]) {
        if self.count == TREE_POSITIONS {
            *self = Self {
                tree_index: self.tree_index + 1,
                ..Self::new()
            };
        }
        let mut node = *leaf;
        let mut placed = false;
        for level in 0..TREE_DEPTH {
            if self.count >> level & 1 == 1 {
                node = tree_node(Tree::Coin, level as u8, &self.left[level], &node);
            } else {
                self.left[level] = node;
                placed = true;
                break;
            }
        }
        if !placed {
            self.full_root = Some(node);
        }
        self.count += 1;
    }

    /// The root of the current coin tree.
    fn root(&self) -> [u8; 32] {
        if let Some(full) = self.full_root {
            return full;
        }
        let zeros = coin_zeros();
        let mut node = zeros[0];
        for level in 0..TREE_DEPTH {
            node = if self.count >> level & 1 == 1 {
                tree_node(Tree::Coin, level as u8, &self.left[level], &node)
            } else {
                tree_node(Tree::Coin, level as u8, &node, &zeros[level])
            };
        }
        node
    }
}

// ---------------------------------------------------------------------------
// Canonical trees across reorganisations
// ---------------------------------------------------------------------------

/// The blocks [`CanonicalTrees`] keeps above its checkpoint, the deepest
/// reorganisation it follows: the design's tail of 64 headers.
pub const REORG_WINDOW: u64 = TAIL_HEADERS;

/// One block as the wallet reads it in bulk, unchecked: what the canonical
/// trees connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalBlock {
    /// Its height.
    pub height: u64,
    /// Its header's hash.
    pub hash: [u8; 32],
    /// Its lookup list, which its header's `lookupDigest` commits to.
    pub list: BlockLookupList,
    /// The coin leaf of each of the list's coin tags, in append order.
    pub coin_leaves: Vec<Commitment>,
    /// For each of the list's coin markers, the global position of the coin
    /// leaf its reveal appended, or `None`.
    pub appended: Vec<Option<u64>>,
}

/// Which root of a header the rebuilt trees did not reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeRoot {
    /// The coin tree's root.
    CoinTree,
    /// `coinLookupRoot`.
    CoinLookup,
    /// `coinMarkerRoot`.
    CoinMarker,
}

/// Why the canonical trees refused to follow a proof. Nothing changes on a
/// refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalError {
    /// The proof and the trees' chain share no header the proof links: the
    /// proof's tail starts above the trees' tip, or the fork is below both.
    /// The wallet restores again.
    NoCommonHeader,
    /// The fork is below the trees' checkpoint, deeper than the blocks they
    /// keep ([`REORG_WINDOW`]). The wallet restores again.
    TooDeep {
        /// The checkpoint's height.
        checkpoint_height: u64,
    },
    /// The blocks given are not every block from `from` to `to`, in order.
    Blocks {
        /// The first height expected.
        from: u64,
        /// The last height expected.
        to: u64,
    },
    /// The block at `height` is not the proof's header there.
    BlockHash {
        /// The block's height.
        height: u64,
    },
    /// The header at `height` carries no readable roots.
    Roots {
        /// The block's height.
        height: u64,
    },
    /// The block's list is not the one its header's `lookupDigest` commits
    /// to.
    LookupDigest {
        /// The block's height.
        height: u64,
    },
    /// The block's coin leaves do not start at the next coin position.
    CoinStart {
        /// The block's height.
        height: u64,
    },
    /// The block has not one coin leaf for every coin tag, or one appended
    /// position for every coin marker.
    Counts {
        /// The block's height.
        height: u64,
    },
    /// A tag or a marker of the block cannot be inserted.
    Insert {
        /// The block's height.
        height: u64,
        /// Why.
        error: InsertError,
    },
    /// The rebuilt trees do not reach the header's root.
    Root {
        /// The block's height.
        height: u64,
        /// Which root.
        root: TreeRoot,
    },
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCommonHeader => f.write_str("the proof links no header of the followed chain"),
            Self::TooDeep { checkpoint_height } => {
                write!(f, "the fork is below the checkpoint at height {checkpoint_height}")
            }
            Self::Blocks { from, to } => write!(f, "the blocks are not every block from {from} to {to}"),
            Self::BlockHash { height } => write!(f, "block {height} is not the proof's header"),
            Self::Roots { height } => write!(f, "header {height} carries no readable roots"),
            Self::LookupDigest { height } => write!(f, "the list of block {height} is not its header's"),
            Self::CoinStart { height } => {
                write!(f, "the coin leaves of block {height} do not start at the next position")
            }
            Self::Counts { height } => write!(f, "block {height} does not match its list's counts"),
            Self::Insert { height, error } => write!(f, "block {height}: {error}"),
            Self::Root { height, root } => write!(f, "block {height} does not rebuild its header's {root:?} root"),
        }
    }
}

impl std::error::Error for CanonicalError {}

/// What following a proof did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Followed {
    /// The proof ends at the trees' tip, or below it on the same branch.
    Unchanged,
    /// The proof's chain runs through the trees' tip; its blocks above it
    /// were connected.
    Extended {
        /// The blocks connected.
        connected: u64,
    },
    /// The proof is on a heavier branch: the blocks above the common
    /// ancestor were disconnected and the new branch's connected.
    Reorganised {
        /// The height of the common ancestor.
        ancestor_height: u64,
        /// The hashes of the disconnected blocks, oldest first.
        disconnected: Vec<[u8; 32]>,
        /// The blocks connected.
        connected: u64,
    },
    /// The proof is on a branch with no more work above the common ancestor:
    /// nothing changed.
    KeptHeavier {
        /// The height of the common ancestor.
        ancestor_height: u64,
    },
}

/// A coin marker's status in the canonical trees, with its witness under
/// the current `coinMarkerRoot`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarkerStatus {
    /// Spent on the canonical chain.
    Spent {
        /// The global position of the coin leaf its reveal appended.
        appended: Option<u64>,
        /// Its membership witness.
        witness: CoinMarkerWitness,
    },
    /// Unspent on the canonical chain.
    Unspent {
        /// Its absence witness.
        witness: CoinMarkerWitness,
    },
}

/// The three trees after some block.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Trees {
    index: LookupIndex,
    markers: CoinMarkerSet,
    coins: CoinFrontier,
}

impl Trees {
    fn genesis() -> Self {
        Self {
            index: LookupIndex::new(LookupTree::Coin),
            markers: CoinMarkerSet::new(),
            coins: CoinFrontier::new(),
        }
    }

    /// Connects `block`: its coin entries into the lookup index, its coin
    /// leaves into the coin tree and its coin spends into the marker set.
    fn apply(&mut self, block: &CanonicalBlock) -> Result<(), CanonicalError> {
        let height = block.height;
        let list = &block.list;
        if list.coin_tags.len() != block.coin_leaves.len() || list.coin_markers.len() != block.appended.len() {
            return Err(CanonicalError::Counts { height });
        }
        if list.coin_start != self.coins.next_position() {
            return Err(CanonicalError::CoinStart { height });
        }
        for ((tag, position), leaf) in list.coin_entries().zip(&block.coin_leaves) {
            self.index.insert(tag, position).map_err(|error| CanonicalError::Insert { height, error })?;
            self.coins.append(leaf.as_bytes());
        }
        for (marker, appended) in list.coin_markers.iter().zip(&block.appended) {
            self.markers
                .insert(*marker, *appended)
                .map_err(|error| CanonicalError::Insert { height, error })?;
        }
        Ok(())
    }

    /// Compares the rebuilt roots with the header's.
    fn check_roots(&self, height: u64, roots: &HeaderRoots) -> Result<(), CanonicalError> {
        let refuse = |root| Err(CanonicalError::Root { height, root });
        if self.coins.root() != roots.coin_tree_root {
            return refuse(TreeRoot::CoinTree);
        }
        if self.index.root() != roots.coin_lookup_root {
            return refuse(TreeRoot::CoinLookup);
        }
        if self.markers.root() != roots.coin_marker_root {
            return refuse(TreeRoot::CoinMarker);
        }
        Ok(())
    }
}

/// A block connected to the canonical trees, with its header's work.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Connected {
    block: CanonicalBlock,
    work: u128,
}

/// The coin lookup index, coin marker-set tree and coin tree rebuilt along
/// the checked chain, followed from one header proof to the next across
/// reorganisations; see "Reorganisations" in the module documentation.
///
/// It keeps a checkpoint, the trees after the block [`REORG_WINDOW`] blocks
/// below the tip (genesis at first), and the blocks above it, so that a
/// reorganisation rebuilds from the checkpoint and the blocks below the
/// common ancestor. A fork below the checkpoint is refused
/// ([`CanonicalError::TooDeep`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalTrees {
    checkpoint: Trees,
    checkpoint_height: u64,
    checkpoint_hash: [u8; 32],
    blocks: Vec<Connected>,
    current: Trees,
    window: u64,
}

impl CanonicalTrees {
    /// The genesis trees, each holding its sentinel or nothing, at the
    /// genesis header `genesis_hash`, keeping [`REORG_WINDOW`] blocks.
    pub fn genesis(genesis_hash: [u8; 32]) -> Self {
        Self::with_window(genesis_hash, REORG_WINDOW)
    }

    /// The genesis trees keeping `window` blocks above the checkpoint, at
    /// least one.
    pub fn with_window(genesis_hash: [u8; 32], window: u64) -> Self {
        Self {
            checkpoint: Trees::genesis(),
            checkpoint_height: 0,
            checkpoint_hash: genesis_hash,
            blocks: Vec::new(),
            current: Trees::genesis(),
            window: window.max(1),
        }
    }

    /// The height of the last block connected.
    pub fn tip_height(&self) -> u64 {
        self.blocks.last().map_or(self.checkpoint_height, |connected| connected.block.height)
    }

    /// The hash of the last block connected.
    pub fn tip_hash(&self) -> [u8; 32] {
        self.blocks.last().map_or(self.checkpoint_hash, |connected| connected.block.hash)
    }

    /// The height of the checkpoint, the lowest block kept.
    pub fn checkpoint_height(&self) -> u64 {
        self.checkpoint_height
    }

    /// The hash of the block at `height`, from the checkpoint to the tip.
    pub fn hash_at(&self, height: u64) -> Option<[u8; 32]> {
        if height == self.checkpoint_height {
            return Some(self.checkpoint_hash);
        }
        let index = usize::try_from(height.checked_sub(self.checkpoint_height + 1)?).ok()?;
        self.blocks.get(index).map(|connected| connected.block.hash)
    }

    /// The coin lookup index at the tip.
    pub fn lookup_index(&self) -> &LookupIndex {
        &self.current.index
    }

    /// The coin marker-set tree at the tip.
    pub fn marker_set(&self) -> &CoinMarkerSet {
        &self.current.markers
    }

    /// The coin tree's root at the tip.
    pub fn coin_tree_root(&self) -> [u8; 32] {
        self.current.coins.root()
    }

    /// The global position the next coin leaf takes.
    pub fn next_coin_position(&self) -> u64 {
        self.current.coins.next_position()
    }

    /// The status of `marker` at the tip, with its witness.
    pub fn marker_status(&self, marker: &Marker) -> MarkerStatus {
        let set = &self.current.markers;
        let bytes = marker.as_bytes();
        match set.membership_witness(bytes) {
            Some(witness) => MarkerStatus::Spent {
                appended: witness.leaf.appended,
                witness,
            },
            None => MarkerStatus::Unspent {
                witness: set.absence_witness(bytes).expect("a marker not in the set has a low leaf"),
            },
        }
    }

    /// Follows `proof`, a header proof checked after the last one followed:
    /// connects `blocks`, every block above the common ancestor up to the
    /// proof's tip in order, when the proof extends the tip or is on a
    /// heavier branch, disconnecting the blocks above the ancestor first.
    ///
    /// Each block must be the proof's header at its height, its list the one
    /// its header's `lookupDigest` commits to, and the trees rebuilt with it
    /// must reach its header's coin tree root, `coinLookupRoot` and
    /// `coinMarkerRoot`, all read by `reader` from the header's bytes. On
    /// any refusal nothing changes.
    pub fn follow(
        &mut self,
        proof: &ProvenChain,
        blocks: &[CanonicalBlock],
        reader: &(impl ReadHeaderRoots + ?Sized),
    ) -> Result<Followed, CanonicalError> {
        let tip = self.tip_height();
        let low = self.checkpoint_height.max(proof.linked_from());
        let high = tip.min(proof.tip_height());
        let ancestor = (low..=high)
            .rev()
            .find(|&height| self.hash_at(height).is_some() && self.hash_at(height) == proof.hash_at(height));
        let Some(ancestor) = ancestor else {
            // The proof links a stretch that reaches down to the checkpoint
            // and still shares nothing: the fork is below it.
            if proof.linked_from() <= self.checkpoint_height && proof.tip_height() >= self.checkpoint_height {
                return Err(CanonicalError::TooDeep {
                    checkpoint_height: self.checkpoint_height,
                });
            }
            return Err(CanonicalError::NoCommonHeader);
        };
        if ancestor == proof.tip_height() {
            return if blocks.is_empty() {
                Ok(Followed::Unchanged)
            } else {
                Err(CanonicalError::Blocks {
                    from: ancestor + 1,
                    to: ancestor,
                })
            };
        }
        let kept = usize::try_from(ancestor - self.checkpoint_height).expect("at most the window");
        let disconnected = &self.blocks[kept..];
        if !disconnected.is_empty() {
            let ours = disconnected.iter().try_fold(0u128, |sum, connected| sum.checked_add(connected.work));
            let theirs = proof.work_above(ancestor);
            if theirs.zip(ours).is_none_or(|(theirs, ours)| theirs <= ours) {
                return Ok(Followed::KeptHeavier {
                    ancestor_height: ancestor,
                });
            }
        }
        let to = proof.tip_height();
        let in_order = blocks.len() as u64 == to - ancestor
            && blocks.iter().zip(ancestor + 1..).all(|(block, height)| block.height == height);
        if !in_order {
            return Err(CanonicalError::Blocks {
                from: ancestor + 1,
                to,
            });
        }

        // The trees at the ancestor: the current ones when nothing is
        // disconnected, else rebuilt from the checkpoint.
        let mut trees = if disconnected.is_empty() {
            self.current.clone()
        } else {
            let mut trees = self.checkpoint.clone();
            for connected in &self.blocks[..kept] {
                trees.apply(&connected.block)?;
            }
            trees
        };
        let mut connected = Vec::with_capacity(blocks.len());
        for block in blocks {
            let height = block.height;
            if proof.hash_at(height) != Some(block.hash) {
                return Err(CanonicalError::BlockHash { height });
            }
            let roots = roots_at(proof, height, reader).ok_or(CanonicalError::Roots { height })?;
            if !crate::lookup::check_lookup_digest(&block.list, &roots.lookup_digest) {
                return Err(CanonicalError::LookupDigest { height });
            }
            trees.apply(block)?;
            trees.check_roots(height, &roots)?;
            let work = proof.work_at(height).expect("a tail header has its work");
            connected.push(Connected {
                block: block.clone(),
                work,
            });
        }

        // Every block checked: commit.
        let gone: Vec<[u8; 32]> = self.blocks.drain(kept..).map(|connected| connected.block.hash).collect();
        self.blocks.extend(connected);
        self.current = trees;
        self.fold();
        Ok(if gone.is_empty() {
            Followed::Extended {
                connected: blocks.len() as u64,
            }
        } else {
            Followed::Reorganised {
                ancestor_height: ancestor,
                disconnected: gone,
                connected: blocks.len() as u64,
            }
        })
    }

    /// Moves the checkpoint up until at most `window` blocks are above it.
    fn fold(&mut self) {
        while self.blocks.len() as u64 > self.window {
            let oldest = self.blocks.remove(0);
            self.checkpoint
                .apply(&oldest.block)
                .expect("a block connected once connects again on the same trees");
            self.checkpoint_height = oldest.block.height;
            self.checkpoint_hash = oldest.block.hash;
        }
    }
}

/// Whether `checked`, a keep-up result, is the coin's current status at the
/// tip of `later`, a proof checked after it: only when `later` ends at the
/// very tip the status was checked to
/// ([`crate::header_sample::ChainChange::Same`]).
///
/// Chain ancestry alone never carries a status forward. A chain that
/// extends the checked tip ([`crate::header_sample::ChainChange::Extended`])
/// can spend the coin in
/// a block the check never read, so an unspent result there is stale; a
/// proof behind it, a reorganisation, a lighter branch or proofs that link
/// no common header are no better. In every such case the wallet calls
/// [`check_keep_up`] against `later` before it reports the coin spendable.
pub fn keep_up_holds(checked: &KeepUp, later: &ProvenChain) -> bool {
    later.tip_hash() == checked.tip_hash && later.tip_height() == checked.tip_height
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;
    use crate::key::KeyFormat;
    use crate::note::encrypt_note;

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
        let note = encrypt_note(&key.note_key(), CHAIN_ID, &commit.commitment, &contents, &Capsule::empty(), rng);
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

    /// The coin tree's root over `leaves` and the path of leaf `index`,
    /// built level by level over the whole depth.
    fn naive_root_and_path(leaves: &[[u8; 32]], index: usize) -> ([u8; 32], [[u8; 32]; TREE_DEPTH]) {
        let zeros = coin_zeros();
        let mut level_nodes = leaves.to_vec();
        let mut path = [[0u8; 32]; TREE_DEPTH];
        let mut at = index;
        for level in 0..TREE_DEPTH {
            path[level] = level_nodes.get(at ^ 1).copied().unwrap_or(zeros[level]);
            at /= 2;
            if level_nodes.is_empty() {
                level_nodes.push(zeros[level]);
            }
            level_nodes = level_nodes
                .chunks(2)
                .map(|pair| tree_node(Tree::Coin, level as u8, &pair[0], pair.get(1).unwrap_or(&zeros[level])))
                .collect();
        }
        (level_nodes[0], path)
    }

    #[test]
    fn coin_frontier_gives_the_root_of_the_whole_tree() {
        let leaves: Vec<[u8; 32]> = (1..=13u8).map(|byte| [byte; 32]).collect();
        let mut frontier = CoinFrontier::new();
        // The empty tree is `Z_32`.
        assert_eq!(frontier.root(), coin_zeros()[TREE_DEPTH]);
        for count in 1..=leaves.len() {
            frontier.append(&leaves[count - 1]);
            assert_eq!(frontier.next_position(), count as u64);
            let (root, _) = naive_root_and_path(&leaves[..count], 0);
            assert_eq!(frontier.root(), root, "{count} leaves");
            // Every leaf's path, as a reveal proves it, folds to that root.
            for index in 0..count {
                let (_, path) = naive_root_and_path(&leaves[..count], index);
                assert_eq!(ghost_proofs::merkle_root(Tree::Coin, &leaves[index], index as u32, &path), root);
            }
        }
        // One leaf changed changes the root.
        let mut other = CoinFrontier::new();
        for (index, leaf) in leaves.iter().enumerate() {
            other.append(if index == 6 { &[0xee; 32] } else { leaf });
        }
        assert_ne!(other.root(), frontier.root());
    }

    #[test]
    fn a_full_coin_tree_is_followed_by_the_next_tree_index() {
        // A frontier one leaf short of a full tree: every left subtree full.
        let zeros = coin_zeros();
        let mut frontier = CoinFrontier {
            tree_index: 0,
            count: TREE_POSITIONS - 1,
            left: core::array::from_fn(|level| zeros[level]),
            full_root: None,
        };
        frontier.append(&zeros[0]);
        // Every position filled with the empty leaf: the empty tree's root,
        // read from the full root.
        assert_eq!(frontier.full_root, Some(zeros[TREE_DEPTH]));
        assert_eq!(frontier.root(), zeros[TREE_DEPTH]);
        assert_eq!(frontier.next_position(), TREE_POSITIONS);
        frontier.append(&[7; 32]);
        assert_eq!((frontier.tree_index, frontier.count), (1, 1));
        assert_eq!(frontier.next_position(), TREE_POSITIONS + 1);
        assert_eq!(frontier.root(), naive_root_and_path(&[[7; 32]], 0).0);
    }
}
