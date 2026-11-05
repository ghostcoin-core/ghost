//! Lookup tags, lookup index witnesses, the coin spent-marker set tree and
//! the block lookup digest (spec 01, section 7; spec 05, sections 2, 3 and 6;
//! decision 0004).
//!
//! ```text
//! lookupTag_i = the first 16 bytes of S("ghost/note-lookup/v1", k_note, i as 8 bytes)
//! g           = k * 2^32 + p, 5 bytes; ff ff ff ff ff is "none"
//!
//! lookup leaf = K("ghost/{coin,data}-lookup-leaf/v1", tag, position, nextTag, nextPosition, nextIndex)
//! lookup node = K("ghost/{coin,data}-lookup-node/v1", l as 1 byte, left, right)
//! marker leaf = K("ghost/coin-marker-set-leaf/v1", value, nextValue, nextIndex, appended)
//! marker node = K("ghost/coin-marker-set-node/v1", l as 1 byte, left, right)
//! ```
//!
//! Every tree here is an append-only indexed Keccak-256 tree of depth 40: the
//! sentinel at position 0, the empty leaf `E = K("ghost/empty-leaf/v1")` at
//! every unused position, and empty subtrees `Z_0 = E`,
//! `Z_(l+1) = node(l, Z_l, Z_l)` under the tree's own node tag. Bit `l` of a
//! position says whether the node folded at level `l` comes from the right.
//!
//! A wallet checks the answers it is given against roots taken from headers
//! on its own checked chain:
//!
//! - [`verify_lookup_membership`]: a pair (tag, global position) is in the
//!   lookup index, and which entry follows it.
//! - [`verify_lookup`]: the first entry carrying a tag, or that no leaf of the
//!   type carries it (the absence witness).
//! - [`verify_marker_membership`]: a coin marker is spent, and the global
//!   position of the leaf its reveal appended.
//! - [`verify_marker_absence`]: a coin marker is unspent.
//!
//! A witness authenticates only its own leaf's fields: tags, markers and
//! global positions, never the commitment or the note at the position it
//! names (spec 05, section 6, "What a witness does not authenticate").
//!
//! [`LookupIndex`] and [`CoinMarkerSet`] rebuild the trees from the tags and
//! markers a wallet reads in block order (each block's list checked against
//! its `lookupDigest` with [`BlockLookupList`]), so that it can compare a
//! rebuilt root with a header's and make its own witnesses. A rebuild follows
//! the canonical chain: after a reorganisation the wallet rebuilds from the
//! common ancestor, and a spend only on a disconnected block is absent from
//! every new root.

use std::fmt;

use crate::derive::NoteKey;
use crate::hash::{
    self, TAG_BLOCK_LOOKUP_DIGEST, TAG_COIN_LOOKUP_LEAF, TAG_COIN_LOOKUP_NODE, TAG_COIN_MARKER_SET_LEAF,
    TAG_COIN_MARKER_SET_NODE, TAG_DATA_LOOKUP_LEAF, TAG_DATA_LOOKUP_NODE, TAG_EMPTY_LEAF, TAG_NOTE_LOOKUP,
};
use crate::key::PhantomKey;

/// Length of a lookup tag.
pub const LOOKUP_TAG_BYTES: usize = 16;
/// Length of a global position, and of every index position.
pub const POSITION_BYTES: usize = 5;
/// Depth of every tree of this module: 2^40 positions.
pub const TREE_DEPTH: usize = 40;
/// Length of a lookup index leaf.
pub const LOOKUP_LEAF_BYTES: usize = 2 * LOOKUP_TAG_BYTES + 3 * POSITION_BYTES;
/// Length of a lookup witness, of every kind.
pub const LOOKUP_WITNESS_BYTES: usize = LOOKUP_LEAF_BYTES + POSITION_BYTES + 32 * TREE_DEPTH;
/// Length of a coin marker-set leaf.
pub const COIN_MARKER_LEAF_BYTES: usize = 2 * 32 + 2 * POSITION_BYTES;
/// Length of a coin marker-set witness, of either kind.
pub const COIN_MARKER_WITNESS_BYTES: usize = COIN_MARKER_LEAF_BYTES + POSITION_BYTES + 32 * TREE_DEPTH;
/// `ff ff ff ff ff`, 2^40 - 1: never a global position, "no leaf". Every
/// global position is below it.
pub const NO_POSITION: u64 = (1 << 40) - 1;
/// The number of positions of one tree index, 2^32.
pub const TREE_POSITIONS: u64 = 1 << 32;

const _: () = assert!(LOOKUP_LEAF_BYTES == 47);
const _: () = assert!(LOOKUP_WITNESS_BYTES == 1332);
const _: () = assert!(COIN_MARKER_LEAF_BYTES == 74);
const _: () = assert!(COIN_MARKER_WITNESS_BYTES == 1359);

/// A 16-byte lookup tag.
pub type LookupTag = [u8; LOOKUP_TAG_BYTES];

/// The zero tag: the sentinel's, and "no larger entry" in `nextTag`. Never a
/// valid tag.
pub const ZERO_TAG: LookupTag = [0; LOOKUP_TAG_BYTES];

/// `lookupTag_i`: the first 16 bytes of `S("ghost/note-lookup/v1", k_note,
/// i as 8 bytes)`, the lookup tag of the key's commitment number `number`.
pub fn lookup_tag(key: &NoteKey, number: u64) -> LookupTag {
    let digest = hash::s(TAG_NOTE_LOOKUP, &[key.as_bytes(), &number.to_be_bytes()]);
    let mut tag = ZERO_TAG;
    tag.copy_from_slice(&digest[..LOOKUP_TAG_BYTES]);
    tag
}

/// The lookup tag of commitment number `number` of a key, from its digits
/// alone.
pub fn key_lookup_tag(key: &PhantomKey, number: u64) -> LookupTag {
    lookup_tag(&key.note_key(), number)
}

/// The lookup tags of the key's commitment numbers in `numbers`, in order,
/// under one derivation of its note key.
pub fn lookup_tags(key: &PhantomKey, numbers: std::ops::Range<u64>) -> Vec<LookupTag> {
    let note_key = key.note_key();
    numbers.map(|number| lookup_tag(&note_key, number)).collect()
}

/// The global position `g = k * 2^32 + p` of position `position` of tree
/// index `tree_index`, or `None` when it would be 2^40 - 1 or more: the last
/// usable leaf is position 4294967294 of tree index 255.
pub fn global_position(tree_index: u64, position: u32) -> Option<u64> {
    let g = tree_index.checked_mul(TREE_POSITIONS)?.checked_add(u64::from(position))?;
    (g < NO_POSITION).then_some(g)
}

/// A position or [`NO_POSITION`] as its 5 big-endian bytes, or `None` above
/// 2^40 - 1.
pub fn position_bytes(position: u64) -> Option<[u8; POSITION_BYTES]> {
    (position <= NO_POSITION).then(|| be5(position))
}

/// The value of 5 big-endian bytes.
pub fn read_position(bytes: &[u8; POSITION_BYTES]) -> u64 {
    bytes.iter().fold(0, |value, &byte| (value << 8) | u64::from(byte))
}

fn be5(value: u64) -> [u8; POSITION_BYTES] {
    let full = value.to_be_bytes();
    let mut out = [0u8; POSITION_BYTES];
    out.copy_from_slice(&full[8 - POSITION_BYTES..]);
    out
}

fn take<const N: usize>(bytes: &[u8], at: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*at..*at + N]);
    *at += N;
    out
}

/// The empty subtrees `Z_0 = E` to `Z_40` under a node tag.
fn empty_subtrees(node_tag: &str) -> [[u8; 32]; TREE_DEPTH + 1] {
    let mut zeros = [[0u8; 32]; TREE_DEPTH + 1];
    zeros[0] = hash::k(TAG_EMPTY_LEAF, &[]);
    for level in 0..TREE_DEPTH {
        zeros[level + 1] = node(node_tag, level, &zeros[level], &zeros[level]);
    }
    zeros
}

fn node(node_tag: &str, level: usize, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let level = u8::try_from(level).expect("a level is below 40");
    hash::k(node_tag, &[&[level], left, right])
}

/// The root that `leaf` at `index` gives with `siblings` from level 0 up.
fn fold(node_tag: &str, leaf: [u8; 32], index: u64, siblings: &[[u8; 32]; TREE_DEPTH]) -> [u8; 32] {
    let mut current = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if (index >> level) & 1 == 1 {
            node(node_tag, level, sibling, &current)
        } else {
            node(node_tag, level, &current, sibling)
        };
    }
    current
}

/// The root of a tree whose used positions `0..leaves.len()` hold these leaf
/// hashes, and the siblings of the leaf at `index`, if one is asked for.
fn root_and_path(node_tag: &str, leaves: Vec<[u8; 32]>, index: Option<usize>) -> ([u8; 32], [[u8; 32]; TREE_DEPTH]) {
    let zeros = empty_subtrees(node_tag);
    let mut level_nodes = leaves;
    let mut index = index;
    let mut siblings = [[0u8; 32]; TREE_DEPTH];
    for level in 0..TREE_DEPTH {
        if level_nodes.is_empty() {
            return (zeros[TREE_DEPTH], siblings);
        }
        if let Some(i) = index {
            siblings[level] = level_nodes.get(i ^ 1).copied().unwrap_or(zeros[level]);
            index = Some(i / 2);
        }
        level_nodes = level_nodes
            .chunks(2)
            .map(|pair| node(node_tag, level, &pair[0], pair.get(1).unwrap_or(&zeros[level])))
            .collect();
    }
    (level_nodes[0], siblings)
}

/// Why a witness is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessError {
    /// The witness is not of its one length.
    Length {
        /// The length of the layout.
        expected: usize,
        /// The length given.
        got: usize,
    },
    /// The tag or marker asked about is zero, the sentinel's key.
    ZeroKey,
    /// The leaf does not fold to the root.
    Root,
    /// The leaf is not the entry asked about.
    NotTheEntry,
    /// The leaf is not the low leaf of the tag or marker asked about.
    NotTheLowLeaf,
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, got } => write!(f, "witness is {got} bytes, not {expected}"),
            Self::ZeroKey => write!(f, "the zero tag or marker is never valid"),
            Self::Root => write!(f, "witness does not fold to the root"),
            Self::NotTheEntry => write!(f, "witness leaf is not the entry asked about"),
            Self::NotTheLowLeaf => write!(f, "witness leaf is not the low leaf of the key asked about"),
        }
    }
}

impl std::error::Error for WitnessError {}

/// Why an insert into a rebuilt tree is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertError {
    /// The tag or marker is zero.
    ZeroKey,
    /// The key is already in the tree: a repeated pair, or a marker spent
    /// before.
    Duplicate,
    /// A global position of 2^40 - 1 or more.
    PositionOutOfRange,
    /// The tree has no unused position left.
    Full,
}

impl fmt::Display for InsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroKey => write!(f, "the zero tag or marker is never valid"),
            Self::Duplicate => write!(f, "the key is already in the tree"),
            Self::PositionOutOfRange => write!(f, "a global position is below 2^40 - 1"),
            Self::Full => write!(f, "the tree is full"),
        }
    }
}

impl std::error::Error for InsertError {}

// ---------------------------------------------------------------------------
// Lookup indices
// ---------------------------------------------------------------------------

/// The type of a lookup index: one per type of leaf, each under its own tags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupTree {
    /// The coin lookup index, root `coinLookupRoot` (header field 19).
    Coin,
    /// The data lookup index, root `dataLookupRoot` (header field 20).
    Data,
}

impl LookupTree {
    /// The tag of its leaf hash.
    pub const fn leaf_tag(self) -> &'static str {
        match self {
            Self::Coin => TAG_COIN_LOOKUP_LEAF,
            Self::Data => TAG_DATA_LOOKUP_LEAF,
        }
    }

    /// The tag of its node hash.
    pub const fn node_tag(self) -> &'static str {
        match self {
            Self::Coin => TAG_COIN_LOOKUP_NODE,
            Self::Data => TAG_DATA_LOOKUP_NODE,
        }
    }

    /// The root of the genesis index, the sentinel alone: the genesis
    /// `coinLookupRoot` or `dataLookupRoot`.
    pub fn genesis_root(self) -> [u8; 32] {
        LookupIndex::new(self).root()
    }
}

/// One used position of a lookup index, the 47-byte leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupLeaf {
    /// The lookup tag of a leaf of the index's type.
    pub tag: LookupTag,
    /// That leaf's global position.
    pub position: u64,
    /// The tag of the next entry in key order; [`ZERO_TAG`] for none.
    pub next_tag: LookupTag,
    /// The global position of that next entry.
    pub next_position: u64,
    /// The position of that next entry in this index.
    pub next_index: u64,
}

impl LookupLeaf {
    /// The sentinel at position 0: every field zero.
    pub const SENTINEL: Self = Self {
        tag: ZERO_TAG,
        position: 0,
        next_tag: ZERO_TAG,
        next_position: 0,
        next_index: 0,
    };

    /// The 47 bytes `tag || position || nextTag || nextPosition || nextIndex`.
    /// Positions take their low 5 bytes.
    pub fn to_bytes(&self) -> [u8; LOOKUP_LEAF_BYTES] {
        let mut out = [0u8; LOOKUP_LEAF_BYTES];
        out[..16].copy_from_slice(&self.tag);
        out[16..21].copy_from_slice(&be5(self.position));
        out[21..37].copy_from_slice(&self.next_tag);
        out[37..42].copy_from_slice(&be5(self.next_position));
        out[42..47].copy_from_slice(&be5(self.next_index));
        out
    }

    /// The leaf from its 47 bytes.
    pub fn from_bytes(bytes: &[u8; LOOKUP_LEAF_BYTES]) -> Self {
        let mut at = 0;
        Self {
            tag: take(bytes, &mut at),
            position: read_position(&take(bytes, &mut at)),
            next_tag: take(bytes, &mut at),
            next_position: read_position(&take(bytes, &mut at)),
            next_index: read_position(&take(bytes, &mut at)),
        }
    }

    /// Its leaf hash in the index of `tree`.
    pub fn hash(&self, tree: LookupTree) -> [u8; 32] {
        hash::k(tree.leaf_tag(), &[&self.to_bytes()])
    }

    /// Its key `(tag, position)`, ordered as `tag || position`.
    pub fn key(&self) -> (LookupTag, u64) {
        (self.tag, self.position)
    }

    /// The key of the next entry, or `None` when `nextTag` is zero.
    pub fn next_key(&self) -> Option<(LookupTag, u64)> {
        (self.next_tag != ZERO_TAG).then_some((self.next_tag, self.next_position))
    }
}

/// A lookup witness of any kind: the leaf's fields, its index position and
/// its 40 siblings from level 0 up, 1,332 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupWitness {
    /// The leaf the witness opens.
    pub leaf: LookupLeaf,
    /// Its position in the index.
    pub index_position: u64,
    /// The siblings from level 0 up.
    pub siblings: [[u8; 32]; TREE_DEPTH],
}

impl LookupWitness {
    /// The witness from its bytes; any other length is rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() != LOOKUP_WITNESS_BYTES {
            return Err(WitnessError::Length {
                expected: LOOKUP_WITNESS_BYTES,
                got: bytes.len(),
            });
        }
        let mut at = 0;
        let leaf = LookupLeaf::from_bytes(&take(bytes, &mut at));
        let index_position = read_position(&take(bytes, &mut at));
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        for sibling in &mut siblings {
            *sibling = take(bytes, &mut at);
        }
        Ok(Self {
            leaf,
            index_position,
            siblings,
        })
    }

    /// The 1,332 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LOOKUP_WITNESS_BYTES);
        out.extend_from_slice(&self.leaf.to_bytes());
        out.extend_from_slice(&be5(self.index_position));
        for sibling in &self.siblings {
            out.extend_from_slice(sibling);
        }
        out
    }

    /// The root its leaf folds to in the index of `tree`.
    pub fn root(&self, tree: LookupTree) -> [u8; 32] {
        fold(tree.node_tag(), self.leaf.hash(tree), self.index_position, &self.siblings)
    }

    fn check_root(&self, tree: LookupTree, root: &[u8; 32]) -> Result<(), WitnessError> {
        if &self.root(tree) == root {
            Ok(())
        } else {
            Err(WitnessError::Root)
        }
    }
}

/// What a membership witness shows besides the pair itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupMembership {
    /// The position of the pair's entry in the index.
    pub index_position: u64,
    /// The global position of the next leaf carrying the same tag, if the
    /// next entry carries it: a copy the wallet passes over one witness at a
    /// time.
    pub next_with_same_tag: Option<u64>,
}

/// The answer of a lookup witness for a tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupAnswer {
    /// The first entry with the tag: no leaf with that tag has a smaller
    /// global position.
    First {
        /// Its global position.
        position: u64,
        /// Its position in the index.
        index_position: u64,
    },
    /// No leaf of this type carries the tag under the root.
    Absent,
}

/// Checks a membership witness for the pair (`tag`, `position`) against a
/// lookup index root: valid if and only if the tag is not zero, the leaf
/// folds to `root`, and the leaf is that pair.
pub fn verify_lookup_membership(
    tree: LookupTree,
    root: &[u8; 32],
    witness: &[u8],
    tag: &LookupTag,
    position: u64,
) -> Result<LookupMembership, WitnessError> {
    let witness = LookupWitness::from_bytes(witness)?;
    if tag == &ZERO_TAG {
        return Err(WitnessError::ZeroKey);
    }
    witness.check_root(tree, root)?;
    let leaf = witness.leaf;
    if &leaf.tag != tag || leaf.position != position {
        return Err(WitnessError::NotTheEntry);
    }
    Ok(LookupMembership {
        index_position: witness.index_position,
        next_with_same_tag: (&leaf.next_tag == tag).then_some(leaf.next_position),
    })
}

/// Checks a lookup witness for `tag`, the low leaf of the query
/// `tag || 0^5`, against a lookup index root: valid if and only if the tag is
/// not zero, the leaf folds to `root`, its tag is below `tag`, and its
/// `nextTag` is zero or not below `tag`. Its answer is the first entry with
/// the tag, or that the tag is absent.
pub fn verify_lookup(
    tree: LookupTree,
    root: &[u8; 32],
    witness: &[u8],
    tag: &LookupTag,
) -> Result<LookupAnswer, WitnessError> {
    let witness = LookupWitness::from_bytes(witness)?;
    if tag == &ZERO_TAG {
        return Err(WitnessError::ZeroKey);
    }
    witness.check_root(tree, root)?;
    let leaf = witness.leaf;
    if &leaf.tag >= tag || (leaf.next_tag != ZERO_TAG && &leaf.next_tag < tag) {
        return Err(WitnessError::NotTheLowLeaf);
    }
    if &leaf.next_tag == tag {
        Ok(LookupAnswer::First {
            position: leaf.next_position,
            index_position: leaf.next_index,
        })
    } else {
        Ok(LookupAnswer::Absent)
    }
}

/// A lookup index rebuilt from the tags of the leaves of one type, in append
/// order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupIndex {
    tree: LookupTree,
    leaves: Vec<LookupLeaf>,
}

impl LookupIndex {
    /// The genesis index: the sentinel alone.
    pub fn new(tree: LookupTree) -> Self {
        Self {
            tree,
            leaves: vec![LookupLeaf::SENTINEL],
        }
    }

    /// The index of `tree` after inserting `entries`, (tag, global position)
    /// pairs, in order.
    pub fn from_entries<I>(tree: LookupTree, entries: I) -> Result<Self, InsertError>
    where
        I: IntoIterator<Item = (LookupTag, u64)>,
    {
        let mut index = Self::new(tree);
        for (tag, position) in entries {
            index.insert(tag, position)?;
        }
        Ok(index)
    }

    /// The type of the index.
    pub fn tree(&self) -> LookupTree {
        self.tree
    }

    /// The used positions, the sentinel included.
    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Never true: the sentinel is always there.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The used leaves, in index position order.
    pub fn leaves(&self) -> &[LookupLeaf] {
        &self.leaves
    }

    /// Inserts the entry of the leaf with tag `tag` at global position
    /// `position` and returns its index position.
    pub fn insert(&mut self, tag: LookupTag, position: u64) -> Result<u64, InsertError> {
        if tag == ZERO_TAG {
            return Err(InsertError::ZeroKey);
        }
        if position >= NO_POSITION {
            return Err(InsertError::PositionOutOfRange);
        }
        let n = self.len();
        if n > NO_POSITION {
            return Err(InsertError::Full);
        }
        let key = (tag, position);
        if self.leaves.iter().any(|leaf| leaf.key() == key) {
            return Err(InsertError::Duplicate);
        }
        let low = self.low_index(key);
        let old = self.leaves[low];
        self.leaves.push(LookupLeaf {
            tag,
            position,
            next_tag: old.next_tag,
            next_position: old.next_position,
            next_index: old.next_index,
        });
        let rewritten = &mut self.leaves[low];
        rewritten.next_tag = tag;
        rewritten.next_position = position;
        rewritten.next_index = n;
        Ok(n)
    }

    /// The index position of the low leaf of `key`: the used leaf whose key is
    /// below it and whose next key is not below it, or none. A key being
    /// inserted is never in the index, so its next key is above it; the
    /// lookup of `t || 0^5` can meet an entry at position 0 as its next key.
    fn low_index(&self, key: (LookupTag, u64)) -> usize {
        self.leaves
            .iter()
            .position(|leaf| leaf.key() < key && leaf.next_key().is_none_or(|next| key <= next))
            .expect("the sentinel is below every key")
    }

    /// The root of the index.
    pub fn root(&self) -> [u8; 32] {
        root_and_path(self.tree.node_tag(), self.hashes(), None).0
    }

    fn hashes(&self) -> Vec<[u8; 32]> {
        self.leaves.iter().map(|leaf| leaf.hash(self.tree)).collect()
    }

    /// The witness of the leaf at `index_position`, if it is used.
    pub fn witness_at(&self, index_position: u64) -> Option<LookupWitness> {
        let at = usize::try_from(index_position).ok()?;
        let leaf = *self.leaves.get(at)?;
        let siblings = root_and_path(self.tree.node_tag(), self.hashes(), Some(at)).1;
        Some(LookupWitness {
            leaf,
            index_position,
            siblings,
        })
    }

    /// The membership witness of the pair (`tag`, `position`), if it is in
    /// the index.
    pub fn membership_witness(&self, tag: &LookupTag, position: u64) -> Option<LookupWitness> {
        let at = self.leaves.iter().position(|leaf| leaf.key() == (*tag, position))?;
        self.witness_at(at as u64)
    }

    /// The lookup witness of `tag`: the low leaf of `tag || 0^5`. `None` for
    /// the zero tag.
    pub fn lookup_witness(&self, tag: &LookupTag) -> Option<LookupWitness> {
        if tag == &ZERO_TAG {
            return None;
        }
        self.witness_at(self.low_index((*tag, 0)) as u64)
    }
}

// ---------------------------------------------------------------------------
// Coin spent-marker set tree
// ---------------------------------------------------------------------------

/// One used position of the coin marker-set tree, the 74-byte leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoinMarkerLeaf {
    /// A spent coin marker.
    pub value: [u8; 32],
    /// The next larger marker in the set; 32 zero bytes for none.
    pub next_value: [u8; 32],
    /// The position of that marker's leaf in this tree.
    pub next_index: u64,
    /// The global position of the coin leaf the reveal spending `value`
    /// appended, or `None`, written `ff ff ff ff ff`.
    pub appended: Option<u64>,
}

impl CoinMarkerLeaf {
    /// The sentinel at position 0: `(0, 0, 0, none)`.
    pub const SENTINEL: Self = Self {
        value: [0; 32],
        next_value: [0; 32],
        next_index: 0,
        appended: None,
    };

    /// The 74 bytes `value || nextValue || nextIndex || appended`.
    pub fn to_bytes(&self) -> [u8; COIN_MARKER_LEAF_BYTES] {
        let mut out = [0u8; COIN_MARKER_LEAF_BYTES];
        out[..32].copy_from_slice(&self.value);
        out[32..64].copy_from_slice(&self.next_value);
        out[64..69].copy_from_slice(&be5(self.next_index));
        out[69..74].copy_from_slice(&be5(self.appended.unwrap_or(NO_POSITION)));
        out
    }

    /// The leaf from its 74 bytes; `ff ff ff ff ff` in `appended` is none.
    pub fn from_bytes(bytes: &[u8; COIN_MARKER_LEAF_BYTES]) -> Self {
        let mut at = 0;
        let value = take(bytes, &mut at);
        let next_value = take(bytes, &mut at);
        let next_index = read_position(&take(bytes, &mut at));
        let appended = read_position(&take(bytes, &mut at));
        Self {
            value,
            next_value,
            next_index,
            appended: (appended != NO_POSITION).then_some(appended),
        }
    }

    /// Its leaf hash.
    pub fn hash(&self) -> [u8; 32] {
        hash::k(TAG_COIN_MARKER_SET_LEAF, &[&self.to_bytes()])
    }
}

/// A coin marker-set witness of either kind: the leaf's fields, its position
/// and its 40 siblings from level 0 up, 1,359 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinMarkerWitness {
    /// The leaf the witness opens.
    pub leaf: CoinMarkerLeaf,
    /// Its position in the tree.
    pub position: u64,
    /// The siblings from level 0 up.
    pub siblings: [[u8; 32]; TREE_DEPTH],
}

impl CoinMarkerWitness {
    /// The witness from its bytes; any other length is rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() != COIN_MARKER_WITNESS_BYTES {
            return Err(WitnessError::Length {
                expected: COIN_MARKER_WITNESS_BYTES,
                got: bytes.len(),
            });
        }
        let mut at = 0;
        let leaf = CoinMarkerLeaf::from_bytes(&take(bytes, &mut at));
        let position = read_position(&take(bytes, &mut at));
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        for sibling in &mut siblings {
            *sibling = take(bytes, &mut at);
        }
        Ok(Self {
            leaf,
            position,
            siblings,
        })
    }

    /// The 1,359 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COIN_MARKER_WITNESS_BYTES);
        out.extend_from_slice(&self.leaf.to_bytes());
        out.extend_from_slice(&be5(self.position));
        for sibling in &self.siblings {
            out.extend_from_slice(sibling);
        }
        out
    }

    /// The root its leaf folds to.
    pub fn root(&self) -> [u8; 32] {
        fold(TAG_COIN_MARKER_SET_NODE, self.leaf.hash(), self.position, &self.siblings)
    }

    fn check(witness: &[u8], root: &[u8; 32], marker: &[u8; 32]) -> Result<Self, WitnessError> {
        let witness = Self::from_bytes(witness)?;
        if marker == &[0; 32] {
            return Err(WitnessError::ZeroKey);
        }
        if &witness.root() != root {
            return Err(WitnessError::Root);
        }
        Ok(witness)
    }
}

/// What a membership witness shows about a spent marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpentMarker {
    /// The position of the marker's leaf in the tree.
    pub position: u64,
    /// The global position of the coin leaf its reveal appended, where the
    /// wallet reads the next commitment, or `None`.
    pub appended: Option<u64>,
}

/// Checks a membership witness for `marker` against a `coinMarkerRoot`:
/// valid if and only if the marker is not zero, the leaf folds to `root` and
/// its value is the marker. The marker is then spent on the chain of `root`.
pub fn verify_marker_membership(
    root: &[u8; 32],
    witness: &[u8],
    marker: &[u8; 32],
) -> Result<SpentMarker, WitnessError> {
    let witness = CoinMarkerWitness::check(witness, root, marker)?;
    if &witness.leaf.value != marker {
        return Err(WitnessError::NotTheEntry);
    }
    Ok(SpentMarker {
        position: witness.position,
        appended: witness.leaf.appended,
    })
}

/// Checks an absence witness for `marker` against a `coinMarkerRoot`: valid
/// if and only if the marker is not zero, the leaf folds to `root`, its value
/// is below the marker and its `nextValue` is above it or zero. The marker is
/// then unspent under `root`.
pub fn verify_marker_absence(root: &[u8; 32], witness: &[u8], marker: &[u8; 32]) -> Result<(), WitnessError> {
    let witness = CoinMarkerWitness::check(witness, root, marker)?;
    let leaf = witness.leaf;
    if &leaf.value < marker && (marker < &leaf.next_value || leaf.next_value == [0; 32]) {
        Ok(())
    } else {
        Err(WitnessError::NotTheLowLeaf)
    }
}

/// The coin spent-marker set tree rebuilt from the coin markers in the
/// order they were spent, each with the global position its reveal
/// appended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinMarkerSet {
    leaves: Vec<CoinMarkerLeaf>,
}

impl Default for CoinMarkerSet {
    fn default() -> Self {
        Self::new()
    }
}

impl CoinMarkerSet {
    /// The genesis set: the sentinel alone.
    pub fn new() -> Self {
        Self {
            leaves: vec![CoinMarkerLeaf::SENTINEL],
        }
    }

    /// The set after inserting `spends`, (marker, appended) pairs, in order.
    pub fn from_spends<I>(spends: I) -> Result<Self, InsertError>
    where
        I: IntoIterator<Item = ([u8; 32], Option<u64>)>,
    {
        let mut set = Self::new();
        for (marker, appended) in spends {
            set.insert(marker, appended)?;
        }
        Ok(set)
    }

    /// The root of the genesis set, the genesis `coinMarkerRoot`.
    pub fn genesis_root() -> [u8; 32] {
        Self::new().root()
    }

    /// The used positions, the sentinel included.
    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Never true: the sentinel is always there.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The used leaves, in position order.
    pub fn leaves(&self) -> &[CoinMarkerLeaf] {
        &self.leaves
    }

    /// Whether `marker` is in the set.
    pub fn contains(&self, marker: &[u8; 32]) -> bool {
        marker != &[0; 32] && self.leaves.iter().any(|leaf| &leaf.value == marker)
    }

    /// Inserts the spend of `marker` whose reveal appended the coin leaf at
    /// global position `appended`, and returns the marker's position. A
    /// rewritten leaf keeps its own `appended`.
    pub fn insert(&mut self, marker: [u8; 32], appended: Option<u64>) -> Result<u64, InsertError> {
        if marker == [0; 32] {
            return Err(InsertError::ZeroKey);
        }
        if appended.is_some_and(|position| position >= NO_POSITION) {
            return Err(InsertError::PositionOutOfRange);
        }
        let n = self.len();
        if n > NO_POSITION {
            return Err(InsertError::Full);
        }
        if self.contains(&marker) {
            return Err(InsertError::Duplicate);
        }
        let low = self.low_index(&marker);
        let old = self.leaves[low];
        self.leaves.push(CoinMarkerLeaf {
            value: marker,
            next_value: old.next_value,
            next_index: old.next_index,
            appended,
        });
        let rewritten = &mut self.leaves[low];
        rewritten.next_value = marker;
        rewritten.next_index = n;
        Ok(n)
    }

    fn low_index(&self, marker: &[u8; 32]) -> usize {
        self.leaves
            .iter()
            .position(|leaf| &leaf.value < marker && (marker < &leaf.next_value || leaf.next_value == [0; 32]))
            .expect("the sentinel is below every marker")
    }

    /// The root of the set.
    pub fn root(&self) -> [u8; 32] {
        root_and_path(TAG_COIN_MARKER_SET_NODE, self.hashes(), None).0
    }

    fn hashes(&self) -> Vec<[u8; 32]> {
        self.leaves.iter().map(CoinMarkerLeaf::hash).collect()
    }

    /// The witness of the leaf at `position`, if it is used.
    pub fn witness_at(&self, position: u64) -> Option<CoinMarkerWitness> {
        let at = usize::try_from(position).ok()?;
        let leaf = *self.leaves.get(at)?;
        let siblings = root_and_path(TAG_COIN_MARKER_SET_NODE, self.hashes(), Some(at)).1;
        Some(CoinMarkerWitness {
            leaf,
            position,
            siblings,
        })
    }

    /// The membership witness of `marker`, if it is spent.
    pub fn membership_witness(&self, marker: &[u8; 32]) -> Option<CoinMarkerWitness> {
        if marker == &[0; 32] {
            return None;
        }
        let at = self.leaves.iter().position(|leaf| &leaf.value == marker)?;
        self.witness_at(at as u64)
    }

    /// The absence witness of `marker`, if it is unspent and not zero.
    pub fn absence_witness(&self, marker: &[u8; 32]) -> Option<CoinMarkerWitness> {
        if marker == &[0; 32] || self.contains(marker) {
            return None;
        }
        self.witness_at(self.low_index(marker) as u64)
    }
}

// ---------------------------------------------------------------------------
// Block lookup digest
// ---------------------------------------------------------------------------

/// Why a block's lookup list cannot be encoded or decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListError {
    /// A start position of 2^40 - 1 or more.
    PositionOutOfRange,
    /// A list of 2^32 items or more.
    TooLong,
    /// The bytes end early or run on after the last list.
    Length,
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PositionOutOfRange => write!(f, "a start position is below 2^40 - 1"),
            Self::TooLong => write!(f, "a list has fewer than 2^32 items"),
            Self::Length => write!(f, "the encoding does not end where its counts say"),
        }
    }
}

impl std::error::Error for ListError {}

/// A block's new coin tags, data tags, coin markers and data markers, each in
/// transaction order: the list the header field `lookupDigest` commits to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockLookupList {
    /// The global position of the block's first new coin leaf: the coin
    /// leaves appended before the block.
    pub coin_start: u64,
    /// The tag of every coin leaf the block appends, in append order.
    pub coin_tags: Vec<LookupTag>,
    /// The global position of the block's first new data leaf.
    pub data_start: u64,
    /// The tag of every data commit of the block.
    pub data_tags: Vec<LookupTag>,
    /// Every marker the block's coin reveals insert.
    pub coin_markers: Vec<[u8; 32]>,
    /// Every marker the block's data reveals and revocations insert.
    pub data_markers: Vec<[u8; 32]>,
}

fn count(len: usize) -> Result<[u8; 4], ListError> {
    u32::try_from(len).map(u32::to_be_bytes).map_err(|_| ListError::TooLong)
}

fn read_list<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<Vec<[u8; N]>, ListError> {
    if bytes.len() < *at + 4 {
        return Err(ListError::Length);
    }
    let n = u32::from_be_bytes(take(bytes, at)) as usize;
    let end = n.checked_mul(N).and_then(|len| len.checked_add(*at)).ok_or(ListError::Length)?;
    if bytes.len() < end {
        return Err(ListError::Length);
    }
    Ok((0..n).map(|_| take(bytes, at)).collect())
}

fn read_start(bytes: &[u8], at: &mut usize) -> Result<u64, ListError> {
    if bytes.len() < *at + POSITION_BYTES {
        return Err(ListError::Length);
    }
    let start = read_position(&take(bytes, at));
    if start >= NO_POSITION {
        return Err(ListError::PositionOutOfRange);
    }
    Ok(start)
}

impl BlockLookupList {
    /// The encoding `coinStart (5) || coinTagCount (4) || coin tags ||
    /// dataStart (5) || dataTagCount (4) || data tags || coinMarkerCount (4)
    /// || coin markers || dataMarkerCount (4) || data markers`.
    pub fn encoding(&self) -> Result<Vec<u8>, ListError> {
        if self.coin_start >= NO_POSITION || self.data_start >= NO_POSITION {
            return Err(ListError::PositionOutOfRange);
        }
        let mut out = Vec::with_capacity(
            26 + 16 * (self.coin_tags.len() + self.data_tags.len())
                + 32 * (self.coin_markers.len() + self.data_markers.len()),
        );
        out.extend_from_slice(&be5(self.coin_start));
        out.extend_from_slice(&count(self.coin_tags.len())?);
        self.coin_tags.iter().for_each(|tag| out.extend_from_slice(tag));
        out.extend_from_slice(&be5(self.data_start));
        out.extend_from_slice(&count(self.data_tags.len())?);
        self.data_tags.iter().for_each(|tag| out.extend_from_slice(tag));
        out.extend_from_slice(&count(self.coin_markers.len())?);
        self.coin_markers.iter().for_each(|marker| out.extend_from_slice(marker));
        out.extend_from_slice(&count(self.data_markers.len())?);
        self.data_markers.iter().for_each(|marker| out.extend_from_slice(marker));
        Ok(out)
    }

    /// The list from its encoding; bytes that do not end where the counts
    /// say are rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self, ListError> {
        let mut at = 0;
        let coin_start = read_start(bytes, &mut at)?;
        let coin_tags = read_list(bytes, &mut at)?;
        let data_start = read_start(bytes, &mut at)?;
        let data_tags = read_list(bytes, &mut at)?;
        let coin_markers = read_list(bytes, &mut at)?;
        let data_markers = read_list(bytes, &mut at)?;
        if at != bytes.len() {
            return Err(ListError::Length);
        }
        Ok(Self {
            coin_start,
            coin_tags,
            data_start,
            data_tags,
            coin_markers,
            data_markers,
        })
    }

    /// `lookupDigest = K("ghost/block-lookup-digest/v1", encoding)`.
    pub fn digest(&self) -> Result<[u8; 32], ListError> {
        Ok(hash::k(TAG_BLOCK_LOOKUP_DIGEST, &[&self.encoding()?]))
    }

    /// The block's new coin entries: the `j`-th coin tag with the global
    /// position `coinStart + j`.
    pub fn coin_entries(&self) -> impl Iterator<Item = (LookupTag, u64)> + '_ {
        self.coin_tags.iter().zip(self.coin_start..).map(|(tag, position)| (*tag, position))
    }

    /// The block's new data entries: the `j`-th data tag with the global
    /// position `dataStart + j`.
    pub fn data_entries(&self) -> impl Iterator<Item = (LookupTag, u64)> + '_ {
        self.data_tags.iter().zip(self.data_start..).map(|(tag, position)| (*tag, position))
    }
}

/// Whether the list is the one a header's `lookupDigest` commits to.
pub fn check_lookup_digest(list: &BlockLookupList, lookup_digest: &[u8; 32]) -> bool {
    list.digest().is_ok_and(|digest| &digest == lookup_digest)
}
