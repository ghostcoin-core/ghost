//! The checks of a restore by private lookup, and the decision they allow
//! (stage 2 design, "Wallet restore volume", "What a wallet does", steps 5
//! and 6).
//!
//! [`crate::restore_requests`] sends the 31 queries of a restore and keeps
//! the answers unchecked. This module believes nothing from them until it
//! has checked it against a header on the wallet's own checked chain:
//!
//! 1. **The snapshot header** ([`check_anchor`]) is one of the tail headers
//!    the wallet checked itself ([`crate::header_sample::CheckedTail::headers`]):
//!    a header that is not, an older one or one of another branch, is
//!    refused as stale, whatever server sent it. Its roots are the only
//!    roots the answers are checked against.
//! 2. **The bulk lists** of the blocks after the snapshot, one for each tail
//!    header above it, each match that header's `lookupDigest`. A missing or
//!    changed list is refused.
//! 3. **The note** of the number found decrypts under the note key with its
//!    leaf as associated data and recomputes that leaf from the digits
//!    ([`crate::restore::restore_coins_at`]), and its number is the one the
//!    probes found.
//! 4. **The coin witness**, the leaf's minipage of 64 leaves and its page's
//!    witness record, takes the leaf at its position to the snapshot
//!    header's `coinTreeRoot`.
//! 5. **The marker witness**, a minipage of the coin marker-set tree and its
//!    page's witness record, gives either the marker's own leaf (a
//!    membership witness) or the low leaf whose value and next value bracket
//!    it (an absence witness), up to the snapshot's `coinMarkerRoot`
//!    ([`verify_marker_membership`], [`verify_marker_absence`]).
//! 6. When the probes found nothing, **the lookup witness** of the first tag,
//!    the low leaf of the coin lookup index, goes up to the snapshot's
//!    `coinLookupRoot` ([`verify_lookup`]).
//!
//! A missing, wrong or misplaced item fails one of these and is refused with
//! a [`CheckError`], never guessed or repaired.
//!
//! # The decision
//!
//! [`check_session`] then decides ([`Decision`]):
//!
//! - an unspent marker absent from the later blocks makes that commitment the
//!   current one, with its path to the snapshot's coin root;
//! - an unspent marker spent in a later block means the coin moved since the
//!   snapshot: the wallet runs again on the next snapshot;
//! - a spent marker leads, through its leaf's `appended` position, to the
//!   next leaf, read in a second session ([`continue_requests`],
//!   [`check_continued`]): a note there that decrypts under the key is the
//!   next number. One that does not proves nothing alone, since no witness
//!   covers a note: the value left the key (claimed into another key) only
//!   if the lookup index's absence witness shows the leaf does not carry the
//!   key's tag of the next number at that position; if its membership
//!   witness shows the tag there, the leaf is the key's and its note is
//!   refused. A spend that appended nothing means the value left the key
//!   (fully revealed);
//! - nothing found, with the lookup index's absence witness, means the key
//!   never made a commitment by the snapshot. A witness that shows the first
//!   tag present after all leads to that leaf in a second session.
//!
//! A second session sends the same [`QUERIES`] queries in the order of the
//! [`plan`], every record hidden by PIR, so it looks like any restore. The hint
//! tables are never believed, so a server whose hints are stale or wrong
//! costs the wallet a second session, never a wrong result.
//! [`restore_with_checks`] runs the sessions one after another.
//!
//! Nothing here depends on which server answered: the roots come from the
//! wallet's own checked chain, so a wallet can restore from any restore
//! server it chooses, and a lying one is caught by the same checks.
//!
//! # Record layout
//!
//! The positional databases are read in these records, the layout the checks
//! read and [`TreeRecords`] builds from a tree's leaves:
//!
//! - A **minipage** is positions `64 m` to `64 m + 63` of one tree. Of the
//!   coin tree it is the 64 leaf values ([`Answer::Leaves`]), the empty leaf
//!   `E` at every unused position. Of the coin marker-set tree and the coin
//!   lookup index it is the encoded leaves of its used positions, in order
//!   ([`Answer::Record`]): 74 or 47 bytes each, at most 64, every position
//!   after them unused.
//! - A **page witness record** of page `p` (positions `4096 p` to
//!   `4096 p + 4095`) is the 64 level-6 nodes of the page, one per minipage
//!   (`Z_6` for an empty one), then the siblings of the page's level-12 node
//!   from level 12 up to the root: 20 for the coin tree (depth 32), 28 for the
//!   trees of depth 40; 32 bytes each ([`RecordTree::page_record_bytes`]).
//!
//! Every tree folds as [`crate::lookup`] and spec 05 fold: bit `l` of a
//! position says whether the node folded at level `l` comes from the right,
//! `node = K(node tag, l as 1 byte, left, right)`.
//!
//! # Header fields
//!
//! The snapshot header and the later headers are read as the 23-field header
//! of decision 0004 (spec 05, section 10), or the 24-field one of decision
//! 0005 with `headerMmrRoot` last: `coinTreeRoot` is field 16,
//! `coinLookupRoot` 19, `coinMarkerRoot` 21 and `lookupDigest` 22. Only the
//! fields read here are checked for size; the header's place on the checked
//! chain is what makes them believed.

use core::fmt;

use rand_core::CryptoRng;

use crate::commit::Commitment;
use crate::hash::{self, keccak256, TAG_COIN_MARKER_SET_NODE, TAG_EMPTY_LEAF};
use crate::header_sample::CheckedTail;
use crate::key::PhantomKey;
use crate::lookup::{
    lookup_tag, verify_lookup, verify_lookup_membership, verify_lookup_pair_absence, verify_marker_absence,
    verify_marker_membership, BlockLookupList, CoinMarkerLeaf,
    CoinMarkerSet, CoinMarkerWitness, LookupAnswer, LookupIndex, LookupLeaf, LookupTag, LookupTree, LookupWitness,
    COIN_MARKER_LEAF_BYTES, LOOKUP_LEAF_BYTES, NO_POSITION, TREE_DEPTH as INDEX_DEPTH, ZERO_TAG,
};
use crate::note::NOTE_BYTES;
use crate::restore::{restore_coins_at, FoundCoin, TreeLeaf};
use crate::restore_requests::{
    hint_bucket, plan, Answer, Database, Exchange, LookupSource, Probed, Query, QueryKind, Request, RestoreRequests,
    MINIPAGE_LEAVES, PAGE_LEAVES, PROBES, QUERIES,
};
use crate::wipe::wipe;

/// Depth of a coin tree: 2^32 leaves (spec 05, section 3).
pub const COIN_TREE_DEPTH: usize = 32;
/// The levels inside a minipage of 64 leaves.
pub const MINIPAGE_LEVELS: usize = 6;
/// The levels inside a page of 4,096 leaves.
pub const PAGE_LEVELS: usize = 12;
/// The minipages of one page.
pub const PAGE_MINIPAGES: usize = 64;
/// The sessions [`restore_with_checks`] runs before it hands the next leaf
/// back to the caller.
pub const MAX_SESSIONS: usize = 4;

const _: () = assert!(1 << MINIPAGE_LEVELS == MINIPAGE_LEAVES);
const _: () = assert!(1 << PAGE_LEVELS == PAGE_LEAVES);
const _: () = assert!(PAGE_MINIPAGES as u64 * MINIPAGE_LEAVES == PAGE_LEAVES);
const _: () = assert!(COIN_TREE_DEPTH == ghost_proofs::TREE_DEPTH);

/// The header items of decision 0004 (fields 0 to 22).
const HEADER_ITEMS: usize = 23;
/// The header items of decision 0005, with `headerMmrRoot` (field 23).
const HEADER_ITEMS_WITH_MMR: usize = 24;
const NUMBER: usize = 8;
const COIN_TREE_ROOT: usize = 16;
const COIN_LOOKUP_ROOT: usize = 19;
const COIN_MARKER_ROOT: usize = 21;
const LOOKUP_DIGEST: usize = 22;

// ---------------------------------------------------------------------------
// Errors and results
// ---------------------------------------------------------------------------

/// Why a restore's answers are refused. Every variant is a refusal: nothing
/// that failed a check is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckError {
    /// The snapshot header does not decode as a header with the lookup
    /// roots.
    SnapshotHeader,
    /// The snapshot header is not one of the tail headers of the wallet's
    /// checked chain: stale, or of another branch.
    SnapshotNotOnChain,
    /// A tail header after the snapshot does not decode as a header with a
    /// `lookupDigest`; `block` counts from the first block after the
    /// snapshot.
    LaterHeader {
        /// The block, 0 for the first after the snapshot.
        block: usize,
    },
    /// The bulk lists are not one for each tail header after the snapshot.
    LaterBlocks {
        /// The tail headers after the snapshot.
        expected: usize,
        /// The lists given.
        got: usize,
    },
    /// The bulk list of a later block does not match its `lookupDigest`.
    BulkList {
        /// The block, 0 for the first after the snapshot.
        block: usize,
    },
    /// The answer a check needs is padding, of the wrong kind or length, or
    /// for another record than the one the check reads.
    Missing(QueryKind),
    /// The note does not decrypt under the key with its leaf as associated
    /// data, or does not recompute that leaf.
    Note,
    /// The note is the key's but of another number than the one it was read
    /// for.
    NoteNumber,
    /// The coin minipage and page record do not take the leaf to the
    /// snapshot's `coinTreeRoot`.
    CoinWitness,
    /// The marker-set records give neither a membership nor an absence
    /// witness of the marker under the snapshot's `coinMarkerRoot`.
    MarkerWitness,
    /// The lookup index records give no lookup witness of the first tag under
    /// the snapshot's `coinLookupRoot`.
    LookupWitness,
    /// The requests are not the session they are checked as.
    NotTheSession,
    /// The key has more commitments than the probes cover.
    TooManyHops,
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SnapshotHeader => f.write_str("the snapshot header does not decode"),
            Self::SnapshotNotOnChain => f.write_str("the snapshot header is not on the wallet's checked chain"),
            Self::LaterHeader { block } => write!(f, "later header {block} does not decode"),
            Self::LaterBlocks { expected, got } => write!(f, "{got} bulk lists for {expected} later blocks"),
            Self::BulkList { block } => write!(f, "the bulk list of later block {block} does not match its digest"),
            Self::Missing(kind) => write!(f, "the {kind:?} answer is missing or malformed"),
            Self::Note => f.write_str("the note does not decrypt to its leaf"),
            Self::NoteNumber => f.write_str("the note is of another commitment number"),
            Self::CoinWitness => f.write_str("the coin witness does not reach the snapshot's coin root"),
            Self::MarkerWitness => f.write_str("the marker witness does not reach the snapshot's marker root"),
            Self::LookupWitness => f.write_str("the lookup witness does not reach the snapshot's lookup root"),
            Self::NotTheSession => f.write_str("the requests are not the session checked"),
            Self::TooManyHops => f.write_str("more commitments than the probes cover"),
        }
    }
}

impl std::error::Error for CheckError {}

/// Where the leaf of a second session was learned. Both are authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextFrom {
    /// The `appended` field of the previous number's spent marker leaf.
    SpentMarker,
    /// The lookup index entry of the first tag, after the hints said there
    /// was none.
    LookupIndex,
}

/// The leaf a second session reads: the key's commitment `number`, at
/// global position `position`. It names a position of the key, so it has no
/// `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NextLeaf {
    /// The commitment number expected there.
    pub number: u64,
    /// The global position of its leaf.
    pub position: u64,
    /// How it was learned.
    pub from: NextFrom,
}

/// The current commitment, checked: its coin, its path to the snapshot's
/// coin root and that snapshot.
pub struct CurrentCoin {
    /// The coin, its note checked against its leaf.
    pub coin: FoundCoin,
    /// The 32 siblings of its leaf from level 0 up, which the coin witness
    /// took to the snapshot's `coinTreeRoot`.
    pub path: [[u8; 32]; COIN_TREE_DEPTH],
    /// The height of the snapshot header.
    pub snapshot_height: u64,
    /// The snapshot header's `coinTreeRoot`.
    pub coin_tree_root: [u8; 32],
}

/// What a checked session shows.
pub enum Decision {
    /// The current commitment: its marker is unspent under the snapshot and
    /// in no later block.
    Current(CurrentCoin),
    /// Read this leaf in another session: the previous number's marker is
    /// spent and its leaf records the leaf its reveal appended, or the lookup
    /// index holds the first tag the hints left out.
    Continue(NextLeaf),
    /// The value left the key: commitment `number` is spent and its spend
    /// appended no leaf (fully revealed), or the leaf it appended does not
    /// carry the key's tag of the next number, by the lookup index's absence
    /// witness under the snapshot (claimed into another key).
    LeftTheKey {
        /// The last commitment number of the key.
        number: u64,
    },
    /// Commitment `number` was unspent at the snapshot and is spent in a
    /// later block: the coin moved since; run again on the next snapshot.
    MovedAfterSnapshot {
        /// The commitment spent after the snapshot.
        number: u64,
    },
    /// The lookup index's absence witness shows the key made no commitment
    /// by the snapshot.
    NeverCommitted {
        /// Whether a later block's bulk list carries the first tag: a first
        /// commitment made since the snapshot.
        after_snapshot: bool,
    },
}

impl fmt::Debug for Decision {
    /// The variant only: a number or a position would say how far the key
    /// has gone.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Current(_) => "Current",
            Self::Continue(_) => "Continue",
            Self::LeftTheKey { .. } => "LeftTheKey",
            Self::MovedAfterSnapshot { .. } => "MovedAfterSnapshot",
            Self::NeverCommitted { .. } => "NeverCommitted",
        })
    }
}

// ---------------------------------------------------------------------------
// The snapshot header and the later blocks
// ---------------------------------------------------------------------------

/// The fields of a header a restore reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderRoots {
    /// `keccak256(rlp(header))`.
    pub hash: [u8; 32],
    /// The block height.
    pub number: u64,
    /// `coinTreeRoot`, field 16.
    pub coin_tree_root: [u8; 32],
    /// `coinLookupRoot`, field 19.
    pub coin_lookup_root: [u8; 32],
    /// `coinMarkerRoot`, field 21.
    pub coin_marker_root: [u8; 32],
    /// `lookupDigest`, field 22.
    pub lookup_digest: [u8; 32],
}

/// Reads a canonical RLP length prefix at `at`: (is a list, prefix length,
/// payload length).
fn rlp_prefix(bytes: &[u8], at: usize) -> Option<(bool, usize, usize)> {
    let first = *bytes.get(at)?;
    let (list, short_base, long_base) = match first {
        0x00..=0x7f => return Some((false, 0, 1)),
        0x80..=0xbf => (false, 0x80u8, 0xb7u8),
        _ => (true, 0xc0, 0xf7),
    };
    if first <= long_base {
        let len = usize::from(first - short_base);
        if !list && len == 1 && *bytes.get(at + 1)? < 0x80 {
            return None;
        }
        return Some((list, 1, len));
    }
    let size = usize::from(first - long_base);
    let digits = bytes.get(at + 1..at + 1 + size)?;
    if digits[0] == 0 || size > 4 {
        return None;
    }
    let len = digits.iter().fold(0usize, |acc, &d| (acc << 8) | usize::from(d));
    (len >= 56).then_some((list, 1 + size, len))
}

/// The string items of a flat RLP list that is the whole of `bytes`.
fn rlp_items(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let (list, header, len) = rlp_prefix(bytes, 0)?;
    if !list || header.checked_add(len)? != bytes.len() {
        return None;
    }
    let mut items = Vec::new();
    let mut at = header;
    while at < bytes.len() {
        let (nested, item_header, item_len) = rlp_prefix(bytes, at)?;
        let start = at + item_header;
        let end = start.checked_add(item_len).filter(|&end| end <= bytes.len())?;
        if nested {
            return None;
        }
        items.push(&bytes[start..end]);
        at = end;
    }
    Some(items)
}

fn root_field(items: &[&[u8]], index: usize) -> Option<[u8; 32]> {
    items[index].try_into().ok()
}

/// Decodes a header of 23 fields (decision 0004) or 24 (decision 0005) and
/// reads the fields a restore needs; `None` if it does not decode or a field
/// read has the wrong size.
pub fn header_roots(header: &[u8]) -> Option<HeaderRoots> {
    let items = rlp_items(header)?;
    if items.len() != HEADER_ITEMS && items.len() != HEADER_ITEMS_WITH_MMR {
        return None;
    }
    let number = items[NUMBER];
    if number.len() > 8 || number.first() == Some(&0) {
        return None;
    }
    Some(HeaderRoots {
        hash: keccak256(header),
        number: number.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)),
        coin_tree_root: root_field(&items, COIN_TREE_ROOT)?,
        coin_lookup_root: root_field(&items, COIN_LOOKUP_ROOT)?,
        coin_marker_root: root_field(&items, COIN_MARKER_ROOT)?,
        lookup_digest: root_field(&items, LOOKUP_DIGEST)?,
    })
}

/// A snapshot header found on the wallet's checked chain, and the checked
/// bulk lists of every block after it up to the tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    snapshot: HeaderRoots,
    later: Vec<BlockLookupList>,
}

impl Anchor {
    /// The snapshot header's fields.
    pub fn snapshot(&self) -> &HeaderRoots {
        &self.snapshot
    }

    /// The bulk lists of the blocks after the snapshot, oldest first, each
    /// matched to its header's `lookupDigest`.
    pub fn later(&self) -> &[BlockLookupList] {
        &self.later
    }

    fn spent_later(&self, marker: &[u8; 32]) -> bool {
        self.later.iter().any(|list| list.coin_markers.contains(marker))
    }

    fn tagged_later(&self, tag: &LookupTag) -> bool {
        self.later.iter().any(|list| list.coin_tags.contains(tag))
    }
}

/// Checks the snapshot header and the later blocks against the tail of the
/// wallet's checked chain, oldest first (`tail`, the headers of a
/// [`CheckedTail`]): the snapshot must be one of them, and `later` must hold
/// one bulk list for each tail header after it, in order, each matching
/// that header's `lookupDigest`.
pub fn check_anchor<H: AsRef<[u8]>>(
    tail: &[H],
    snapshot_header: &[u8],
    later: &[BlockLookupList],
) -> Result<Anchor, CheckError> {
    let snapshot = header_roots(snapshot_header).ok_or(CheckError::SnapshotHeader)?;
    let at = tail
        .iter()
        .position(|header| keccak256(header.as_ref()) == snapshot.hash)
        .ok_or(CheckError::SnapshotNotOnChain)?;
    let after = &tail[at + 1..];
    if after.len() != later.len() {
        return Err(CheckError::LaterBlocks {
            expected: after.len(),
            got: later.len(),
        });
    }
    for (block, (header, list)) in after.iter().zip(later).enumerate() {
        let roots = header_roots(header.as_ref()).ok_or(CheckError::LaterHeader { block })?;
        if !crate::lookup::check_lookup_digest(list, &roots.lookup_digest) {
            return Err(CheckError::BulkList { block });
        }
    }
    Ok(Anchor {
        snapshot,
        later: later.to_vec(),
    })
}

/// [`check_anchor`] against a tail the header sampler checked.
pub fn check_anchor_on(
    tail: &CheckedTail,
    snapshot_header: &[u8],
    later: &[BlockLookupList],
) -> Result<Anchor, CheckError> {
    check_anchor(tail.headers(), snapshot_header, later)
}

// ---------------------------------------------------------------------------
// Records and folding
// ---------------------------------------------------------------------------

/// A tree whose records a restore reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordTree {
    /// The coin tree, depth 32, root `coinTreeRoot`.
    Coin,
    /// The coin marker-set tree, depth 40, root `coinMarkerRoot`.
    CoinMarkerSet,
    /// A lookup index, depth 40, root `coinLookupRoot` or `dataLookupRoot`.
    Lookup(LookupTree),
}

impl RecordTree {
    /// The levels of inner nodes above the leaves.
    pub const fn depth(self) -> usize {
        match self {
            Self::Coin => COIN_TREE_DEPTH,
            Self::CoinMarkerSet | Self::Lookup(_) => INDEX_DEPTH,
        }
    }

    /// The tag of its node hash.
    pub fn node_tag(self) -> &'static str {
        match self {
            Self::Coin => ghost_proofs::Tree::Coin.node_tag(),
            Self::CoinMarkerSet => TAG_COIN_MARKER_SET_NODE,
            Self::Lookup(tree) => tree.node_tag(),
        }
    }

    /// The bytes of one page witness record: 64 level-6 nodes and the
    /// siblings above the page.
    pub const fn page_record_bytes(self) -> usize {
        32 * (PAGE_MINIPAGES + self.depth() - PAGE_LEVELS)
    }

    /// The bytes of one encoded leaf of a minipage record; 0 for the coin
    /// tree, whose minipage is its leaf values.
    pub const fn leaf_bytes(self) -> usize {
        match self {
            Self::Coin => 0,
            Self::CoinMarkerSet => COIN_MARKER_LEAF_BYTES,
            Self::Lookup(_) => LOOKUP_LEAF_BYTES,
        }
    }
}

/// The empty leaf `E = K("ghost/empty-leaf/v1")`.
pub fn empty_leaf() -> [u8; 32] {
    hash::k(TAG_EMPTY_LEAF, &[])
}

fn node(tag: &str, level: usize, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let level = u8::try_from(level).expect("a level is below 40");
    hash::k(tag, &[&[level], left, right])
}

/// `Z_0 = E` to `Z_depth` under a node tag.
fn empty_subtrees(tag: &str, depth: usize) -> Vec<[u8; 32]> {
    let mut zeros = Vec::with_capacity(depth + 1);
    zeros.push(empty_leaf());
    for level in 0..depth {
        let below = zeros[level];
        zeros.push(node(tag, level, &below, &below));
    }
    zeros
}

/// The levels of a full binary subtree over `nodes` (a power of two), from
/// `nodes` itself up to its one root; level 0 of it is at tree level `base`.
fn subtree_levels(tag: &str, base: usize, nodes: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    let mut levels = vec![nodes];
    while levels.last().expect("one level").len() > 1 {
        let below = levels.last().expect("one level");
        let level = base + levels.len() - 1;
        let above = below.chunks(2).map(|pair| node(tag, level, &pair[0], &pair[1])).collect();
        levels.push(above);
    }
    levels
}

/// The root that `leaf` at `index` gives with `siblings` from level 0 up.
fn fold(tag: &str, leaf: [u8; 32], index: u64, siblings: &[[u8; 32]]) -> [u8; 32] {
    siblings.iter().enumerate().fold(leaf, |current, (level, sibling)| {
        if (index >> level) & 1 == 1 {
            node(tag, level, sibling, &current)
        } else {
            node(tag, level, &current, sibling)
        }
    })
}

fn chunks32(bytes: &[u8]) -> Vec<[u8; 32]> {
    bytes
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().expect("32 bytes"))
        .collect()
}

/// The siblings of the leaf at `position` from level 0 up and the root they
/// give, from the 64 leaf hashes of its minipage and its page's witness
/// record. `None` if the record has the wrong length or the minipage does
/// not climb to its own node in the record.
fn fold_records(
    tree: RecordTree,
    minipage: &[[u8; 32]],
    position: u64,
    page: &[u8],
) -> Option<([u8; 32], Vec<[u8; 32]>)> {
    let depth = tree.depth();
    if minipage.len() != MINIPAGE_LEAVES as usize || page.len() != tree.page_record_bytes() {
        return None;
    }
    let tag = tree.node_tag();
    let position = position & ((1u64 << depth) - 1);
    let offset = (position % MINIPAGE_LEAVES) as usize;
    let in_page = ((position / MINIPAGE_LEAVES) % PAGE_MINIPAGES as u64) as usize;
    let page_index = position / PAGE_LEAVES;

    let mut siblings = Vec::with_capacity(depth);
    let low = subtree_levels(tag, 0, minipage.to_vec());
    for (level, nodes) in low.iter().take(MINIPAGE_LEVELS).enumerate() {
        siblings.push(nodes[(offset >> level) ^ 1]);
    }
    let entries = chunks32(&page[..32 * PAGE_MINIPAGES]);
    if low[MINIPAGE_LEVELS][0] != entries[in_page] {
        return None;
    }
    let middle = subtree_levels(tag, MINIPAGE_LEVELS, entries);
    for (level, nodes) in middle.iter().take(PAGE_LEVELS - MINIPAGE_LEVELS).enumerate() {
        siblings.push(nodes[(in_page >> level) ^ 1]);
    }
    let page_root = middle[PAGE_LEVELS - MINIPAGE_LEVELS][0];
    let upper = chunks32(&page[32 * PAGE_MINIPAGES..]);
    let root = upper.iter().enumerate().fold(page_root, |current, (step, sibling)| {
        let level = PAGE_LEVELS + step;
        if (page_index >> step) & 1 == 1 {
            node(tag, level, sibling, &current)
        } else {
            node(tag, level, &current, sibling)
        }
    });
    siblings.extend(upper);
    debug_assert_eq!(fold(tag, minipage[offset], position, &siblings), root);
    Some((root, siblings))
}

/// The used leaves of a minipage record, `size` bytes each, at most 64.
fn decode_minipage(bytes: &[u8], size: usize) -> Option<Vec<&[u8]>> {
    if bytes.len() % size != 0 || bytes.len() / size > MINIPAGE_LEAVES as usize {
        return None;
    }
    Some(bytes.chunks_exact(size).collect())
}

/// Leaf hashes of a minipage of encoded leaves, `E` after the used ones.
fn minipage_hashes(hashes: impl Iterator<Item = [u8; 32]>) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = hashes.collect();
    out.resize(MINIPAGE_LEAVES as usize, empty_leaf());
    out
}

/// A tree's records as a restore server serves them, built from the tree's
/// leaves: the minipages and page witness records this module reads, and
/// the root. A test's server, or any server, can build them; the checks never
/// trust them for that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeRecords {
    tree: RecordTree,
    /// The encoded leaves of the used positions; empty for the coin tree.
    encoded: Vec<Vec<u8>>,
    /// Every level of the tree from the leaf hashes up, the used nodes only.
    levels: Vec<Vec<[u8; 32]>>,
    zeros: Vec<[u8; 32]>,
}

impl TreeRecords {
    fn build(tree: RecordTree, hashes: Vec<[u8; 32]>, encoded: Vec<Vec<u8>>) -> Self {
        let tag = tree.node_tag();
        let depth = tree.depth();
        let zeros = empty_subtrees(tag, depth);
        let mut levels = vec![hashes];
        for level in 0..depth {
            let above = levels[level]
                .chunks(2)
                .map(|pair| node(tag, level, &pair[0], pair.get(1).unwrap_or(&zeros[level])))
                .collect();
            levels.push(above);
        }
        Self {
            tree,
            encoded,
            levels,
            zeros,
        }
    }

    /// The coin tree whose positions `0..leaves.len()` hold these leaf
    /// values; the caller puts [`empty_leaf`] at any it leaves unused.
    pub fn coin_tree(leaves: &[[u8; 32]]) -> Self {
        Self::build(RecordTree::Coin, leaves.to_vec(), Vec::new())
    }

    /// The records of a coin marker set.
    pub fn marker_set(set: &CoinMarkerSet) -> Self {
        let leaves = set.leaves();
        Self::build(
            RecordTree::CoinMarkerSet,
            leaves.iter().map(CoinMarkerLeaf::hash).collect(),
            leaves.iter().map(|leaf| leaf.to_bytes().to_vec()).collect(),
        )
    }

    /// The records of a lookup index.
    pub fn lookup_index(index: &LookupIndex) -> Self {
        let tree = index.tree();
        let leaves = index.leaves();
        Self::build(
            RecordTree::Lookup(tree),
            leaves.iter().map(|leaf| leaf.hash(tree)).collect(),
            leaves.iter().map(|leaf| leaf.to_bytes().to_vec()).collect(),
        )
    }

    /// Which tree these are the records of.
    pub fn tree(&self) -> RecordTree {
        self.tree
    }

    fn node_at(&self, level: usize, index: u64) -> [u8; 32] {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.levels[level].get(index))
            .copied()
            .unwrap_or(self.zeros[level])
    }

    /// The root.
    pub fn root(&self) -> [u8; 32] {
        self.node_at(self.tree.depth(), 0)
    }

    /// Minipage `record`: positions `64 record` to `64 record + 63`.
    pub fn minipage(&self, record: u64) -> Answer {
        let positions = record * MINIPAGE_LEAVES..(record + 1) * MINIPAGE_LEAVES;
        match self.tree {
            RecordTree::Coin => Answer::Leaves(positions.map(|position| self.node_at(0, position)).collect()),
            _ => Answer::Record(
                positions
                    .filter_map(|position| usize::try_from(position).ok().and_then(|at| self.encoded.get(at)))
                    .flatten()
                    .copied()
                    .collect(),
            ),
        }
    }

    /// The witness record of page `record`: positions `4096 record` to
    /// `4096 record + 4095`.
    pub fn page(&self, record: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.tree.page_record_bytes());
        for minipage in 0..PAGE_MINIPAGES as u64 {
            out.extend_from_slice(&self.node_at(MINIPAGE_LEVELS, record * PAGE_MINIPAGES as u64 + minipage));
        }
        for level in PAGE_LEVELS..self.tree.depth() {
            out.extend_from_slice(&self.node_at(level, (record >> (level - PAGE_LEVELS)) ^ 1));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// The checks of one session
// ---------------------------------------------------------------------------

/// The real exchange of `kind` for `record`, or the refusal.
fn real(requests: &RestoreRequests, kind: QueryKind, record: u64) -> Result<&Exchange, CheckError> {
    requests
        .exchange(kind)
        .filter(|exchange| !exchange.padding && exchange.record == record)
        .ok_or(CheckError::Missing(kind))
}

/// The record of a real exchange of `kind`, whatever it is, or the refusal.
fn real_any(requests: &RestoreRequests, kind: QueryKind) -> Result<&Exchange, CheckError> {
    requests
        .exchange(kind)
        .filter(|exchange| !exchange.padding)
        .ok_or(CheckError::Missing(kind))
}

fn record_bytes(exchange: &Exchange, kind: QueryKind) -> Result<&[u8], CheckError> {
    match &exchange.answer {
        Answer::Record(bytes) => Ok(bytes),
        _ => Err(CheckError::Missing(kind)),
    }
}

/// The note and the coin witness of the leaf at `position`: the leaf, the
/// note and the leaf's path, checked to the snapshot's coin root.
fn checked_leaf(
    anchor: &Anchor,
    requests: &RestoreRequests,
    position: u64,
) -> Result<(Commitment, [u8; NOTE_BYTES], [[u8; 32]; COIN_TREE_DEPTH]), CheckError> {
    if position >= NO_POSITION {
        return Err(CheckError::CoinWitness);
    }
    let note = match &real(requests, QueryKind::Note, position)?.answer {
        Answer::Note(bytes) => {
            <[u8; NOTE_BYTES]>::try_from(bytes.as_slice()).map_err(|_| CheckError::Missing(QueryKind::Note))?
        }
        _ => return Err(CheckError::Missing(QueryKind::Note)),
    };
    let leaves = match &real(requests, QueryKind::CoinLeaves, position / MINIPAGE_LEAVES)?.answer {
        Answer::Leaves(leaves) if leaves.len() == MINIPAGE_LEAVES as usize => leaves,
        _ => return Err(CheckError::Missing(QueryKind::CoinLeaves)),
    };
    let page = record_bytes(real(requests, QueryKind::CoinPage, position / PAGE_LEAVES)?, QueryKind::CoinPage)?;
    let (root, siblings) = fold_records(RecordTree::Coin, leaves, position, page).ok_or(CheckError::CoinWitness)?;
    if root != anchor.snapshot.coin_tree_root {
        return Err(CheckError::CoinWitness);
    }
    let path = <[[u8; 32]; COIN_TREE_DEPTH]>::try_from(siblings).map_err(|_| CheckError::CoinWitness)?;
    let leaf = Commitment::from_bytes(leaves[(position % MINIPAGE_LEAVES) as usize]);
    Ok((leaf, note, path))
}

/// The key's coin in a leaf and its note, if the note decrypts under the key
/// and recomputes the leaf: `Ok(None)` when the note is not the key's,
/// [`CheckError::Note`] when it is the key's but does not recompute its leaf.
fn open_leaf(
    key: &PhantomKey,
    chain_id: u64,
    position: u64,
    commitment: Commitment,
    note: [u8; NOTE_BYTES],
) -> Result<Option<FoundCoin>, CheckError> {
    let tree_index = u32::try_from(position >> 32).map_err(|_| CheckError::CoinWitness)?;
    let leaf = TreeLeaf {
        commitment,
        note,
        salt: None,
    };
    let restored = restore_coins_at(key, chain_id, tree_index, &[(position as u32, leaf)], &[])
        .expect("one leaf is within a tree");
    if !restored.discarded.is_empty() {
        return Err(CheckError::Note);
    }
    Ok(restored.found.into_iter().next())
}

/// The marker's status under the snapshot's `coinMarkerRoot`: `Some` of the
/// position its spend appended (itself an option) when spent, `None` when
/// unspent.
fn checked_marker(
    anchor: &Anchor,
    requests: &RestoreRequests,
    marker: &[u8; 32],
) -> Result<Option<Option<u64>>, CheckError> {
    let leaves_exchange = real_any(requests, QueryKind::MarkerLeaves)?;
    let minipage = leaves_exchange.record;
    let bytes = record_bytes(leaves_exchange, QueryKind::MarkerLeaves)?;
    let page_record = minipage / PAGE_MINIPAGES as u64;
    let page = record_bytes(real(requests, QueryKind::MarkerPage, page_record)?, QueryKind::MarkerPage)?;
    let leaves: Vec<CoinMarkerLeaf> = decode_minipage(bytes, COIN_MARKER_LEAF_BYTES)
        .ok_or(CheckError::MarkerWitness)?
        .into_iter()
        .map(|leaf| CoinMarkerLeaf::from_bytes(leaf.try_into().expect("74 bytes")))
        .collect();
    let brackets = |leaf: &CoinMarkerLeaf| {
        &leaf.value < marker && (marker < &leaf.next_value || leaf.next_value == [0; 32])
    };
    let offset = leaves
        .iter()
        .position(|leaf| &leaf.value == marker)
        .or_else(|| leaves.iter().position(brackets))
        .ok_or(CheckError::MarkerWitness)?;
    let position = minipage * MINIPAGE_LEAVES + offset as u64;
    let hashes = minipage_hashes(leaves.iter().map(CoinMarkerLeaf::hash));
    let (_, siblings) =
        fold_records(RecordTree::CoinMarkerSet, &hashes, position, page).ok_or(CheckError::MarkerWitness)?;
    let witness = CoinMarkerWitness {
        leaf: leaves[offset],
        position,
        siblings: siblings.try_into().map_err(|_| CheckError::MarkerWitness)?,
    }
    .to_bytes();
    let root = &anchor.snapshot.coin_marker_root;
    if &leaves[offset].value == marker {
        let spent = verify_marker_membership(root, &witness, marker).map_err(|_| CheckError::MarkerWitness)?;
        Ok(Some(spent.appended))
    } else {
        verify_marker_absence(root, &witness, marker).map_err(|_| CheckError::MarkerWitness)?;
        Ok(None)
    }
}

/// The lookup index leaf the session's lookup records hold that `select`
/// picks, with its witness built from the minipage and page records: the
/// witness is not yet checked against a root.
fn lookup_witness(
    requests: &RestoreRequests,
    select: impl Fn(&LookupLeaf) -> bool,
) -> Result<(LookupLeaf, Vec<u8>), CheckError> {
    let leaves_exchange = real_any(requests, QueryKind::LookupLeaves)?;
    let minipage = leaves_exchange.record;
    let bytes = record_bytes(leaves_exchange, QueryKind::LookupLeaves)?;
    let page_record = minipage / PAGE_MINIPAGES as u64;
    let page = record_bytes(real(requests, QueryKind::LookupPage, page_record)?, QueryKind::LookupPage)?;
    let leaves: Vec<LookupLeaf> = decode_minipage(bytes, LOOKUP_LEAF_BYTES)
        .ok_or(CheckError::LookupWitness)?
        .into_iter()
        .map(|leaf| LookupLeaf::from_bytes(leaf.try_into().expect("47 bytes")))
        .collect();
    let offset = leaves.iter().position(select).ok_or(CheckError::LookupWitness)?;
    let position = minipage * MINIPAGE_LEAVES + offset as u64;
    let tree = LookupTree::Coin;
    let hashes = minipage_hashes(leaves.iter().map(|leaf| leaf.hash(tree)));
    let (_, siblings) =
        fold_records(RecordTree::Lookup(tree), &hashes, position, page).ok_or(CheckError::LookupWitness)?;
    let witness = LookupWitness {
        leaf: leaves[offset],
        index_position: position,
        siblings: siblings.try_into().map_err(|_| CheckError::LookupWitness)?,
    }
    .to_bytes();
    Ok((leaves[offset], witness))
}

/// The lookup index's answer for the first tag under the snapshot's
/// `coinLookupRoot`.
fn checked_lookup(anchor: &Anchor, requests: &RestoreRequests, tag: &LookupTag) -> Result<LookupAnswer, CheckError> {
    let (_, witness) =
        lookup_witness(requests, |leaf| &leaf.tag < tag && (leaf.next_tag == ZERO_TAG || &leaf.next_tag >= tag))?;
    verify_lookup(LookupTree::Coin, &anchor.snapshot.coin_lookup_root, &witness, tag)
        .map_err(|_| CheckError::LookupWitness)
}

/// Whether the coin lookup index under the snapshot's `coinLookupRoot`
/// holds the pair (`tag`, `position`): `Ok(true)` with its membership
/// witness, `Ok(false)` with the absence witness of its low leaf. Anything
/// else is refused.
fn checked_pair(
    anchor: &Anchor,
    requests: &RestoreRequests,
    tag: &LookupTag,
    position: u64,
) -> Result<bool, CheckError> {
    let pair = (*tag, position);
    let (leaf, witness) = lookup_witness(requests, |leaf| {
        leaf.key() == pair || (leaf.key() < pair && leaf.next_key().is_none_or(|next| pair < next))
    })?;
    let root = &anchor.snapshot.coin_lookup_root;
    if leaf.key() == pair {
        verify_lookup_membership(LookupTree::Coin, root, &witness, tag, position)
            .map_err(|_| CheckError::LookupWitness)?;
        Ok(true)
    } else {
        verify_lookup_pair_absence(LookupTree::Coin, root, &witness, tag, position)
            .map_err(|_| CheckError::LookupWitness)?;
        Ok(false)
    }
}

/// Checks the session that read commitment `number` at `position`, and
/// decides. `from` is how the position was learned: `None` from the
/// unauthenticated hints, whose leaf must be the key's.
fn check_found(
    key: &PhantomKey,
    chain_id: u64,
    anchor: &Anchor,
    requests: &RestoreRequests,
    number: u64,
    position: u64,
    from: Option<NextFrom>,
) -> Result<Decision, CheckError> {
    let (commitment, note, path) = checked_leaf(anchor, requests, position)?;
    let coin = match open_leaf(key, chain_id, position, commitment, note)? {
        Some(coin) => coin,
        // A leaf a spent marker leads to whose note does not open. The coin
        // witness authenticates the leaf, never the note served beside it,
        // so a note that does not open proves nothing on its own. The key's
        // own remainder carries the key's tag of `number` at its position:
        // only an absence witness of that pair in the lookup index shows the
        // leaf is another key's, the value claimed away. A membership witness
        // shows the leaf is the key's, so its note is wrong and refused.
        None if from == Some(NextFrom::SpentMarker) => {
            let tag = lookup_tag(&key.note_key(), number);
            if checked_pair(anchor, requests, &tag, position)? {
                return Err(CheckError::Note);
            }
            return Ok(Decision::LeftTheKey {
                number: number.checked_sub(1).ok_or(CheckError::NotTheSession)?,
            });
        }
        None => return Err(CheckError::Note),
    };
    if coin.number != number {
        return Err(CheckError::NoteNumber);
    }
    let mut marker = *coin.marker.as_bytes();
    let status = checked_marker(anchor, requests, &marker);
    let spent_later = anchor.spent_later(&marker);
    wipe(&mut marker);
    Ok(match status? {
        Some(Some(appended)) => Decision::Continue(NextLeaf {
            number: number.checked_add(1).ok_or(CheckError::TooManyHops)?,
            position: appended,
            from: NextFrom::SpentMarker,
        }),
        Some(None) => Decision::LeftTheKey { number },
        None if spent_later => Decision::MovedAfterSnapshot { number },
        None => Decision::Current(CurrentCoin {
            coin,
            path,
            snapshot_height: anchor.snapshot.number,
            coin_tree_root: anchor.snapshot.coin_tree_root,
        }),
    })
}

/// Checks every answer of a first session ([`crate::restore_requests::restore_requests`])
/// against the anchor and decides; see the module documentation.
pub fn check_session(
    key: &PhantomKey,
    chain_id: u64,
    anchor: &Anchor,
    requests: &RestoreRequests,
) -> Result<Decision, CheckError> {
    if requests.exchanges.len() != QUERIES {
        return Err(CheckError::NotTheSession);
    }
    match requests.probed {
        Probed::Found { number, position } => check_found(key, chain_id, anchor, requests, number, position, None),
        Probed::BeyondLimit => Err(CheckError::TooManyHops),
        Probed::Nothing => {
            let first = lookup_tag(&key.note_key(), 0);
            match checked_lookup(anchor, requests, &first)? {
                LookupAnswer::Absent => Ok(Decision::NeverCommitted {
                    after_snapshot: anchor.tagged_later(&first),
                }),
                LookupAnswer::First { position, .. } => Ok(Decision::Continue(NextLeaf {
                    number: 0,
                    position,
                    from: NextFrom::LookupIndex,
                })),
            }
        }
    }
}

/// Checks a second session ([`continue_requests`] for `next`) and decides.
pub fn check_continued(
    key: &PhantomKey,
    chain_id: u64,
    anchor: &Anchor,
    next: &NextLeaf,
    requests: &RestoreRequests,
) -> Result<Decision, CheckError> {
    let expected = Probed::Found {
        number: next.number,
        position: next.position,
    };
    if requests.exchanges.len() != QUERIES || requests.probed != expected {
        return Err(CheckError::NotTheSession);
    }
    check_found(key, chain_id, anchor, requests, next.number, next.position, Some(next.from))
}

// ---------------------------------------------------------------------------
// A second session
// ---------------------------------------------------------------------------

/// A uniform value below `bound` from the caller's source, by rejection; 0
/// when `bound` is 0 or 1.
fn random_below<R: CryptoRng + ?Sized>(rng: &mut R, bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    let zone = u64::MAX - u64::MAX % bound;
    loop {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        let value = u64::from_be_bytes(bytes);
        if value < zone {
            return value % bound;
        }
    }
}

/// Sends the next query of the plan for `record`, or as padding at a uniform
/// record, with fresh randomness.
fn send<S: LookupSource + ?Sized, R: CryptoRng + ?Sized>(
    source: &mut S,
    rng: &mut R,
    exchanges: &mut Vec<Exchange>,
    record: Option<u64>,
) -> usize {
    let slot = exchanges.len();
    let shape = plan()[slot];
    let mut randomness = [0u8; 32];
    rng.fill_bytes(&mut randomness);
    let query = Query {
        database: shape.database,
        kind: shape.kind,
        slot: shape.slot,
        randomness,
    };
    let padding = record.is_none();
    let record = record.unwrap_or_else(|| random_below(rng, source.records(shape.database)));
    let answer = source.fetch(&Request { query, record });
    exchanges.push(Exchange {
        query,
        record,
        padding,
        answer,
    });
    slot
}

/// The set position for a marker in a marker hint answer: its own entry when
/// spent, else the entry of the largest marker below it. Unauthenticated, as
/// every hint.
fn marker_position(answer: &Answer, marker: &[u8; 32]) -> Option<u64> {
    let Answer::MarkerHints(hints) = answer else {
        return None;
    };
    hints
        .iter()
        .find(|hint| &hint.marker == marker)
        .or_else(|| hints.iter().filter(|hint| &hint.marker < marker).max_by_key(|hint| hint.marker))
        .map(|hint| hint.set_position)
}

/// The index position of the pair (`tag`, `position`) in a lookup hint
/// bucket answer: its own entry, else the entry with the largest key below
/// it (its low leaf). Unauthenticated, as every hint.
fn pair_index_position(answer: &Answer, tag: &LookupTag, position: u64) -> Option<u64> {
    let Answer::LookupHints(hints) = answer else {
        return None;
    };
    let pair = (*tag, position);
    hints
        .iter()
        .find(|hint| (hint.tag, hint.position) == pair)
        .or_else(|| {
            hints
                .iter()
                .filter(|hint| (hint.tag, hint.position) < pair)
                .max_by_key(|hint| (hint.tag, hint.position))
        })
        .map(|hint| hint.index_position)
}

/// The requests of a second session for `next`: the same [`QUERIES`]
/// queries in the order of the [`plan`]. The first probe asks for the hint
/// bucket of the expected number's tag and the other probes pad; then come
/// the follow-ups for the leaf at `next.position`: its note, its coin
/// minipage and page, its marker's hint, minipage and page (from the salt in
/// its note, padding when the note does not open as the key's), the lookup
/// index minipage and page of the pair (the expected tag, the position) when
/// the note does not open (padding otherwise), and the overflow bucket of the
/// first tag. Every record is hidden by the PIR query, so to the server it
/// is a restore like any other.
pub fn continue_requests<S, R>(
    key: &PhantomKey,
    chain_id: u64,
    next: &NextLeaf,
    source: &mut S,
    rng: &mut R,
) -> RestoreRequests
where
    S: LookupSource + ?Sized,
    R: CryptoRng + ?Sized,
{
    let note_key = key.note_key();
    let position = next.position;
    let mut exchanges = Vec::with_capacity(QUERIES);
    // The first probe asks for the hint bucket of the expected number's tag,
    // the index position of the pair's own entry or low leaf; the rest pad.
    let next_tag = lookup_tag(&note_key, next.number);
    let lookup_buckets = source.records(Database::LookupHints);
    let probe_slot = send(source, rng, &mut exchanges, Some(hint_bucket(&next_tag, lookup_buckets)));
    let pair_index = pair_index_position(&exchanges[probe_slot].answer, &next_tag, position);
    for _ in 1..PROBES {
        send(source, rng, &mut exchanges, None);
    }
    let note_slot = send(source, rng, &mut exchanges, Some(position));
    let leaves_slot = send(source, rng, &mut exchanges, Some(position / MINIPAGE_LEAVES));
    send(source, rng, &mut exchanges, Some(position / PAGE_LEAVES));

    let note = match &exchanges[note_slot].answer {
        Answer::Note(bytes) => <[u8; NOTE_BYTES]>::try_from(bytes.as_slice()).ok(),
        _ => None,
    };
    let leaf = match &exchanges[leaves_slot].answer {
        Answer::Leaves(leaves) => leaves.get((position % MINIPAGE_LEAVES) as usize).copied(),
        _ => None,
    };
    let mut marker = match (note, leaf) {
        (Some(note), Some(leaf)) => open_leaf(key, chain_id, position, Commitment::from_bytes(leaf), note)
            .ok()
            .flatten()
            .filter(|coin| coin.number == next.number)
            .map(|coin| *coin.marker.as_bytes()),
        _ => None,
    };
    let buckets = source.records(Database::MarkerHints);
    let hint_slot = send(source, rng, &mut exchanges, marker.map(|m| hint_bucket(&m, buckets)));
    let set_position = marker.and_then(|m| marker_position(&exchanges[hint_slot].answer, &m));
    send(source, rng, &mut exchanges, set_position.map(|p| p / MINIPAGE_LEAVES));
    send(source, rng, &mut exchanges, set_position.map(|p| p / PAGE_LEAVES));
    // A note that does not open: the lookup index leaf that shows whether the
    // leaf carries the key's tag, the evidence the check needs.
    let lookup_index = if marker.is_none() { pair_index } else { None };
    if let Some(marker) = marker.as_mut() {
        wipe(marker);
    }
    send(source, rng, &mut exchanges, lookup_index.map(|p| p / MINIPAGE_LEAVES));
    send(source, rng, &mut exchanges, lookup_index.map(|p| p / PAGE_LEAVES));
    let first = lookup_tag(&note_key, 0);
    let overflow = source.records(Database::HintOverflow);
    send(source, rng, &mut exchanges, Some(hint_bucket(&first, overflow)));
    debug_assert_eq!(exchanges.len(), QUERIES);
    RestoreRequests {
        probed: Probed::Found {
            number: next.number,
            position,
        },
        exchanges,
    }
}

/// A restore checked to its decision.
pub struct CheckedRestore {
    /// The decision of the last session.
    pub decision: Decision,
    /// The sessions run, the first included.
    pub sessions: usize,
}

/// Runs a restore by private lookup against `source`, checks every session
/// against `anchor` and follows each [`Decision::Continue`] with a second
/// session, up to [`MAX_SESSIONS`] in all; a decision still `Continue` after
/// them is returned for the caller to carry on. The first refusal stops the
/// restore.
pub fn restore_with_checks<S, R>(
    key: &PhantomKey,
    chain_id: u64,
    anchor: &Anchor,
    source: &mut S,
    rng: &mut R,
) -> Result<CheckedRestore, CheckError>
where
    S: LookupSource + ?Sized,
    R: CryptoRng + ?Sized,
{
    let requests = crate::restore_requests::restore_requests(key, chain_id, source, rng);
    let mut decision = check_session(key, chain_id, anchor, &requests)?;
    let mut sessions = 1;
    while sessions < MAX_SESSIONS {
        let Decision::Continue(next) = decision else {
            break;
        };
        let requests = continue_requests(key, chain_id, &next, source, rng);
        decision = check_continued(key, chain_id, anchor, &next, &requests)?;
        sessions += 1;
    }
    Ok(CheckedRestore { decision, sessions })
}
