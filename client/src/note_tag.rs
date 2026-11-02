//! Key-derived note lookup tags and restore by note buckets (spec 01,
//! sections 8 and 9; spec 05, section 8).
//!
//! ```text
//! tag_i = the first 3 bytes of S("ghost/note-tag/v1", k_note, i as 8 bytes)
//! nonce = tag_i (3) || 9 random bytes
//! m     = bucket_bits(n) = clamp(floor(log2(n / 4096)), 0, 24)
//! ```
//!
//! Every note's nonce starts with the lookup tag of its commitment number `i`
//! under the key's note key, so only the key can compute where its notes are.
//! A bucket is the set of notes of one tree whose tag starts with the same
//! `m` bits, where `n` is the tree's leaf count at the anchor: an expected
//! bucket holds at least [`MIN_BUCKET_NOTES`] notes, and below 8,192 notes
//! `m = 0`, the whole tree.
//!
//! [`restore_coins_by_tags`] asks for the buckets of the tags of numbers
//! `0..15` in one batch, always 16 even when it expects fewer, then for those
//! of `16..31` only if number 15 was found, and so on: numbers have no gaps
//! (spec 01, section 8). Each distinct prefix is read once. It passes every
//! note it read, with its position, to [`restore_coins_at`].
//!
//! A bucket read returns notes by a hint, not completeness: an endpoint can
//! withhold a note, so the wallet then shows less, never more, and the
//! full-page scan of [`crate::restore::restore_coins`] stays the fallback. A
//! bucket result is unchecked like any page result until its notes are checked
//! against the block receipts (spec 05, section 8, item 5). A note with a
//! fully random nonce still decrypts, but no bucket read returns it.

use std::collections::BTreeSet;

use crate::commit::Marker;
use crate::derive::NoteKey;
use crate::hash::{self, TAG_NOTE_TAG};
use crate::key::PhantomKey;
use crate::note::NOTE_BYTES;
use crate::restore::{restore_coins_at, RestoreError, Restored, TreeLeaf, MAX_TREE_LEAVES};

/// Length of a lookup tag: the first bytes of a note's nonce.
pub const LOOKUP_TAG_BYTES: usize = 3;
/// How many commitment numbers one lookup batch asks for.
pub const TAG_BATCH: u64 = 16;
/// The fewest notes an expected bucket holds once a tree is split.
pub const MIN_BUCKET_NOTES: u64 = 4096;
/// The most prefix bits of a bucket: every bit of the tag.
pub const MAX_BUCKET_BITS: u32 = 24;

const _: () = assert!(MAX_BUCKET_BITS as usize == 8 * LOOKUP_TAG_BYTES);

/// A note's lookup tag `tag_i`.
pub type LookupTag = [u8; LOOKUP_TAG_BYTES];

/// `tag_i`: the first 3 bytes of `S("ghost/note-tag/v1", k_note, i as 8
/// bytes)`, the lookup tag of the key's commitment number `number`.
pub fn lookup_tag(key: &NoteKey, number: u64) -> LookupTag {
    let digest = hash::s(TAG_NOTE_TAG, &[key.as_bytes(), &number.to_be_bytes()]);
    let mut tag = [0u8; LOOKUP_TAG_BYTES];
    tag.copy_from_slice(&digest[..LOOKUP_TAG_BYTES]);
    tag
}

/// `m = clamp(floor(log2(n / 4096)), 0, 24)`: the prefix bits of a bucket of
/// a tree of `note_count` leaves. Zero, the whole tree, below 8,192 notes.
pub fn bucket_bits(note_count: u64) -> u32 {
    match note_count / MIN_BUCKET_NOTES {
        0 => 0,
        quotient => quotient.ilog2().min(MAX_BUCKET_BITS),
    }
}

/// The first `bits` bits of `tag`, read big-endian, as an integer: the
/// bucket the tag falls in. `bits` above [`MAX_BUCKET_BITS`] counts as
/// [`MAX_BUCKET_BITS`].
pub fn bucket_prefix(tag: &LookupTag, bits: u32) -> u32 {
    let whole = u32::from_be_bytes([0, tag[0], tag[1], tag[2]]);
    whole >> (MAX_BUCKET_BITS - bits.min(MAX_BUCKET_BITS))
}

/// The lookup tag a note carries: the first 3 bytes of its nonce.
pub fn note_lookup_tag(note: &[u8; NOTE_BYTES]) -> LookupTag {
    let mut tag = [0u8; LOOKUP_TAG_BYTES];
    tag.copy_from_slice(&note[..LOOKUP_TAG_BYTES]);
    tag
}

/// One note of a bucket: its leaf, as a page carries it, and its position.
#[derive(Clone, PartialEq, Eq)]
pub struct BucketNote {
    /// The position of the leaf in its tree.
    pub position: u32,
    /// The leaf, its note and the salt served beside it.
    pub leaf: TreeLeaf,
}

/// Where a wallet reads note buckets from: one coin tree as of one anchor.
pub trait NoteBuckets {
    /// Every filled position of the tree whose note's tag starts with the
    /// `bits`-bit `prefix`.
    fn read_bucket(&mut self, bits: u32, prefix: u32) -> Vec<BucketNote>;
}

/// What restore by tags found, and what it read to find it.
pub struct TagRestore {
    /// The coins found, as [`restore_coins_at`] gives them, in position order.
    pub restored: Restored,
    /// The notes tried: the sum of the lengths of the buckets read.
    pub notes_tried: u64,
    /// The buckets read, one per distinct prefix.
    pub bucket_reads: u64,
}

/// Restores the key's coins from the note buckets of its own lookup tags in
/// one coin tree of `note_count` leaves at the anchor, and the coin spent
/// markers. `tree_index` is the index of that tree; each coin found carries
/// it.
///
/// It reads buckets of [`bucket_bits`]`(note_count)` bits only, and only the
/// prefixes of the tags of its batches: numbers `0..15`, then `16..31` if
/// number 15 was found, and so on. A `note_count` above [`MAX_TREE_LEAVES`]
/// is [`RestoreError::TooManyLeaves`].
pub fn restore_coins_by_tags<B: NoteBuckets>(
    key: &PhantomKey,
    chain_id: u64,
    tree_index: u32,
    note_count: u64,
    source: &mut B,
    spent: &[Marker],
) -> Result<TagRestore, RestoreError> {
    if note_count > MAX_TREE_LEAVES {
        return Err(RestoreError::TooManyLeaves);
    }
    let bits = bucket_bits(note_count);
    let note_key = key.note_key();
    let mut read = BTreeSet::new();
    let mut leaves: Vec<(u32, TreeLeaf)> = Vec::new();
    let mut notes_tried = 0u64;
    let mut first = 0u64;
    loop {
        let last = first.saturating_add(TAG_BATCH - 1);
        for number in first..=last {
            let prefix = bucket_prefix(&lookup_tag(&note_key, number), bits);
            if !read.insert(prefix) {
                continue;
            }
            let bucket = source.read_bucket(bits, prefix);
            notes_tried = notes_tried.saturating_add(bucket.len() as u64);
            leaves.extend(bucket.into_iter().map(|note| (note.position, note.leaf)));
        }
        // Position order, and a note served twice is tried once.
        leaves.sort_by_key(|(position, _)| *position);
        leaves.dedup();
        let restored = restore_coins_at(key, chain_id, tree_index, &leaves, spent)?;
        let more = restored.found.iter().any(|coin| coin.number == last);
        match last.checked_add(1) {
            Some(next) if more => first = next,
            _ => {
                return Ok(TagRestore {
                    restored,
                    notes_tried,
                    bucket_reads: read.len() as u64,
                })
            }
        }
    }
}
