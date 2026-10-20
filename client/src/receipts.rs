//! Checking block receipts against a header's `receiptsRoot`, and the coin
//! tree's leaves, notes and spent markers against those receipts (spec 05,
//! section 8, item 5 and "Marker status").
//!
//! Every function here is pure, over bytes the caller fetched in bulk:
//!
//! 1. [`check_block_receipts`] (or [`check_block_receipts_against_header`])
//!    computes the receipts root of a block's receipts, each given as its
//!    consensus encoding (the type byte, then RLP, for a typed receipt), and
//!    compares it with the header's. Only then does it read the coin tree
//!    records out of the receipts' logs, in block and log order, into a
//!    [`CheckedBlock`].
//! 2. [`check_leaves`] compares a downloaded run of leaves and notes with the
//!    records of the checked blocks: the same positions, leaves and note
//!    bytes, with no position missing, repeated, reordered or invented.
//! 3. [`check_markers`] compares a downloaded spent-marker list with the
//!    markers of the reveal records: the same markers in the same order.
//!
//! The log layout is the node's (ghost-node `docs/private-transactions.md`,
//! "Receipts"). Both logs have the coin tree account as address:
//!
//! | Log | Topics | Data |
//! |---|---|---|
//! | commit | `K("ghost/commit-receipt/v1")` | tree index (4), position (4), leaf (32), `v` (32), note (156) |
//! | reveal | `K("ghost/reveal-receipt/v1")`, marker | tree index (4), position (4), remainder (32), note (156), recipient (20), out (32) |
//!
//! Integers are big-endian. Logs of any other address are not read here.
//!
//! Uncertain means rejected: a receipt that does not decode, a root that
//! differs, a coin tree log whose topics or data length are not exactly the
//! layout above, and a leaf, note or marker that differs from the records, or
//! is missing, repeated, reordered or invented, are each an error. Nothing is
//! skipped.

use core::fmt;

use crate::commit::{Commitment, Marker};
use crate::hash::{k, keccak256};
use crate::note::NOTE_BYTES;
use crate::restore::TreeLeaf;
use crate::seal::{header_fields, HeaderError};

/// The coin tree account, the address of every commit and reveal log.
pub const COIN_TREE_ACCOUNT: [u8; 20] = [
    0x67, 0x68, 0x6f, 0x73, 0x74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];
/// Tag of the first topic of a commit log.
pub const TAG_COMMIT_RECEIPT: &str = "ghost/commit-receipt/v1";
/// Tag of the first topic of a reveal log.
pub const TAG_REVEAL_RECEIPT: &str = "ghost/reveal-receipt/v1";
/// Data bytes of a commit log: tree index, position, leaf, `v`, note.
pub const COMMIT_LOG_BYTES: usize = 4 + 4 + 32 + 32 + NOTE_BYTES;
/// Data bytes of a reveal log: tree index, position, remainder, note,
/// recipient, out.
pub const REVEAL_LOG_BYTES: usize = 4 + 4 + 32 + NOTE_BYTES + 20 + 32;
/// The root of an empty trie: Keccak-256 of the RLP of the empty string.
pub const EMPTY_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

const BLOOM_BYTES: usize = 256;

/// A leaf appended to the coin tree, as its receipt records it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AppendedLeaf {
    /// The coin tree index the leaf went into.
    pub tree_index: u32,
    /// Its position in that tree.
    pub position: u32,
    /// The leaf `C`.
    pub leaf: Commitment,
    /// The note stored with it.
    pub note: [u8; NOTE_BYTES],
}

/// One coin tree record of a receipt.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CoinRecord {
    /// A commit log: the appended leaf and the committed value `v`.
    Commit { appended: AppendedLeaf, v: [u8; 32] },
    /// A reveal log: the remainder's leaf, the spent marker, the recipient
    /// and the amount paid out.
    Reveal { remainder: AppendedLeaf, marker: Marker, recipient: [u8; 20], out: [u8; 32] },
}

impl CoinRecord {
    /// The leaf the record appended.
    pub fn appended(&self) -> &AppendedLeaf {
        match self {
            Self::Commit { appended, .. } => appended,
            Self::Reveal { remainder, .. } => remainder,
        }
    }

    /// The spent marker, for a reveal.
    pub fn marker(&self) -> Option<&Marker> {
        match self {
            Self::Commit { .. } => None,
            Self::Reveal { marker, .. } => Some(marker),
        }
    }
}

/// The coin tree records of one block whose receipts matched its header's
/// `receiptsRoot`. Only [`check_block_receipts`] makes one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CheckedBlock {
    records: Vec<CoinRecord>,
}

impl CheckedBlock {
    /// The block's coin tree records, in receipt and log order.
    pub fn records(&self) -> &[CoinRecord] {
        &self.records
    }
}

/// Why receipts, leaves or markers were refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReceiptError {
    /// The header's bytes do not decode.
    Header(HeaderError),
    /// The receipts' root is not the header's `receiptsRoot`.
    RootMismatch,
    /// A receipt (by index in its block) does not decode.
    Receipt { receipt: usize, reason: &'static str },
    /// A log of the coin tree account is not exactly a commit or reveal log.
    CoinLog { receipt: usize, log: usize, reason: &'static str },
    /// The records of the checked blocks do not append one position after
    /// another: a block is missing, repeated or out of order.
    RecordSequence { tree_index: u32, position: u32 },
    /// The run has no leaf where the records have one.
    LeafMissing { position: u32 },
    /// The run has a leaf where the records have none.
    LeafInvented { position: u32 },
    /// The records' next position in the run's tree is not the run's.
    LeafPosition { expected: u32, found: u32 },
    /// The run's leaf differs from the record's.
    LeafMismatch { position: u32 },
    /// The run's note differs from the record's.
    NoteMismatch { position: u32 },
    /// The list lacks a marker the records hold, at this index.
    MarkerMissing { index: usize },
    /// The list holds a marker the records do not, at this index.
    MarkerInvented { index: usize },
    /// The list's marker at this index differs from the records'.
    MarkerMismatch { index: usize },
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(error) => write!(f, "the header does not decode ({error:?})"),
            Self::RootMismatch => f.write_str("the receipts do not match the header's receipts root"),
            Self::Receipt { receipt, reason } => write!(f, "receipt {receipt} does not decode: {reason}"),
            Self::CoinLog { receipt, log, reason } => {
                write!(f, "log {log} of receipt {receipt} is not a coin tree log: {reason}")
            }
            Self::RecordSequence { tree_index, position } => {
                write!(f, "the record of tree {tree_index}, position {position} is out of sequence")
            }
            Self::LeafMissing { position } => write!(f, "the leaf at position {position} is missing"),
            Self::LeafInvented { position } => write!(f, "the leaf at position {position} is not in the receipts"),
            Self::LeafPosition { expected, found } => {
                write!(f, "the receipts hold position {found} where the run holds {expected}")
            }
            Self::LeafMismatch { position } => write!(f, "the leaf at position {position} differs from its receipt"),
            Self::NoteMismatch { position } => write!(f, "the note at position {position} differs from its receipt"),
            Self::MarkerMissing { index } => write!(f, "spent marker {index} is missing"),
            Self::MarkerInvented { index } => write!(f, "spent marker {index} is not in the receipts"),
            Self::MarkerMismatch { index } => write!(f, "spent marker {index} differs from its receipt"),
        }
    }
}

/// The receipts root of a block's receipts, each its consensus encoding: the
/// Merkle Patricia trie keyed by the RLP of each receipt's index, valued by
/// its encoding, hashed with Keccak-256.
pub fn receipts_root<R: AsRef<[u8]>>(receipts: &[R]) -> [u8; 32] {
    let mut items: Vec<(Vec<u8>, &[u8])> = receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            let mut key = Vec::new();
            rlp::uint(&mut key, index as u64);
            (nibbles(&key), receipt.as_ref())
        })
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    trie_root(&items)
}

/// Checks a block's receipts against its header's `receiptsRoot`, then reads
/// their coin tree records.
pub fn check_block_receipts<R: AsRef<[u8]>>(
    receipts: &[R],
    receipts_root: &[u8; 32],
) -> Result<CheckedBlock, ReceiptError> {
    if &self::receipts_root(receipts) != receipts_root {
        return Err(ReceiptError::RootMismatch);
    }
    let mut records = Vec::new();
    for (index, receipt) in receipts.iter().enumerate() {
        read_receipt(index, receipt.as_ref(), &mut records)?;
    }
    Ok(CheckedBlock { records })
}

/// [`check_block_receipts`] against the `receiptsRoot` of a header given as
/// its RLP (spec 05, section 10). The header itself is the caller's to check
/// against its header chain.
pub fn check_block_receipts_against_header<R: AsRef<[u8]>>(
    header: &[u8],
    receipts: &[R],
) -> Result<CheckedBlock, ReceiptError> {
    check_block_receipts(receipts, &header_receipts_root(header)?)
}

/// The `receiptsRoot` field of a header given as its RLP.
pub fn header_receipts_root(header: &[u8]) -> Result<[u8; 32], ReceiptError> {
    header_fields(header).map_err(ReceiptError::Header)?;
    let undecodable = ReceiptError::Header(HeaderError::NonCanonicalRlp);
    let mut outer = rlp::Reader::new(header);
    let mut fields = rlp::Reader::new(outer.list().map_err(|_| undecodable)?);
    for _ in 0..5 {
        fields.bytes().map_err(|_| undecodable)?;
    }
    let root = fields.bytes().map_err(|_| undecodable)?;
    root.try_into().map_err(|_| ReceiptError::Header(HeaderError::FieldSize))
}

/// Checks a downloaded run of leaves and notes of coin tree `tree_index`,
/// starting at `start`, against the records of checked blocks given in chain
/// order. Records of other trees and at lower positions are passed over; the
/// records from `start` must match the run exactly, leaf for leaf and note
/// for note, and the blocks must cover the whole run.
pub fn check_leaves(
    blocks: &[CheckedBlock],
    tree_index: u32,
    start: u32,
    run: &[TreeLeaf],
) -> Result<(), ReceiptError> {
    check_sequence(blocks)?;
    let mut expected = start;
    let mut leaves = run.iter();
    let records = blocks.iter().flat_map(|block| &block.records).map(CoinRecord::appended);
    for record in records.filter(|r| r.tree_index == tree_index && r.position >= start) {
        if record.position != expected {
            return Err(ReceiptError::LeafPosition { expected, found: record.position });
        }
        let Some(leaf) = leaves.next() else {
            return Err(ReceiptError::LeafMissing { position: record.position });
        };
        if leaf.commitment != record.leaf {
            return Err(ReceiptError::LeafMismatch { position: record.position });
        }
        if leaf.note != record.note {
            return Err(ReceiptError::NoteMismatch { position: record.position });
        }
        expected = expected.wrapping_add(1);
    }
    if leaves.next().is_some() {
        return Err(ReceiptError::LeafInvented { position: expected });
    }
    Ok(())
}

/// Checks a downloaded spent-marker list against the markers of the reveal
/// records of checked blocks given in chain order. The list is compared
/// whole, so the blocks must cover the same range as the list.
pub fn check_markers(blocks: &[CheckedBlock], markers: &[Marker]) -> Result<(), ReceiptError> {
    let mut expected = blocks.iter().flat_map(|block| &block.records).filter_map(CoinRecord::marker);
    for (index, marker) in markers.iter().enumerate() {
        match expected.next() {
            None => return Err(ReceiptError::MarkerInvented { index }),
            Some(record) if record != marker => return Err(ReceiptError::MarkerMismatch { index }),
            Some(_) => {}
        }
    }
    if expected.next().is_some() {
        return Err(ReceiptError::MarkerMissing { index: markers.len() });
    }
    Ok(())
}

/// Every record must append right after the one before it: the next position
/// in the same tree, or position 0 of the next tree once a tree is full.
fn check_sequence(blocks: &[CheckedBlock]) -> Result<(), ReceiptError> {
    let mut last: Option<(u32, u32)> = None;
    for record in blocks.iter().flat_map(|block| &block.records).map(CoinRecord::appended) {
        let here = (record.tree_index, record.position);
        if let Some((tree, position)) = last {
            let next = match position.checked_add(1) {
                Some(position) => Some((tree, position)),
                None => tree.checked_add(1).map(|tree| (tree, 0)),
            };
            if next != Some(here) {
                return Err(ReceiptError::RecordSequence { tree_index: here.0, position: here.1 });
            }
        }
        last = Some(here);
    }
    Ok(())
}

/// Decodes one receipt, `[status, cumulativeGasUsed, logsBloom, logs]`
/// optionally after a type byte, and appends its coin tree records.
fn read_receipt(index: usize, bytes: &[u8], records: &mut Vec<CoinRecord>) -> Result<(), ReceiptError> {
    let bad = |reason| ReceiptError::Receipt { receipt: index, reason };
    let body = match bytes.first() {
        None => return Err(bad("the receipt is empty")),
        Some(0x01..=0x7f) => &bytes[1..],
        Some(0xc0..=0xff) => bytes,
        Some(_) => return Err(bad("not a type byte or a list")),
    };
    let mut outer = rlp::Reader::new(body);
    let mut fields = rlp::Reader::new(outer.list().map_err(bad)?);
    outer.end().map_err(bad)?;
    let status = fields.bytes().map_err(bad)?;
    let succeeded = match status {
        [] => false,
        [1] => true,
        _ => return Err(bad("the status is not 0 or 1")),
    };
    fields.uint_u64().map_err(bad)?;
    if fields.bytes().map_err(bad)?.len() != BLOOM_BYTES {
        return Err(bad("the bloom is not 256 bytes"));
    }
    let mut logs = rlp::Reader::new(fields.list().map_err(bad)?);
    fields.end().map_err(bad)?;
    let mut log_index = 0;
    while !logs.is_empty() {
        let mut log = rlp::Reader::new(logs.list().map_err(bad)?);
        let address = log.bytes().map_err(bad)?;
        let mut topic_reader = rlp::Reader::new(log.list().map_err(bad)?);
        let mut topics = Vec::new();
        while !topic_reader.is_empty() {
            let topic: [u8; 32] = topic_reader.bytes().map_err(bad)?.try_into().map_err(|_| bad("a topic is not 32 bytes"))?;
            topics.push(topic);
        }
        let data = log.bytes().map_err(bad)?;
        log.end().map_err(bad)?;
        if address.len() != 20 {
            return Err(bad("an address is not 20 bytes"));
        }
        if address == COIN_TREE_ACCOUNT {
            if !succeeded {
                return Err(ReceiptError::CoinLog { receipt: index, log: log_index, reason: "a failed receipt has a coin tree log" });
            }
            let record = coin_record(&topics, data)
                .map_err(|reason| ReceiptError::CoinLog { receipt: index, log: log_index, reason })?;
            records.push(record);
        }
        log_index += 1;
    }
    Ok(())
}

/// Reads a commit or reveal log of the coin tree account, which must be
/// exactly the layout.
fn coin_record(topics: &[[u8; 32]], data: &[u8]) -> Result<CoinRecord, &'static str> {
    let first = topics.first().ok_or("the log has no topic")?;
    if *first == k(TAG_COMMIT_RECEIPT, &[]) {
        if topics.len() != 1 {
            return Err("a commit log does not have exactly one topic");
        }
        if data.len() != COMMIT_LOG_BYTES {
            return Err("a commit log's data is not its length");
        }
        let mut data = Fields(data);
        let appended = data.appended_head();
        let v = data.take();
        let note = data.take();
        Ok(CoinRecord::Commit { appended: AppendedLeaf { note, ..appended }, v })
    } else if *first == k(TAG_REVEAL_RECEIPT, &[]) {
        if topics.len() != 2 {
            return Err("a reveal log does not have exactly two topics");
        }
        if data.len() != REVEAL_LOG_BYTES {
            return Err("a reveal log's data is not its length");
        }
        let mut data = Fields(data);
        let remainder = data.appended_head();
        let note = data.take();
        let recipient = data.take();
        let out = data.take();
        Ok(CoinRecord::Reveal {
            remainder: AppendedLeaf { note, ..remainder },
            marker: Marker::from_bytes(topics[1]),
            recipient,
            out,
        })
    } else {
        Err("the first topic is neither a commit nor a reveal")
    }
}

/// Fixed-size fields read in order from data whose length is checked.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        head.try_into().expect("a field of its own size")
    }

    /// Tree index, position and leaf, with the note still to read.
    fn appended_head(&mut self) -> AppendedLeaf {
        AppendedLeaf {
            tree_index: u32::from_be_bytes(self.take()),
            position: u32::from_be_bytes(self.take()),
            leaf: Commitment::from_bytes(self.take()),
            note: [0; NOTE_BYTES],
        }
    }
}

fn nibbles(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|&b| [b >> 4, b & 0x0f]).collect()
}

/// The hex-prefix encoding of a path, with the leaf flag.
fn hex_prefix(path: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 2 } else { 0 };
    let mut out = Vec::with_capacity(path.len() / 2 + 1);
    let rest = if path.len() % 2 == 1 {
        out.push((flag + 1) << 4 | path[0]);
        &path[1..]
    } else {
        out.push(flag << 4);
        path
    };
    out.extend(rest.chunks(2).map(|pair| pair[0] << 4 | pair[1]));
    out
}

fn trie_root(items: &[(Vec<u8>, &[u8])]) -> [u8; 32] {
    if items.is_empty() {
        return EMPTY_ROOT;
    }
    keccak256(&node(items, 0))
}

/// How a node is referred to from its parent: inline below 32 bytes,
/// otherwise by its hash.
fn reference(out: &mut Vec<u8>, encoded: Vec<u8>) {
    if encoded.len() < 32 {
        out.extend_from_slice(&encoded);
    } else {
        rlp::bytes(out, &keccak256(&encoded));
    }
}

/// The RLP of the node holding `items` (sorted, distinct, non-empty) below
/// `depth` nibbles.
fn node(items: &[(Vec<u8>, &[u8])], depth: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    if let [(key, value)] = items {
        rlp::bytes(&mut payload, &hex_prefix(&key[depth..], true));
        rlp::bytes(&mut payload, value);
    } else {
        let first = &items[0].0[depth..];
        let last = &items[items.len() - 1].0[depth..];
        let shared = first.iter().zip(last).take_while(|(a, b)| a == b).count();
        if shared > 0 {
            rlp::bytes(&mut payload, &hex_prefix(&first[..shared], false));
            reference(&mut payload, node(items, depth + shared));
        } else {
            let mut value: &[u8] = &[];
            let mut rest = items;
            if rest[0].0.len() == depth {
                value = rest[0].1;
                rest = &rest[1..];
            }
            for nibble in 0..16u8 {
                let count = rest.iter().take_while(|(key, _)| key[depth] == nibble).count();
                if count == 0 {
                    payload.push(rlp::EMPTY);
                } else {
                    reference(&mut payload, node(&rest[..count], depth + 1));
                }
                rest = &rest[count..];
            }
            rlp::bytes(&mut payload, value);
        }
    }
    let mut out = Vec::new();
    rlp::list(&mut out, &payload);
    out
}

/// The RLP rules receipts and the trie need: byte strings, unsigned integers
/// without leading zeros and lists, encoded and read strictly.
mod rlp {
    pub const EMPTY: u8 = 0x80;

    fn length(out: &mut Vec<u8>, len: usize, short: u8) {
        if len < 56 {
            out.push(short + len as u8);
        } else {
            let be = (len as u64).to_be_bytes();
            let skip = be.iter().take_while(|&&b| b == 0).count();
            out.push(short + 55 + (8 - skip) as u8);
            out.extend_from_slice(&be[skip..]);
        }
    }

    pub fn bytes(out: &mut Vec<u8>, b: &[u8]) {
        if b.len() == 1 && b[0] < 0x80 {
            out.push(b[0]);
        } else {
            length(out, b.len(), 0x80);
            out.extend_from_slice(b);
        }
    }

    pub fn uint(out: &mut Vec<u8>, v: u64) {
        let be = v.to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        bytes(out, &be[skip..]);
    }

    pub fn list(out: &mut Vec<u8>, payload: &[u8]) {
        length(out, payload.len(), 0xc0);
        out.extend_from_slice(payload);
    }

    pub struct Reader<'a> {
        rest: &'a [u8],
    }

    type R<T> = Result<T, &'static str>;

    impl<'a> Reader<'a> {
        pub fn new(rest: &'a [u8]) -> Self {
            Self { rest }
        }

        pub fn is_empty(&self) -> bool {
            self.rest.is_empty()
        }

        pub fn end(&self) -> R<()> {
            if self.rest.is_empty() { Ok(()) } else { Err("bytes after the item") }
        }

        fn take(&mut self, n: usize) -> R<&'a [u8]> {
            if self.rest.len() < n {
                return Err("an item runs past the end");
            }
            let (part, rest) = self.rest.split_at(n);
            self.rest = rest;
            Ok(part)
        }

        /// The payload of the next item and whether it is a list.
        fn item(&mut self) -> R<(&'a [u8], bool)> {
            let prefix = *self.rest.first().ok_or("an item runs past the end")?;
            if prefix < 0x80 {
                return Ok((self.take(1)?, false));
            }
            self.take(1)?;
            match prefix {
                0x80..=0xb7 => {
                    let n = usize::from(prefix - 0x80);
                    let payload = self.take(n)?;
                    if n == 1 && payload[0] < 0x80 {
                        return Err("a single byte below 0x80 is wrapped");
                    }
                    Ok((payload, false))
                }
                0xb8..=0xbf => Ok((self.long(prefix - 0xb7)?, false)),
                0xc0..=0xf7 => Ok((self.take(usize::from(prefix - 0xc0))?, true)),
                _ => Ok((self.long(prefix - 0xf7)?, true)),
            }
        }

        fn long(&mut self, size_bytes: u8) -> R<&'a [u8]> {
            let size = self.take(usize::from(size_bytes))?;
            if size[0] == 0 {
                return Err("a length has a leading zero");
            }
            if size.len() > 4 {
                return Err("a length is too large");
            }
            let n = size.iter().fold(0usize, |n, &b| n << 8 | usize::from(b));
            if n < 56 {
                return Err("a long length is used for a short item");
            }
            self.take(n)
        }

        pub fn bytes(&mut self) -> R<&'a [u8]> {
            match self.item()? {
                (payload, false) => Ok(payload),
                _ => Err("a list where a byte string belongs"),
            }
        }

        pub fn list(&mut self) -> R<&'a [u8]> {
            match self.item()? {
                (payload, true) => Ok(payload),
                _ => Err("a byte string where a list belongs"),
            }
        }

        pub fn uint_u64(&mut self) -> R<u64> {
            let b = self.bytes()?;
            if b.first() == Some(&0) {
                return Err("an integer has a leading zero");
            }
            if b.len() > 8 {
                return Err("an integer is too large");
            }
            Ok(b.iter().fold(0u64, |n, &x| n << 8 | u64::from(x)))
        }
    }
}
