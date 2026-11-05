//! The header chain checked by sampling, in place of every header from
//! genesis (docs/scale/stage2-design.md, "Wallet restore volume", step 2).
//!
//! The wallet checks the last [`TAIL_HEADERS`] headers in full and samples
//! the headers before them by cumulative work, with its own randomness: a
//! point `x` of the chain's work is drawn with density
//! `1 / ((1 - x) ln(1/delta))` on `[0, 1 - delta]`, `delta` the share of the
//! total work the tail carries, and the server answers with the header whose
//! work covers the point. Each answer is checked here: its RandomX seal under
//! its key block, the key block itself (the header at [`seed_height`], which
//! must be the chain's own leaf there), the difficulty the rule requires of
//! it (spec 06, section 4.3, which needs only the header's own height and
//! timestamp) and a path to the root of the Merkle mountain range over every
//! header and its work up to the tip.
//!
//! Against an attacker whose valid work after its fork is at most a ratio `c`
//! of the honest work, every fork point leaves an invalid stretch that one
//! sample hits with probability at least `ln(1/c) / ln(1/delta)` (the
//! FlyClient argument, derived for the design page; the bound for Ghost's
//! difficulty rule is not yet established). [`sample_count`] takes the
//! samples from an assurance target in bits, at
//! `-log2(1 - ln(1/c) / ln(1/delta))` bits a sample ([`bits_per_sample`]).
//! The attacker ratio and the target are the caller's settings
//! ([`SampleSettings`]); a full check of every header stays an option
//! ([`HeaderCheck::Full`]).
//!
//! The root of the mountain range is the caller's: a 32-byte hash over a
//! 48-byte node, a 32-byte hash and 16 bytes of work ([`MmrNode`]), as the
//! design models; the node's header field is not built yet. A leaf is the
//! header hash and its difficulty; the leaf at index `i` is the header at
//! height `i`, from genesis to the tip.
//!
//! # What the sampled check credits
//!
//! A path proves only that a header is a leaf of the range, not that it is an
//! ancestor of the tip. A range of copied honest headers through height
//! `H - 2`, a sealed header at `H - 1` whose parent is not the leaf at
//! `H - 2`, and a sealed tail from `H` linked to it passes every sample and
//! the tail's own checks: the range then claims the honest chain's work for a
//! tip that has only the tail's. So the sampled check credits only the work
//! of the contiguous tail, the last `tail_headers` headers, whose links by
//! `parentHash` it checked one by one: [`CheckedChain::credited_work`] is that
//! work and never more. The work below the tail is returned as
//! [`CheckedChain::claimed_prefix_work`], and it is **unauthenticated**: the
//! root claims it, the samples found no unsealed header in it, but nothing
//! binds those leaves to the tip's ancestry. A caller must not add it to the
//! credited work, compare chains by it or treat it as proof of work done. A
//! caller that needs the whole chain's work uses [`HeaderCheck::Full`], which
//! checks every link from genesis and credits all of it.
//!
//! Binding the sampled leaves to the tip's ancestry (the FlyClient ancestry
//! check over the header's `headerMmrRoot`, with its written bound) is not
//! built here.
//!
//! The header before the tail's first is sent too, checked in the same way
//! as a tail header (path, difficulty, key block and seal), and must be the
//! parent the tail's first header names, so a tail mined on a parent the
//! range does not hold is refused outright. That header's work is not
//! credited, and it says nothing of the headers below it.
//!
//! The flow has two steps, so the caller can fetch in bulk:
//! [`HeaderSampler::check_tail`] checks the tail, and the header before it,
//! against the root and learns
//! the total work and `delta`; [`HeaderSampler::request`] draws the points
//! from the caller's generator; [`HeaderSampler::check_samples`] checks the
//! server's answers. The library has no network code and no clock.

use core::fmt;
use std::collections::HashMap;

use rand_core::CryptoRng;

use crate::hash::{k, keccak256};
use crate::header_chain::{required_difficulty, Added, ChainError, ChainParams, HeaderChain, StartError, U256};
use crate::seal::{header_fields, seed_height, verify_seal, HeaderError, HeaderFields, SealError, SealKey};

/// The headers at the tip that are checked in full, not sampled.
pub const TAIL_HEADERS: u64 = 64;
/// The bytes of a mountain-range node: a 32-byte hash and 16 bytes of work.
pub const MMR_NODE_BYTES: usize = 48;

/// Tag of a leaf: a header hash and its work.
pub const TAG_HEADER_MMR_LEAF: &str = "ghost/header-mmr-leaf/v1";
/// Tag of an inner node over two 48-byte children.
pub const TAG_HEADER_MMR_NODE: &str = "ghost/header-mmr-node/v1";
/// Tag of the root: the leaf count and the bagged peaks.
pub const TAG_HEADER_MMR_ROOT: &str = "ghost/header-mmr-root/v1";

/// At most this many RandomX caches, 256 MiB each, are held at a time.
const MAX_CACHES: usize = 2;
/// Seal results remembered before the memory is cleared.
const SEAL_MEMO_LIMIT: usize = 1 << 16;
const TIMESTAMP_LIMIT: u64 = 1 << 63;

/// A node of the header mountain range: a hash and the total work of the
/// headers below it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MmrNode {
    pub hash: [u8; 32],
    pub work: u128,
}

impl MmrNode {
    /// The leaf of a header: `K(TAG_HEADER_MMR_LEAF, hash, work)`, work as
    /// 16 big-endian bytes.
    pub fn leaf(header_hash: &[u8; 32], work: u128) -> Self {
        Self { hash: k(TAG_HEADER_MMR_LEAF, &[header_hash, &work.to_be_bytes()]), work }
    }

    /// The node over `left` and `right`: `K(TAG_HEADER_MMR_NODE, left,
    /// right)` over their 48-byte encodings, with the sum of their work.
    /// `None` if the work does not fit in 16 bytes.
    pub fn parent(left: &Self, right: &Self) -> Option<Self> {
        let work = left.work.checked_add(right.work)?;
        Some(Self { hash: k(TAG_HEADER_MMR_NODE, &[&left.to_bytes(), &right.to_bytes()]), work })
    }

    /// The 48-byte encoding: the hash, then the work big-endian.
    pub fn to_bytes(&self) -> [u8; MMR_NODE_BYTES] {
        let mut out = [0u8; MMR_NODE_BYTES];
        out[..32].copy_from_slice(&self.hash);
        out[32..].copy_from_slice(&self.work.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; MMR_NODE_BYTES]) -> Self {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[..32]);
        let mut work = [0u8; 16];
        work.copy_from_slice(&bytes[32..]);
        Self { hash, work: u128::from_be_bytes(work) }
    }
}

/// The mountains of a range of `leaf_count` leaves, left to right: (first
/// leaf, height), one for each set bit of the count, the largest first.
fn mountains(leaf_count: u64) -> Vec<(u64, u32)> {
    let mut out = Vec::new();
    let mut start = 0u64;
    for height in (0..64).rev() {
        if leaf_count >> height & 1 == 1 {
            out.push((start, height));
            start += 1 << height;
        }
    }
    out
}

/// The peaks bagged from the right: the last peak, then each peak to its
/// left as the left child. `None` if there are none or the work overflows.
fn bag(peaks: &[MmrNode]) -> Option<MmrNode> {
    let (last, rest) = peaks.split_last()?;
    rest.iter().rev().try_fold(*last, |bagged, peak| MmrNode::parent(peak, &bagged))
}

fn root_of_bag(leaf_count: u64, bagged: &MmrNode) -> [u8; 32] {
    k(TAG_HEADER_MMR_ROOT, &[&leaf_count.to_be_bytes(), &bagged.to_bytes()])
}

/// The root of a range of `leaf_count` leaves with these peaks, left to
/// right: `K(TAG_HEADER_MMR_ROOT, leaf_count as 8 bytes, bagged peaks)`.
/// `None` if the peaks do not fit the count or their work overflows.
pub fn mmr_root(leaf_count: u64, peaks: &[MmrNode]) -> Option<[u8; 32]> {
    if peaks.len() != mountains(leaf_count).len() {
        return None;
    }
    bag(peaks).map(|bagged| root_of_bag(leaf_count, &bagged))
}

/// The root over a whole list of leaves, built here (the full check).
fn root_of_leaves(leaves: &[MmrNode]) -> Option<[u8; 32]> {
    let mut stack: Vec<(u32, MmrNode)> = Vec::new();
    for leaf in leaves {
        let mut node = (0, *leaf);
        while let Some(&(height, left)) = stack.last() {
            if height != node.0 {
                break;
            }
            stack.pop();
            node = (height + 1, MmrNode::parent(&left, &node.1)?);
        }
        stack.push(node);
    }
    let peaks: Vec<MmrNode> = stack.into_iter().map(|(_, node)| node).collect();
    mmr_root(leaves.len() as u64, &peaks)
}

/// A leaf's path to the root: the leaf count the root commits to, the
/// siblings inside its mountain from the bottom up, and the other peaks left
/// to right.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmrPath {
    pub leaf_count: u64,
    pub siblings: Vec<MmrNode>,
    pub peaks: Vec<MmrNode>,
}

/// Where a leaf sits in the chain's work, read from a checked path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafPosition {
    /// The work of every leaf before this one.
    pub work_before: u128,
    /// The work of every leaf in the range.
    pub total_work: u128,
}

/// Why a path does not take its leaf to the root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// The leaf's index is not below the leaf count.
    Index,
    /// The path's leaf count is not the one the rest of the proof has.
    LeafCount,
    /// The path has the wrong number of siblings or peaks for its index.
    Shape,
    /// The work does not fit in 16 bytes.
    Work,
    /// The path ends at another root.
    Root,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Index => "the leaf's index is not below the leaf count",
            Self::LeafCount => "the path's leaf count is not the tip's",
            Self::Shape => "the path has the wrong number of siblings or peaks",
            Self::Work => "the path's work does not fit in 16 bytes",
            Self::Root => "the path does not reach the root",
        })
    }
}

/// Checks that `leaf` is the leaf at `index` under `root`, and returns the
/// work before it and the total work, both read from the authenticated nodes.
pub fn verify_mmr_path(root: &[u8; 32], index: u64, leaf: &MmrNode, path: &MmrPath) -> Result<LeafPosition, PathError> {
    if index >= path.leaf_count {
        return Err(PathError::Index);
    }
    let mountains = mountains(path.leaf_count);
    let (mountain, &(start, height)) = mountains
        .iter()
        .enumerate()
        .find(|&(_, &(start, height))| index < start + (1u64 << height))
        .expect("an index below the leaf count is in a mountain");
    if path.siblings.len() != height as usize || path.peaks.len() != mountains.len() - 1 {
        return Err(PathError::Shape);
    }
    let offset = index - start;
    let mut node = *leaf;
    let mut work_before = 0u128;
    for (level, sibling) in path.siblings.iter().enumerate() {
        node = if offset >> level & 1 == 0 {
            MmrNode::parent(&node, sibling)
        } else {
            work_before = work_before.checked_add(sibling.work).ok_or(PathError::Work)?;
            MmrNode::parent(sibling, &node)
        }
        .ok_or(PathError::Work)?;
    }
    for peak in &path.peaks[..mountain] {
        work_before = work_before.checked_add(peak.work).ok_or(PathError::Work)?;
    }
    let mut peaks = Vec::with_capacity(mountains.len());
    peaks.extend_from_slice(&path.peaks[..mountain]);
    peaks.push(node);
    peaks.extend_from_slice(&path.peaks[mountain..]);
    let bagged = bag(&peaks).ok_or(PathError::Work)?;
    if root_of_bag(path.leaf_count, &bagged) != *root {
        return Err(PathError::Root);
    }
    Ok(LeafPosition { work_before, total_work: bagged.work })
}

/// Bits of assurance one sample gives against an attacker whose valid work
/// after its fork is at most `attacker_ratio` of the honest work, when the
/// tail carries the share `delta` of the work:
/// `-log2(1 - ln(1/c) / ln(1/delta))`. Infinite when one sample always hits
/// (`c <= delta`); not a number when an input is out of range.
pub fn bits_per_sample(attacker_ratio: f64, delta: f64) -> f64 {
    let hit = (1.0 / attacker_ratio).ln() / (1.0 / delta).ln();
    if hit >= 1.0 { f64::INFINITY } else { -(1.0 - hit).log2() }
}

/// The samples that reach `assurance_bits` against `attacker_ratio` when the
/// tail carries the share `delta` of the work: the bits divided by the bits a
/// sample, rounded up. 0 when the tail is the whole chain. `None` unless the
/// ratio is strictly between 0 and 1, the bits are positive and finite and
/// `delta` is positive.
pub fn sample_count(attacker_ratio: f64, assurance_bits: f64, delta: f64) -> Option<u64> {
    let ratio_ok = attacker_ratio > 0.0 && attacker_ratio < 1.0;
    let bits_ok = assurance_bits > 0.0 && assurance_bits.is_finite();
    if !ratio_ok || !bits_ok || delta.is_nan() || delta <= 0.0 {
        return None;
    }
    if delta >= 1.0 {
        return Some(0);
    }
    let per_sample = bits_per_sample(attacker_ratio, delta);
    if per_sample.is_infinite() {
        return Some(1);
    }
    Some((assurance_bits / per_sample).ceil().max(1.0) as u64)
}

/// One point of the chain's work below the tail, drawn from the caller's
/// generator with density `1 / ((1 - x) ln(1/delta))` on `[0, 1 - delta]`,
/// `delta = (total_work - tail_start_work) / total_work`: `x = 1 - delta^u`
/// for `u` uniform on `[0, 1)`, then scaled by the total work. The point is
/// below `tail_start_work`. `None` if there is no work below the tail or the
/// tail does not end the chain.
pub fn draw_point<R: CryptoRng + ?Sized>(rng: &mut R, tail_start_work: u128, total_work: u128) -> Option<u128> {
    if tail_start_work == 0 || tail_start_work >= total_work {
        return None;
    }
    let delta = (total_work - tail_start_work) as f64 / total_work as f64;
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    let u = (u64::from_be_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64;
    let x = -(u * delta.ln()).exp_m1();
    let point = (x * total_work as f64) as u128;
    Some(point.min(tail_start_work - 1))
}

/// How the headers before the tail are checked.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HeaderCheck {
    /// Sampled by work: enough samples for `assurance_bits` against an
    /// attacker whose valid work after its fork is at most `attacker_ratio`
    /// of the honest work.
    Sampled { attacker_ratio: f64, assurance_bits: f64 },
    /// Every header, as [`HeaderChain`] checks them.
    Full,
}

/// The sampler's settings.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SampleSettings {
    /// The headers at the tip checked in full; the design has 64.
    pub tail_headers: u64,
    pub check: HeaderCheck,
}

impl SampleSettings {
    /// Sampling with the design's tail of [`TAIL_HEADERS`].
    pub fn sampled(attacker_ratio: f64, assurance_bits: f64) -> Self {
        Self { tail_headers: TAIL_HEADERS, check: HeaderCheck::Sampled { attacker_ratio, assurance_bits } }
    }

    /// Every header checked, with the design's tail.
    pub fn full() -> Self {
        Self { tail_headers: TAIL_HEADERS, check: HeaderCheck::Full }
    }

    /// Whether the tail has a header, and a sampled check has a ratio
    /// strictly between 0 and 1 and a positive, finite target.
    pub fn is_valid(&self) -> bool {
        self.tail_headers > 0
            && match self.check {
                HeaderCheck::Sampled { attacker_ratio, assurance_bits } => {
                    attacker_ratio > 0.0
                        && attacker_ratio < 1.0
                        && assurance_bits > 0.0
                        && assurance_bits.is_finite()
                }
                HeaderCheck::Full => true,
            }
    }
}

/// A header with its path in the mountain range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenHeader {
    /// The header's RLP (spec 05, section 10).
    pub header: Vec<u8>,
    pub path: MmrPath,
}

/// A header the server sends for a sample or the tail: the header with its
/// path, and its key block with its path (none for the genesis header).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenSample {
    pub header: ProvenHeader,
    pub key_block: Option<ProvenHeader>,
}

/// A tail checked against the root: the first step of the check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedTail {
    root: [u8; 32],
    leaf_count: u64,
    total_work: u128,
    tail_start_work: u128,
    tip_hash: [u8; 32],
    tip_height: u64,
    headers: Vec<Vec<u8>>,
}

impl CheckedTail {
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The headers the root covers, the tip's height plus one.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// The work of every header up to the tip, as the root claims it; only
    /// [`tail_work`](Self::tail_work) of it is checked by links.
    pub fn total_work(&self) -> u128 {
        self.total_work
    }

    /// The work before the tail's first header, as the root claims it:
    /// samples are drawn below it.
    pub fn tail_start_work(&self) -> u128 {
        self.tail_start_work
    }

    /// The work of the tail's headers, each checked and linked by its parent
    /// hash to the one before it: the work a sampled check credits.
    pub fn tail_work(&self) -> u128 {
        self.total_work - self.tail_start_work
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    /// The share of the total work the tail carries.
    pub fn delta(&self) -> f64 {
        (self.total_work - self.tail_start_work) as f64 / self.total_work as f64
    }

    /// The tail's headers, oldest first.
    pub fn headers(&self) -> &[Vec<u8>] {
        &self.headers
    }
}

/// What the wallet asks the server for after the tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// For each point, the header whose work covers it, with its key block.
    Points(Vec<u128>),
    /// Every header from genesis below the tail: heights `0..count`.
    EveryHeader { count: u64 },
}

/// A header chain checked to its tip; see "What the sampled check credits"
/// in the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedChain {
    pub tip_hash: [u8; 32],
    pub tip_height: u64,
    /// The work the check authenticated: under a sampled check, the work of
    /// the contiguous tail linked by parent hashes and never more; under the
    /// full check, the work of every header from genesis.
    pub credited_work: u128,
    /// The work below the tail that the root claims, **unauthenticated**:
    /// nothing binds those leaves to the tip's ancestry. Never add it to
    /// `credited_work`. Zero under the full check, which credits it.
    pub claimed_prefix_work: u128,
    /// The headers before the tail that were checked: the samples, or every
    /// one of them.
    pub checked_before_tail: u64,
}

/// Why one header of the proof is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The header does not decode.
    Header(HeaderError),
    /// A tail header is not at the height its place in the tail requires.
    Height,
    /// A tail header's parent is not the header before it.
    Parent,
    /// A tail header's timestamp is not after the one before it, or a
    /// timestamp is `2^63` or more.
    Timestamp,
    /// The tip is more than the future drift ahead of the caller's clock.
    TooFarAhead,
    /// The difficulty is not the one the rule requires of the header, or does
    /// not fit in 16 bytes.
    Difficulty,
    /// A header at height 0 is not the genesis header.
    Genesis,
    /// The header's path does not take it to the root.
    Path(PathError),
    /// The header's work does not cover the sampled point.
    WorkRange,
    /// No key block was sent.
    MissingKeyBlock,
    /// The key block does not decode.
    KeyBlockHeader(HeaderError),
    /// The key block is not at the header's seed height.
    KeyBlockHeight,
    /// The key block at height 0 is not the genesis header.
    KeyBlockGenesis,
    /// The key block's difficulty is not the one the rule requires of it.
    KeyBlockDifficulty,
    /// The key block's path does not take it to the root at its height.
    KeyBlockPath(PathError),
    /// The seal is not valid under the key block.
    Seal(SealError),
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(e) => fmt::Display::fmt(&SealError::Header(*e), f),
            Self::Height => f.write_str("a tail header is not at its height"),
            Self::Parent => f.write_str("a tail header's parent is not the header before it"),
            Self::Timestamp => f.write_str("the header's timestamp is out of order or out of range"),
            Self::TooFarAhead => f.write_str("the tip is too far ahead of the clock"),
            Self::Difficulty => f.write_str("the header does not carry the required difficulty"),
            Self::Genesis => f.write_str("the header at height 0 is not the genesis header"),
            Self::Path(e) => write!(f, "the header's path: {e}"),
            Self::WorkRange => f.write_str("the header's work does not cover the sampled point"),
            Self::MissingKeyBlock => f.write_str("the key block was not sent"),
            Self::KeyBlockHeader(e) => write!(f, "the key block: {}", SealError::Header(*e)),
            Self::KeyBlockHeight => f.write_str("the key block is not at the header's seed height"),
            Self::KeyBlockGenesis => f.write_str("the key block at height 0 is not the genesis header"),
            Self::KeyBlockDifficulty => f.write_str("the key block does not carry the required difficulty"),
            Self::KeyBlockPath(e) => write!(f, "the key block's path: {e}"),
            Self::Seal(e) => fmt::Display::fmt(e, f),
        }
    }
}

/// Why a header proof is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleError {
    /// The settings are out of range.
    Settings,
    /// The genesis header or the chain constants are refused.
    Start(StartError),
    /// The tail is empty or not the last `tail_headers` headers.
    TailLength,
    /// A tail header is refused; `index` is its place in the tail.
    Tail { index: usize, fault: Fault },
    /// The tail does not start at genesis and the header before it was not
    /// sent.
    TailParentMissing,
    /// The header before the tail is refused, or was sent for a tail that
    /// starts at genesis.
    TailParent { fault: Fault },
    /// The call does not match the configured check.
    Mode,
    /// The points or the answers are not as many as the settings require.
    Count,
    /// A point is not below the tail.
    Point { index: usize },
    /// A sampled header is refused; `index` is its point's place.
    Sample { index: usize, fault: Fault },
    /// The full check did not get every header below the tail.
    FullCount,
    /// The first header of the full check is not the genesis header.
    FullGenesis,
    /// The full check refused the header at `height`.
    Full { height: u64, error: ChainError },
    /// The full check's headers do not link into one chain.
    FullNotLinear { height: u64 },
    /// The headers of the full check do not build the root.
    FullRoot,
}

impl fmt::Display for SampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Settings => f.write_str("the sampler's settings are out of range"),
            Self::Start(e) => fmt::Display::fmt(e, f),
            Self::TailLength => f.write_str("the tail is not the last headers of the chain"),
            Self::Tail { index, fault } => write!(f, "tail header {index}: {fault}"),
            Self::TailParentMissing => f.write_str("the header before the tail was not sent"),
            Self::TailParent { fault } => write!(f, "the header before the tail: {fault}"),
            Self::Mode => f.write_str("the check called is not the configured one"),
            Self::Count => f.write_str("the samples are not as many as the settings require"),
            Self::Point { index } => write!(f, "point {index} is not below the tail"),
            Self::Sample { index, fault } => write!(f, "sample {index}: {fault}"),
            Self::FullCount => f.write_str("the full check did not get every header below the tail"),
            Self::FullGenesis => f.write_str("the full check does not start at the genesis header"),
            Self::Full { height, error } => write!(f, "header {height}: {error}"),
            Self::FullNotLinear { height } => write!(f, "header {height} does not extend the chain"),
            Self::FullRoot => f.write_str("the headers do not build the root"),
        }
    }
}

/// A header that passed every check but its seal.
struct Seen {
    fields: HeaderFields,
    work: u128,
    difficulty: U256,
    position: LeafPosition,
    /// The key block's hash; none for the genesis header, which has no seal.
    key: Option<[u8; 32]>,
}

fn to_u128(value: U256) -> Option<u128> {
    let bytes = value.to_be_bytes();
    if bytes[..16].iter().any(|&b| b != 0) {
        return None;
    }
    let mut low = [0u8; 16];
    low.copy_from_slice(&bytes[16..]);
    Some(u128::from_be_bytes(low))
}

/// The wallet's sampled check of a header chain; see the module
/// documentation.
///
/// It remembers the result of every seal it checked, by header and key
/// block, so a header sampled twice (in one proof or in a later keep-up
/// check) is hashed once; the memory is cleared past 65,536 results. It
/// holds at most two RandomX caches, 256 MiB each.
pub struct HeaderSampler {
    chain: ChainParams,
    settings: SampleSettings,
    genesis: Vec<u8>,
    genesis_hash: [u8; 32],
    genesis_timestamp: u64,
    /// The most recently used first.
    caches: Vec<([u8; 32], SealKey)>,
    seals: HashMap<([u8; 32], [u8; 32]), Result<(), SealError>>,
}

impl HeaderSampler {
    /// A sampler for the chain that starts at `genesis` under `chain`'s
    /// constants. The genesis header is accepted by its derivation (spec 06,
    /// section 8), as in [`HeaderChain::from_genesis`].
    pub fn new(genesis: &[u8], chain: ChainParams, settings: SampleSettings) -> Result<Self, SampleError> {
        if !settings.is_valid() {
            return Err(SampleError::Settings);
        }
        if !chain.is_valid() {
            return Err(SampleError::Start(StartError::Params));
        }
        let fields = header_fields(genesis).map_err(|e| SampleError::Start(StartError::Header(e)))?;
        if fields.number != 0 {
            return Err(SampleError::Start(StartError::NotGenesis));
        }
        if U256::from_be_bytes(&fields.difficulty) != Some(U256::from(chain.start_difficulty)) {
            return Err(SampleError::Start(StartError::GenesisDifficulty));
        }
        if fields.timestamp >= TIMESTAMP_LIMIT {
            return Err(SampleError::Start(StartError::Timestamp));
        }
        Ok(Self {
            chain,
            settings,
            genesis: genesis.to_vec(),
            genesis_hash: fields.hash,
            genesis_timestamp: fields.timestamp,
            caches: Vec::new(),
            seals: HashMap::new(),
        })
    }

    pub fn settings(&self) -> SampleSettings {
        self.settings
    }

    /// The samples the settings require for this tail.
    pub fn required_samples(&self, tail: &CheckedTail) -> u64 {
        match self.settings.check {
            HeaderCheck::Full => 0,
            HeaderCheck::Sampled { .. } if tail.tail_start_work == 0 => 0,
            HeaderCheck::Sampled { attacker_ratio, assurance_bits } => {
                sample_count(attacker_ratio, assurance_bits, tail.delta()).expect("the settings were checked")
            }
        }
    }

    /// Checks the tail: the last `min(tail_headers, leaf count)` headers,
    /// each at its height with its path to `root`, linked by parent hashes
    /// with rising timestamps, each with the difficulty the rule requires and
    /// a valid seal under its key block, and the tip within the future drift
    /// of `now` (the caller's clock, Unix seconds).
    ///
    /// Unless the tail starts at genesis, `parent` is the header before the
    /// tail's first, with its key block and path: it is checked in the same
    /// way, and the tail's first header must name it as its parent and be
    /// stamped after it. This refuses a tail mined on a parent the range does
    /// not hold; it does not bind the leaves further down to the tip, and its
    /// own work is not credited.
    pub fn check_tail(
        &mut self,
        root: &[u8; 32],
        parent: Option<&ProvenSample>,
        tail: &[ProvenSample],
        now: u64,
    ) -> Result<CheckedTail, SampleError> {
        let last = tail.last().ok_or(SampleError::TailLength)?;
        let leaf_count = last.header.path.leaf_count;
        let length = leaf_count.min(self.settings.tail_headers);
        if leaf_count == 0 || tail.len() as u64 != length {
            return Err(SampleError::TailLength);
        }
        let first_height = leaf_count - length;
        let mut seen: Vec<Seen> = Vec::with_capacity(tail.len() + 1);
        let mut headers: Vec<&[u8]> = Vec::with_capacity(tail.len() + 1);
        match (first_height, parent) {
            (0, None) => {}
            (0, Some(_)) => return Err(SampleError::TailParent { fault: Fault::Height }),
            (_, None) => return Err(SampleError::TailParentMissing),
            (_, Some(parent)) => {
                let refuse = |fault| SampleError::TailParent { fault };
                let header = self.check_header(root, leaf_count, parent).map_err(refuse)?;
                if header.fields.number != first_height - 1 {
                    return Err(refuse(Fault::Height));
                }
                seen.push(header);
                headers.push(&parent.header.header);
            }
        }
        // The header before the tail, if any, comes first in `seen`.
        let offset = seen.len();
        for (index, sample) in tail.iter().enumerate() {
            let refuse = |fault| SampleError::Tail { index, fault };
            let header = self.check_header(root, leaf_count, sample).map_err(refuse)?;
            if header.fields.number != first_height + index as u64 {
                return Err(refuse(Fault::Height));
            }
            if let Some(before) = seen.last() {
                if header.fields.parent_hash != before.fields.hash {
                    return Err(refuse(Fault::Parent));
                }
                if header.fields.timestamp <= before.fields.timestamp {
                    return Err(refuse(Fault::Timestamp));
                }
            }
            seen.push(header);
            headers.push(&sample.header.header);
        }
        let tip = seen.last().expect("the tail is not empty");
        if tip.fields.timestamp > now.saturating_add(self.chain.future_drift) {
            return Err(SampleError::Tail { index: tail.len() - 1, fault: Fault::TooFarAhead });
        }
        self.check_seals(&seen, &headers).map_err(|(index, e)| match index.checked_sub(offset) {
            Some(index) => SampleError::Tail { index, fault: Fault::Seal(e) },
            None => SampleError::TailParent { fault: Fault::Seal(e) },
        })?;
        let tip = seen.last().expect("the tail is not empty");
        Ok(CheckedTail {
            root: *root,
            leaf_count,
            total_work: tip.position.total_work,
            tail_start_work: seen[offset].position.work_before,
            tip_hash: tip.fields.hash,
            tip_height: tip.fields.number,
            headers: headers[offset..].iter().map(|header| header.to_vec()).collect(),
        })
    }

    /// What to ask the server for: under a sampled check, the required number
    /// of points drawn from `rng`, the wallet's own generator; under a full
    /// check, every header below the tail.
    pub fn request<R: CryptoRng + ?Sized>(&self, tail: &CheckedTail, rng: &mut R) -> Request {
        match self.settings.check {
            HeaderCheck::Full => Request::EveryHeader { count: tail.leaf_count - tail.headers.len() as u64 },
            HeaderCheck::Sampled { .. } => {
                let count = self.required_samples(tail);
                Request::Points(
                    (0..count).filter_map(|_| draw_point(rng, tail.tail_start_work, tail.total_work)).collect(),
                )
            }
        }
    }

    /// Checks the server's answers to the points of [`request`](Self::request):
    /// `samples[i]` answers `points[i]`. Each sample must be the leaf whose
    /// work covers its point, with its path to the tail's root, the
    /// difficulty the rule requires of it, its key block (the chain's leaf at
    /// its seed height, or the genesis header) and a valid seal under that
    /// key block. The cheap checks of every sample come first, then the
    /// seals, grouped by key block; the first refusal found is returned.
    ///
    /// The chain returned credits only the tail's work; the work below it is
    /// the unauthenticated `claimed_prefix_work`.
    pub fn check_samples(
        &mut self,
        tail: &CheckedTail,
        points: &[u128],
        samples: &[ProvenSample],
    ) -> Result<CheckedChain, SampleError> {
        if !matches!(self.settings.check, HeaderCheck::Sampled { .. }) {
            return Err(SampleError::Mode);
        }
        if points.len() != samples.len() || points.len() as u64 != self.required_samples(tail) {
            return Err(SampleError::Count);
        }
        let mut seen = Vec::with_capacity(samples.len());
        for (index, (&point, sample)) in points.iter().zip(samples).enumerate() {
            if point >= tail.tail_start_work {
                return Err(SampleError::Point { index });
            }
            let refuse = |fault| SampleError::Sample { index, fault };
            let header = self.check_header(&tail.root, tail.leaf_count, sample).map_err(refuse)?;
            let start = header.position.work_before;
            if point < start || point - start >= header.work {
                return Err(refuse(Fault::WorkRange));
            }
            seen.push(header);
        }
        let headers: Vec<&[u8]> = samples.iter().map(|sample| sample.header.header.as_slice()).collect();
        self.check_seals(&seen, &headers)
            .map_err(|(index, e)| SampleError::Sample { index, fault: Fault::Seal(e) })?;
        Ok(CheckedChain {
            tip_hash: tail.tip_hash,
            tip_height: tail.tip_height,
            credited_work: tail.tail_work(),
            claimed_prefix_work: tail.tail_start_work,
            checked_before_tail: samples.len() as u64,
        })
    }

    /// The full check, kept as an option: every header from genesis below the
    /// tail, in order, is checked as [`HeaderChain`] checks it (parent,
    /// number, timestamp, difficulty, seal under the key block on its own
    /// branch), the tail's headers follow them, and the mountain range built
    /// from all of them must be the tail's root. The work of every header is
    /// credited. The tail's seals were checked
    /// by [`check_tail`](Self::check_tail) and are not hashed again. The
    /// sampler's own RandomX caches are dropped first.
    pub fn check_every_header(
        &mut self,
        tail: &CheckedTail,
        below_tail: &[Vec<u8>],
        now: u64,
    ) -> Result<CheckedChain, SampleError> {
        let count = tail.leaf_count - tail.headers.len() as u64;
        if below_tail.len() as u64 != count {
            return Err(SampleError::FullCount);
        }
        self.caches.clear();
        let mut all = below_tail.iter().chain(&tail.headers);
        let first = all.next().expect("the chain has a header");
        if keccak256(first) != self.genesis_hash {
            return Err(SampleError::FullGenesis);
        }
        let mut chain = HeaderChain::from_genesis(&self.genesis, self.chain).map_err(SampleError::Start)?;
        let mut leaves = Vec::with_capacity(tail.leaf_count as usize);
        leaves.push(MmrNode::leaf(&self.genesis_hash, u128::from(self.chain.start_difficulty)));
        for (height, header) in (1u64..).zip(all) {
            let added =
                if height < count { chain.add_header(header, now) } else { chain.add_saved_header(header, now) };
            match added {
                Ok(Added::Extended) => {}
                Ok(_) => return Err(SampleError::FullNotLinear { height }),
                Err(error) => return Err(SampleError::Full { height, error }),
            }
            // Adopted, so it decodes and carries the required difficulty.
            let fields = header_fields(header).map_err(|e| SampleError::Full { height, error: ChainError::Header(e) })?;
            let work = U256::from_be_bytes(&fields.difficulty).and_then(to_u128);
            let work = work.ok_or(SampleError::Full { height, error: ChainError::WorkOverflow })?;
            leaves.push(MmrNode::leaf(&fields.hash, work));
        }
        if root_of_leaves(&leaves) != Some(tail.root) {
            return Err(SampleError::FullRoot);
        }
        // Every header was linked and checked, and the root is built from
        // their leaves, so their whole work is credited.
        let credited_work = leaves.iter().try_fold(0u128, |sum, leaf| sum.checked_add(leaf.work));
        let credited_work = credited_work.ok_or(SampleError::FullRoot)?;
        Ok(CheckedChain {
            tip_hash: tail.tip_hash,
            tip_height: tail.tip_height,
            credited_work,
            claimed_prefix_work: 0,
            checked_before_tail: count,
        })
    }

    /// Every check of one header but its seal: it decodes, a header at
    /// height 0 is the genesis header, any other carries the difficulty the
    /// rule requires and has its key block, and its leaf (hash and work) has
    /// a path to `root` at its height.
    fn check_header(&self, root: &[u8; 32], leaf_count: u64, sample: &ProvenSample) -> Result<Seen, Fault> {
        let fields = header_fields(&sample.header.header).map_err(Fault::Header)?;
        let difficulty = if fields.number == 0 {
            if fields.hash != self.genesis_hash {
                return Err(Fault::Genesis);
            }
            U256::from(self.chain.start_difficulty)
        } else {
            self.required(&fields).ok_or(Fault::Difficulty)?
        };
        let work = to_u128(difficulty).ok_or(Fault::Difficulty)?;
        if sample.header.path.leaf_count != leaf_count {
            return Err(Fault::Path(PathError::LeafCount));
        }
        let position =
            verify_mmr_path(root, fields.number, &MmrNode::leaf(&fields.hash, work), &sample.header.path)
                .map_err(Fault::Path)?;
        let key = if fields.number == 0 {
            None
        } else {
            Some(self.check_key_block(root, leaf_count, fields.number, sample.key_block.as_ref())?)
        };
        Ok(Seen { fields, work, difficulty, position, key })
    }

    /// The difficulty the rule requires of a header, if it carries exactly
    /// that and its timestamp is in range.
    fn required(&self, fields: &HeaderFields) -> Option<U256> {
        if fields.timestamp >= TIMESTAMP_LIMIT {
            return None;
        }
        let required = required_difficulty(&self.chain, self.genesis_timestamp, fields.number, fields.timestamp);
        (U256::from_be_bytes(&fields.difficulty) == Some(required)).then_some(required)
    }

    /// The hash of the key block of the header at `height`, checked: it is
    /// at the seed height, it is the genesis header there or carries the
    /// required difficulty, and its leaf has a path to `root` at that height.
    fn check_key_block(
        &self,
        root: &[u8; 32],
        leaf_count: u64,
        height: u64,
        key_block: Option<&ProvenHeader>,
    ) -> Result<[u8; 32], Fault> {
        let key_block = key_block.ok_or(Fault::MissingKeyBlock)?;
        let fields = header_fields(&key_block.header).map_err(Fault::KeyBlockHeader)?;
        let seed = seed_height(height);
        if fields.number != seed {
            return Err(Fault::KeyBlockHeight);
        }
        let difficulty = if seed == 0 {
            if fields.hash != self.genesis_hash {
                return Err(Fault::KeyBlockGenesis);
            }
            U256::from(self.chain.start_difficulty)
        } else {
            self.required(&fields).ok_or(Fault::KeyBlockDifficulty)?
        };
        let work = to_u128(difficulty).ok_or(Fault::KeyBlockDifficulty)?;
        if key_block.path.leaf_count != leaf_count {
            return Err(Fault::KeyBlockPath(PathError::LeafCount));
        }
        verify_mmr_path(root, seed, &MmrNode::leaf(&fields.hash, work), &key_block.path)
            .map_err(Fault::KeyBlockPath)?;
        Ok(fields.hash)
    }

    /// The seals of `seen` (with their RLP in `headers`), grouped by seed
    /// height so each key's cache is built once; the first refusal by its
    /// index.
    fn check_seals(&mut self, seen: &[Seen], headers: &[&[u8]]) -> Result<(), (usize, SealError)> {
        let mut order: Vec<usize> = (0..seen.len()).filter(|&i| seen[i].key.is_some()).collect();
        order.sort_by_key(|&i| (seed_height(seen[i].fields.number), i));
        for i in order {
            let key = seen[i].key.expect("filtered");
            self.seal(headers[i], seen[i].fields.hash, &seen[i].difficulty, key).map_err(|e| (i, e))?;
        }
        Ok(())
    }

    fn seal(&mut self, header: &[u8], hash: [u8; 32], difficulty: &U256, key: [u8; 32]) -> Result<(), SealError> {
        if let Some(result) = self.seals.get(&(hash, key)) {
            return *result;
        }
        let result = verify_seal(header, &difficulty.to_be_bytes(), self.seal_key(key));
        if self.seals.len() >= SEAL_MEMO_LIMIT {
            self.seals.clear();
        }
        self.seals.insert((hash, key), result);
        result
    }

    /// The cache for `key`, built if it is not held; the least recently used
    /// is dropped first when two are held.
    fn seal_key(&mut self, key: [u8; 32]) -> &SealKey {
        if let Some(index) = self.caches.iter().position(|(held, _)| *held == key) {
            let entry = self.caches.remove(index);
            self.caches.insert(0, entry);
        } else {
            self.caches.truncate(MAX_CACHES - 1);
            self.caches.insert(0, (key, SealKey::new(&key)));
        }
        &self.caches[0].1
    }
}
