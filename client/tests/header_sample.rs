//! The sampled header-chain check of `header_sample` (docs/scale/stage2-design.md,
//! "Wallet restore volume", step 2).
//!
//! The headers and the Merkle mountain range are built here, apart from the
//! library: a test-side RLP encoder and a test-side tree over 48-byte nodes.
//!
//! The chains are cheap to seal and to check. The genesis header carries the
//! start difficulty, 4096, as its work, and is trusted by its hash, so it
//! stands for a long honest history that costs no RandomX hash. Every other
//! honest header is stamped 13 half-lives behind the schedule, where the rule
//! requires difficulty 1 (`D_MIN`), so any nonce seals it. The attacker's
//! invalid stretch is a header stamped 9 half-lives behind, where the rule
//! requires difficulty 8, with a nonce whose hash misses that target: it
//! claims 8 of work it never did. The tail is 4 headers, not the design's 64,
//! to keep the RandomX hashes few; the sampler takes the tail length as a
//! setting.
//!
//! Each RandomX cache takes 256 MiB, so the tests that build one run one at a
//! time.

use std::sync::{Mutex, MutexGuard};

use ghost_client::header_chain::{required_difficulty, ChainError, ChainParams};
use ghost_client::header_sample::{
    bits_per_sample, draw_point, mmr_root, sample_count, verify_mmr_path, CheckedTail, Fault, HeaderCheck,
    HeaderSampler, MmrNode, MmrPath, PathError, ProvenHeader, ProvenSample, Request, SampleError, SampleSettings,
    MMR_NODE_BYTES, TAIL_HEADERS,
};
use ghost_client::seal::{seed_height, SealError};
use rand::rngs::StdRng;
use rand::SeedableRng;
use tiny_keccak::{Hasher, Keccak};

const DESIGN: &str = include_str!("../../docs/scale/stage2-design.md");

/// The test chain: the 30-second chain's block time, half-life and drift,
/// a start difficulty of 4096 and a floor of 1.
const CHAIN: ChainParams =
    ChainParams { block_time: 30, half_life: 3600, start_difficulty: 4096, min_difficulty: 1, future_drift: 30 };
const GENESIS_TIME: u64 = 0x6abd_a280;
/// A clock well after every test header.
const LATER: u64 = GENESIS_TIME + 1_000_000_000;
const TAIL: u64 = 4;
/// Behind the schedule by 13 half-lives: difficulty 1.
const SLOW: u64 = 13 * 3600;
/// Behind the schedule by 9 half-lives: difficulty 8.
const INVALID_LAG: u64 = 9 * 3600;
/// Honest headers after genesis that both branches share.
const PREFIX: u64 = 3;
/// The height of the first header after the fork.
const FORK: u64 = PREFIX + 1;

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

// ---------------------------------------------------------------------------
// Headers.

fn int(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    bytes[first..].to_vec()
}

fn rlp_length(len: usize, base: u8) -> Vec<u8> {
    if len < 56 {
        return vec![base + len as u8];
    }
    let digits = int(len as u64);
    let mut out = vec![base + 55 + digits.len() as u8];
    out.extend(digits);
    out
}

fn rlp_list(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for field in fields {
        if field.len() == 1 && field[0] < 0x80 {
            payload.push(field[0]);
        } else {
            payload.extend(rlp_length(field.len(), 0x80));
            payload.extend(field);
        }
    }
    let mut out = rlp_length(payload.len(), 0xc0);
    out.extend(payload);
    out
}

/// A header under construction. `branch` goes into the coinbase so that
/// headers of two branches at the same height differ; `mix` is the first
/// byte of `mixDigest`, zero in a valid seal.
#[derive(Clone)]
struct Draft {
    parent: [u8; 32],
    number: u64,
    timestamp: u64,
    difficulty: u64,
    nonce: u64,
    branch: u8,
    mix: u8,
}

impl Draft {
    fn rlp(&self) -> Vec<u8> {
        let mut coinbase = vec![0u8; 20];
        coinbase[19] = self.branch;
        let mut mix = vec![0u8; 32];
        mix[0] = self.mix;
        rlp_list(&[
            self.parent.to_vec(),
            vec![0x1d; 32],
            coinbase,
            vec![0x11; 32],
            vec![0x22; 32],
            vec![0x33; 32],
            vec![0; 256],
            int(self.difficulty),
            int(self.number),
            int(30_000_000),
            int(0),
            int(self.timestamp),
            vec![],
            mix,
            self.nonce.to_be_bytes().to_vec(),
            int(1_000_000_000),
            vec![0x44; 32],
            vec![0x55; 32],
            vec![0x66; 32],
        ])
    }

    fn hash(&self) -> [u8; 32] {
        keccak(&self.rlp())
    }
}

fn genesis() -> Draft {
    Draft { parent: [0; 32], number: 0, timestamp: GENESIS_TIME, difficulty: 4096, nonce: 0, branch: 0, mix: 0 }
}

fn required(number: u64, timestamp: u64) -> u64 {
    let be = required_difficulty(&CHAIN, GENESIS_TIME, number, timestamp).to_be_bytes();
    assert!(be[..24].iter().all(|&b| b == 0), "a test difficulty fits in 8 bytes");
    u64::from_be_bytes(be[24..].try_into().unwrap())
}

/// A header at `number` on `branch`, `lag` seconds behind its place on the
/// schedule, with the difficulty the rule requires there.
fn stamped(parent: [u8; 32], number: u64, branch: u8, lag: u64) -> Draft {
    let timestamp = GENESIS_TIME + 30 * number + lag;
    Draft { parent, number, timestamp, difficulty: required(number, timestamp), nonce: 0, branch, mix: 0 }
}

fn extend(headers: &mut Vec<Draft>, branch: u8, count: u64) {
    for _ in 0..count {
        let last = headers.last().unwrap();
        let next = stamped(last.hash(), last.number + 1, branch, SLOW);
        assert_eq!(next.difficulty, 1);
        headers.push(next);
    }
}

/// Genesis and the headers both branches share.
fn prefix() -> Vec<Draft> {
    let mut headers = vec![genesis()];
    extend(&mut headers, 0, PREFIX);
    headers
}

/// The honest chain: the prefix, then 16 sealed headers after the fork.
fn honest() -> Vec<Draft> {
    let mut headers = prefix();
    extend(&mut headers, 1, 16);
    headers
}

/// The attacker's chain: the prefix, then one header claiming difficulty 8
/// sealed with `nonce` (the invalid stretch when the nonce misses), then 8
/// headers it did seal, the tail among them. Its valid work after the fork
/// is 8, half the honest 16, and it claims as much work as the honest chain.
fn attacker(nonce: u64) -> Vec<Draft> {
    let mut headers = prefix();
    let mut unsealed = stamped(headers.last().unwrap().hash(), FORK, 2, INVALID_LAG);
    assert_eq!(unsealed.difficulty, 8);
    unsealed.nonce = nonce;
    headers.push(unsealed);
    extend(&mut headers, 2, 8);
    headers
}

// ---------------------------------------------------------------------------
// The mountain range, built here.

fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(&[tag.len() as u8]);
    hasher.update(tag.as_bytes());
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn bytes(node: &MmrNode) -> Vec<u8> {
    let mut out = node.hash.to_vec();
    out.extend(node.work.to_be_bytes());
    out
}

fn leaf(hash: &[u8; 32], work: u128) -> MmrNode {
    MmrNode { hash: tagged("ghost/header-mmr-leaf/v1", &[hash, &work.to_be_bytes()]), work }
}

fn join(left: &MmrNode, right: &MmrNode) -> MmrNode {
    MmrNode { hash: tagged("ghost/header-mmr-node/v1", &[&bytes(left), &bytes(right)]), work: left.work + right.work }
}

struct Tree {
    leaves: Vec<MmrNode>,
}

impl Tree {
    fn count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// (first leaf, height) of each mountain, left to right.
    fn mountains(&self) -> Vec<(u64, u32)> {
        let mut out = Vec::new();
        let mut start = 0;
        for height in (0..64u32).rev() {
            if self.count() >> height & 1 == 1 {
                out.push((start, height));
                start += 1 << height;
            }
        }
        out
    }

    fn node(&self, start: u64, height: u32) -> MmrNode {
        if height == 0 {
            return self.leaves[start as usize];
        }
        let half = 1u64 << (height - 1);
        join(&self.node(start, height - 1), &self.node(start + half, height - 1))
    }

    fn peaks(&self) -> Vec<MmrNode> {
        self.mountains().into_iter().map(|(start, height)| self.node(start, height)).collect()
    }

    fn root(&self) -> [u8; 32] {
        let peaks = self.peaks();
        let mut bagged = *peaks.last().unwrap();
        for peak in peaks.iter().rev().skip(1) {
            bagged = join(peak, &bagged);
        }
        tagged("ghost/header-mmr-root/v1", &[&self.count().to_be_bytes(), &bytes(&bagged)])
    }

    fn path(&self, index: u64) -> MmrPath {
        let mountains = self.mountains();
        let which = mountains.iter().position(|&(start, height)| index < start + (1 << height)).unwrap();
        let (start, height) = mountains[which];
        let offset = index - start;
        let siblings = (0..height)
            .map(|level| self.node(start + (((offset >> level) ^ 1) << level), level))
            .collect();
        let peaks = mountains
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != which)
            .map(|(_, &(start, height))| self.node(start, height))
            .collect();
        MmrPath { leaf_count: self.count(), siblings, peaks }
    }

    fn work_before(&self, index: u64) -> u128 {
        self.leaves[..index as usize].iter().map(|leaf| leaf.work).sum()
    }

    fn total(&self) -> u128 {
        self.work_before(self.count())
    }
}

/// A chain of real headers with its tree, its paths and a server that
/// answers points.
struct Chain {
    rlp: Vec<Vec<u8>>,
    tree: Tree,
    paths: Vec<MmrPath>,
    root: [u8; 32],
}

impl Chain {
    fn new(headers: &[Draft]) -> Self {
        let leaves = headers.iter().map(|h| leaf(&h.hash(), u128::from(h.difficulty))).collect();
        Self::with_leaves(headers, leaves)
    }

    /// The headers under a tree of the given leaves, which may lie about them.
    fn with_leaves(headers: &[Draft], leaves: Vec<MmrNode>) -> Self {
        let tree = Tree { leaves };
        let paths = (0..tree.count()).map(|i| tree.path(i)).collect();
        let root = tree.root();
        Self { rlp: headers.iter().map(Draft::rlp).collect(), tree, paths, root }
    }

    fn count(&self) -> u64 {
        self.tree.count()
    }

    fn proven(&self, height: u64) -> ProvenHeader {
        ProvenHeader { header: self.rlp[height as usize].clone(), path: self.paths[height as usize].clone() }
    }

    fn sample(&self, height: u64) -> ProvenSample {
        ProvenSample { header: self.proven(height), key_block: (height > 0).then(|| self.proven(seed_height(height))) }
    }

    fn tail(&self) -> Vec<ProvenSample> {
        (self.count() - TAIL..self.count()).map(|h| self.sample(h)).collect()
    }

    /// The header before the tail, which the tail's first must extend.
    fn before_tail(&self) -> ProvenSample {
        self.sample(self.count() - TAIL - 1)
    }

    /// The tail and the header before it, checked against the root.
    fn check_tail(&self, sampler: &mut HeaderSampler, now: u64) -> Result<CheckedTail, SampleError> {
        sampler.check_tail(&self.root, Some(&self.before_tail()), &self.tail(), now)
    }

    fn at(&self, height: u64) -> u128 {
        self.tree.work_before(height)
    }

    /// The height whose work covers `point`.
    fn height_at(&self, point: u128) -> u64 {
        let mut before = 0;
        for (height, leaf) in self.tree.leaves.iter().enumerate() {
            if point < before + leaf.work {
                return height as u64;
            }
            before += leaf.work;
        }
        panic!("the point is past the chain's work");
    }

    fn answer(&self, points: &[u128]) -> Vec<ProvenSample> {
        points.iter().map(|&point| self.sample(self.height_at(point))).collect()
    }
}

fn settings(attacker_ratio: f64, assurance_bits: f64) -> SampleSettings {
    SampleSettings { tail_headers: TAIL, check: HeaderCheck::Sampled { attacker_ratio, assurance_bits } }
}

fn sampler(settings: SampleSettings) -> HeaderSampler {
    HeaderSampler::new(&genesis().rlp(), CHAIN, settings).unwrap()
}

fn points(request: Request) -> Vec<u128> {
    match request {
        Request::Points(points) => points,
        other => panic!("expected points, got {other:?}"),
    }
}

fn fault(result: Result<impl std::fmt::Debug, SampleError>) -> Fault {
    match result {
        Err(SampleError::Sample { index: 0, fault }) => fault,
        other => panic!("expected sample 0 refused, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The formula and the design page.

/// The page's table of bits a sample against the attacker's ratio at one
/// year of chain: `delta` is 64 headers of 2,880 a day for 365 days, and the
/// assurance column is the 599 samples the 64-bit target needs at half the
/// honest work.
#[test]
fn bits_per_sample_matches_the_design_table() {
    let start = DESIGN.find("| Attacker's valid work against the honest chain's").expect("the table");
    let rows: Vec<Vec<&str>> = DESIGN[start..]
        .lines()
        .skip(2)
        .take_while(|line| line.starts_with('|'))
        .map(|line| line.trim_matches('|').split('|').map(str::trim).collect())
        .collect();
    assert_eq!(rows.len(), 4);
    let year = TAIL_HEADERS as f64 / (2880.0 * 365.0);
    let samples = sample_count(0.5, 64.0, year).unwrap();
    assert_eq!(samples, 599);
    for (row, ratio) in rows.iter().zip([0.25, 0.5, 0.75, 0.9]) {
        assert_eq!(row[0], format!("{ratio:.2} (modeled)"));
        let bits = bits_per_sample(ratio, year);
        assert_eq!(row[1], format!("{bits:.4}"), "ratio {ratio}");
        assert_eq!(row[2], format!("{:.1} bits", samples as f64 * bits), "ratio {ratio}");
    }
    // Step 2 of the page: 599 samples at one year, 702 at five.
    assert!(DESIGN.contains("599 samples at one year of chain, 702 at five"));
    assert_eq!(sample_count(0.5, 64.0, year / 5.0), Some(702));
}

#[test]
fn sample_count_follows_the_ratio_and_the_target() {
    let year = 64.0 / (2880.0 * 365.0);
    let base = sample_count(0.5, 64.0, year).unwrap();
    assert!(sample_count(0.5, 128.0, year).unwrap() > base);
    assert!(sample_count(0.5, 32.0, year).unwrap() < base);
    assert!(sample_count(0.75, 64.0, year).unwrap() > base);
    assert!(sample_count(0.25, 64.0, year).unwrap() < base);
    // Each count is the least that reaches the target.
    for (ratio, bits) in [(0.25, 64.0), (0.5, 64.0), (0.75, 26.0), (0.9, 9.4), (0.5, 2.0)] {
        let count = sample_count(ratio, bits, year).unwrap() as f64;
        let per = bits_per_sample(ratio, year);
        assert!(count * per >= bits && (count - 1.0) * per < bits, "{ratio} {bits}");
    }
    // The tail is the whole chain: nothing to sample. One sample always hits
    // when the ratio is at most delta.
    assert_eq!(sample_count(0.5, 64.0, 1.0), Some(0));
    assert_eq!(sample_count(0.001, 64.0, 0.01), Some(1));
    assert_eq!(bits_per_sample(0.001, 0.01), f64::INFINITY);
    for (ratio, bits, delta) in [
        (0.0, 64.0, year),
        (1.0, 64.0, year),
        (-0.5, 64.0, year),
        (f64::NAN, 64.0, year),
        (0.5, 0.0, year),
        (0.5, -1.0, year),
        (0.5, f64::INFINITY, year),
        (0.5, f64::NAN, year),
        (0.5, 64.0, 0.0),
    ] {
        assert_eq!(sample_count(ratio, bits, delta), None, "{ratio} {bits} {delta}");
    }

    let design = SampleSettings::sampled(0.5, 64.0);
    assert_eq!(design.tail_headers, 64);
    assert_eq!(TAIL_HEADERS, 64);
    assert!(design.is_valid() && SampleSettings::full().is_valid());
    for bad in [settings(1.0, 64.0), settings(0.5, 0.0), SampleSettings { tail_headers: 0, ..design }] {
        assert!(!bad.is_valid());
        assert!(matches!(HeaderSampler::new(&genesis().rlp(), CHAIN, bad), Err(SampleError::Settings)));
    }
    let not_genesis = stamped([1; 32], 1, 0, SLOW).rlp();
    assert!(matches!(
        HeaderSampler::new(&not_genesis, CHAIN, design),
        Err(SampleError::Start(ghost_client::StartError::NotGenesis))
    ));
}

/// The points follow the density `1 / ((1 - x) ln(1/delta))`: the share
/// below `x` is `ln(1/(1 - x)) / ln(1/delta)`. They come from the caller's
/// generator alone.
#[test]
fn points_follow_the_density_from_the_callers_generator() {
    let total: u128 = 1_000_000;
    let tail_start: u128 = 999_000;
    let delta = (total - tail_start) as f64 / total as f64;
    let mut rng = StdRng::seed_from_u64(0xd5);
    let draws = 40_000;
    let points: Vec<u128> = (0..draws).map(|_| draw_point(&mut rng, tail_start, total).unwrap()).collect();
    assert!(points.iter().all(|&p| p < tail_start));
    for x in [0.25, 0.5, 0.9, 0.99, 0.998] {
        let below = points.iter().filter(|&&p| (p as f64) < x * total as f64).count() as f64 / draws as f64;
        let expected = (1.0 / (1.0 - x)).ln() / (1.0 / delta).ln();
        let sigma = (expected * (1.0 - expected) / draws as f64).sqrt();
        assert!((below - expected).abs() < 5.0 * sigma + 1e-3, "x {x}: {below} against {expected}");
    }

    let draw = |seed| -> Vec<u128> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..16).map(|_| draw_point(&mut rng, tail_start, total).unwrap()).collect()
    };
    assert_eq!(draw(7), draw(7));
    assert_ne!(draw(7), draw(8));
    assert_eq!(draw_point(&mut rng, 0, total), None);
    assert_eq!(draw_point(&mut rng, total, total), None);
}

/// The library's nodes, root and paths agree with the tree built here, and
/// a path gives the work before its leaf and the total.
#[test]
fn mountain_range_paths_give_each_leafs_work() {
    let leaves: Vec<MmrNode> =
        (0..13u8).map(|i| leaf(&[i; 32], u128::from(i) * 1000 + 1)).collect();
    let tree = Tree { leaves: leaves.clone() };
    assert_eq!(MmrNode::leaf(&[3; 32], 3001), leaves[3]);
    assert_eq!(MmrNode::parent(&leaves[0], &leaves[1]), Some(join(&leaves[0], &leaves[1])));
    assert_eq!(MmrNode::parent(&MmrNode { hash: [0; 32], work: u128::MAX }, &leaves[1]), None);
    assert_eq!(MmrNode::from_bytes(&leaves[5].to_bytes()), leaves[5]);
    assert_eq!(leaves[5].to_bytes().len(), MMR_NODE_BYTES);
    assert_eq!(leaves[5].to_bytes().to_vec(), bytes(&leaves[5]));
    assert_eq!(mmr_root(13, &tree.peaks()), Some(tree.root()));
    assert_eq!(mmr_root(12, &tree.peaks()), None);

    let root = tree.root();
    for index in 0..13 {
        let position = verify_mmr_path(&root, index, &leaves[index as usize], &tree.path(index)).unwrap();
        assert_eq!(position.work_before, tree.work_before(index));
        assert_eq!(position.total_work, tree.total());
    }
    assert_eq!(verify_mmr_path(&root, 13, &leaves[0], &tree.path(0)), Err(PathError::Index));
    assert_eq!(verify_mmr_path(&root, 4, &leaves[3], &tree.path(4)), Err(PathError::Root));
    assert_eq!(verify_mmr_path(&root, 12, &leaves[12], &tree.path(4)), Err(PathError::Shape));
}

// ---------------------------------------------------------------------------
// The sampler on real headers.

/// The attacker's chain with a nonce that leaves its claimed header unsealed,
/// found by asking the sampler: its tail checked, and the stretch's seal
/// refused as above the target.
fn unsealed_attacker(sampler: &mut HeaderSampler) -> (Chain, CheckedTail) {
    for nonce in 0..64 {
        let chain = Chain::new(&attacker(nonce));
        let tail = chain.check_tail(sampler, LATER).expect("the attacker's tail is sealed");
        let count = sampler.required_samples(&tail) as usize;
        let result = sampler.check_samples(&tail, &vec![chain.at(FORK); count], &vec![chain.sample(FORK); count]);
        match result {
            Err(SampleError::Sample { fault: Fault::Seal(SealError::AboveTarget), .. }) => return (chain, tail),
            Ok(_) => continue,
            Err(other) => panic!("unexpected refusal: {other}"),
        }
    }
    panic!("every nonce sealed the claimed header");
}

/// The forked chain is caught exactly when a sample lands in its invalid
/// stretch, at the rate the density gives: per sample the stretch's mass
/// `ln((1 - a) / (1 - b)) / ln(1/delta)`, which is the bound
/// `ln(1/c) / ln(1/delta)` for a stretch right after the fork, and per proof
/// `1 - (1 - mass)^m`, at least `1 - 2^-bits` for the configured target.
#[test]
fn sampler_catches_a_forked_invalid_stretch_at_the_stated_rate() {
    let _one = one_at_a_time();
    let bits = 2.0;
    let mut sampler = sampler(settings(0.5, bits));
    let (chain, tail) = unsealed_attacker(&mut sampler);
    let honest = Chain::new(&honest());

    // The attacker claims the honest chain's work with half its valid work.
    let total = tail.total_work();
    assert_eq!(total, honest.tree.total());
    assert_eq!(tail.leaf_count(), chain.count());
    let honest_after_fork = (honest.tree.total() - honest.at(FORK)) as f64;
    let (start, end) = (chain.at(FORK), chain.at(FORK + 1));
    assert_eq!(end - start, 8);
    let ratio = (total - end) as f64 / honest_after_fork;
    assert_eq!(ratio, 0.5);

    let delta = tail.delta();
    assert_eq!(delta, TAIL as f64 / total as f64);
    let bound = (1.0 / ratio).ln() / (1.0 / delta).ln();
    let mass = ((total - start) as f64 / (total - end) as f64).ln() / (1.0 / delta).ln();
    assert!(mass >= bound - 1e-12, "{mass} against the bound {bound}");
    let count = sampler.required_samples(&tail);
    assert_eq!(Some(count), sample_count(0.5, bits, delta));
    assert_eq!(count as f64, (bits / bits_per_sample(0.5, delta)).ceil());
    let expected = 1.0 - (1.0 - mass).powi(count as i32);
    assert!(expected >= 1.0 - 2f64.powf(-bits));

    let seeds = 2000u64;
    let (mut caught, mut hits) = (0u64, 0u64);
    for seed in 0..seeds {
        let points = points(sampler.request(&tail, &mut StdRng::seed_from_u64(seed)));
        assert_eq!(points.len() as u64, count);
        let in_stretch = |p: u128| start <= p && p < end;
        let landed = points.iter().filter(|&&p| in_stretch(p)).count() as u64;
        hits += landed;
        match sampler.check_samples(&tail, &points, &chain.answer(&points)) {
            Ok(checked) => {
                assert_eq!(landed, 0, "seed {seed}: a sample hit the stretch and passed: {checked:?}");
                // A pass credits the linked tail alone, not the claimed work.
                assert_eq!(checked.credited_work, tail.tail_work());
                assert_eq!(checked.credited_work, TAIL.into());
                assert_eq!(checked.claimed_prefix_work, chain.at(chain.count() - TAIL));
                assert_eq!(checked.credited_work + checked.claimed_prefix_work, total);
            }
            Err(SampleError::Sample { index, fault: Fault::Seal(SealError::AboveTarget) }) => {
                assert!(in_stretch(points[index]), "seed {seed}: refused outside the stretch");
                caught += 1;
            }
            Err(other) => panic!("seed {seed}: unexpected refusal: {other}"),
        }
    }

    let samples = (seeds * count) as f64;
    let per_sample = hits as f64 / samples;
    let sigma = (mass * (1.0 - mass) / samples).sqrt();
    assert!((per_sample - mass).abs() < 4.0 * sigma, "per sample {per_sample} against {mass}");
    let rate = caught as f64 / seeds as f64;
    let sigma = (expected * (1.0 - expected) / seeds as f64).sqrt();
    assert!((rate - expected).abs() < 4.0 * sigma, "caught {rate} against {expected}");
    assert!(rate >= 1.0 - 2f64.powf(-bits) - 4.0 * sigma, "caught {rate}");
}

#[test]
fn honest_chain_passes_with_the_wallets_own_points() {
    let _one = one_at_a_time();
    let mut sampler = sampler(settings(0.5, 2.0));
    let drafts = honest();
    let chain = Chain::new(&drafts);
    let tail = chain.check_tail(&mut sampler, LATER).unwrap();
    assert_eq!(tail.tip_hash(), drafts.last().unwrap().hash());
    assert_eq!(tail.tip_height(), 19);
    assert_eq!(tail.tail_start_work(), chain.at(16));
    assert_eq!(tail.headers().len() as u64, TAIL);
    let count = sampler.required_samples(&tail);
    for seed in [1, 2, 3] {
        let request = sampler.request(&tail, &mut StdRng::seed_from_u64(seed));
        assert_eq!(request, sampler.request(&tail, &mut StdRng::seed_from_u64(seed)));
        let points = points(request);
        let checked = sampler.check_samples(&tail, &points, &chain.answer(&points)).unwrap();
        assert_eq!(checked.tip_hash, tail.tip_hash());
        assert_eq!(checked.credited_work, chain.tree.total() - chain.at(16));
        assert_eq!(checked.credited_work, u128::from(TAIL));
        assert_eq!(checked.claimed_prefix_work, chain.at(16));
        assert_eq!(checked.checked_before_tail, count);
    }
    assert_ne!(
        sampler.request(&tail, &mut StdRng::seed_from_u64(1)),
        sampler.request(&tail, &mut StdRng::seed_from_u64(2))
    );
    // Fewer samples than the target requires are refused.
    assert_eq!(sampler.check_samples(&tail, &[], &[]), Err(SampleError::Count));
}

#[test]
fn bad_seal_wrong_key_block_and_bad_path_are_rejected() {
    let _one = one_at_a_time();
    // A target low enough for one sample, so each case is one header.
    let mut sampler = sampler(settings(0.5, 0.1));
    let drafts = honest();
    let chain = Chain::new(&drafts);
    let tail = chain.check_tail(&mut sampler, LATER).unwrap();
    assert_eq!(sampler.required_samples(&tail), 1);
    let mut check = |tail: &CheckedTail, point: u128, sample: ProvenSample| {
        sampler.check_samples(tail, &[point], &[sample])
    };
    let six = chain.at(6);
    assert!(check(&tail, six, chain.sample(6)).is_ok());
    assert!(check(&tail, chain.at(0), chain.sample(0)).is_ok());

    // Bad paths.
    let mut s = chain.sample(6);
    s.header.path.siblings[0].hash[0] ^= 1;
    assert_eq!(fault(check(&tail, six, s)), Fault::Path(PathError::Root));
    let mut s = chain.sample(6);
    s.header.path.siblings[1].work += 1;
    assert_eq!(fault(check(&tail, six, s)), Fault::Path(PathError::Root));
    let mut s = chain.sample(6);
    s.header.path.peaks[0].work -= 1;
    assert_eq!(fault(check(&tail, six, s)), Fault::Path(PathError::Root));
    let mut s = chain.sample(6);
    s.header.path.siblings.pop();
    assert_eq!(fault(check(&tail, six, s)), Fault::Path(PathError::Shape));
    let mut s = chain.sample(6);
    s.header.path.peaks.push(chain.tree.leaves[0]);
    assert_eq!(fault(check(&tail, six, s)), Fault::Path(PathError::Shape));
    let mut s = chain.sample(6);
    s.header.path = chain.paths[7].clone();
    assert_eq!(fault(check(&tail, six, s)), Fault::Path(PathError::Root));
    let mut s = chain.sample(6);
    s.header.path.leaf_count += 1;
    assert_eq!(fault(check(&tail, six, s)), Fault::Path(PathError::LeafCount));
    // A header the range does not hold, on the right path.
    let mut s = chain.sample(6);
    s.header.header = Draft { branch: 9, ..drafts[6].clone() }.rlp();
    assert_eq!(fault(check(&tail, six, s)), Fault::Path(PathError::Root));
    // A held header that does not cover the point.
    assert_eq!(fault(check(&tail, chain.at(7), chain.sample(6))), Fault::WorkRange);
    // A difficulty the rule does not require there.
    let mut s = chain.sample(6);
    s.header.header = Draft { difficulty: 2, ..drafts[6].clone() }.rlp();
    assert_eq!(fault(check(&tail, six, s)), Fault::Difficulty);
    assert_eq!(check(&tail, tail.tail_start_work(), chain.sample(16)), Err(SampleError::Point { index: 0 }));
    assert_eq!(sampler.check_samples(&tail, &[six, six], &[chain.sample(6), chain.sample(6)]), Err(SampleError::Count));
    let mut check = |tail: &CheckedTail, point: u128, sample: ProvenSample| {
        sampler.check_samples(tail, &[point], &[sample])
    };

    // Wrong key blocks.
    let mut s = chain.sample(6);
    s.key_block = None;
    assert_eq!(fault(check(&tail, six, s)), Fault::MissingKeyBlock);
    let mut s = chain.sample(6);
    s.key_block = Some(chain.proven(1));
    assert_eq!(fault(check(&tail, six, s)), Fault::KeyBlockHeight);
    let mut s = chain.sample(6);
    s.key_block = Some(ProvenHeader { header: Draft { branch: 9, ..genesis() }.rlp(), path: chain.paths[0].clone() });
    assert_eq!(fault(check(&tail, six, s)), Fault::KeyBlockGenesis);
    let mut s = chain.sample(6);
    s.key_block.as_mut().unwrap().path.peaks[0].hash[31] ^= 1;
    assert_eq!(fault(check(&tail, six, s)), Fault::KeyBlockPath(PathError::Root));
    let mut s = chain.sample(6);
    s.key_block.as_mut().unwrap().header = vec![0xc0];
    assert!(matches!(fault(check(&tail, six, s)), Fault::KeyBlockHeader(_)));
    // Height 0 must be the genesis header itself.
    let mut s = chain.sample(0);
    s.header.header = Draft { branch: 9, ..genesis() }.rlp();
    assert_eq!(fault(check(&tail, 0, s)), Fault::Genesis);

    // Bad seals. The range holds header 6 with a nonzero mix digest in place
    // of the sealed one; the rest of the chain, the tail included, is as it was.
    let mut mixed = drafts.clone();
    mixed[6].mix = 1;
    let bad = Chain::new(&mixed);
    let bad_tail = bad.check_tail(&mut sampler, LATER).unwrap();
    assert_eq!(
        fault(sampler.check_samples(&bad_tail, &[six], &[bad.sample(6)])),
        Fault::Seal(SealError::MixDigestNotZero)
    );
    // Header 6 stamped 9 half-lives behind, claiming difficulty 8, with a
    // nonce whose hash misses the target.
    let mut refused = false;
    for nonce in 0..64 {
        let mut claimed = drafts.clone();
        claimed[6] = Draft { nonce, ..stamped(drafts[5].hash(), 6, 1, INVALID_LAG) };
        assert_eq!(claimed[6].difficulty, 8);
        let bad = Chain::new(&claimed);
        let bad_tail = bad.check_tail(&mut sampler, LATER).unwrap();
        match sampler.check_samples(&bad_tail, &[bad.at(6) + 7], &[bad.sample(6)]) {
            Ok(_) => continue,
            Err(e) => {
                assert_eq!(fault(Err::<(), _>(e)), Fault::Seal(SealError::AboveTarget));
                refused = true;
                break;
            }
        }
    }
    assert!(refused);

    // The tail: a bad path, a missing header, out of order, and a tip ahead
    // of the clock.
    let before = chain.before_tail();
    let mut t = chain.tail();
    t[1].header.path.siblings[0].hash[0] ^= 1;
    assert_eq!(
        sampler.check_tail(&chain.root, Some(&before), &t, LATER),
        Err(SampleError::Tail { index: 1, fault: Fault::Path(PathError::Root) })
    );
    let mut t = chain.tail();
    t.remove(0);
    assert_eq!(sampler.check_tail(&chain.root, Some(&before), &t, LATER), Err(SampleError::TailLength));
    let mut t = chain.tail();
    t.swap(1, 2);
    assert_eq!(
        sampler.check_tail(&chain.root, Some(&before), &t, LATER),
        Err(SampleError::Tail { index: 1, fault: Fault::Height })
    );
    assert_eq!(
        chain.check_tail(&mut sampler, GENESIS_TIME),
        Err(SampleError::Tail { index: 3, fault: Fault::TooFarAhead })
    );
    assert_eq!(sampler.check_tail(&chain.root, Some(&before), &[], LATER), Err(SampleError::TailLength));
}

/// A range of copied honest headers under a sealed tail mined on some other
/// parent. Every header in the range is a sealed leaf with its true work, so
/// any sample of the copied part passes; the tail's link to the leaf below it
/// is what refuses the range.
#[test]
fn copied_honest_headers_under_a_disconnected_tail_are_refused() {
    let _one = one_at_a_time();
    let mut sampler = sampler(settings(0.5, 2.0));
    let honest = honest();
    let first = honest.len() as u64 - TAIL;
    let copied = &honest[..first as usize];

    // The tail names a parent that is not the leaf below it.
    let mut forged = copied.to_vec();
    forged.push(stamped([0x77; 32], first, 3, SLOW));
    extend(&mut forged, 3, TAIL - 1);
    let chain = Chain::new(&forged);
    assert_eq!(chain.tree.total(), Chain::new(&honest).tree.total());
    assert_eq!(chain.check_tail(&mut sampler, LATER), Err(SampleError::Tail { index: 0, fault: Fault::Parent }));
    // Leaving out the header before the tail, or sending another leaf in
    // its place, does not get round the link.
    assert_eq!(sampler.check_tail(&chain.root, None, &chain.tail(), LATER), Err(SampleError::TailParentMissing));
    assert_eq!(
        sampler.check_tail(&chain.root, Some(&chain.sample(first - 2)), &chain.tail(), LATER),
        Err(SampleError::TailParent { fault: Fault::Height })
    );
    let mut stand_in = chain.before_tail();
    stand_in.header.header = Draft { branch: 9, ..copied[first as usize - 1].clone() }.rlp();
    assert_eq!(
        sampler.check_tail(&chain.root, Some(&stand_in), &chain.tail(), LATER),
        Err(SampleError::TailParent { fault: Fault::Path(PathError::Root) })
    );

    // The leaf below the tail replaced by the header the tail names, which
    // was never sealed: the header before the tail is checked in full.
    let mut unsealed = copied[..first as usize - 1].to_vec();
    unsealed.push(Draft { mix: 1, ..stamped(unsealed.last().unwrap().hash(), first - 1, 3, SLOW) });
    extend(&mut unsealed, 3, TAIL);
    let chain = Chain::new(&unsealed);
    assert_eq!(
        chain.check_tail(&mut sampler, LATER),
        Err(SampleError::TailParent { fault: Fault::Seal(SealError::MixDigestNotZero) })
    );

    // The tail's first header stamped no later than the header before it.
    let mut early = copied.to_vec();
    early.push(stamped(copied.last().unwrap().hash(), first, 3, SLOW - 30));
    assert_eq!(early[first as usize].timestamp, early[first as usize - 1].timestamp);
    extend(&mut early, 3, TAIL - 1);
    let chain = Chain::new(&early);
    assert_eq!(chain.check_tail(&mut sampler, LATER), Err(SampleError::Tail { index: 0, fault: Fault::Timestamp }));

    // A tail that does extend the copied headers is a fork of them, every
    // header after the fork sealed, and passes.
    let mut fork = copied.to_vec();
    extend(&mut fork, 3, TAIL);
    let chain = Chain::new(&fork);
    let tail = chain.check_tail(&mut sampler, LATER).unwrap();
    let points = points(sampler.request(&tail, &mut StdRng::seed_from_u64(5)));
    let checked = sampler.check_samples(&tail, &points, &chain.answer(&points)).unwrap();
    assert_eq!(checked.tip_hash, fork.last().unwrap().hash());
    assert_eq!(checked.credited_work, u128::from(TAIL));
    assert_eq!(checked.claimed_prefix_work, chain.at(first));

    // A tail that starts at genesis has no header before it, and is the
    // whole chain: all of its work is linked and credited.
    let mut short = vec![genesis()];
    extend(&mut short, 0, TAIL - 1);
    let chain = Chain::new(&short);
    let tail = sampler.check_tail(&chain.root, None, &chain.tail(), LATER).unwrap();
    assert_eq!(sampler.required_samples(&tail), 0);
    let checked = sampler.check_samples(&tail, &[], &[]).unwrap();
    assert_eq!(checked.credited_work, chain.tree.total());
    assert_eq!(checked.claimed_prefix_work, 0);
    assert_eq!(
        sampler.check_tail(&chain.root, Some(&chain.sample(0)), &chain.tail(), LATER),
        Err(SampleError::TailParent { fault: Fault::Height })
    );
}

/// The attack the link below the tail does not stop: copied honest leaves
/// through `H - 2`, a sealed replacement header at `H - 1` whose parent is
/// not the leaf at `H - 2`, then a sealed tail from `H` linked to it. Every
/// header the sampled check can see is sealed and on its path, so it passes,
/// but it credits only the tail's work; the copied work comes back as the
/// unauthenticated claimed prefix. The full check refuses the range at the
/// replacement.
#[test]
fn copied_leaves_under_a_sealed_replacement_credit_only_the_tail() {
    let _one = one_at_a_time();
    let honest_drafts = honest();
    let honest = Chain::new(&honest_drafts);
    let first = honest.count() - TAIL;
    let mut forged = honest_drafts[..first as usize - 1].to_vec();
    let replacement = stamped([0x77; 32], first - 1, 4, SLOW);
    assert_ne!(replacement.parent, forged.last().unwrap().hash());
    assert_eq!(replacement.difficulty, 1);
    forged.push(replacement);
    extend(&mut forged, 4, TAIL);
    let chain = Chain::new(&forged);
    assert_eq!(chain.count(), honest.count());
    // The root claims the honest chain's whole work for the forged tip.
    assert_eq!(chain.tree.total(), honest.tree.total());
    assert_eq!(chain.tree.leaves[..first as usize - 1], honest.tree.leaves[..first as usize - 1]);

    let mut sampled = sampler(settings(0.5, 2.0));
    let tail = chain.check_tail(&mut sampled, LATER).expect("the replacement and the tail are sealed and linked");
    assert_eq!(tail.tip_hash(), forged.last().unwrap().hash());
    assert_eq!(tail.tail_work(), u128::from(TAIL));
    for seed in 0..64 {
        let points = points(sampled.request(&tail, &mut StdRng::seed_from_u64(seed)));
        let checked = sampled.check_samples(&tail, &points, &chain.answer(&points)).unwrap();
        assert_eq!(checked.tip_hash, forged.last().unwrap().hash());
        // Only the tail linked by parent hashes is credited, never more.
        assert_eq!(checked.credited_work, u128::from(TAIL));
        assert_eq!(checked.credited_work, tail.tail_work());
        assert!(checked.credited_work < chain.tree.total());
        // The copied work is returned apart, as claimed.
        assert_eq!(checked.claimed_prefix_work, honest.at(first));
        assert_eq!(checked.credited_work + checked.claimed_prefix_work, honest.tree.total());
    }

    let mut full = sampler(SampleSettings { tail_headers: TAIL, check: HeaderCheck::Full });
    let tail = chain.check_tail(&mut full, LATER).unwrap();
    assert_eq!(full.request(&tail, &mut StdRng::seed_from_u64(1)), Request::EveryHeader { count: first });
    assert_eq!(
        full.check_every_header(&tail, &chain.rlp[..first as usize], LATER),
        Err(SampleError::Full { height: first - 1, error: ChainError::UnknownParent })
    );
    // The honest chain under the same check is credited all of its work.
    let honest_tail = honest.check_tail(&mut full, LATER).unwrap();
    let checked = full.check_every_header(&honest_tail, &honest.rlp[..first as usize], LATER).unwrap();
    assert_eq!(checked.credited_work, honest.tree.total());
    assert_eq!(checked.claimed_prefix_work, 0);
}

/// Past the first epoch the key block is the chain's own leaf at the seed
/// height. Most leaves of this range are synthetic: only the headers the
/// proof shows are real.
#[test]
fn key_block_past_the_first_epoch_is_the_chains_own_leaf() {
    let _one = one_at_a_time();
    let count = 8471u64;
    let key = stamped([0x31; 32], 8192, 0, SLOW);
    let sampled = stamped([0x32; 32], 8460, 0, SLOW);
    // The header before the tail, then the tail extending it.
    let mut tail = vec![stamped([0x33; 32], count - TAIL - 1, 0, SLOW)];
    extend(&mut tail, 0, TAIL);
    assert_eq!(seed_height(sampled.number), 8192);
    assert!(tail.iter().all(|h| seed_height(h.number) == 8192));

    let mut real: Vec<(u64, Draft)> = vec![(0, genesis()), (8192, key.clone()), (8460, sampled.clone())];
    real.extend(tail.iter().map(|h| (h.number, h.clone())));
    let before = tail.remove(0);
    let leaves = (0..count)
        .map(|i| match real.iter().find(|(height, _)| *height == i) {
            Some((_, h)) => leaf(&h.hash(), u128::from(h.difficulty)),
            None => leaf(&tagged("synthetic leaf", &[&i.to_be_bytes()]), 1),
        })
        .collect();
    let tree = Tree { leaves };
    let root = tree.root();
    let proven = |draft: &Draft| ProvenHeader { header: draft.rlp(), path: tree.path(draft.number) };
    let sample = |draft: &Draft, key_block: ProvenHeader| ProvenSample {
        header: proven(draft),
        key_block: Some(key_block),
    };

    let mut sampler = sampler(settings(0.5, 0.1));
    let proof: Vec<ProvenSample> = tail.iter().map(|h| sample(h, proven(&key))).collect();
    let checked = sampler.check_tail(&root, Some(&sample(&before, proven(&key))), &proof, LATER).unwrap();
    assert_eq!(sampler.required_samples(&checked), 1);
    let point = tree.work_before(8460);
    let mut check = |key_block: ProvenHeader| sampler.check_samples(&checked, &[point], &[sample(&sampled, key_block)]);

    assert!(check(proven(&key)).is_ok());
    // Another header at the seed height, not the chain's leaf there.
    let other = Draft { branch: 9, ..key.clone() };
    assert_eq!(fault(check(proven(&other))), Fault::KeyBlockPath(PathError::Root));
    // The chain's key block on the path of its neighbour in the same
    // mountain, and on the path of a leaf in the mountain before.
    assert_eq!(
        fault(check(ProvenHeader { header: key.rlp(), path: tree.path(8193) })),
        Fault::KeyBlockPath(PathError::Root)
    );
    assert_eq!(
        fault(check(ProvenHeader { header: key.rlp(), path: tree.path(8191) })),
        Fault::KeyBlockPath(PathError::Shape)
    );
    // The key block of an earlier epoch.
    assert_eq!(fault(check(ProvenHeader { header: genesis().rlp(), path: tree.path(0) })), Fault::KeyBlockHeight);
    // A key block without the required difficulty.
    let heavy = Draft { difficulty: 2, ..key.clone() };
    assert_eq!(fault(check(proven(&heavy))), Fault::KeyBlockDifficulty);
}

/// The full check, kept as an option: every header below the tail goes
/// through the header chain's checks and the root is rebuilt from them, so
/// a root that lies about one header's work is refused, which sampling
/// alone need not see.
#[test]
fn full_check_option_checks_every_header() {
    let _one = one_at_a_time();
    let mut sampler = sampler(SampleSettings { tail_headers: TAIL, check: HeaderCheck::Full });
    let mut drafts = prefix();
    extend(&mut drafts, 1, 4);
    let chain = Chain::new(&drafts);
    let tail = chain.check_tail(&mut sampler, LATER).unwrap();
    assert_eq!(sampler.request(&tail, &mut StdRng::seed_from_u64(1)), Request::EveryHeader { count: 4 });
    assert_eq!(sampler.check_samples(&tail, &[], &[]), Err(SampleError::Mode));

    let below: Vec<Vec<u8>> = chain.rlp[..4].to_vec();
    let checked = sampler.check_every_header(&tail, &below, LATER).unwrap();
    assert_eq!(checked.tip_hash, drafts[7].hash());
    assert_eq!(checked.tip_height, 7);
    assert_eq!(checked.checked_before_tail, 4);
    assert_eq!(checked.credited_work, 4096 + 7);
    assert_eq!(checked.claimed_prefix_work, 0);

    assert_eq!(sampler.check_every_header(&tail, &below[..3], LATER), Err(SampleError::FullCount));
    let shifted = vec![below[1].clone(), below[1].clone(), below[2].clone(), below[3].clone()];
    assert_eq!(sampler.check_every_header(&tail, &shifted, LATER), Err(SampleError::FullGenesis));

    // The root claims 5 of work for header 2.
    let mut leaves = chain.tree.leaves.clone();
    leaves[2] = leaf(&drafts[2].hash(), 5);
    let lie = Chain::with_leaves(&drafts, leaves);
    let lie_tail = lie.check_tail(&mut sampler, LATER).unwrap();
    assert_eq!(sampler.check_every_header(&lie_tail, &below, LATER), Err(SampleError::FullRoot));

    // Header 2 with a nonzero mix digest.
    let mut mixed = drafts.clone();
    mixed[2].mix = 1;
    let bad = Chain::new(&mixed);
    let bad_tail = bad.check_tail(&mut sampler, LATER).unwrap();
    assert_eq!(
        sampler.check_every_header(&bad_tail, &bad.rlp[..4], LATER),
        Err(SampleError::Full { height: 2, error: ChainError::Seal(SealError::MixDigestNotZero) })
    );
}
