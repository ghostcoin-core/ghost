//! The written sampling bound for Ghost's difficulty rule
//! (docs/scale/stage2-design.md, "Written sampling bound for Ghost's
//! difficulty rule"), held against the client.
//!
//! - Lemma B: on the 30-second chain the difficulty the client's rule
//!   requires depends only on the header's lag behind the schedule, never
//!   rises as the lag grows, and is at most the page's `rho` times the
//!   difficulty 29 seconds of lag later, the most a child stamped after its
//!   parent can fall behind it. Every lag from past the difficulty floor to a
//!   difficulty of 2^81 is checked.
//! - The header proof bytes: the proof the client's sampler checks (each
//!   sample, the tail and the header before it as a `ProvenSample` with its
//!   key block, every path in the client's layout) on a chain of one and of
//!   five years at the target, every header on schedule at the start
//!   difficulty, with the wallet's points drawn by the client from seeded
//!   generators. Each header is spec 05's block-one example at its own height
//!   with every field of the stage 2 design (24 items, decision 0005), and its
//!   first 19 items decode with the client. The proof is counted two ways and
//!   held against the stage 2 model's bytes and the figures the page records.

use std::collections::BTreeSet;

use ghost_client::header_chain::{required_difficulty, ChainParams};
use ghost_client::header_sample::{
    draw_point, sample_count, verify_mmr_path, MmrNode, MmrPath, PathError, MMR_NODE_BYTES, TAIL_HEADERS,
};
use ghost_client::seal::{header_fields, seed_height};
use rand::rngs::StdRng;
use rand::SeedableRng;

const DESIGN: &str = include_str!("../../docs/scale/stage2-design.md");
const CHAIN: ChainParams = ChainParams::THIRTY_SECONDS;
/// The genesis timestamp under spec 05's block-one example, which is stamped
/// on schedule 30 seconds after it.
const GENESIS_TIME: u64 = 1_798_767_600;
const BLOCKS_PER_DAY: u64 = 2880;
const DAYS_PER_YEAR: u64 = 365;
/// The sampler's settings of the page: half the honest work, 64 bits.
const ATTACKER_RATIO: f64 = 0.5;
const ASSURANCE_BITS: f64 = 64.0;
/// The wallet generators whose proofs are counted; the page records the
/// largest count.
const SEEDS: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

// ---------------------------------------------------------------------------
// Lemma B.

/// The difficulty the client requires of a header `lag` seconds behind the
/// schedule (ahead of it when negative).
fn difficulty_at_lag(height: u64, lag: i64) -> u128 {
    let timestamp = GENESIS_TIME as i64 + CHAIN.block_time as i64 * height as i64 + lag;
    let be = required_difficulty(&CHAIN, GENESIS_TIME, height, timestamp as u64).to_be_bytes();
    assert!(be[..16].iter().all(|&b| b == 0), "a difficulty below 2^128");
    u128::from_be_bytes(be[16..].try_into().unwrap())
}

/// The page's `rho`, the most a header's difficulty exceeds its parent's.
fn page_rho() -> f64 {
    let marker = "`rho = ";
    let start = DESIGN.find(marker).expect("the page states rho") + marker.len();
    let end = start + DESIGN[start..].find('`').expect("rho is closed");
    DESIGN[start..end].parse().expect("rho is a number")
}

#[test]
fn difficulty_depends_only_on_the_lag() {
    for lag in [-200_000i64, -3_601, -29, 0, 1, 3_600, 30_000] {
        let at = difficulty_at_lag(1_000_000, lag);
        for height in [400_000u64, 1_051_200, 5_256_000] {
            assert_eq!(difficulty_at_lag(height, lag), at, "lag {lag} at height {height}");
        }
    }
    assert_eq!(difficulty_at_lag(1, 0), u128::from(CHAIN.start_difficulty));
    assert_eq!(difficulty_at_lag(7, -3_600), 2 * u128::from(CHAIN.start_difficulty));
}

#[test]
fn difficulty_rises_at_most_rho_from_a_header_to_its_child() {
    let rho = page_rho();
    assert_eq!(rho, 1.0059);
    // A child is one block further on the schedule and stamped at least one
    // second later, so its lag is at least 29 seconds less than its parent's.
    let step = (CHAIN.block_time - 1) as usize;
    let low: i64 = -57 * 3600;
    let high: i64 = 8 * 3600;
    let values: Vec<u128> = (low..=high).map(|lag| difficulty_at_lag(1_000_000, lag)).collect();
    assert!(values[0] >= 1 << 81, "the range reaches past 2^80");
    assert_eq!(*values.last().unwrap(), u128::from(CHAIN.min_difficulty), "the range reaches the floor");

    for (k, pair) in values.windows(2).enumerate() {
        assert!(pair[0] >= pair[1], "difficulty rises with the lag at {}", low + k as i64);
    }
    let mut largest = 0f64;
    for k in step..values.len() {
        let ratio = values[k - step] as f64 / values[k] as f64;
        assert!(ratio <= rho, "lag {}: a child {ratio} times its parent", low + k as i64);
        largest = largest.max(ratio);
    }
    // The bound is nearly tight: the largest rise is within 0.026% of the
    // exact 2^(29/3600), the cubic's 0.013% either way.
    let exact = 2f64.powf(29.0 / 3600.0);
    println!("largest rise {largest}, exact {exact}");
    assert!((largest / exact - 1.0).abs() < 2.6e-4, "largest rise {largest}");

    // Two blocks' worth of lag, 58 seconds, does exceed rho: the bound is one
    // block's and holds only because each child is checked against its parent.
    let two = (2 * step..values.len()).map(|k| values[k - 2 * step] as f64 / values[k] as f64);
    assert!(two.fold(0f64, f64::max) > rho);
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

/// The 24 items of spec 05's block-one example at `height`, stamped on
/// schedule with the difficulty the rule requires there; the genesis header
/// carries its 32 bytes of `extraData` and no gas used, as spec 05's genesis
/// example does. Hash fields keep their 32 bytes; their values do not change a
/// length.
fn header_items(height: u64) -> Vec<Vec<u8>> {
    let timestamp = GENESIS_TIME + CHAIN.block_time * height;
    let difficulty = if height == 0 { u128::from(CHAIN.start_difficulty) } else { difficulty_at_lag(height, 0) };
    let mut coinbase = vec![0u8; 20];
    coinbase[18..].copy_from_slice(&[0x04, 0xd2]);
    vec![
        vec![0xd2; 32], // parentHash
        vec![0x1d; 32], // uncleHash
        coinbase,
        vec![0x11; 32], // stateRoot
        vec![0x22; 32], // transactionsRoot
        vec![0x33; 32], // receiptsRoot
        vec![0; 256],   // logsBloom
        int(difficulty as u64),
        int(height),
        int(30_000_000),  // gasLimit
        int(if height == 0 { 0 } else { 126_000 }), // gasUsed
        int(timestamp),
        if height == 0 { vec![0x19; 32] } else { vec![] }, // extraData
        vec![0x44; 32],                                      // mixDigest
        vec![1, 2, 3, 4, 5, 6, 7, 8],                        // nonce
        int(875_000_000),                                    // baseFee
        vec![0x14; 32],                                      // coinTreeRoot
        vec![0xdf; 32],                                      // dataTreeRoot
        vec![0xf1; 32],                                      // dataMarkerRoot
        vec![0x48; 32],                                      // coinLookupRoot (decision 0004)
        vec![0x04; 32],                                      // dataLookupRoot
        vec![0xd2; 32],                                      // coinMarkerRoot
        vec![0xda; 32],                                      // lookupDigest
        vec![0xee; 32],                                      // headerMmrRoot (decision 0005)
    ]
}

/// The header the stage 2 design sends: all 24 items.
fn design_header(height: u64) -> Vec<u8> {
    rlp_list(&header_items(height))
}

/// The client's header today: the first 19 items, which it decodes.
fn client_header(height: u64) -> Vec<u8> {
    rlp_list(&header_items(height)[..19])
}

#[test]
fn headers_have_the_recorded_sizes_and_decode() {
    // Spec 05's `header-nineteen-items` and decision 0005's `block-one-24`.
    assert_eq!(client_header(1).len(), 615);
    assert_eq!(design_header(1).len(), 780);
    // Decision 0005's `genesis-24`.
    assert_eq!(design_header(0).len(), 809);
    for height in [1u64, 8192, 1_051_199, 5_255_999] {
        let fields = header_fields(&client_header(height)).expect("the client decodes the header");
        assert_eq!(fields.number, height);
        assert_eq!(fields.timestamp, GENESIS_TIME + 30 * height);
        assert_eq!(design_header(height).len(), client_header(height).len() + 5 * 33);
    }
}

// ---------------------------------------------------------------------------
// Paths, in the client's layout.

/// (first leaf, height) of each mountain of `leaf_count` leaves, left to right.
fn mountains(leaf_count: u64) -> Vec<(u64, u32)> {
    let mut out = Vec::new();
    let mut start = 0;
    for height in (0..64u32).rev() {
        if leaf_count >> height & 1 == 1 {
            out.push((start, height));
            start += 1 << height;
        }
    }
    out
}

/// The nodes a leaf's path holds, each as (first leaf, height): its siblings
/// from the bottom, then every other mountain's peak.
fn path_entries(leaf_count: u64, index: u64) -> (Vec<(u64, u32)>, Vec<(u64, u32)>) {
    let all = mountains(leaf_count);
    let which = all.iter().position(|&(start, height)| index < start + (1 << height)).unwrap();
    let (start, height) = all[which];
    let offset = index - start;
    let siblings = (0..height).map(|level| (start + (((offset >> level) ^ 1) << level), level)).collect();
    let peaks = all.iter().enumerate().filter(|&(i, _)| i != which).map(|(_, &node)| node).collect();
    (siblings, peaks)
}

/// The client takes a path of exactly this shape for the leaf: it folds it
/// and fails only at the root, which these zero nodes do not reach.
fn assert_client_shape(leaf_count: u64, index: u64) {
    let (siblings, peaks) = path_entries(leaf_count, index);
    let zero = MmrNode { hash: [0; 32], work: 0 };
    let leaf = MmrNode::leaf(&[7; 32], 1);
    let path = MmrPath { leaf_count, siblings: vec![zero; siblings.len()], peaks: vec![zero; peaks.len()] };
    assert_eq!(verify_mmr_path(&[0; 32], index, &leaf, &path), Err(PathError::Root), "leaf {index} of {leaf_count}");
    let mut short = path.clone();
    if short.siblings.pop().is_none() {
        short.peaks.push(zero);
    }
    assert_eq!(verify_mmr_path(&[0; 32], index, &leaf, &short), Err(PathError::Shape), "leaf {index}");
}

/// A header with its path, as one `ProvenHeader` holds it.
fn proven_bytes(leaf_count: u64, height: u64) -> usize {
    let (siblings, peaks) = path_entries(leaf_count, height);
    design_header(height).len() + (siblings.len() + peaks.len()) * MMR_NODE_BYTES
}

// ---------------------------------------------------------------------------
// The proof.

struct Count {
    samples: u64,
    /// Every header the proof carries and every path entry, each sent once.
    shared: usize,
    /// The same with the parent check's header before each sample, and its
    /// key block, which the client does not ask for yet.
    with_parents: usize,
    /// Each `ProvenSample` as the client's structures hold it: the header,
    /// its path, its key block and the key block's path, nothing shared.
    unshared: usize,
}

fn count(days: u64, seed: u64) -> Count {
    let leaf_count = BLOCKS_PER_DAY * days;
    let work = u128::from(CHAIN.start_difficulty);
    let total = u128::from(leaf_count) * work;
    let tail_start = u128::from(leaf_count - TAIL_HEADERS) * work;
    let delta = (total - tail_start) as f64 / total as f64;
    let samples = sample_count(ATTACKER_RATIO, ASSURANCE_BITS, delta).unwrap();
    let mut rng = StdRng::seed_from_u64(seed);
    let sampled: Vec<u64> =
        (0..samples).map(|_| (draw_point(&mut rng, tail_start, total).unwrap() / work) as u64).collect();
    assert!(sampled.iter().all(|&height| height < leaf_count - TAIL_HEADERS));

    // The samples, then the header before the tail and the tail.
    let carried = sampled.iter().copied().chain(leaf_count - TAIL_HEADERS - 1..leaf_count);
    let mut unshared = 0;
    let mut heights = BTreeSet::new();
    for height in carried {
        unshared += proven_bytes(leaf_count, height);
        heights.insert(height);
        if height > 0 {
            let key = seed_height(height);
            unshared += proven_bytes(leaf_count, key);
            heights.insert(key);
        }
    }
    let mut with_parents = heights.clone();
    for &height in sampled.iter().filter(|&&height| height > 0) {
        with_parents.insert(height - 1);
        if height > 1 {
            with_parents.insert(seed_height(height - 1));
        }
    }
    Count {
        samples,
        shared: sent_once(leaf_count, &heights),
        with_parents: sent_once(leaf_count, &with_parents),
        unshared,
    }
}

/// The bytes of these headers and of every entry of their paths, each once.
fn sent_once(leaf_count: u64, heights: &BTreeSet<u64>) -> usize {
    let mut entries = BTreeSet::new();
    let mut header_bytes = 0;
    for &height in heights {
        assert_client_shape(leaf_count, height);
        assert_eq!(header_fields(&client_header(height)).unwrap().number, height);
        header_bytes += design_header(height).len();
        let (siblings, peaks) = path_entries(leaf_count, height);
        entries.extend(siblings);
        entries.extend(peaks);
    }
    header_bytes + entries.len() * MMR_NODE_BYTES
}

/// The two figures of the page's row that starts with `start`, in bytes, and
/// the words after each.
fn page_row(start: &str) -> Vec<(usize, String)> {
    let line = DESIGN.lines().find(|line| line.starts_with(start)).unwrap_or_else(|| panic!("no row {start}"));
    let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
    assert_eq!(cells.len(), 3, "{line}");
    cells[1..]
        .iter()
        .map(|cell| {
            let (figure, rest) = cell.split_once(" bytes").unwrap_or_else(|| panic!("no bytes in {cell}"));
            (figure.replace(',', "").parse().unwrap(), rest.trim_start_matches([',', ' ']).to_string())
        })
        .collect()
}

/// "under the model" or "over the model", as the page words a count.
fn against(count: usize, model: usize) -> String {
    if count <= model { "under the model" } else { "over the model" }.to_string()
}

#[test]
fn header_proof_bytes_against_the_model_and_the_page() {
    let mut measured = Vec::new();
    for (years, expected_samples) in [(1u64, 599u64), (5, 702)] {
        let counts: Vec<Count> = SEEDS.iter().map(|&seed| count(years * DAYS_PER_YEAR, seed)).collect();
        assert!(counts.iter().all(|c| c.samples == expected_samples), "{years} years");
        let most = |f: fn(&Count) -> usize| counts.iter().map(f).max().unwrap();
        let row = (most(|c| c.shared), most(|c| c.with_parents), most(|c| c.unshared));
        println!("{years} years: sent once {} bytes, with parents {} bytes, unshared {} bytes", row.0, row.1, row.2);
        measured.push((years, row));
    }

    let modeled = page_row("| Modeled: the stage 2 model's header proof");
    let shared = page_row("| Measured: the client's proof with every header and path entry sent once");
    let with_parents = page_row("| Measured: the same with the parent check's header before each sample");
    let unshared = page_row("| Measured: the client's proof as its structures hold it");
    for (column, (years, (most_shared, most_with_parents, most_unshared))) in measured.into_iter().enumerate() {
        let model = modeled[column].0;
        // The client's proof, every item sent once, fits the modeled bytes.
        assert!(most_shared <= model, "{years} years: {most_shared} over the modeled {model}");
        assert!(most_shared < most_with_parents && most_with_parents < most_unshared, "{years} years");
        assert_eq!(shared[column], (most_shared, against(most_shared, model)), "{years} years");
        assert_eq!(with_parents[column], (most_with_parents, against(most_with_parents, model)), "{years} years");
        assert_eq!(unshared[column], (most_unshared, against(most_unshared, model)), "{years} years");
    }
    // The model's own figures, as the stage 2 model prints them.
    assert_eq!(modeled[0], (1_247_246, "(1.2 MB)".to_string()));
    assert_eq!(modeled[1], (1_667_534, "(1.7 MB)".to_string()));
}

/// Two generators draw different points, so the counts are of the wallet's
/// own randomness, and a proof of fewer samples is smaller.
#[test]
fn counts_follow_the_samples() {
    let year = BLOCKS_PER_DAY * DAYS_PER_YEAR;
    let one = count(DAYS_PER_YEAR, 1);
    let two = count(DAYS_PER_YEAR, 2);
    assert_ne!(one.shared, two.shared);
    assert!(one.shared < one.unshared);
    // The tip's key block, the first of its 128th epoch.
    assert_eq!(seed_height(year - 1), 128 * 8192);
    let five = count(5 * DAYS_PER_YEAR, 1);
    assert!(five.shared > one.shared && five.unshared > one.unshared);
}
