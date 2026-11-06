//! The keep-up status check and reorganisation handling of `restore`, on
//! header proofs checked by `header_sample` (docs/scale/stage2-design.md,
//! "Wallet restore volume", steps 5 and 6, and the paragraph on spent status
//! following the canonical chain; spec 05, section 7).
//!
//! The test chain is real headers, sealed and checked as in the header
//! sample tests: the genesis header carries the start difficulty, 4096, and
//! every other header is stamped 13 half-lives behind the schedule, where the
//! rule requires difficulty 1, so any nonce seals it and a branch's work above
//! a fork is its number of blocks. The tail is 6 headers, not the design's 64.
//!
//! The client's header decoder reads the 19-item header, so the four roots of
//! decision 0004's fields 16, 19, 21 and 22 ride in stand-in fields of the
//! test header: the coin tree root in field 16, its own place, and
//! `coinLookupRoot`, `coinMarkerRoot` and `lookupDigest` in fields 3, 4 and
//! 5. The test's reader reads them from the header's bytes, as the wallet's
//! reader of the 23-item header will. Every root is built here, apart from
//! the trees under test: the lookup index and marker set from the library's
//! tree builders, the coin tree level by level over the proofs crate's hash.
//!
//! The chain, from genesis:
//!
//! - heights 1 to 4, shared by every branch: another key's coin at coin
//!   leaf 0 and the test key's number 0 at leaf 1 (block 1), another coin at
//!   leaf 2 (block 2), two empty blocks;
//! - branch A, heights 5 to 7: block 5 reveals number 0 (its marker spent,
//!   its remainder appended at leaf 3), two empty blocks;
//! - branch B, heights 5 to 8: another coin at leaf 3, three empty blocks.
//!   One block heavier than A above the fork: number 0 is not spent on it;
//! - branch C, heights 5 to 8: another coin at leaf 3, then block 6 reveals
//!   number 0 (remainder at leaf 4), two empty blocks: the spend kept;
//! - branch D, heights 5 to 8: four empty blocks, as heavy as B;
//! - branch B long: B and four more empty blocks, to height 12.
//!
//! Each RandomX cache takes 256 MiB; the proofs are built once, under one
//! sampler, and shared.

use std::sync::OnceLock;

use ghost_client::header_chain::{required_difficulty, ChainParams};
use ghost_client::header_sample::{
    ChainChange, HeaderCheck, HeaderSampler, MmrNode, MmrPath, ProvenChain, ProvenHeader, ProvenSample, Request,
    SampleSettings,
};
use ghost_client::lookup::{
    key_lookup_tag, verify_lookup, verify_marker_absence, verify_marker_membership, BlockLookupList, CoinMarkerSet,
    LookupAnswer, LookupIndex, LookupTag, LookupTree, SpentMarker, WitnessError,
};
use ghost_client::restore::{
    check_keep_up, keep_up_holds, CanonicalBlock, CanonicalError, CanonicalTrees, Followed, HeaderRoots, KeepUp,
    KeepUpAnswer, KeepUpError, KeepUpStatus, MarkerStatus, SpentAt, TreeRoot,
};
use ghost_client::seal::seed_height;
use ghost_client::{
    encrypt_note, restore_coins, Amount, Capsule, Commitment, Current, KeyFormat, Marker, NoteContents, PhantomKey,
    Rule, TreeLeaf, NOTE_BYTES,
};
use ghost_proofs::{empty_leaf, tree_node, Tree as CoinTree};
use rand::rngs::StdRng;
use rand::SeedableRng;
use tiny_keccak::{Hasher, Keccak};

const CHAIN: ChainParams =
    ChainParams { block_time: 30, half_life: 3600, start_difficulty: 4096, min_difficulty: 1, future_drift: 30 };
const GENESIS_TIME: u64 = 0x6abd_a280;
/// A clock well after every test header.
const LATER: u64 = GENESIS_TIME + 1_000_000_000;
const TAIL: u64 = 6;
/// Behind the schedule by 13 half-lives: difficulty 1.
const SLOW: u64 = 13 * 3600;
/// The last height every branch shares.
const FORK: u64 = 4;
const CHAIN_ID: u64 = 1234;
const KEY_SEED: u64 = 0x6b65_6570;

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

// ---------------------------------------------------------------------------
// Headers, with the roots in their stand-in fields.

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

/// An RLP prefix at `at`: (prefix length, payload length).
fn rlp_prefix(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *bytes.get(at)?;
    let long = |base: u8| -> Option<(usize, usize)> {
        let size = usize::from(first - base);
        let digits = bytes.get(at + 1..at + 1 + size)?;
        Some((1 + size, digits.iter().fold(0usize, |acc, &d| (acc << 8) | usize::from(d))))
    };
    match first {
        0x00..=0x7f => Some((0, 1)),
        0x80..=0xb7 => Some((1, usize::from(first - 0x80))),
        0xb8..=0xbf => long(0xb7),
        0xc0..=0xf7 => Some((1, usize::from(first - 0xc0))),
        _ => long(0xf7),
    }
}

/// The items of a header's RLP list.
fn rlp_items(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let (header, len) = rlp_prefix(bytes, 0)?;
    let end = header + len;
    let mut items = Vec::new();
    let mut at = header;
    while at < end {
        let (prefix, item) = rlp_prefix(bytes, at)?;
        items.push(bytes.get(at + prefix..at + prefix + item)?);
        at += prefix + item;
    }
    (at == end && end == bytes.len()).then_some(items)
}

/// The test's reader: the four roots from their fields of the header's own
/// bytes.
fn read_roots(header: &[u8]) -> Option<HeaderRoots> {
    let items = rlp_items(header)?;
    if items.len() != 19 {
        return None;
    }
    let field = |index: usize| <[u8; 32]>::try_from(items[index]).ok();
    Some(HeaderRoots {
        coin_tree_root: field(16)?,
        coin_lookup_root: field(3)?,
        coin_marker_root: field(4)?,
        lookup_digest: field(5)?,
    })
}

/// A reader that finds no roots in any header.
fn read_nothing(_: &[u8]) -> Option<HeaderRoots> {
    None
}

#[derive(Clone)]
struct Draft {
    parent: [u8; 32],
    number: u64,
    timestamp: u64,
    difficulty: u64,
    branch: u8,
    roots: HeaderRoots,
}

impl Draft {
    fn rlp(&self) -> Vec<u8> {
        let mut coinbase = vec![0u8; 20];
        coinbase[19] = self.branch;
        rlp_list(&[
            self.parent.to_vec(),
            vec![0x1d; 32],
            coinbase,
            self.roots.coin_lookup_root.to_vec(),
            self.roots.coin_marker_root.to_vec(),
            self.roots.lookup_digest.to_vec(),
            vec![0; 256],
            int(self.difficulty),
            int(self.number),
            int(30_000_000),
            int(0),
            int(self.timestamp),
            vec![],
            vec![0u8; 32],
            0u64.to_be_bytes().to_vec(),
            int(1_000_000_000),
            self.roots.coin_tree_root.to_vec(),
            vec![0x55; 32],
            vec![0x66; 32],
        ])
    }

    fn hash(&self) -> [u8; 32] {
        keccak(&self.rlp())
    }
}

fn required(number: u64, timestamp: u64) -> u64 {
    let be = required_difficulty(&CHAIN, GENESIS_TIME, number, timestamp).to_be_bytes();
    assert!(be[..24].iter().all(|&b| b == 0), "a test difficulty fits in 8 bytes");
    u64::from_be_bytes(be[24..].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// The trees, built here, and the branches.

/// The coin tree's root over `leaves`, level by level over the whole depth.
fn coin_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = leaves.to_vec();
    let mut zero = empty_leaf();
    for depth in 0..32u8 {
        if level.is_empty() {
            level.push(zero);
        }
        level = level
            .chunks(2)
            .map(|pair| tree_node(CoinTree::Coin, depth, &pair[0], pair.get(1).unwrap_or(&zero)))
            .collect();
        zero = tree_node(CoinTree::Coin, depth, &zero, &zero);
    }
    level[0]
}

/// The trees after one block.
#[derive(Clone)]
struct State {
    index: LookupIndex,
    markers: CoinMarkerSet,
    leaves: Vec<[u8; 32]>,
}

impl State {
    fn genesis() -> Self {
        Self { index: LookupIndex::new(LookupTree::Coin), markers: CoinMarkerSet::new(), leaves: Vec::new() }
    }

    fn roots(&self, list: &BlockLookupList) -> HeaderRoots {
        HeaderRoots {
            coin_tree_root: coin_root(&self.leaves),
            coin_lookup_root: self.index.root(),
            coin_marker_root: self.markers.root(),
            lookup_digest: list.digest().unwrap(),
        }
    }
}

/// What one block appends and spends.
#[derive(Clone, Default)]
struct Contents {
    coins: Vec<(LookupTag, Commitment)>,
    spends: Vec<([u8; 32], Option<u64>)>,
}

/// A branch from genesis: its headers, its blocks and the trees after each.
#[derive(Clone)]
struct Branch {
    drafts: Vec<Draft>,
    blocks: Vec<CanonicalBlock>,
    states: Vec<State>,
}

impl Branch {
    fn genesis() -> Self {
        let state = State::genesis();
        let roots = state.roots(&BlockLookupList::default());
        let genesis =
            Draft { parent: [0; 32], number: 0, timestamp: GENESIS_TIME, difficulty: 4096, branch: 0, roots };
        Self { drafts: vec![genesis], blocks: Vec::new(), states: vec![state] }
    }

    fn tip(&self) -> u64 {
        self.drafts.len() as u64 - 1
    }

    fn push(&mut self, branch: u8, contents: Contents) {
        let mut state = self.states.last().unwrap().clone();
        let list = BlockLookupList {
            coin_start: state.leaves.len() as u64,
            coin_tags: contents.coins.iter().map(|(tag, _)| *tag).collect(),
            coin_markers: contents.spends.iter().map(|(marker, _)| *marker).collect(),
            ..BlockLookupList::default()
        };
        for (tag, position) in list.coin_entries() {
            state.index.insert(tag, position).unwrap();
        }
        state.leaves.extend(contents.coins.iter().map(|(_, leaf)| *leaf.as_bytes()));
        for (marker, appended) in &contents.spends {
            state.markers.insert(*marker, *appended).unwrap();
        }
        let roots = state.roots(&list);
        let parent = self.drafts.last().unwrap().hash();
        let number = self.drafts.len() as u64;
        let timestamp = GENESIS_TIME + 30 * number + SLOW;
        let draft = Draft { parent, number, timestamp, difficulty: required(number, timestamp), branch, roots };
        assert_eq!(draft.difficulty, 1);
        self.blocks.push(CanonicalBlock {
            height: number,
            hash: draft.hash(),
            list,
            coin_leaves: contents.coins.iter().map(|(_, leaf)| *leaf).collect(),
            appended: contents.spends.iter().map(|(_, appended)| *appended).collect(),
        });
        self.drafts.push(draft);
        self.states.push(state);
    }

    fn empty(&mut self, branch: u8, count: u64) {
        for _ in 0..count {
            self.push(branch, Contents::default());
        }
    }

    fn hash(&self, height: u64) -> [u8; 32] {
        self.drafts[height as usize].hash()
    }

    fn hashes(&self, from: u64, to: u64) -> Vec<[u8; 32]> {
        (from..=to).map(|height| self.hash(height)).collect()
    }

    /// The blocks from `from` to `to`, both included.
    fn blocks(&self, from: u64, to: u64) -> Vec<CanonicalBlock> {
        self.blocks[from as usize - 1..to as usize].to_vec()
    }

    fn lists(&self, from: u64, to: u64) -> Vec<BlockLookupList> {
        self.blocks(from, to).into_iter().map(|block| block.list).collect()
    }

    fn roots(&self, height: u64) -> HeaderRoots {
        self.drafts[height as usize].roots
    }

    fn absence(&self, height: u64, marker: &Marker) -> Vec<u8> {
        self.states[height as usize].markers.absence_witness(marker.as_bytes()).unwrap().to_bytes()
    }

    /// The keep-up answer an honest server gives for `marker` at `snapshot`.
    fn answer(&self, snapshot: u64, marker: &Marker) -> KeepUpAnswer {
        let set = &self.states[snapshot as usize].markers;
        let witness = match set.membership_witness(marker.as_bytes()) {
            Some(witness) => witness,
            None => set.absence_witness(marker.as_bytes()).unwrap(),
        };
        KeepUpAnswer {
            snapshot_height: snapshot,
            marker_witness: witness.to_bytes(),
            later_blocks: self.lists(snapshot + 1, self.tip()),
        }
    }
}

// ---------------------------------------------------------------------------
// The mountain range and the proofs.

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

fn node_bytes(node: &MmrNode) -> Vec<u8> {
    let mut out = node.hash.to_vec();
    out.extend(node.work.to_be_bytes());
    out
}

fn join(left: &MmrNode, right: &MmrNode) -> MmrNode {
    MmrNode {
        hash: tagged("ghost/header-mmr-node/v1", &[&node_bytes(left), &node_bytes(right)]),
        work: left.work + right.work,
    }
}

struct Mmr {
    leaves: Vec<MmrNode>,
}

impl Mmr {
    fn count(&self) -> u64 {
        self.leaves.len() as u64
    }

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

    fn root(&self) -> [u8; 32] {
        let peaks: Vec<MmrNode> = self.mountains().into_iter().map(|(s, h)| self.node(s, h)).collect();
        let mut bagged = *peaks.last().unwrap();
        for peak in peaks.iter().rev().skip(1) {
            bagged = join(peak, &bagged);
        }
        tagged("ghost/header-mmr-root/v1", &[&self.count().to_be_bytes(), &node_bytes(&bagged)])
    }

    fn path(&self, index: u64) -> MmrPath {
        let mountains = self.mountains();
        let which = mountains.iter().position(|&(start, height)| index < start + (1 << height)).unwrap();
        let (start, height) = mountains[which];
        let offset = index - start;
        let siblings = (0..height).map(|level| self.node(start + (((offset >> level) ^ 1) << level), level)).collect();
        let peaks = mountains
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != which)
            .map(|(_, &(start, height))| self.node(start, height))
            .collect();
        MmrPath { leaf_count: self.count(), siblings, peaks }
    }

    fn height_at(&self, point: u128) -> u64 {
        let mut before = 0;
        for (height, leaf) in self.leaves.iter().enumerate() {
            if point < before + leaf.work {
                return height as u64;
            }
            before += leaf.work;
        }
        panic!("the point is past the chain's work");
    }
}

/// The header proof of a branch, checked by samples as a wallet checks it.
fn prove(sampler: &mut HeaderSampler, branch: &Branch, rng: &mut StdRng) -> ProvenChain {
    let rlp: Vec<Vec<u8>> = branch.drafts.iter().map(Draft::rlp).collect();
    let leaves = branch
        .drafts
        .iter()
        .map(|draft| {
            let hash = draft.hash();
            let work = u128::from(draft.difficulty);
            MmrNode { hash: tagged("ghost/header-mmr-leaf/v1", &[&hash, &work.to_be_bytes()]), work }
        })
        .collect();
    let mmr = Mmr { leaves };
    let root = mmr.root();
    let proven = |height: u64| ProvenHeader { header: rlp[height as usize].clone(), path: mmr.path(height) };
    let sample = |height: u64| ProvenSample {
        header: proven(height),
        key_block: (height > 0).then(|| proven(seed_height(height))),
    };
    let count = mmr.count();
    let first = count.saturating_sub(TAIL);
    let tail: Vec<ProvenSample> = (first..count).map(sample).collect();
    let parent = (first > 0).then(|| sample(first - 1));
    let tail = sampler.check_tail(&root, parent.as_ref(), &tail, LATER).unwrap();
    let Request::Points(points) = sampler.request(&tail, rng) else {
        panic!("a sampled check asks for points");
    };
    let samples: Vec<ProvenSample> = points.iter().map(|&point| sample(mmr.height_at(point))).collect();
    sampler.prove_sampled(tail, &points, &samples).unwrap()
}

// ---------------------------------------------------------------------------
// The world, built once.

fn key() -> PhantomKey {
    PhantomKey::generate(KeyFormat::Words, &mut StdRng::seed_from_u64(KEY_SEED))
}

fn tag(byte: u8) -> LookupTag {
    [byte; 16]
}

fn coin(byte: u8) -> Commitment {
    Commitment::from_bytes([byte; 32])
}

struct World {
    /// The test key's number 0: its leaf as the chain holds it, note and
    /// salt beside it.
    ours: TreeLeaf,
    /// Its marker, as the wallet computes it.
    marker: Marker,
    /// Another key's marker, never spent.
    unrelated: Marker,
    prefix: Branch,
    a: Branch,
    b: Branch,
    c: Branch,
    d: Branch,
    b_long: Branch,
    prefix_proof: ProvenChain,
    a_proof: ProvenChain,
    b_proof: ProvenChain,
    c_proof: ProvenChain,
    d_proof: ProvenChain,
    b_long_proof: ProvenChain,
}

fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(build_world)
}

fn build_world() -> World {
    let key = key();
    let mut rng = StdRng::seed_from_u64(0x7265_6f72);
    let amount = Amount::new(1_000_000_000).unwrap();
    let commit = key.salted_coin_commit(0, amount, Rule::EMPTY, &mut rng).unwrap();
    let note = encrypt_note(
        &key.note_key(),
        CHAIN_ID,
        &commit.commitment,
        &NoteContents::salted_coin(0, amount, Rule::EMPTY, commit.salt),
        &Capsule::empty(),
        &mut rng,
    );
    let ours = TreeLeaf { commitment: commit.commitment, note, salt: Some(commit.salt) };
    let marker = commit.marker;
    let reveal = |appended: u64| Contents {
        coins: vec![(key_lookup_tag(&key, 1), coin(0xa0 + appended as u8))],
        spends: vec![(*marker.as_bytes(), Some(appended))],
    };

    let mut prefix = Branch::genesis();
    let first = vec![(tag(0x10), coin(0x10)), (key_lookup_tag(&key, 0), ours.commitment)];
    prefix.push(1, Contents { coins: first, ..Contents::default() });
    prefix.push(1, Contents { coins: vec![(tag(0x12), coin(0x12))], ..Contents::default() });
    prefix.empty(1, 2);
    assert_eq!(prefix.tip(), FORK);

    let mut a = prefix.clone();
    a.push(0xa, reveal(3));
    a.empty(0xa, 2);

    let mut b = prefix.clone();
    b.push(0xb, Contents { coins: vec![(tag(0xb5), coin(0xb5))], ..Contents::default() });
    b.empty(0xb, 3);

    let mut c = prefix.clone();
    c.push(0xc, Contents { coins: vec![(tag(0xc5), coin(0xc5))], ..Contents::default() });
    c.push(0xc, reveal(4));
    c.empty(0xc, 2);

    let mut d = prefix.clone();
    d.empty(0xd, 4);

    let mut b_long = b.clone();
    b_long.empty(0xb, 4);

    let mut sampler = HeaderSampler::new(
        &prefix.drafts[0].rlp(),
        CHAIN,
        SampleSettings { tail_headers: TAIL, check: HeaderCheck::Sampled { attacker_ratio: 0.5, assurance_bits: 4.0 } },
    )
    .unwrap();
    let mut points = StdRng::seed_from_u64(0x706f_696e);
    let mut prove = |branch: &Branch| prove(&mut sampler, branch, &mut points);
    World {
        ours,
        marker,
        unrelated: Marker::from_bytes([0x77; 32]),
        prefix_proof: prove(&prefix),
        a_proof: prove(&a),
        b_proof: prove(&b),
        c_proof: prove(&c),
        d_proof: prove(&d),
        b_long_proof: prove(&b_long),
        prefix,
        a,
        b,
        c,
        d,
        b_long,
    }
}

impl World {
    fn genesis_hash(&self) -> [u8; 32] {
        self.prefix.hash(0)
    }

    /// Canonical trees that followed the shared blocks, then `branch`.
    fn trees_on(&self, branch: &Branch, proof: &ProvenChain) -> CanonicalTrees {
        let mut trees = CanonicalTrees::genesis(self.genesis_hash());
        follow_ok(&mut trees, &self.prefix_proof, &self.prefix.blocks(1, FORK));
        follow_ok(&mut trees, proof, &branch.blocks(FORK + 1, branch.tip()));
        trees
    }

    /// The test key's restore over a branch's coin leaves and the markers
    /// the trees hold spent.
    fn restore_on(&self, branch: &Branch, trees: &CanonicalTrees) -> Current {
        let leaves: Vec<TreeLeaf> = branch
            .states
            .last()
            .unwrap()
            .leaves
            .iter()
            .map(|leaf| {
                if leaf == self.ours.commitment.as_bytes() {
                    self.ours.clone()
                } else {
                    TreeLeaf { commitment: Commitment::from_bytes(*leaf), note: [leaf[0]; NOTE_BYTES], salt: None }
                }
            })
            .collect();
        let spent: Vec<Marker> =
            trees.marker_set().leaves().iter().skip(1).map(|leaf| Marker::from_bytes(leaf.value)).collect();
        restore_coins(&key(), CHAIN_ID, 0, &leaves, &spent).unwrap().current
    }
}

fn follow_ok(trees: &mut CanonicalTrees, proof: &ProvenChain, blocks: &[CanonicalBlock]) -> Followed {
    trees.follow(proof, blocks, &read_roots).unwrap()
}

fn status(world: &World, proof: &ProvenChain, answer: &KeepUpAnswer) -> Result<KeepUpStatus, KeepUpError> {
    check_keep_up(&world.marker, proof, answer, &read_roots).map(|checked| checked.status)
}

/// The trees' coin tree, lookup index and marker set roots.
fn tree_roots(trees: &CanonicalTrees) -> ([u8; 32], [u8; 32], [u8; 32]) {
    (trees.coin_tree_root(), trees.lookup_index().root(), trees.marker_set().root())
}

fn header_roots(roots: HeaderRoots) -> ([u8; 32], [u8; 32], [u8; 32]) {
    (roots.coin_tree_root, roots.coin_lookup_root, roots.coin_marker_root)
}

// ---------------------------------------------------------------------------
// The tests.

#[test]
fn the_proofs_link_what_the_branches_hold() {
    let w = world();
    // Restore finds the coin the keep-up check follows, its marker the one
    // the wallet computed.
    let Current::One(found) = w.restore_on(&w.prefix, &CanonicalTrees::genesis(w.genesis_hash())) else {
        panic!("the test key's one coin");
    };
    assert_eq!((found.position, found.marker), (1, w.marker));

    // A tail of 6 from height 2 on A, the header before it at height 1.
    let a = &w.a_proof;
    assert_eq!((a.tip_height(), a.first_height(), a.linked_from()), (7, 2, 1));
    assert_eq!(a.tip_hash(), w.a.hash(7));
    assert_eq!(a.hash_at(1), Some(w.a.hash(1)));
    assert_eq!(a.hash_at(0), None);
    assert_eq!(a.header_at(1), None);
    assert_eq!(a.header_at(2), Some(w.a.drafts[2].rlp().as_slice()));
    assert_eq!(a.work_above(FORK), Some(3));
    assert_eq!(a.work_above(1), Some(6));
    assert_eq!(a.work_above(0), None);
    assert_eq!(a.height_of(&w.a.hash(5)), Some(5));
    assert_eq!(a.height_of(&w.b.hash(5)), None);
    // The prefix fits the tail: linked from genesis.
    assert_eq!((w.prefix_proof.first_height(), w.prefix_proof.linked_from()), (0, 0));
    assert_eq!(w.prefix_proof.hash_at(0), Some(w.genesis_hash()));
    // The test reader reads the roots from the header's bytes.
    assert_eq!(read_roots(a.header_at(5).unwrap()), Some(w.a.roots(5)));
}

#[test]
fn keep_up_reads_the_spent_status_from_a_later_proof() {
    let w = world();
    // Before the spend: absent from the prefix tip's set.
    let before = w.prefix.answer(FORK, &w.marker);
    assert_eq!(
        check_keep_up(&w.marker, &w.prefix_proof, &before, &read_roots),
        Ok(KeepUp {
            status: KeepUpStatus::Unspent,
            snapshot_height: FORK,
            tip_height: FORK,
            tip_hash: w.prefix.hash(FORK),
        })
    );

    // On A, a snapshot at the spend's block: spent, with the leaf the
    // reveal appended, from the membership witness.
    let spent = KeepUpStatus::Spent(SpentAt::Snapshot { set_position: 1, appended: Some(3) });
    assert_eq!(status(w, &w.a_proof, &w.a.answer(5, &w.marker)), Ok(spent));
    assert_eq!(status(w, &w.a_proof, &w.a.answer(7, &w.marker)), Ok(spent));
    let checked = check_keep_up(&w.marker, &w.a_proof, &w.a.answer(5, &w.marker), &read_roots).unwrap();
    assert_eq!((checked.snapshot_height, checked.tip_height, checked.tip_hash), (5, 7, w.a.hash(7)));

    // A snapshot below the spend: absent there, found in block 5's list.
    let answer = w.a.answer(3, &w.marker);
    assert_eq!(answer.later_blocks.len(), 4);
    assert_eq!(status(w, &w.a_proof, &answer), Ok(KeepUpStatus::Spent(SpentAt::LaterBlock { height: 5 })));

    // Another key's marker is unspent on A, from any snapshot.
    for snapshot in 2..=7 {
        let answer = w.a.answer(snapshot, &w.unrelated);
        let checked = check_keep_up(&w.unrelated, &w.a_proof, &answer, &read_roots);
        assert_eq!(checked.map(|c| c.status), Ok(KeepUpStatus::Unspent), "snapshot {snapshot}");
    }
}

#[test]
fn keep_up_refuses_a_wrong_or_missing_item() {
    let w = world();
    let proof = &w.a_proof;
    let honest = w.a.answer(FORK, &w.marker);
    assert_eq!(status(w, proof, &honest), Ok(KeepUpStatus::Spent(SpentAt::LaterBlock { height: 5 })));

    // The snapshot must be a tail header: not the header before the tail,
    // nor one past the tip.
    for height in [0, 1, 8] {
        let answer = KeepUpAnswer { snapshot_height: height, ..honest.clone() };
        assert_eq!(status(w, proof, &answer), Err(KeepUpError::SnapshotNotInTail { height }));
    }

    // A later block missing, or one too many.
    let mut short = honest.clone();
    short.later_blocks.pop();
    assert_eq!(status(w, proof, &short), Err(KeepUpError::LaterBlocks { expected: 3, got: 2 }));
    let mut long = honest.clone();
    long.later_blocks.push(BlockLookupList::default());
    assert_eq!(status(w, proof, &long), Err(KeepUpError::LaterBlocks { expected: 3, got: 4 }));

    // Block 5's list with the spend taken out: not the list its header
    // commits to, so the spend cannot be hidden.
    let mut hidden = honest.clone();
    hidden.later_blocks[0].coin_markers.clear();
    assert_eq!(status(w, proof, &hidden), Err(KeepUpError::LookupDigest { height: 5 }));

    // At the spend's block, the absence witness of the block before: it
    // folds to another root.
    let stale = KeepUpAnswer {
        snapshot_height: 5,
        marker_witness: w.a.absence(FORK, &w.marker),
        later_blocks: w.a.lists(6, 7),
    };
    assert_eq!(status(w, proof, &stale), Err(KeepUpError::Witness(WitnessError::Root)));

    // A witness cut short.
    let mut cut = w.a.answer(5, &w.marker);
    cut.marker_witness.truncate(100);
    assert!(matches!(status(w, proof, &cut), Err(KeepUpError::Witness(WitnessError::Length { .. }))));

    // Another marker's absence witness at the spend's block never says
    // unspent: it is refused, or it is the spent leaf itself.
    let other = KeepUpAnswer { marker_witness: w.a.absence(5, &w.unrelated), ..w.a.answer(5, &w.marker) };
    match status(w, proof, &other) {
        Err(KeepUpError::Witness(WitnessError::NotTheLowLeaf)) => {}
        Ok(KeepUpStatus::Spent(SpentAt::Snapshot { appended: Some(3), .. })) => {}
        result => panic!("a wrong witness gave {result:?}"),
    }

    // A header without readable roots.
    assert_eq!(
        check_keep_up(&w.marker, proof, &honest, &read_nothing),
        Err(KeepUpError::Roots { height: FORK })
    );
}

#[test]
fn chain_change_tracks_the_checked_chain_across_a_reorganisation() {
    let w = world();
    assert_eq!(w.a_proof.compare(&w.a_proof), ChainChange::Same);
    assert_eq!(w.prefix_proof.compare(&w.a_proof), ChainChange::Extended { from_height: FORK });
    assert_eq!(w.a_proof.compare(&w.prefix_proof), ChainChange::Behind { tip_height: FORK });

    let ChainChange::Reorganised(reorg) = w.a_proof.compare(&w.b_proof) else {
        panic!("B is heavier above the fork");
    };
    assert_eq!((reorg.ancestor_height, reorg.ancestor_hash), (FORK, w.prefix.hash(FORK)));
    assert_eq!(reorg.disconnected, w.a.hashes(5, 7));
    assert_eq!(reorg.connected, w.b.hashes(5, 8));
    assert_eq!((reorg.disconnected_work, reorg.connected_work), (3, 4));

    // Back from B to A, or to D of equal work: B stays.
    let ChainChange::Lighter(lighter) = w.b_proof.compare(&w.a_proof) else {
        panic!("A is lighter than B");
    };
    assert_eq!((lighter.ancestor_height, lighter.disconnected_work, lighter.connected_work), (FORK, 4, 3));
    assert!(matches!(w.b_proof.compare(&w.d_proof), ChainChange::Lighter(tie) if tie.connected_work == 4));
    assert!(matches!(w.d_proof.compare(&w.b_proof), ChainChange::Lighter(_)));

    // The long tail starts at height 7, above the prefix's tip: nothing in
    // common is linked.
    assert_eq!(w.b_long_proof.linked_from(), 6);
    assert_eq!(w.prefix_proof.compare(&w.b_long_proof), ChainChange::Unknown);
    assert_eq!(w.b_proof.compare(&w.b_long_proof), ChainChange::Extended { from_height: 8 });

    // A status checked on A holds on a later proof through A's tip, and on
    // no other branch.
    assert!(keep_up_holds(&w.prefix_proof, &w.a_proof));
    assert!(keep_up_holds(&w.a_proof, &w.prefix_proof));
    assert!(keep_up_holds(&w.b_proof, &w.b_long_proof));
    assert!(!keep_up_holds(&w.a_proof, &w.b_proof));
    assert!(!keep_up_holds(&w.b_proof, &w.d_proof));
    assert!(!keep_up_holds(&w.prefix_proof, &w.b_long_proof));
}

#[test]
fn a_spend_only_on_a_disconnected_block_shows_unspent_again() {
    let w = world();
    let mut trees = CanonicalTrees::genesis(w.genesis_hash());
    assert_eq!(follow_ok(&mut trees, &w.prefix_proof, &w.prefix.blocks(1, FORK)), Followed::Extended { connected: 4 });
    assert!(matches!(trees.marker_status(&w.marker), MarkerStatus::Unspent { .. }));

    // A: the spend.
    assert_eq!(follow_ok(&mut trees, &w.a_proof, &w.a.blocks(5, 7)), Followed::Extended { connected: 3 });
    assert_eq!((trees.tip_height(), trees.tip_hash()), (7, w.a.hash(7)));
    assert_eq!(tree_roots(&trees), header_roots(w.a.roots(7)));
    let MarkerStatus::Spent { appended: Some(3), witness } = trees.marker_status(&w.marker) else {
        panic!("spent on A");
    };
    let old_spend = witness.to_bytes();
    let a_root = trees.marker_set().root();
    assert_eq!(
        verify_marker_membership(&a_root, &old_spend, w.marker.as_bytes()),
        Ok(SpentMarker { position: 1, appended: Some(3) })
    );
    assert!(matches!(w.restore_on(&w.a, &trees), Current::None));

    // B, heavier: A's blocks are disconnected and B's connected.
    assert_eq!(
        follow_ok(&mut trees, &w.b_proof, &w.b.blocks(5, 8)),
        Followed::Reorganised { ancestor_height: FORK, disconnected: w.a.hashes(5, 7), connected: 4 }
    );
    assert_eq!((trees.tip_height(), trees.tip_hash()), (8, w.b.hash(8)));
    for height in 0..=8 {
        assert_eq!(trees.hash_at(height), Some(w.b.hash(height)), "height {height}");
    }

    // Every root is the new branch's, as a wallet that never saw A builds
    // them.
    assert_eq!(tree_roots(&trees), header_roots(w.b.roots(8)));
    let fresh = w.trees_on(&w.b, &w.b_proof);
    assert_eq!(tree_roots(&trees), tree_roots(&fresh));
    assert_eq!(trees.next_coin_position(), 4);

    // The coin shows unspent again, with an absence witness under B's root,
    // and A's membership witness no longer holds.
    let MarkerStatus::Unspent { witness } = trees.marker_status(&w.marker) else {
        panic!("the spend was only on A");
    };
    let b_root = trees.marker_set().root();
    assert_ne!(b_root, a_root);
    assert_eq!(verify_marker_absence(&b_root, &witness.to_bytes(), w.marker.as_bytes()), Ok(()));
    assert_eq!(verify_marker_membership(&b_root, &old_spend, w.marker.as_bytes()), Err(WitnessError::Root));
    // A's remainder entry is gone from the lookup index: number 1 is absent.
    let number_1 = key_lookup_tag(&key(), 1);
    assert!(trees.lookup_index().membership_witness(&number_1, 3).is_none());
    let lookup = trees.lookup_index().lookup_witness(&number_1).unwrap().to_bytes();
    let lookup_root = trees.lookup_index().root();
    assert_eq!(verify_lookup(LookupTree::Coin, &lookup_root, &lookup, &number_1), Ok(LookupAnswer::Absent));
    // Restore over B finds the coin current again.
    let Current::One(found) = w.restore_on(&w.b, &trees) else {
        panic!("the coin is current on B");
    };
    assert_eq!(found.marker, w.marker);

    // The keep-up check on B's proof agrees: A's witness is refused, B's
    // says unspent from any snapshot.
    let replayed = KeepUpAnswer { marker_witness: old_spend.clone(), ..w.b.answer(8, &w.marker) };
    assert_eq!(status(w, &w.b_proof, &replayed), Err(KeepUpError::Witness(WitnessError::Root)));
    for snapshot in 3..=8 {
        assert_eq!(status(w, &w.b_proof, &w.b.answer(snapshot, &w.marker)), Ok(KeepUpStatus::Unspent), "{snapshot}");
    }
    // A's later lists do not pass under B's headers.
    let crossed = KeepUpAnswer { later_blocks: w.a.lists(5, 7), ..w.b.answer(FORK, &w.marker) };
    assert_eq!(status(w, &w.b_proof, &crossed), Err(KeepUpError::LaterBlocks { expected: 4, got: 3 }));
    let mut crossed = w.b.answer(FORK, &w.marker);
    crossed.later_blocks[0] = w.a.lists(5, 5).remove(0);
    assert_eq!(status(w, &w.b_proof, &crossed), Err(KeepUpError::LookupDigest { height: 5 }));
}

#[test]
fn a_spend_kept_on_the_new_branch_stays_spent() {
    let w = world();
    let mut trees = w.trees_on(&w.a, &w.a_proof);
    assert!(matches!(trees.marker_status(&w.marker), MarkerStatus::Spent { appended: Some(3), .. }));

    // C spends number 0 too, one block later, its remainder at leaf 4.
    assert_eq!(
        follow_ok(&mut trees, &w.c_proof, &w.c.blocks(5, 8)),
        Followed::Reorganised { ancestor_height: FORK, disconnected: w.a.hashes(5, 7), connected: 4 }
    );
    assert_eq!(tree_roots(&trees), header_roots(w.c.roots(8)));
    let MarkerStatus::Spent { appended, witness } = trees.marker_status(&w.marker) else {
        panic!("spent on C");
    };
    assert_eq!(appended, Some(4));
    assert_eq!(
        verify_marker_membership(&trees.marker_set().root(), &witness.to_bytes(), w.marker.as_bytes()),
        Ok(SpentMarker { position: 1, appended: Some(4) })
    );
    assert_eq!(
        status(w, &w.c_proof, &w.c.answer(5, &w.marker)),
        Ok(KeepUpStatus::Spent(SpentAt::LaterBlock { height: 6 }))
    );
    assert_eq!(
        status(w, &w.c_proof, &w.c.answer(6, &w.marker)),
        Ok(KeepUpStatus::Spent(SpentAt::Snapshot { set_position: 1, appended: Some(4) }))
    );
}

#[test]
fn a_lighter_or_equal_branch_is_not_followed() {
    let w = world();
    let mut trees = w.trees_on(&w.b, &w.b_proof);
    let before = trees.clone();
    assert_eq!(follow_ok(&mut trees, &w.a_proof, &w.a.blocks(5, 7)), Followed::KeptHeavier { ancestor_height: FORK });
    // Equal work: the first seen stays.
    assert_eq!(follow_ok(&mut trees, &w.d_proof, &w.d.blocks(5, 8)), Followed::KeptHeavier { ancestor_height: FORK });
    assert_eq!(trees, before);
    assert!(matches!(trees.marker_status(&w.marker), MarkerStatus::Unspent { .. }));

    // A proof of the trees' own tip, or behind it, changes nothing.
    assert_eq!(follow_ok(&mut trees, &w.b_proof, &[]), Followed::Unchanged);
    assert_eq!(follow_ok(&mut trees, &w.prefix_proof, &[]), Followed::Unchanged);
    assert_eq!(trees, before);
    // And the long branch extends it.
    assert_eq!(follow_ok(&mut trees, &w.b_long_proof, &w.b_long.blocks(9, 12)), Followed::Extended { connected: 4 });
    assert_eq!(tree_roots(&trees), header_roots(w.b_long.roots(12)));
}

#[test]
fn a_refused_follow_changes_nothing() {
    let w = world();
    let trees = w.trees_on(&w.a, &w.a_proof);
    let try_follow = |proof: &ProvenChain, blocks: &[CanonicalBlock]| {
        let mut copy = trees.clone();
        let result = copy.follow(proof, blocks, &read_roots);
        // Nothing changes on a refusal, the disconnection included.
        assert_eq!(copy, trees, "{result:?}");
        assert!(matches!(copy.marker_status(&w.marker), MarkerStatus::Spent { .. }));
        result
    };

    // A block missing, or out of order.
    let mut missing = w.b.blocks(5, 8);
    missing.pop();
    assert_eq!(try_follow(&w.b_proof, &missing), Err(CanonicalError::Blocks { from: 5, to: 8 }));
    let mut swapped = w.b.blocks(5, 8);
    swapped.swap(1, 2);
    assert_eq!(try_follow(&w.b_proof, &swapped), Err(CanonicalError::Blocks { from: 5, to: 8 }));

    // A block that is not the proof's header: another branch's.
    let mut foreign = w.b.blocks(5, 8);
    foreign[0] = w.d.blocks(5, 5).remove(0);
    assert_eq!(try_follow(&w.b_proof, &foreign), Err(CanonicalError::BlockHash { height: 5 }));

    // The last block's list changed: refused after the others were
    // connected, and still nothing changes.
    let mut tampered = w.b.blocks(5, 8);
    tampered[3].list.coin_markers.push([0x99; 32]);
    tampered[3].appended.push(None);
    assert_eq!(try_follow(&w.b_proof, &tampered), Err(CanonicalError::LookupDigest { height: 8 }));

    // A coin leaf that is not the one the header's coin tree holds.
    let mut leaf = w.b.blocks(5, 8);
    leaf[0].coin_leaves[0] = coin(0xee);
    assert_eq!(try_follow(&w.b_proof, &leaf), Err(CanonicalError::Root { height: 5, root: TreeRoot::CoinTree }));

    // An appended position the header's marker set does not hold.
    let mut appended = w.c.blocks(5, 8);
    appended[1].appended[0] = Some(9);
    assert_eq!(
        try_follow(&w.c_proof, &appended),
        Err(CanonicalError::Root { height: 6, root: TreeRoot::CoinMarker })
    );

    // A coin leaf too many for the list.
    let mut extra = w.b.blocks(5, 8);
    extra[0].coin_leaves.push(coin(0xef));
    assert_eq!(try_follow(&w.b_proof, &extra), Err(CanonicalError::Counts { height: 5 }));

    // Headers without readable roots.
    let mut copy = trees.clone();
    assert_eq!(copy.follow(&w.b_proof, &w.b.blocks(5, 8), &read_nothing), Err(CanonicalError::Roots { height: 5 }));
    assert_eq!(copy, trees);

    // The honest blocks are followed.
    let mut copy = trees.clone();
    assert!(matches!(follow_ok(&mut copy, &w.b_proof, &w.b.blocks(5, 8)), Followed::Reorganised { .. }));
}

#[test]
fn a_fork_out_of_reach_is_refused() {
    let w = world();
    // Two blocks kept above the checkpoint.
    let mut trees = CanonicalTrees::with_window(w.genesis_hash(), 2);
    follow_ok(&mut trees, &w.prefix_proof, &w.prefix.blocks(1, FORK));
    assert_eq!(trees.checkpoint_height(), 2);
    follow_ok(&mut trees, &w.a_proof, &w.a.blocks(5, 7));
    assert_eq!(trees.checkpoint_height(), 5);
    assert_eq!(trees.hash_at(4), None);
    // The trees folded into the checkpoint still reach every root.
    assert_eq!(tree_roots(&trees), header_roots(w.a.roots(7)));
    assert!(matches!(trees.marker_status(&w.marker), MarkerStatus::Spent { appended: Some(3), .. }));

    // B forks at 4, below the checkpoint at 5: refused, and nothing changes.
    let before = trees.clone();
    assert_eq!(
        trees.follow(&w.b_proof, &w.b.blocks(5, 8), &read_roots),
        Err(CanonicalError::TooDeep { checkpoint_height: 5 })
    );
    assert_eq!(trees, before);

    // The design's window of 64 follows the same reorganisation.
    let mut wide = w.trees_on(&w.a, &w.a_proof);
    assert_eq!(wide.checkpoint_height(), 0);
    assert!(matches!(follow_ok(&mut wide, &w.b_proof, &w.b.blocks(5, 8)), Followed::Reorganised { .. }));

    // A proof whose linked headers start above the trees' tip.
    let mut genesis = CanonicalTrees::genesis(w.genesis_hash());
    assert_eq!(genesis.follow(&w.a_proof, &w.a.blocks(1, 7), &read_roots), Err(CanonicalError::NoCommonHeader));
    let mut at_prefix = CanonicalTrees::genesis(w.genesis_hash());
    follow_ok(&mut at_prefix, &w.prefix_proof, &w.prefix.blocks(1, FORK));
    assert_eq!(
        at_prefix.follow(&w.b_long_proof, &w.b_long.blocks(5, 12), &read_roots),
        Err(CanonicalError::NoCommonHeader)
    );
}
