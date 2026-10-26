//! The header chain of `header_chain`: the ASERT rule against spec 06's
//! vectors, and a chain that refuses headers whose seal, difficulty, parent,
//! number, timestamp or key block is wrong, picks the heaviest branch and
//! reports reorganisations; and the headers read back from the caller's own
//! store, which skip the seal and nothing else.
//!
//! The headers are mined at the internal network's test constants
//! (difficulty 1: its genesis difficulty, `D_START = D_MIN = 1`, the 30-second
//! chain's block time, half-life and drift), so most seals pass at any nonce
//! and the tests run quickly. Where a seal must be able to fail, the headers
//! are stamped early on the schedule, which raises the required difficulty.
//!
//! Each RandomX cache takes 256 MiB, so the tests run one at a time.

use std::sync::{Mutex, MutexGuard};

use ghost_client::header_chain::{
    required_difficulty, Added, ChainError, ChainParams, HeaderChain, PinnedStart, StartError, MAX_CACHES, U256,
};
use ghost_client::seal::{meets_target, seal_input, SealError, SealKey, EPOCH_BLOCKS, EPOCH_LAG};
use tiny_keccak::{Hasher, Keccak};

const SPEC: &str = include_str!("../../docs/spec/06-consensus-and-emission.md");

/// The internal network's test constants.
const TEST_CHAIN: ChainParams =
    ChainParams { block_time: 30, half_life: 3600, start_difficulty: 1, min_difficulty: 1, future_drift: 30 };
/// The internal network's genesis timestamp.
const GENESIS_TIME: u64 = 0x6abd_a280;

static ONE_CHAIN_AT_A_TIME: Mutex<()> = Mutex::new(());

fn one_chain() -> MutexGuard<'static, ()> {
    ONE_CHAIN_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// A test-side RLP encoder, written apart from the client's decoder.
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
/// headers of two branches at the same height differ.
#[derive(Clone)]
struct Draft {
    parent: [u8; 32],
    number: u64,
    timestamp: u64,
    difficulty: u64,
    nonce: u64,
    branch: u8,
}

impl Draft {
    fn rlp(&self) -> Vec<u8> {
        let mut coinbase = vec![0u8; 20];
        coinbase[19] = self.branch;
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
            vec![0; 32],
            self.nonce.to_be_bytes().to_vec(),
            int(1_000_000_000),
            vec![0x44; 32],
            vec![0x55; 32],
        ])
    }

    fn hash(&self) -> [u8; 32] {
        keccak(&self.rlp())
    }

    /// The child `seconds` later on the same branch, at difficulty 1.
    fn child(&self, seconds: u64) -> Draft {
        Draft {
            parent: self.hash(),
            number: self.number + 1,
            timestamp: self.timestamp + seconds,
            difficulty: 1,
            nonce: 0,
            branch: self.branch,
        }
    }
}

fn genesis() -> Draft {
    Draft { parent: [0; 32], number: 0, timestamp: GENESIS_TIME, difficulty: 1, nonce: 0, branch: 0 }
}

/// A clock well after every test header.
const LATER: u64 = GENESIS_TIME + 1_000_000_000;

fn genesis_chain() -> HeaderChain {
    HeaderChain::from_genesis(&genesis().rlp(), TEST_CHAIN).unwrap()
}

/// `count` headers after `from` on `branch`, 30 seconds apart.
fn branch(from: &Draft, branch: u8, count: usize) -> Vec<Draft> {
    let mut out: Vec<Draft> = Vec::new();
    for _ in 0..count {
        let mut next = out.last().unwrap_or(from).child(30);
        next.branch = branch;
        out.push(next);
    }
    out
}

/// A synthetic genesis hash for pinned starts above it.
const PINNED_GENESIS_HASH: [u8; 32] = [0x99; 32];

/// A pinned header at `height`, stamped `early` seconds before its place on
/// the schedule, with the genesis hash as its only key block.
fn pinned(height: u64, early: u64) -> (Draft, PinnedStart) {
    let draft = Draft {
        parent: [0x77; 32],
        number: height,
        timestamp: GENESIS_TIME + 30 * height - early,
        difficulty: 1,
        nonce: 0,
        branch: 0,
    };
    let start = PinnedStart {
        header: draft.rlp(),
        height,
        total_work: U256::from(height + 1),
        genesis_timestamp: GENESIS_TIME,
        key_blocks: vec![(0, PINNED_GENESIS_HASH)],
    };
    (draft, start)
}

fn add(chain: &mut HeaderChain, draft: &Draft) -> Result<Added, ChainError> {
    chain.add_header(&draft.rlp(), LATER)
}

/// Whether `draft`'s seal meets its difficulty under `key`, computed here
/// apart from the chain.
fn passes(draft: &Draft, key: &SealKey) -> bool {
    let rlp = draft.rlp();
    meets_target(&key.hash(&seal_input(&rlp).unwrap()), &int(draft.difficulty))
}

/// The table of spec 06, section 4.6: (case, n, ts - genesis, difficulty).
fn spec_vectors() -> Vec<(String, u64, u64, String)> {
    let start = SPEC.find("### 4.6 Test vectors").expect("section 4.6");
    let end = start + SPEC[start..].find("### 4.7").expect("section 4.7");
    let mut out = Vec::new();
    for line in SPEC[start..end].lines() {
        let cells: Vec<String> = line.split('|').map(|c| c.trim().replace(',', "")).collect();
        // A row is `| case | n | ts - genesis | lag | ... | difficulty |`.
        if cells.len() != 11 {
            continue;
        }
        let (Ok(n), Ok(ts)) = (cells[2].parse::<u64>(), cells[3].parse::<u64>()) else { continue };
        out.push((cells[1].clone(), n, ts, cells[9].clone()));
    }
    out
}

#[test]
fn asert_vectors_from_spec_agree() {
    let vectors = spec_vectors();
    assert_eq!(vectors.len(), 17, "spec 06 section 4.6 has 17 vectors");
    let params = ChainParams::THIRTY_SECONDS;
    for (case, n, since_genesis, expected) in vectors {
        let genesis = 1_798_767_600;
        let got = required_difficulty(&params, genesis, n, genesis + since_genesis);
        assert_eq!(got.to_string(), expected, "{case}");
        // The rule depends on the genesis timestamp only through `ts - G`.
        assert_eq!(required_difficulty(&params, 0, n, since_genesis), got, "{case}");
    }

    // The constants are spec 06's, section 4.2.
    for anchor in ["D_START = 16,777,216", "D_MIN = 131,072", "| `TAU` | 3,600 | 3,600 |", "| `FUTURE_DRIFT` | 30 | 30 |"] {
        assert!(SPEC.contains(anchor), "spec 06 does not state {anchor}");
    }
    assert_eq!(
        (params.block_time, params.half_life, params.start_difficulty, params.min_difficulty, params.future_drift),
        (30, 3600, 1 << 24, 1 << 17, 30)
    );
    let sixty = ChainParams::SIXTY_SECONDS;
    assert_eq!(
        (sixty.block_time, sixty.half_life, sixty.start_difficulty, sixty.min_difficulty, sixty.future_drift),
        (60, 3600, 1 << 25, 1 << 17, 30)
    );
    // On the 60-second chain an on-schedule block has D_START, one half-life
    // late half of it and 24 hours late the minimum.
    assert_eq!(required_difficulty(&sixty, 0, 1, 60), U256::from(1 << 25));
    assert_eq!(required_difficulty(&sixty, 0, 1000, 60_000 + 3600), U256::from(1 << 24));
    assert_eq!(required_difficulty(&sixty, 0, 1000, 60_000 + 86_400), U256::from(1 << 17));

    // The test chain: difficulty 1 on or behind schedule, 2 once an hour
    // ahead of it.
    assert_eq!(required_difficulty(&TEST_CHAIN, 0, 1, 30), U256::ONE);
    assert_eq!(required_difficulty(&TEST_CHAIN, 0, 1000, 30_000 - 3590), U256::ONE);
    assert_eq!(required_difficulty(&TEST_CHAIN, 0, 1000, 30_000 - 3619), U256::from(2));
    assert_eq!(required_difficulty(&TEST_CHAIN, 0, 1000, 30_000 - 10_800), U256::from(8));
}

#[test]
fn seal_above_the_target_is_refused() {
    let _one = one_chain();
    // Three half-lives ahead of the schedule: difficulty 8.
    let (pin, start) = pinned(1000, 10_800);
    let mut draft = pin.child(30);
    draft.difficulty = 8;
    assert_eq!(required_difficulty(&TEST_CHAIN, GENESIS_TIME, draft.number, draft.timestamp), U256::from(8));

    let key = SealKey::new(&PINNED_GENESIS_HASH);
    let mut above = draft.clone();
    while passes(&above, &key) {
        above.nonce += 1;
    }
    let mut sealed = draft.clone();
    while !passes(&sealed, &key) {
        sealed.nonce += 1;
    }
    drop(key);

    let mut chain = HeaderChain::from_pinned(start, TEST_CHAIN).unwrap();
    assert_eq!(add(&mut chain, &above), Err(ChainError::Seal(SealError::AboveTarget)));
    assert!(!chain.contains(&above.hash()));
    assert_eq!(chain.best_hash(), pin.hash());
    assert_eq!(add(&mut chain, &sealed), Ok(Added::Extended));
    assert_eq!(chain.best_hash(), sealed.hash());
    assert_eq!(chain.best_total_work(), U256::from(1001 + 8));
}

#[test]
fn wrong_difficulty_is_refused() {
    let _one = one_chain();
    let mut chain = genesis_chain();
    let one = genesis().child(30);
    for difficulty in [0, 2, 1 << 17] {
        let wrong = Draft { difficulty, ..one.clone() };
        assert_eq!(add(&mut chain, &wrong), Err(ChainError::Difficulty), "difficulty {difficulty}");
    }
    assert_eq!(add(&mut chain, &one), Ok(Added::Extended));

    // Exactly the required difficulty, not "at least": 7 and 9 are refused
    // where 8 is required, before any cache is built.
    let (pin, start) = pinned(1000, 10_800);
    let mut chain = HeaderChain::from_pinned(start, TEST_CHAIN).unwrap();
    for difficulty in [1, 7, 9, 16] {
        let wrong = Draft { difficulty, ..pin.child(30) };
        assert_eq!(add(&mut chain, &wrong), Err(ChainError::Difficulty), "difficulty {difficulty}");
    }
    assert_eq!(chain.cache_count(), 0);
}

#[test]
fn lighter_competing_chain_stays_a_side_branch() {
    let _one = one_chain();
    let mut chain = genesis_chain();
    let main = branch(&genesis(), 0, 4);
    for draft in &main {
        assert_eq!(add(&mut chain, draft), Ok(Added::Extended));
    }
    // A branch from block 1, two headers long: lighter.
    let side = branch(&main[0], 1, 3);
    assert_eq!(add(&mut chain, &side[0]), Ok(Added::SideBranch));
    assert_eq!(add(&mut chain, &side[1]), Ok(Added::SideBranch));
    assert_eq!(chain.best_hash(), main[3].hash());
    assert_eq!(chain.total_work(&side[1].hash()), Some(U256::from(4)));
    assert_eq!(chain.best_total_work(), U256::from(5));
    // As heavy as the best chain: the first seen stays best.
    assert_eq!(add(&mut chain, &side[2]), Ok(Added::SideBranch));
    assert_eq!(chain.total_work(&side[2].hash()), chain.total_work(&main[3].hash()));
    assert_eq!(chain.best_hash(), main[3].hash());
    assert_eq!(chain.best_hash_at(2), Some(main[1].hash()));
    assert_eq!(chain.confirmations(&main[0].hash()), Some(4));
    assert_eq!(chain.confirmations(&side[0].hash()), None);
    // Offered again, a held header changes nothing.
    assert_eq!(add(&mut chain, &side[1]), Ok(Added::AlreadyHeld));
    assert_eq!(add(&mut chain, &main[3]), Ok(Added::AlreadyHeld));
    assert_eq!(chain.best_hash(), main[3].hash());
}

#[test]
fn heavier_side_branch_reorganises() {
    let _one = one_chain();
    let mut chain = genesis_chain();
    let main = branch(&genesis(), 0, 3);
    for draft in &main {
        assert_eq!(add(&mut chain, draft), Ok(Added::Extended));
    }
    let side = branch(&main[0], 1, 3);
    assert_eq!(add(&mut chain, &side[0]), Ok(Added::SideBranch));
    assert_eq!(add(&mut chain, &side[1]), Ok(Added::SideBranch));
    // Blocks 2 and 3 of the old best chain leave it; blocks 2, 3 and 4 of
    // the branch join it.
    assert_eq!(add(&mut chain, &side[2]), Ok(Added::Reorganised { removed: 2, added: 3 }));
    assert_eq!(chain.best_hash(), side[2].hash());
    assert_eq!(chain.best_height(), 4);
    assert_eq!(chain.best_total_work(), U256::from(5));
    assert_eq!(chain.best_hash_at(1), Some(main[0].hash()));
    assert_eq!(chain.best_hash_at(2), Some(side[0].hash()));
    assert_eq!(chain.confirmations(&main[2].hash()), None);
    assert_eq!(chain.confirmations(&side[0].hash()), Some(3));
    assert_eq!(chain.header(&side[2].hash()), Some(side[2].rlp().as_slice()));

    // The old branch overtakes again, from further down: a branch from
    // genesis five headers long removes four and adds five.
    let deep = branch(&genesis(), 2, 5);
    for draft in &deep[..4] {
        assert_eq!(add(&mut chain, draft), Ok(Added::SideBranch));
    }
    assert_eq!(add(&mut chain, &deep[4]), Ok(Added::Reorganised { removed: 4, added: 5 }));
    assert_eq!(chain.best_hash(), deep[4].hash());
    // Extending the new best chain is an extension again.
    assert_eq!(add(&mut chain, &deep[4].child(30)), Ok(Added::Extended));
}

#[test]
fn unknown_parent_wrong_number_and_early_timestamp_are_refused() {
    let _one = one_chain();
    let mut chain = genesis_chain();
    let one = genesis().child(30);

    let orphan = Draft { parent: [0x42; 32], ..one.clone() };
    assert_eq!(add(&mut chain, &orphan), Err(ChainError::UnknownParent));
    // A header two above a held one, its parent missing.
    assert_eq!(add(&mut chain, &one.child(30)), Err(ChainError::UnknownParent));

    for number in [0, 2, 3] {
        let wrong = Draft { number, ..one.clone() };
        assert_eq!(add(&mut chain, &wrong), Err(ChainError::Number), "number {number}");
    }
    for timestamp in [GENESIS_TIME, GENESIS_TIME - 1] {
        let wrong = Draft { timestamp, ..one.clone() };
        assert_eq!(add(&mut chain, &wrong), Err(ChainError::TimestampNotAfterParent));
    }
    let mut broken = one.rlp();
    broken.push(0);
    assert!(matches!(chain.add_header(&broken, LATER), Err(ChainError::Header(_))));
    assert_eq!(chain.best_hash(), chain.start_hash());

    // One second after the parent is enough.
    let soon = Draft { timestamp: GENESIS_TIME + 1, ..one.clone() };
    assert_eq!(add(&mut chain, &soon), Ok(Added::Extended));

    // Too far ahead of the clock is reported as such, not held, and accepted
    // once the clock catches up.
    let ahead = soon.child(30);
    assert_eq!(chain.add_header(&ahead.rlp(), ahead.timestamp - 31), Err(ChainError::TooFarAhead));
    assert!(!chain.contains(&ahead.hash()));
    assert_eq!(chain.add_header(&ahead.rlp(), ahead.timestamp - 30), Ok(Added::Extended));
    // Too far ahead and wrong in another way: the other reason is reported.
    let bad = Draft { difficulty: 2, ..ahead.child(30) };
    assert_eq!(chain.add_header(&bad.rlp(), GENESIS_TIME), Err(ChainError::Difficulty));
}

#[test]
fn missing_key_block_is_refused() {
    let _one = one_chain();
    let (pin, mut start) = pinned(1000, 0);
    start.key_blocks.clear();
    let mut chain = HeaderChain::from_pinned(start.clone(), TEST_CHAIN).unwrap();
    assert_eq!(add(&mut chain, &pin.child(30)), Err(ChainError::MissingKeyBlock));
    assert_eq!(chain.cache_count(), 0);

    // The pin's own checks.
    let bad = |edit: &dyn Fn(&mut PinnedStart)| {
        let mut start = start.clone();
        edit(&mut start);
        HeaderChain::from_pinned(start, TEST_CHAIN).err()
    };
    assert_eq!(bad(&|s| s.height = 999), Some(StartError::Height));
    assert_eq!(bad(&|s| s.total_work = U256::ZERO), Some(StartError::Work));
    assert_eq!(bad(&|s| s.key_blocks = vec![(100, [1; 32])]), Some(StartError::KeyBlock));
    assert_eq!(bad(&|s| s.key_blocks = vec![(0, [1; 32]), (0, [2; 32])]), Some(StartError::KeyBlock));
    assert_eq!(bad(&|s| s.key_blocks = vec![(EPOCH_BLOCKS, [1; 32])]), Some(StartError::KeyBlock));
    let genesis_at_two = Draft { difficulty: 2, ..genesis() };
    assert_eq!(HeaderChain::from_genesis(&genesis_at_two.rlp(), TEST_CHAIN).err(), Some(StartError::GenesisDifficulty));
    assert_eq!(HeaderChain::from_genesis(&pin.rlp(), TEST_CHAIN).err(), Some(StartError::NotGenesis));
}

/// A header read back from the caller's own store skips the RandomX seal and
/// nothing else: one whose seal fails is adopted, but a wrong difficulty, an
/// unknown parent, a wrong number, a timestamp not after the parent's and one
/// too far ahead are still refused, and the total work is the one
/// `add_header` gives.
#[test]
fn saved_header_skips_only_the_seal() {
    let _one = one_chain();
    // Three half-lives ahead of the schedule: difficulty 8.
    let (pin, start) = pinned(1000, 10_800);
    let draft = Draft { difficulty: 8, ..pin.child(30) };
    let key = SealKey::new(&PINNED_GENESIS_HASH);
    let mut above = draft.clone();
    while passes(&above, &key) {
        above.nonce += 1;
    }
    let mut sealed = draft.clone();
    while !passes(&sealed, &key) {
        sealed.nonce += 1;
    }
    drop(key);

    let mut checked = HeaderChain::from_pinned(start.clone(), TEST_CHAIN).unwrap();
    assert_eq!(add(&mut checked, &above), Err(ChainError::Seal(SealError::AboveTarget)));
    assert_eq!(add(&mut checked, &sealed), Ok(Added::Extended));

    let mut saved = HeaderChain::from_pinned(start.clone(), TEST_CHAIN).unwrap();
    let refused = |chain: &mut HeaderChain, d: &Draft| chain.add_saved_header(&d.rlp(), LATER);
    for difficulty in [1, 7, 9] {
        let wrong = Draft { difficulty, ..sealed.clone() };
        assert_eq!(refused(&mut saved, &wrong), Err(ChainError::Difficulty), "difficulty {difficulty}");
    }
    let orphan = Draft { parent: [0x42; 32], ..sealed.clone() };
    assert_eq!(refused(&mut saved, &orphan), Err(ChainError::UnknownParent));
    for number in [1000, 1002] {
        let wrong = Draft { number, ..sealed.clone() };
        assert_eq!(refused(&mut saved, &wrong), Err(ChainError::Number), "number {number}");
    }
    for timestamp in [pin.timestamp, pin.timestamp - 1] {
        let wrong = Draft { timestamp, ..sealed.clone() };
        assert_eq!(refused(&mut saved, &wrong), Err(ChainError::TimestampNotAfterParent));
    }
    assert_eq!(saved.add_saved_header(&sealed.rlp(), sealed.timestamp - 31), Err(ChainError::TooFarAhead));
    let mut broken = sealed.rlp();
    broken.push(0);
    assert!(matches!(saved.add_saved_header(&broken, LATER), Err(ChainError::Header(_))));
    assert_eq!(saved.best_hash(), pin.hash(), "nothing refused is held");

    // The seal that fails is not checked here, and no RandomX cache is built.
    assert_eq!(refused(&mut saved, &above), Ok(Added::Extended));
    assert_eq!(saved.cache_count(), 0);
    assert_eq!(saved.best_total_work(), U256::from(1001 + 8));

    // The valid header: the same total work as add_header's.
    let mut again = HeaderChain::from_pinned(start, TEST_CHAIN).unwrap();
    assert_eq!(again.add_saved_header(&sealed.rlp(), LATER), Ok(Added::Extended));
    assert_eq!(again.best_total_work(), checked.best_total_work());
    assert_eq!(again.best_hash(), checked.best_hash());
    assert_eq!(again.add_saved_header(&sealed.rlp(), LATER), Ok(Added::AlreadyHeld));
}

/// Saved headers re-link by parent hash to a pinned start: the best chain's
/// height, tip and total work are those `add_header` gives, a saved header
/// that does not follow the ones held is refused, and the next header from
/// the endpoint is checked in full on top of them.
#[test]
fn saved_headers_relink_to_the_pin() {
    let _one = one_chain();
    let (pin, start) = pinned(1000, 0);
    let headers = branch(&pin, 0, 12);
    let (saved_part, next) = (&headers[..11], &headers[11]);

    let mut checked = HeaderChain::from_pinned(start.clone(), TEST_CHAIN).unwrap();
    for draft in saved_part {
        assert_eq!(add(&mut checked, draft), Ok(Added::Extended));
    }

    let mut saved = HeaderChain::from_pinned(start, TEST_CHAIN).unwrap();
    // Out of order, a saved header has no parent held yet.
    assert_eq!(saved.add_saved_header(&saved_part[1].rlp(), LATER), Err(ChainError::UnknownParent));
    for draft in saved_part {
        assert_eq!(saved.add_saved_header(&draft.rlp(), LATER), Ok(Added::Extended));
    }
    assert_eq!(saved.cache_count(), 0, "no seal was checked");
    assert_eq!(saved.best_height(), checked.best_height());
    assert_eq!(saved.best_height(), 1011);
    assert_eq!(saved.best_hash(), checked.best_hash());
    assert_eq!(saved.best_total_work(), checked.best_total_work());
    assert_eq!(saved.best_total_work(), U256::from(1001 + 11));
    assert_eq!(saved.best_hash_at(1000), Some(pin.hash()));
    assert_eq!(saved.confirmations(&saved_part[0].hash()), Some(11));

    // A header whose parent hash is not the saved one before it.
    let stray = Draft { parent: [0x42; 32], ..next.clone() };
    assert_eq!(saved.add_saved_header(&stray.rlp(), LATER), Err(ChainError::UnknownParent));

    // Above the saved tip the seal is checked again, under the pinned key block.
    assert_eq!(add(&mut saved, next), Ok(Added::Extended));
    assert_eq!(saved.cached_keys(), vec![PINNED_GENESIS_HASH]);
    assert_eq!(saved.best_total_work(), U256::from(1001 + 12));
}

/// Spec 08 section 8: the key of a header past `E + L` is the key block on
/// its own branch. Two branches fork below key block `E`; a header on one
/// branch sealed under the other branch's key block is refused, and the same
/// header sealed under its own branch's key block is accepted.
#[test]
fn key_block_not_on_its_own_branch_is_refused() {
    let _one = one_chain();
    let first_keyed = EPOCH_BLOCKS + EPOCH_LAG + 1;
    // Pinned just below the key block, 3590 seconds ahead of the schedule:
    // difficulty 1 while the branch keeps the schedule.
    let (pin, start) = pinned(EPOCH_BLOCKS - 1, 3590);
    let a = branch(&pin, 0xa, 1);
    let b = branch(&pin, 0xb, (first_keyed - EPOCH_BLOCKS) as usize);
    assert_eq!(b.last().unwrap().number, first_keyed - 1);
    // One second after its parent the last header is 3619 seconds ahead:
    // difficulty 2, so a seal under the wrong key can fail.
    let last = Draft { difficulty: 2, ..b.last().unwrap().child(1) };
    assert_eq!(last.number, first_keyed);
    assert_eq!(required_difficulty(&TEST_CHAIN, GENESIS_TIME, last.number, last.timestamp), U256::from(2));
    let (key_a, key_b) = (a[0].hash(), b[0].hash());

    let nonces = 0..32u64;
    let with = |nonce| Draft { nonce, ..last.clone() };
    let key = SealKey::new(&key_a);
    let under_a: Vec<bool> = nonces.clone().map(|n| passes(&with(n), &key)).collect();
    drop(key);
    let key = SealKey::new(&key_b);
    let under_b: Vec<bool> = nonces.clone().map(|n| passes(&with(n), &key)).collect();
    drop(key);
    let wrong_key = with(nonces.clone().find(|&n| under_a[n as usize] && !under_b[n as usize]).unwrap());
    let own_key = with(nonces.clone().find(|&n| under_b[n as usize]).unwrap());

    let mut chain = HeaderChain::from_pinned(start, TEST_CHAIN).unwrap();
    assert_eq!(add(&mut chain, &a[0]), Ok(Added::Extended));
    assert_eq!(add(&mut chain, &b[0]), Ok(Added::SideBranch));
    assert_eq!(add(&mut chain, &b[1]), Ok(Added::Reorganised { removed: 1, added: 2 }));
    for draft in &b[2..] {
        assert_eq!(add(&mut chain, draft), Ok(Added::Extended));
    }
    assert_eq!(chain.cached_keys(), vec![PINNED_GENESIS_HASH]);

    assert_eq!(add(&mut chain, &wrong_key), Err(ChainError::Seal(SealError::AboveTarget)));
    assert!(!chain.contains(&wrong_key.hash()));
    assert_eq!(add(&mut chain, &own_key), Ok(Added::Extended));
    assert_eq!(chain.best_hash(), own_key.hash());
    assert_eq!(chain.cached_keys(), vec![key_b, PINNED_GENESIS_HASH]);
    assert!(chain.cache_count() <= MAX_CACHES);
}
