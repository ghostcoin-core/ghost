//! The checks of a restore by private lookup before use, and the decision
//! (stage 2 design, "Wallet restore volume", "What a wallet does", steps 5
//! and 6): a wrong note, a wrong witness, a stale snapshot header and a
//! tampered bulk list are each refused; the current commitment is decided,
//! a spent marker continues in a second session, and a key that never
//! committed gets an absence witness.

use std::collections::HashMap;

use ghost_client::commit::{Amount, Rule, Salt};
use ghost_client::hash::keccak256;
use ghost_client::lookup::{key_lookup_tag, BlockLookupList, CoinMarkerSet, LookupIndex, LookupTag, LookupTree};
use ghost_client::note::{encrypt_note, Capsule, NoteContents, NOTE_BYTES};
use ghost_client::restore_checks::{
    check_anchor, check_session, continue_requests, empty_leaf, header_roots, restore_with_checks, Anchor,
    CheckError, Decision, NextFrom, RecordTree, TreeRecords, COIN_TREE_DEPTH,
};
use ghost_client::restore_requests::{
    hint_bucket, plan, restore_requests, Answer, Database, LookupHint, LookupSource, MarkerHint, QueryKind, Request,
    MINIPAGE_LEAVES, PAGE_LEAVES, PROBES, QUERIES,
};
use ghost_client::{KeyFormat, PhantomKey};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// A test chain id.
const CHAIN_ID: u64 = 7357;

// ---------------------------------------------------------------------------
// A fake chain
// ---------------------------------------------------------------------------

/// One coin of a key on the fake chain.
struct Coin {
    number: u64,
    position: u64,
    marker: [u8; 32],
}

/// The coin tree's leaves with their tags and notes, and the coin spends in
/// order, each with the leaf its reveal appended.
#[derive(Clone, Default)]
struct Chain {
    leaves: Vec<[u8; 32]>,
    tags: Vec<LookupTag>,
    notes: HashMap<u64, [u8; NOTE_BYTES]>,
    spends: Vec<([u8; 32], Option<u64>)>,
}

impl Chain {
    fn append(&mut self, tag: LookupTag, leaf: [u8; 32], note: [u8; NOTE_BYTES]) -> u64 {
        let position = self.leaves.len() as u64;
        self.leaves.push(leaf);
        self.tags.push(tag);
        self.notes.insert(position, note);
        position
    }

    /// A stranger's leaf, tag and note.
    fn noise(&mut self, rng: &mut StdRng) {
        let mut tag = [0u8; 16];
        let mut leaf = [0u8; 32];
        let mut note = [0u8; NOTE_BYTES];
        rng.fill_bytes(&mut tag);
        rng.fill_bytes(&mut leaf);
        rng.fill_bytes(&mut note);
        self.append(tag, leaf, note);
    }

    /// Strangers' spends.
    fn spend_noise(&mut self, count: usize, rng: &mut StdRng) {
        for _ in 0..count {
            let mut marker = [0u8; 32];
            rng.fill_bytes(&mut marker);
            self.spends.push((marker, None));
        }
    }

    /// Commitment `number` of `key`, with its real leaf, tag and note.
    fn add_coin(&mut self, key: &PhantomKey, number: u64, rng: &mut StdRng) -> Coin {
        let salt = Salt::random(rng);
        let amount = Amount::new(1000 + u128::from(number)).unwrap();
        let commit = key.coin_commit_with_salt(number, amount, Rule::EMPTY, salt).unwrap();
        let contents = NoteContents::salted_coin(number, amount, Rule::EMPTY, salt);
        let note = encrypt_note(&key.note_key(), CHAIN_ID, &commit.commitment, &contents, &Capsule::empty(), rng);
        let position = self.append(key_lookup_tag(key, number), *commit.commitment.as_bytes(), note);
        Coin {
            number,
            position,
            marker: *commit.marker.as_bytes(),
        }
    }

    /// Commitments 0 to `hops` of `key`, each spent by the reveal that
    /// appended the next, the last unspent, with strangers between.
    fn add_key(&mut self, key: &PhantomKey, hops: u64, rng: &mut StdRng) -> Vec<Coin> {
        let mut coins: Vec<Coin> = Vec::new();
        for number in 0..=hops {
            self.noise(rng);
            let coin = self.add_coin(key, number, rng);
            if let Some(previous) = coins.last() {
                self.spends.push((previous.marker, Some(coin.position)));
            }
            self.spend_noise(3, rng);
            coins.push(coin);
        }
        coins
    }

    fn coin_records(&self) -> TreeRecords {
        TreeRecords::coin_tree(&self.leaves)
    }

    fn index(&self) -> LookupIndex {
        LookupIndex::from_entries(LookupTree::Coin, self.tags.iter().copied().zip(0u64..)).unwrap()
    }

    fn set(&self) -> CoinMarkerSet {
        CoinMarkerSet::from_spends(self.spends.iter().copied()).unwrap()
    }
}

/// The roots a header carries for a chain.
#[derive(Clone, Copy)]
struct Roots {
    coin_tree: [u8; 32],
    coin_lookup: [u8; 32],
    coin_marker: [u8; 32],
}

fn roots(chain: &Chain) -> Roots {
    Roots {
        coin_tree: chain.coin_records().root(),
        coin_lookup: chain.index().root(),
        coin_marker: chain.set().root(),
    }
}

// ---------------------------------------------------------------------------
// A fake restore server
// ---------------------------------------------------------------------------

type Tamper = Box<dyn FnMut(&Request, &mut Answer)>;

/// A restore server: the public tables and records a full node builds,
/// answered in the clear, with an optional hook that changes answers.
struct FakeServer {
    lookup_buckets: u64,
    marker_buckets: u64,
    lookup_hints: Vec<LookupHint>,
    marker_hints: Vec<MarkerHint>,
    overflow: Vec<LookupHint>,
    notes: HashMap<u64, [u8; NOTE_BYTES]>,
    coin: TreeRecords,
    markers: TreeRecords,
    lookup: TreeRecords,
    tamper: Option<Tamper>,
}

impl FakeServer {
    fn new(chain: &Chain) -> Self {
        Self::with_buckets(chain, 64, 32)
    }

    fn with_buckets(chain: &Chain, lookup_buckets: u64, marker_buckets: u64) -> Self {
        let index = chain.index();
        let set = chain.set();
        let lookup_hints = index
            .leaves()
            .iter()
            .zip(0u64..)
            .map(|(leaf, index_position)| LookupHint {
                tag: leaf.tag,
                position: leaf.position,
                index_position,
            })
            .collect();
        let marker_hints = set
            .leaves()
            .iter()
            .zip(0u64..)
            .map(|(leaf, set_position)| MarkerHint {
                marker: leaf.value,
                set_position,
            })
            .collect();
        Self {
            lookup_buckets,
            marker_buckets,
            lookup_hints,
            marker_hints,
            overflow: Vec::new(),
            notes: chain.notes.clone(),
            coin: chain.coin_records(),
            markers: TreeRecords::marker_set(&set),
            lookup: TreeRecords::lookup_index(&index),
            tamper: None,
        }
    }

    fn tamper(mut self, hook: impl FnMut(&Request, &mut Answer) + 'static) -> Self {
        self.tamper = Some(Box::new(hook));
        self
    }

    /// The entries of one bucket and the entry just before it in key order.
    fn bucket<T: Copy, K: Ord + AsRef<[u8]>>(
        entries: &[T],
        key: impl Fn(&T) -> K,
        buckets: u64,
        bucket: u64,
    ) -> Vec<T> {
        let mut out: Vec<T> = entries
            .iter()
            .filter(|entry| hint_bucket(key(*entry).as_ref(), buckets) == bucket)
            .copied()
            .collect();
        if let Some(before) = entries
            .iter()
            .filter(|entry| hint_bucket(key(*entry).as_ref(), buckets) < bucket)
            .max_by_key(|entry| key(*entry))
        {
            out.push(*before);
        }
        out
    }
}

impl LookupSource for FakeServer {
    fn records(&self, database: Database) -> u64 {
        match database {
            Database::LookupHints => self.lookup_buckets,
            Database::HintOverflow => 8,
            Database::MarkerHints => self.marker_buckets,
            Database::Notes => 1 << 20,
            Database::CoinLeaves | Database::MarkerLeaves | Database::LookupLeaves => (1 << 20) / MINIPAGE_LEAVES,
            Database::CoinPages | Database::MarkerPages | Database::LookupPages => (1 << 20) / PAGE_LEAVES,
        }
    }

    fn fetch(&mut self, request: &Request) -> Answer {
        assert!(request.record < self.records(request.query.database), "record beyond the database");
        let record = request.record;
        let mut answer = match request.query.database {
            Database::LookupHints => {
                Answer::LookupHints(Self::bucket(&self.lookup_hints, |hint| hint.tag, self.lookup_buckets, record))
            }
            Database::HintOverflow => Answer::LookupHints(Self::bucket(&self.overflow, |hint| hint.tag, 8, record)),
            Database::MarkerHints => {
                Answer::MarkerHints(Self::bucket(&self.marker_hints, |hint| hint.marker, self.marker_buckets, record))
            }
            Database::Notes => {
                Answer::Note(self.notes.get(&record).map_or_else(|| vec![0; NOTE_BYTES], |note| note.to_vec()))
            }
            Database::CoinLeaves => self.coin.minipage(record),
            Database::CoinPages => Answer::Record(self.coin.page(record)),
            Database::MarkerLeaves => self.markers.minipage(record),
            Database::MarkerPages => Answer::Record(self.markers.page(record)),
            Database::LookupLeaves => self.lookup.minipage(record),
            Database::LookupPages => Answer::Record(self.lookup.page(record)),
        };
        if let Some(hook) = self.tamper.as_mut() {
            hook(request, &mut answer);
        }
        answer
    }
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

fn rlp_string(bytes: &[u8]) -> Vec<u8> {
    match bytes.len() {
        1 if bytes[0] < 0x80 => bytes.to_vec(),
        len if len < 56 => [&[0x80 + len as u8][..], bytes].concat(),
        len => {
            let digits: Vec<u8> = (len as u32).to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
            [&[0xb7 + digits.len() as u8][..], &digits, bytes].concat()
        }
    }
}

fn rlp_int(value: u64) -> Vec<u8> {
    let bytes: Vec<u8> = value.to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
    rlp_string(&bytes)
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload = items.concat();
    let digits: Vec<u8> = (payload.len() as u32).to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
    if payload.len() < 56 {
        [&[0xc0 + payload.len() as u8][..], &payload].concat()
    } else {
        [&[0xf7 + digits.len() as u8][..], &digits, &payload].concat()
    }
}

/// A header of `fields` items (19, 23 or 24) at `number` on `parent`.
fn header_with(fields: usize, parent: [u8; 32], number: u64, roots: Roots, lookup_digest: [u8; 32]) -> Vec<u8> {
    let mut items = vec![
        rlp_string(&parent),
        rlp_string(&[0; 32]),
        rlp_string(&[0; 20]),
        rlp_string(&[0; 32]),
        rlp_string(&[0; 32]),
        rlp_string(&[0; 32]),
        rlp_string(&[0; 256]),
        rlp_int(1),
        rlp_int(number),
        rlp_int(30_000_000),
        rlp_int(0),
        rlp_int(1_000 + number),
        rlp_string(&[]),
        rlp_string(&[0; 32]),
        rlp_string(&[0; 8]),
        rlp_int(1),
        rlp_string(&roots.coin_tree),
        rlp_string(&[0; 32]),
        rlp_string(&[0; 32]),
        rlp_string(&roots.coin_lookup),
        rlp_string(&[0; 32]),
        rlp_string(&roots.coin_marker),
        rlp_string(&lookup_digest),
        rlp_string(&[0x33; 32]),
    ];
    items.truncate(fields);
    rlp_list(&items)
}

fn header(parent: [u8; 32], number: u64, roots: Roots, lookup_digest: [u8; 32]) -> Vec<u8> {
    header_with(23, parent, number, roots, lookup_digest)
}

/// A checked tail: `before` headers, the snapshot header carrying `roots`,
/// then one header for each later list carrying its digest. Returns the tail
/// and the snapshot header.
fn tail_with(roots: Roots, before: usize, later: &[BlockLookupList]) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut tail: Vec<Vec<u8>> = Vec::new();
    let mut parent = [0u8; 32];
    let mut number = 1000;
    for _ in 0..before {
        let next = header(parent, number, roots, [0x44; 32]);
        parent = keccak256(&next);
        number += 1;
        tail.push(next);
    }
    let snapshot = header(parent, number, roots, [0x55; 32]);
    parent = keccak256(&snapshot);
    tail.push(snapshot.clone());
    for list in later {
        number += 1;
        let next = header(parent, number, roots, list.digest().unwrap());
        parent = keccak256(&next);
        tail.push(next);
    }
    (tail, snapshot)
}

/// Strangers' tags and markers of `count` later blocks.
fn later_blocks(count: usize, start: u64, rng: &mut StdRng) -> Vec<BlockLookupList> {
    (0..count as u64)
        .map(|block| {
            let mut list = BlockLookupList {
                coin_start: start + 3 * block,
                data_start: 0,
                ..BlockLookupList::default()
            };
            for _ in 0..3 {
                let mut tag = [0u8; 16];
                rng.fill_bytes(&mut tag);
                list.coin_tags.push(tag);
                let mut marker = [0u8; 32];
                rng.fill_bytes(&mut marker);
                list.coin_markers.push(marker);
            }
            list
        })
        .collect()
}

fn anchor_for(chain: &Chain, later: &[BlockLookupList]) -> Anchor {
    let (tail, snapshot) = tail_with(roots(chain), 5, later);
    check_anchor(&tail, &snapshot, later).unwrap()
}

// ---------------------------------------------------------------------------
// Worlds
// ---------------------------------------------------------------------------

fn key(rng: &mut StdRng) -> PhantomKey {
    PhantomKey::generate(KeyFormat::Words, rng)
}

/// A chain holding a key of `hops` hops among strangers.
fn world(seed: u64, hops: u64) -> (PhantomKey, Vec<Coin>, Chain, StdRng) {
    let mut rng = StdRng::seed_from_u64(seed);
    let wallet = key(&mut rng);
    let mut chain = Chain::default();
    let stranger = key(&mut rng);
    chain.add_key(&stranger, 2, &mut rng);
    let coins = chain.add_key(&wallet, hops, &mut rng);
    for _ in 0..40 {
        chain.noise(&mut rng);
    }
    chain.spend_noise(20, &mut rng);
    (wallet, coins, chain, rng)
}

fn first_session(
    key: &PhantomKey,
    anchor: &Anchor,
    server: &mut FakeServer,
    rng: &mut StdRng,
) -> Result<Decision, CheckError> {
    let requests = restore_requests(key, CHAIN_ID, server, rng);
    check_session(key, CHAIN_ID, anchor, &requests)
}

fn refusal(result: Result<Decision, CheckError>) -> CheckError {
    match result {
        Ok(decision) => panic!("accepted: {decision:?}"),
        Err(error) => error,
    }
}

/// Flips one byte of an answer of `database`, in a record answer at `at`
/// bytes from its end.
fn flip_record(database: Database, at: usize) -> impl FnMut(&Request, &mut Answer) {
    move |request, answer| {
        if request.query.database == database {
            if let Answer::Record(bytes) = answer {
                let len = bytes.len();
                bytes[len - at] ^= 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn the_records_rebuild_the_header_roots() {
    let (wallet, coins, chain, _) = world(0x2ec_0, 3);
    let index = chain.index();
    let set = chain.set();
    assert_eq!(TreeRecords::lookup_index(&index).root(), index.root());
    assert_eq!(TreeRecords::marker_set(&set).root(), set.root());
    assert_eq!(RecordTree::Coin.page_record_bytes(), 32 * (64 + 20));
    assert_eq!(RecordTree::CoinMarkerSet.page_record_bytes(), 32 * (64 + 28));

    // The coin tree's root is the one the proofs crate folds a leaf to.
    let records = chain.coin_records();
    let coin = &coins[3];
    let Answer::Leaves(minipage) = records.minipage(coin.position / MINIPAGE_LEAVES) else {
        panic!("a coin minipage is its leaves");
    };
    assert_eq!(minipage.len(), 64);
    assert_eq!(minipage[(coin.position % MINIPAGE_LEAVES) as usize], chain.leaves[coin.position as usize]);
    assert!(minipage[chain.leaves.len() % 64..].iter().all(|leaf| *leaf == empty_leaf()));
    let anchor = anchor_for(&chain, &[]);
    let mut server = FakeServer::new(&chain);
    let decision = first_session(&wallet, &anchor, &mut server, &mut StdRng::seed_from_u64(1));
    let Ok(Decision::Current(current)) = decision else {
        panic!("the current coin");
    };
    let root = ghost_proofs::merkle_root(
        ghost_proofs::Tree::Coin,
        &chain.leaves[coin.position as usize],
        coin.position as u32,
        &current.path,
    );
    assert_eq!(root, records.root());
    assert_eq!(current.path.len(), COIN_TREE_DEPTH);
}

#[test]
fn an_honest_restore_finds_the_current_coin_in_one_session() {
    let (wallet, coins, chain, mut rng) = world(0x0_c0, 6);
    let later = later_blocks(3, chain.leaves.len() as u64, &mut rng);
    let anchor = anchor_for(&chain, &later);
    let mut server = FakeServer::new(&chain);
    let restored = restore_with_checks(&wallet, CHAIN_ID, &anchor, &mut server, &mut rng).unwrap();
    assert_eq!(restored.sessions, 1);
    let Decision::Current(current) = restored.decision else {
        panic!("not current: {:?}", restored.decision);
    };
    assert_eq!(current.coin.number, coins[6].number);
    assert_eq!(current.coin.number, 6);
    assert_eq!(u64::from(current.coin.position), coins[6].position);
    assert_eq!(current.coin.marker.as_bytes(), &coins[6].marker);
    assert_eq!(current.snapshot_height, 1005);
    assert_eq!(current.coin_tree_root, roots(&chain).coin_tree);
    assert_eq!(anchor.later().len(), 3);
}

#[test]
fn a_wrong_note_is_refused() {
    let (wallet, coins, chain, mut rng) = world(0x0_bad, 4);
    let anchor = anchor_for(&chain, &[]);
    let current = coins[4].position;

    // One byte of the current note changed.
    let mut server = FakeServer::new(&chain);
    server.notes.get_mut(&current).unwrap()[100] ^= 1;
    assert_eq!(refusal(first_session(&wallet, &anchor, &mut server, &mut rng)), CheckError::Note);

    // The key's own note of another number, served at this leaf: it is bound
    // to its own leaf and does not open here.
    let mut server = FakeServer::new(&chain);
    let other = chain.notes[&coins[3].position];
    server.notes.insert(current, other);
    assert_eq!(refusal(first_session(&wallet, &anchor, &mut server, &mut rng)), CheckError::Note);

    // A stranger's note.
    let mut server = FakeServer::new(&chain);
    let stranger = chain.notes[&0];
    server.notes.insert(current, stranger);
    assert_eq!(refusal(first_session(&wallet, &anchor, &mut server, &mut rng)), CheckError::Note);

    // A note cut short is a missing item.
    let mut server = FakeServer::new(&chain).tamper(|request, answer| {
        if request.query.kind == QueryKind::Note {
            *answer = Answer::Note(vec![0; 10]);
        }
    });
    assert_eq!(
        refusal(first_session(&wallet, &anchor, &mut server, &mut rng)),
        CheckError::Missing(QueryKind::Note)
    );

    // The untouched server is accepted.
    let mut server = FakeServer::new(&chain);
    assert!(matches!(first_session(&wallet, &anchor, &mut server, &mut rng), Ok(Decision::Current(_))));
}

#[test]
fn a_wrong_witness_is_refused() {
    let (wallet, coins, chain, mut rng) = world(0x317, 4);
    let anchor = anchor_for(&chain, &[]);

    // A sibling above the page in the coin page record.
    let mut server = FakeServer::new(&chain).tamper(flip_record(Database::CoinPages, 1));
    assert_eq!(refusal(first_session(&wallet, &anchor, &mut server, &mut rng)), CheckError::CoinWitness);

    // A level-6 node of the coin page record: the first byte.
    let len = RecordTree::Coin.page_record_bytes();
    let mut server = FakeServer::new(&chain).tamper(flip_record(Database::CoinPages, len));
    assert_eq!(refusal(first_session(&wallet, &anchor, &mut server, &mut rng)), CheckError::CoinWitness);

    // Another leaf of the coin minipage.
    let own = (coins[4].position % MINIPAGE_LEAVES) as usize;
    let mut server = FakeServer::new(&chain).tamper(move |request, answer| {
        if let (Database::CoinLeaves, Answer::Leaves(leaves)) = (request.query.database, answer) {
            leaves[own ^ 1][0] ^= 1;
        }
    });
    assert_eq!(refusal(first_session(&wallet, &anchor, &mut server, &mut rng)), CheckError::CoinWitness);

    // A sibling of the marker page record.
    let mut server = FakeServer::new(&chain).tamper(flip_record(Database::MarkerPages, 1));
    assert_eq!(refusal(first_session(&wallet, &anchor, &mut server, &mut rng)), CheckError::MarkerWitness);

    // A marker minipage with one leaf's next value changed.
    let mut server = FakeServer::new(&chain).tamper(|request, answer| {
        if let (Database::MarkerLeaves, Answer::Record(bytes)) = (request.query.database, answer) {
            bytes[40] ^= 1;
        }
    });
    assert_eq!(refusal(first_session(&wallet, &anchor, &mut server, &mut rng)), CheckError::MarkerWitness);

    // The untouched server is accepted.
    let mut server = FakeServer::new(&chain);
    assert!(matches!(first_session(&wallet, &anchor, &mut server, &mut rng), Ok(Decision::Current(_))));
}

#[test]
fn a_server_that_hides_a_spend_is_refused() {
    // The key's last coin is spent by a full reveal; the server serves the
    // marker set without that spend, so its absence witness would show the
    // coin unspent.
    let (wallet, coins, mut chain, mut rng) = world(0x41de, 3);
    let honest = chain.clone();
    chain.spends.push((coins[3].marker, None));
    let anchor = anchor_for(&chain, &[]);

    let mut lying = FakeServer::new(&honest);
    assert_eq!(refusal(first_session(&wallet, &anchor, &mut lying, &mut rng)), CheckError::MarkerWitness);

    // The honest server shows the value left the key.
    let mut server = FakeServer::new(&chain);
    let decision = first_session(&wallet, &anchor, &mut server, &mut rng).unwrap();
    assert!(matches!(decision, Decision::LeftTheKey { number: 3 }), "{decision:?}");
}

#[test]
fn a_stale_snapshot_header_is_refused() {
    let (wallet, _, chain, mut rng) = world(0x57a1e, 3);
    let later = later_blocks(2, chain.leaves.len() as u64, &mut rng);
    let (tail, snapshot) = tail_with(roots(&chain), 5, &later);
    assert!(check_anchor(&tail, &snapshot, &later).is_ok());

    // A header below the checked tail: the tail starts after it.
    let at = tail.iter().position(|header| header == &snapshot).unwrap();
    assert_eq!(
        check_anchor(&tail[at + 1..], &snapshot, &later).err(),
        Some(CheckError::SnapshotNotOnChain)
    );

    // A header of the same height on another branch.
    let fields = header_roots(&snapshot).unwrap();
    let other_branch = header([0x99; 32], fields.number, roots(&chain), [0x55; 32]);
    assert_eq!(
        check_anchor(&tail, &other_branch, &later).err(),
        Some(CheckError::SnapshotNotOnChain)
    );

    // A snapshot header whose roots are from before the server's records:
    // on the chain, but the records no longer reach its roots.
    let old = chain.clone();
    let mut newer = chain.clone();
    for _ in 0..5 {
        newer.noise(&mut rng);
    }
    let anchor = anchor_for(&old, &[]);
    let mut server = FakeServer::new(&newer);
    assert_eq!(refusal(first_session(&wallet, &anchor, &mut server, &mut rng)), CheckError::CoinWitness);

    // A header that does not decode, or without the lookup fields.
    assert_eq!(check_anchor(&tail, &[0xc0], &later).err(), Some(CheckError::SnapshotHeader));
    let old_format = header_with(19, [0; 32], 1, roots(&chain), [0; 32]);
    assert_eq!(header_roots(&old_format), None);
    let with_mmr = header_with(24, [0; 32], 1, roots(&chain), [0x12; 32]);
    assert_eq!(header_roots(&with_mmr).unwrap().lookup_digest, [0x12; 32]);
}

#[test]
fn a_tampered_bulk_list_is_refused() {
    let (_, _, chain, mut rng) = world(0x1157, 2);
    let later = later_blocks(3, chain.leaves.len() as u64, &mut rng);
    let (tail, snapshot) = tail_with(roots(&chain), 5, &later);
    assert!(check_anchor(&tail, &snapshot, &later).is_ok());

    // A marker added to the second block's list.
    let mut added = later.clone();
    added[1].coin_markers.push([0x42; 32]);
    assert_eq!(check_anchor(&tail, &snapshot, &added).err(), Some(CheckError::BulkList { block: 1 }));

    // A tag left out of the first.
    let mut removed = later.clone();
    removed[0].coin_tags.pop();
    assert_eq!(check_anchor(&tail, &snapshot, &removed).err(), Some(CheckError::BulkList { block: 0 }));

    // Two blocks' lists swapped.
    let mut swapped = later.clone();
    swapped.swap(1, 2);
    assert_eq!(check_anchor(&tail, &snapshot, &swapped).err(), Some(CheckError::BulkList { block: 1 }));

    // A list missing, or one too many.
    assert_eq!(
        check_anchor(&tail, &snapshot, &later[..2]).err(),
        Some(CheckError::LaterBlocks { expected: 3, got: 2 })
    );
    let mut extra = later.clone();
    extra.push(BlockLookupList::default());
    assert_eq!(
        check_anchor(&tail, &snapshot, &extra).err(),
        Some(CheckError::LaterBlocks { expected: 3, got: 4 })
    );
}

#[test]
fn a_spend_after_the_snapshot_shows_the_coin_moved() {
    let (wallet, coins, chain, mut rng) = world(0x30e, 4);
    let mut later = later_blocks(3, chain.leaves.len() as u64, &mut rng);
    later[2].coin_markers.insert(1, coins[4].marker);
    let anchor = anchor_for(&chain, &later);
    let mut server = FakeServer::new(&chain);
    let decision = first_session(&wallet, &anchor, &mut server, &mut rng).unwrap();
    assert!(matches!(decision, Decision::MovedAfterSnapshot { number: 4 }), "{decision:?}");
}

#[test]
fn a_spent_marker_continues_in_a_second_session() {
    // The hint table leaves out the current number, so the probes find the
    // one before it, whose marker is spent.
    let (wallet, coins, chain, mut rng) = world(0x2_5e55, 5);
    let anchor = anchor_for(&chain, &[]);
    let hidden = key_lookup_tag(&wallet, 5);
    let mut server = FakeServer::new(&chain);
    server.lookup_hints.retain(|hint| hint.tag != hidden);

    let decision = first_session(&wallet, &anchor, &mut server, &mut rng).unwrap();
    let Decision::Continue(next) = decision else {
        panic!("not continued: {decision:?}");
    };
    assert_eq!(next.number, 5);
    assert_eq!(next.position, coins[5].position);
    assert_eq!(next.from, NextFrom::SpentMarker);

    // The second session is the same plan: the first probe asks for the
    // bucket of the expected tag, the other probes pad, and with a note that
    // opens the lookup index queries pad too.
    let requests = continue_requests(&wallet, CHAIN_ID, &next, &mut server, &mut rng);
    assert_eq!(requests.exchanges.len(), QUERIES);
    assert_eq!(requests.shapes(), plan().to_vec());
    assert!(!requests.exchanges[0].padding);
    assert_eq!(requests.exchanges[0].record, hint_bucket(&hidden, 64));
    assert!(requests.exchanges[1..PROBES].iter().all(|exchange| exchange.padding));
    assert!(requests.exchanges[PROBES..PROBES + 6].iter().all(|exchange| !exchange.padding));
    assert!(requests.exchange(QueryKind::LookupLeaves).unwrap().padding);
    assert!(requests.exchange(QueryKind::LookupPage).unwrap().padding);

    let restored = restore_with_checks(&wallet, CHAIN_ID, &anchor, &mut server, &mut rng).unwrap();
    assert_eq!(restored.sessions, 2);
    let Decision::Current(current) = restored.decision else {
        panic!("not current: {:?}", restored.decision);
    };
    assert_eq!(current.coin.number, 5);
    assert_eq!(u64::from(current.coin.position), coins[5].position);
}

fn restore_refusal(
    key: &PhantomKey,
    anchor: &Anchor,
    server: &mut FakeServer,
    rng: &mut StdRng,
) -> CheckError {
    match restore_with_checks(key, CHAIN_ID, anchor, server, rng) {
        Ok(restored) => panic!("accepted after {} sessions: {:?}", restored.sessions, restored.decision),
        Err(error) => error,
    }
}

#[test]
fn a_corrupted_continuation_note_is_refused_not_read_as_value_left() {
    // The server hides the latest number in its hints, so the first session
    // reads the spent number before it, and corrupts the note of the leaf
    // that spend appended. The leaf and every witness stay valid; only the
    // note is wrong.
    let (wallet, coins, chain, mut rng) = world(0xc0_2207, 5);
    let anchor = anchor_for(&chain, &[]);
    let hidden = key_lookup_tag(&wallet, 5);
    let latest = coins[5].position;
    let corrupted = |chain: &Chain| {
        let mut server = FakeServer::new(chain);
        server.lookup_hints.retain(|hint| hint.tag != hidden);
        server.notes.get_mut(&latest).unwrap()[200] ^= 1;
        server
    };

    let mut server = corrupted(&chain);
    assert_eq!(restore_refusal(&wallet, &anchor, &mut server, &mut rng), CheckError::Note);

    // The second session fetched the lookup index leaf of the pair, which
    // shows the leaf carries the key's tag of number 5.
    let decision = first_session(&wallet, &anchor, &mut server, &mut rng).unwrap();
    let Decision::Continue(next) = decision else {
        panic!("not continued: {decision:?}");
    };
    let requests = continue_requests(&wallet, CHAIN_ID, &next, &mut server, &mut rng);
    assert!(!requests.exchange(QueryKind::LookupLeaves).unwrap().padding);
    assert!(!requests.exchange(QueryKind::LookupPage).unwrap().padding);
    assert!(matches!(
        ghost_client::restore_checks::check_continued(&wallet, CHAIN_ID, &anchor, &next, &requests),
        Err(CheckError::Note)
    ));

    // Withholding that leaf, or changing it to fake an absence, is refused
    // too, never read as value that left the key.
    let mut withheld = corrupted(&chain).tamper(|request, answer| {
        if let (Database::LookupLeaves, Answer::Record(bytes)) = (request.query.database, answer) {
            bytes.clear();
        }
    });
    assert_eq!(restore_refusal(&wallet, &anchor, &mut withheld, &mut rng), CheckError::LookupWitness);
    let mut faked = corrupted(&chain).tamper(move |request, answer| {
        if let (Database::LookupLeaves, Answer::Record(bytes)) = (request.query.database, answer) {
            // Every leaf's next tag cleared: some leaf then looks like the
            // pair's low leaf, but no longer folds to the root.
            for leaf in bytes.chunks_exact_mut(47) {
                leaf[16 + 5..16 + 5 + 16].fill(0);
            }
        }
    });
    assert_eq!(restore_refusal(&wallet, &anchor, &mut faked, &mut rng), CheckError::LookupWitness);
    let mut padded = corrupted(&chain).tamper(|request, answer| {
        if request.query.database == Database::LookupPages {
            *answer = Answer::Leaves(Vec::new());
        }
    });
    assert_eq!(
        restore_refusal(&wallet, &anchor, &mut padded, &mut rng),
        CheckError::Missing(QueryKind::LookupPage)
    );
}

#[test]
fn a_spend_into_another_key_shows_the_value_left() {
    // The current coin is claimed into another key: its marker leaf records
    // the other key's new leaf, whose note does not open under this key.
    let (wallet, coins, mut chain, mut rng) = world(0xc1a1, 2);
    let other = key(&mut rng);
    let claimed = chain.add_coin(&other, 0, &mut rng);
    chain.spends.push((coins[2].marker, Some(claimed.position)));
    let anchor = anchor_for(&chain, &[]);
    let mut server = FakeServer::new(&chain);
    let restored = restore_with_checks(&wallet, CHAIN_ID, &anchor, &mut server, &mut rng).unwrap();
    assert_eq!(restored.sessions, 2);
    assert!(matches!(restored.decision, Decision::LeftTheKey { number: 2 }), "{:?}", restored.decision);
}

#[test]
fn a_key_that_never_committed_gets_an_absence_witness() {
    let (_, _, chain, mut rng) = world(0x0_0e, 2);
    let fresh = key(&mut rng);
    let anchor = anchor_for(&chain, &[]);
    let mut server = FakeServer::new(&chain);
    let decision = first_session(&fresh, &anchor, &mut server, &mut rng).unwrap();
    assert!(matches!(decision, Decision::NeverCommitted { after_snapshot: false }), "{decision:?}");

    // Its first tag in a later block: committed since the snapshot.
    let mut later = later_blocks(2, chain.leaves.len() as u64, &mut rng);
    later[1].coin_tags.push(key_lookup_tag(&fresh, 0));
    let anchor_later = anchor_for(&chain, &later);
    let decision = first_session(&fresh, &anchor_later, &mut server, &mut rng).unwrap();
    assert!(matches!(decision, Decision::NeverCommitted { after_snapshot: true }), "{decision:?}");

    // A changed lookup witness is refused.
    let mut lying = FakeServer::new(&chain).tamper(flip_record(Database::LookupPages, 1));
    assert_eq!(refusal(first_session(&fresh, &anchor, &mut lying, &mut rng)), CheckError::LookupWitness);
    let mut lying = FakeServer::new(&chain).tamper(|request, answer| {
        if let (Database::LookupLeaves, Answer::Record(bytes)) = (request.query.database, answer) {
            bytes.clear();
        }
    });
    assert_eq!(refusal(first_session(&fresh, &anchor, &mut lying, &mut rng)), CheckError::LookupWitness);
}

#[test]
fn hints_that_hide_the_first_tag_lead_to_it_through_the_lookup_index() {
    // A key that did commit, whose first tag the hints leave out: the probes
    // find nothing, and the lookup index witness shows the tag present.
    let (wallet, coins, chain, mut rng) = world(0xf1_257, 1);
    let anchor = anchor_for(&chain, &[]);
    let first = key_lookup_tag(&wallet, 0);
    let mut server = FakeServer::new(&chain);
    server.lookup_hints.retain(|hint| hint.tag != first);

    let decision = first_session(&wallet, &anchor, &mut server, &mut rng).unwrap();
    let Decision::Continue(next) = decision else {
        panic!("not continued: {decision:?}");
    };
    assert_eq!((next.number, next.position, next.from), (0, coins[0].position, NextFrom::LookupIndex));

    // Number 0 is spent, so number 1 follows in a third session: a wrong
    // hint costs sessions, never the result.
    let restored = restore_with_checks(&wallet, CHAIN_ID, &anchor, &mut server, &mut rng).unwrap();
    assert_eq!(restored.sessions, 3);
    let Decision::Current(current) = restored.decision else {
        panic!("not current: {:?}", restored.decision);
    };
    assert_eq!(current.coin.number, 1);
}

#[test]
fn any_restore_server_gives_the_same_result() {
    let (wallet, coins, chain, mut rng) = world(0xa11, 3);
    let anchor = anchor_for(&chain, &[]);
    for (lookup_buckets, marker_buckets) in [(64, 32), (16, 4), (256, 128)] {
        let mut server = FakeServer::with_buckets(&chain, lookup_buckets, marker_buckets);
        let restored = restore_with_checks(&wallet, CHAIN_ID, &anchor, &mut server, &mut rng).unwrap();
        let Decision::Current(current) = restored.decision else {
            panic!("not current with {lookup_buckets} buckets: {:?}", restored.decision);
        };
        assert_eq!(u64::from(current.coin.position), coins[3].position);
        assert_eq!(restored.sessions, 1);
    }
}
