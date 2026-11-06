//! A copied public tag, and restore against any restore server (stage 2
//! design, "What a wallet does" and "Denial of service").
//!
//! A lookup tag is public once its commit or reveal is in the pool, and
//! anyone can write it into a commit they pay for. The design's claim: a copy
//! costs the victim at most one extra session of the same 31 queries, and
//! never a wrong result. Copies made after the victim's leaf sort after it
//! and are never asked for; a copy that front-runs the victim's pending
//! commit or reveal is asked for once, its note does not open under the
//! victim's key, and the next session passes over that one entry and finds
//! the victim's own leaf.
//!
//! The restore here is the wallet's side of a session, written over the
//! [`LookupSource`] trait alone: [`restore_requests`] for the queries, then
//! [`restore_coins_at`] on the leaf and note fetched, against the marker
//! hints fetched. It draws only the conclusions these tests need ("this coin
//! is current", "no first commitment", or unknown), and believes the fake
//! servers' answers, which serve the chain as it is: the witness and receipt
//! checks that authenticate a leaf and its note are tested elsewhere.
//!
//! Two servers that share no code serve the same chain: one scans its
//! entries on every request, the other answers from tables built once, with
//! other bucket counts, other record counts and another entry order. Restore
//! must reach the same result through either.

use std::collections::HashMap;

use ghost_client::commit::{Amount, Commitment, Marker, Rule};
use ghost_client::lookup::{key_lookup_tag, LookupTag, NO_POSITION, ZERO_TAG};
use ghost_client::note::{encrypt_note, Capsule, NoteContents, NOTE_BYTES};
use ghost_client::restore::{restore_coins_at, Current, TreeLeaf};
use ghost_client::restore_requests::{
    hint_bucket, plan, restore_requests, Answer, Database, LookupHint, LookupSource, MarkerHint, Probed, QueryKind,
    QueryShape, Request, RestoreRequests, MINIPAGE_LEAVES, PAGE_LEAVES, QUERIES,
};
use ghost_client::{KeyFormat, PhantomKey};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// A test chain id.
const CHAIN_ID: u64 = 7357;

/// The most sessions a restore here may take before it reports unknown.
const SESSION_BUDGET: usize = 4;

/// One leaf of the chain: the tag it carries, its commitment and its note.
#[derive(Clone)]
struct Leaf {
    tag: LookupTag,
    commitment: [u8; 32],
    note: [u8; NOTE_BYTES],
}

/// A coin of a key: what restore must report for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    number: u64,
    wei: u128,
    position: u64,
    commitment: [u8; 32],
    marker: [u8; 32],
    salt: [u8; 16],
}

/// A commit or a reveal's remainder in the pool, not yet on the chain: its
/// tag, commitment and note are public to anyone watching the pool.
#[derive(Clone)]
struct Pending {
    leaf: Leaf,
    held: Held,
}

/// The coin number `number` of `key`, holding `wei`, with its note version 3.
fn pending(key: &PhantomKey, number: u64, wei: u128, rng: &mut StdRng) -> Pending {
    let amount = Amount::new(wei).unwrap();
    let commit = key.salted_coin_commit(number, amount, Rule::EMPTY, rng).unwrap();
    let contents = NoteContents::salted_coin(number, amount, Rule::EMPTY, commit.salt);
    let note = encrypt_note(&key.note_key(), CHAIN_ID, &commit.commitment, &contents, &Capsule::empty(), rng);
    Pending {
        leaf: Leaf {
            tag: key_lookup_tag(key, number),
            commitment: *commit.commitment.as_bytes(),
            note,
        },
        held: Held {
            number,
            wei,
            position: 0,
            commitment: *commit.commitment.as_bytes(),
            marker: *commit.marker.as_bytes(),
            salt: *commit.salt.as_bytes(),
        },
    }
}

/// The amount of a key's number `number` in these tests.
fn wei_of(number: u64) -> u128 {
    5_000_000 - 10_000 * u128::from(number)
}

/// The chain: its leaves in global position order, its spent markers in
/// set order, and the hint overflow table.
#[derive(Clone)]
struct Chain {
    leaves: Vec<Leaf>,
    spent: Vec<[u8; 32]>,
    overflow: Vec<LookupHint>,
}

impl Chain {
    /// An empty chain with a filled overflow table.
    fn new(rng: &mut StdRng) -> Self {
        let overflow = (0..24)
            .map(|index_position| {
                let mut tag = [0u8; 16];
                rng.fill_bytes(&mut tag);
                LookupHint {
                    tag,
                    position: index_position * 7,
                    index_position,
                }
            })
            .collect();
        Self {
            leaves: Vec::new(),
            spent: Vec::new(),
            overflow,
        }
    }

    /// Appends a commit or a remainder from the pool.
    fn land(&mut self, pending: Pending) -> Held {
        let position = self.leaves.len() as u64;
        self.leaves.push(pending.leaf);
        Held {
            position,
            ..pending.held
        }
    }

    /// A reveal of `spent` lands: its marker is spent and its remainder
    /// appended.
    fn reveal(&mut self, spent: &Held, remainder: Pending) -> Held {
        self.spent.push(spent.marker);
        self.land(remainder)
    }

    /// A stranger's commit and a stranger's spend.
    fn noise(&mut self, rng: &mut StdRng) {
        let mut leaf = Leaf {
            tag: [0; 16],
            commitment: [0; 32],
            note: [0; NOTE_BYTES],
        };
        rng.fill_bytes(&mut leaf.tag);
        rng.fill_bytes(&mut leaf.commitment);
        rng.fill_bytes(&mut leaf.note);
        self.leaves.push(leaf);
        let mut marker = [0u8; 32];
        rng.fill_bytes(&mut marker);
        self.spent.push(marker);
    }

    /// An attacker's commit carrying a copied tag and a copied note, under
    /// a commitment of its own: the note cannot follow the tag, because the
    /// leaf is its associated data.
    fn copy(&mut self, tag: LookupTag, note: [u8; NOTE_BYTES], rng: &mut StdRng) -> u64 {
        let mut commitment = [0u8; 32];
        rng.fill_bytes(&mut commitment);
        let position = self.leaves.len() as u64;
        self.leaves.push(Leaf { tag, commitment, note });
        position
    }

    /// A key's commit of number 0 and its reveals up to number `hops`,
    /// each but the last spent, with strangers' commits and spends between.
    fn history(&mut self, key: &PhantomKey, hops: u64, rng: &mut StdRng) -> Vec<Held> {
        let mut coins: Vec<Held> = Vec::new();
        for number in 0..=hops {
            self.noise(rng);
            let next = pending(key, number, wei_of(number), rng);
            let held = match coins.last().copied() {
                None => self.land(next),
                Some(previous) => self.reveal(&previous, next),
            };
            coins.push(held);
        }
        self.noise(rng);
        coins
    }

    /// The lookup index entries a full node builds: the sentinel, then the
    /// leaf at global position `g` at index position `g + 1`.
    fn lookup_hints(&self) -> Vec<LookupHint> {
        let mut hints = vec![LookupHint {
            tag: ZERO_TAG,
            position: NO_POSITION,
            index_position: 0,
        }];
        hints.extend(self.leaves.iter().enumerate().map(|(position, leaf)| LookupHint {
            tag: leaf.tag,
            position: position as u64,
            index_position: position as u64 + 1,
        }));
        hints
    }

    /// The marker-set entries: the sentinel, then each spend in order.
    fn marker_hints(&self) -> Vec<MarkerHint> {
        let mut hints = vec![MarkerHint {
            marker: [0; 32],
            set_position: 0,
        }];
        hints.extend(self.spent.iter().enumerate().map(|(index, marker)| MarkerHint {
            marker: *marker,
            set_position: index as u64 + 1,
        }));
        hints
    }
}

/// The first restore server: it keeps the entries in chain order and scans
/// them for every request.
struct ScanServer {
    lookup: Vec<LookupHint>,
    overflow: Vec<LookupHint>,
    markers: Vec<MarkerHint>,
    leaves: Vec<[u8; 32]>,
    notes: Vec<[u8; NOTE_BYTES]>,
    seen: Vec<Request>,
}

const SCAN_POSITIONS: u64 = 1 << 16;

impl ScanServer {
    fn new(chain: &Chain) -> Self {
        Self {
            lookup: chain.lookup_hints(),
            overflow: chain.overflow.clone(),
            markers: chain.marker_hints(),
            leaves: chain.leaves.iter().map(|leaf| leaf.commitment).collect(),
            notes: chain.leaves.iter().map(|leaf| leaf.note).collect(),
            seen: Vec::new(),
        }
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

impl LookupSource for ScanServer {
    fn records(&self, database: Database) -> u64 {
        match database {
            Database::LookupHints => 64,
            Database::HintOverflow => 8,
            Database::MarkerHints => 32,
            Database::Notes => SCAN_POSITIONS,
            Database::CoinLeaves | Database::MarkerLeaves | Database::LookupLeaves => SCAN_POSITIONS / MINIPAGE_LEAVES,
            Database::CoinPages | Database::MarkerPages | Database::LookupPages => SCAN_POSITIONS / PAGE_LEAVES,
        }
    }

    fn fetch(&mut self, request: &Request) -> Answer {
        let database = request.query.database;
        assert!(request.record < self.records(database), "record beyond the database");
        self.seen.push(*request);
        let record = request.record;
        let buckets = self.records(database);
        match database {
            Database::LookupHints => Answer::LookupHints(Self::bucket(&self.lookup, |hint| hint.tag, buckets, record)),
            Database::HintOverflow => {
                Answer::LookupHints(Self::bucket(&self.overflow, |hint| hint.tag, buckets, record))
            }
            Database::MarkerHints => {
                Answer::MarkerHints(Self::bucket(&self.markers, |hint| hint.marker, buckets, record))
            }
            Database::Notes => Answer::Note(
                self.notes
                    .get(record as usize)
                    .map_or_else(|| vec![0; NOTE_BYTES], |note| note.to_vec()),
            ),
            Database::CoinLeaves => Answer::Leaves(
                (record * MINIPAGE_LEAVES..(record + 1) * MINIPAGE_LEAVES)
                    .map(|position| self.leaves.get(position as usize).copied().unwrap_or([0; 32]))
                    .collect(),
            ),
            _ => Answer::Record(record.to_be_bytes().to_vec()),
        }
    }
}

/// The second restore server, sharing no code with the first: its buckets
/// are built once into tables, with other bucket counts, the entry just
/// before a bucket first, and its record counts sized to the chain.
struct TableServer {
    lookup: Vec<Vec<LookupHint>>,
    overflow: Vec<Vec<LookupHint>>,
    markers: Vec<Vec<MarkerHint>>,
    minipages: Vec<Vec<[u8; 32]>>,
    notes: HashMap<u64, [u8; NOTE_BYTES]>,
    positions: u64,
    seen: Vec<Request>,
}

const TABLE_LOOKUP_BUCKETS: u64 = 1021;
const TABLE_OVERFLOW_BUCKETS: u64 = 3;
const TABLE_MARKER_BUCKETS: u64 = 5;

/// Every bucket of a hint table: the entry just before it in key order,
/// then its own entries in key order (equal keys in chain order).
fn tables<T: Copy, K: Ord + AsRef<[u8]>>(mut entries: Vec<T>, key: impl Fn(&T) -> K, buckets: u64) -> Vec<Vec<T>> {
    entries.sort_by_key(|entry| key(entry));
    let bucket_of = |entry: &T| hint_bucket(key(entry).as_ref(), buckets);
    (0..buckets)
        .map(|bucket| {
            let start = entries.partition_point(|entry| bucket_of(entry) < bucket);
            let end = entries.partition_point(|entry| bucket_of(entry) <= bucket);
            let mut out = Vec::with_capacity(end - start + 1);
            if start > 0 {
                out.push(entries[start - 1]);
            }
            out.extend_from_slice(&entries[start..end]);
            out
        })
        .collect()
}

impl TableServer {
    fn new(chain: &Chain) -> Self {
        let positions = chain.leaves.len() as u64;
        let mut minipages: Vec<Vec<[u8; 32]>> = chain
            .leaves
            .chunks(MINIPAGE_LEAVES as usize)
            .map(|chunk| chunk.iter().map(|leaf| leaf.commitment).collect())
            .collect();
        for minipage in &mut minipages {
            minipage.resize(MINIPAGE_LEAVES as usize, [0; 32]);
        }
        Self {
            lookup: tables(chain.lookup_hints(), |hint| hint.tag, TABLE_LOOKUP_BUCKETS),
            overflow: tables(chain.overflow.clone(), |hint| hint.tag, TABLE_OVERFLOW_BUCKETS),
            markers: tables(chain.marker_hints(), |hint| hint.marker, TABLE_MARKER_BUCKETS),
            minipages,
            notes: chain
                .leaves
                .iter()
                .enumerate()
                .map(|(position, leaf)| (position as u64, leaf.note))
                .collect(),
            positions,
            seen: Vec::new(),
        }
    }
}

impl LookupSource for TableServer {
    fn records(&self, database: Database) -> u64 {
        let pages = |leaves: u64| self.positions.div_ceil(leaves).max(1);
        match database {
            Database::LookupHints => TABLE_LOOKUP_BUCKETS,
            Database::HintOverflow => TABLE_OVERFLOW_BUCKETS,
            Database::MarkerHints => TABLE_MARKER_BUCKETS,
            Database::Notes => self.positions.max(1),
            Database::CoinLeaves | Database::MarkerLeaves | Database::LookupLeaves => pages(MINIPAGE_LEAVES),
            Database::CoinPages | Database::MarkerPages | Database::LookupPages => pages(PAGE_LEAVES),
        }
    }

    fn fetch(&mut self, request: &Request) -> Answer {
        let database = request.query.database;
        assert!(request.record < self.records(database), "record beyond the database");
        self.seen.push(*request);
        let record = request.record as usize;
        match database {
            Database::LookupHints => Answer::LookupHints(self.lookup[record].clone()),
            Database::HintOverflow => Answer::LookupHints(self.overflow[record].clone()),
            Database::MarkerHints => Answer::MarkerHints(self.markers[record].clone()),
            Database::Notes => {
                Answer::Note(self.notes.get(&request.record).copied().unwrap_or([0; NOTE_BYTES]).to_vec())
            }
            Database::CoinLeaves => Answer::Leaves(self.minipages[record].clone()),
            _ => Answer::Record(vec![0xee; 8]),
        }
    }
}

/// The wallet's view of a source: the same requests, with the hint entries
/// it has already found to be copies taken out of the answers, on the
/// wallet's side, so the server sees nothing of it.
struct PassOver<'a, S: ?Sized> {
    source: &'a mut S,
    passed: &'a [(LookupTag, u64)],
}

impl<S: LookupSource + ?Sized> LookupSource for PassOver<'_, S> {
    fn records(&self, database: Database) -> u64 {
        self.source.records(database)
    }

    fn fetch(&mut self, request: &Request) -> Answer {
        match self.source.fetch(request) {
            Answer::LookupHints(mut hints) => {
                hints.retain(|hint| !self.passed.contains(&(hint.tag, hint.position)));
                Answer::LookupHints(hints)
            }
            answer => answer,
        }
    }
}

/// What a restore concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The key's current coin.
    Current(Held),
    /// The key made no first commitment.
    NothingCommitted,
    /// No conclusion: a result here would rest on something unread.
    Unknown,
}

/// A restore of one key: its conclusion, the sessions it took and the hint
/// entries it passed over as copies.
struct Restore {
    outcome: Outcome,
    sessions: usize,
    passed: Vec<(LookupTag, u64)>,
}

/// What one session's fetches say about the highest number found.
enum Read {
    /// The key's coin, unspent by the marker hints.
    Unspent(Held),
    /// The key's coin, spent. This test's wallet does not go on along the
    /// spend, so it draws no conclusion.
    Spent,
    /// The note there does not open under the key, or does not recompute
    /// the leaf: the entry is a copy of the tag.
    NotTheKeys,
    /// An answer of the wrong shape: nothing is concluded.
    Unanswered,
}

/// Reads the note and leaf the follow-ups fetched for the number `number`
/// found at `position`, and the marker hints, through [`restore_coins_at`].
fn read_found(key: &PhantomKey, requests: &RestoreRequests, number: u64, position: u64) -> Read {
    let answer = |kind| &requests.exchange(kind).expect("every follow-up is sent").answer;
    let Answer::Note(note) = answer(QueryKind::Note) else {
        return Read::Unanswered;
    };
    let Ok(note) = <[u8; NOTE_BYTES]>::try_from(note.as_slice()) else {
        return Read::Unanswered;
    };
    let Answer::Leaves(leaves) = answer(QueryKind::CoinLeaves) else {
        return Read::Unanswered;
    };
    let Some(leaf) = leaves.get((position % MINIPAGE_LEAVES) as usize) else {
        return Read::Unanswered;
    };
    let Answer::MarkerHints(markers) = answer(QueryKind::MarkerHint) else {
        return Read::Unanswered;
    };
    let Ok(at) = u32::try_from(position) else {
        return Read::Unanswered;
    };
    let spent: Vec<Marker> = markers.iter().map(|hint| Marker::from_bytes(hint.marker)).collect();
    let leaf = TreeLeaf {
        commitment: Commitment::from_bytes(*leaf),
        note,
        salt: None,
    };
    let restored = restore_coins_at(key, CHAIN_ID, 0, &[(at, leaf)], &spent).unwrap();
    match restored.current {
        Current::One(coin) if coin.number == number => Read::Unspent(Held {
            number: coin.number,
            wei: coin.amount.wei(),
            position: u64::from(coin.position),
            commitment: *coin.commitment.as_bytes(),
            marker: *coin.marker.as_bytes(),
            salt: *coin.salt.as_bytes(),
        }),
        _ if restored.found.iter().any(|coin| coin.number == number) => Read::Spent,
        _ => Read::NotTheKeys,
    }
}

/// Restores `key` against any [`LookupSource`], one session of the fixed
/// plan at a time, for at most `budget` sessions. A note that does not open
/// at the highest number found marks that one entry a copy; the next
/// session passes over it.
fn restore_by_lookup<S: LookupSource + ?Sized>(
    key: &PhantomKey,
    source: &mut S,
    rng: &mut StdRng,
    budget: usize,
) -> Restore {
    let mut passed = Vec::new();
    let mut sessions = 0;
    let outcome = loop {
        if sessions == budget {
            break Outcome::Unknown;
        }
        sessions += 1;
        let mut view = PassOver {
            source: &mut *source,
            passed: &passed,
        };
        let requests = restore_requests(key, CHAIN_ID, &mut view, rng);
        let (number, position) = match requests.probed {
            Probed::Nothing => break Outcome::NothingCommitted,
            Probed::BeyondLimit => break Outcome::Unknown,
            Probed::Found { number, position } => (number, position),
        };
        match read_found(key, &requests, number, position) {
            Read::Unspent(held) => break Outcome::Current(held),
            Read::Spent | Read::Unanswered => break Outcome::Unknown,
            Read::NotTheKeys => passed.push((key_lookup_tag(key, number), position)),
        }
    };
    Restore {
        outcome,
        sessions,
        passed,
    }
}

fn key(rng: &mut StdRng) -> PhantomKey {
    PhantomKey::generate(KeyFormat::Words, rng)
}

/// The shapes a server saw: the fixed plan once per session, nothing else.
fn assert_sessions_seen(seen: &[Request], sessions: usize) {
    let shapes: Vec<QueryShape> = seen.iter().map(|request| request.query.shape()).collect();
    let expected: Vec<QueryShape> = (0..sessions).flat_map(|_| plan()).collect();
    assert_eq!(shapes.len(), sessions * QUERIES);
    assert_eq!(shapes, expected);
}

#[test]
fn a_copied_public_tag_costs_the_victim_at_most_one_extra_session() {
    let mut rng = StdRng::seed_from_u64(0x7a9_c0b1);
    let victim = key(&mut rng);

    // The honest chain: numbers 0 to 4, number 4 current. One session.
    let mut chain = Chain::new(&mut rng);
    let coins = chain.history(&victim, 4, &mut rng);
    let mut server = ScanServer::new(&chain);
    let honest = restore_by_lookup(&victim, &mut server, &mut rng, SESSION_BUDGET);
    assert_eq!(honest.outcome, Outcome::Current(coins[4]));
    assert_eq!(honest.sessions, 1);
    assert_sessions_seen(&server.seen, 1);

    // Copies made after the victim's leaves, of every tag it has published,
    // three times each with its note copied: they sort after the originals
    // and are never asked for. No extra session, the same result.
    let mut copied = chain.clone();
    for coin in &coins {
        let leaf = chain.leaves[coin.position as usize].clone();
        for _ in 0..3 {
            copied.copy(leaf.tag, leaf.note, &mut rng);
            copied.noise(&mut rng);
        }
    }
    let mut server = ScanServer::new(&copied);
    let restore = restore_by_lookup(&victim, &mut server, &mut rng, SESSION_BUDGET);
    assert_eq!(restore.outcome, Outcome::Current(coins[4]));
    assert_eq!(restore.sessions, 1);
    assert!(restore.passed.is_empty());
    assert_sessions_seen(&server.seen, 1);
    // Every real fetch went to the victim's own leaf, never to a copy.
    let note = server.seen.iter().find(|request| request.query.kind == QueryKind::Note).unwrap();
    assert_eq!(note.record, coins[4].position);

    // A copy that front-runs the victim's pending reveal of number 4: its
    // remainder's tag and note are in the pool, and the copy lands first.
    let remainder = pending(&victim, 5, wei_of(5), &mut rng);
    let mut honest_chain = chain.clone();
    let honest_five = honest_chain.reveal(&coins[4], remainder.clone());
    let mut attacked = chain.clone();
    let copy_position = attacked.copy(remainder.leaf.tag, remainder.leaf.note, &mut rng);
    let five = attacked.reveal(&coins[4], remainder);
    assert!(copy_position < five.position);
    // The same coin as on the honest chain, one leaf later.
    assert_eq!(Held { position: 0, ..five }, Held { position: 0, ..honest_five });

    // One session alone ends at the copy, whose note does not open: unknown,
    // never number 4 (spent), never "nothing committed".
    let mut server = ScanServer::new(&attacked);
    let one = restore_by_lookup(&victim, &mut server, &mut rng, 1);
    assert_eq!(one.outcome, Outcome::Unknown);
    assert_eq!(one.sessions, 1);
    assert_eq!(one.passed, vec![(key_lookup_tag(&victim, 5), copy_position)]);
    let note = server.seen.iter().find(|request| request.query.kind == QueryKind::Note).unwrap();
    assert_eq!(note.record, copy_position);

    // With a second session the victim's own leaf is found: one extra
    // session of the same 31 queries, and the right coin.
    let mut server = ScanServer::new(&attacked);
    let restore = restore_by_lookup(&victim, &mut server, &mut rng, SESSION_BUDGET);
    assert_eq!(restore.outcome, Outcome::Current(five));
    assert_eq!(restore.sessions, 2);
    assert_eq!(restore.passed, vec![(key_lookup_tag(&victim, 5), copy_position)]);
    assert_sessions_seen(&server.seen, 2);

    // Later copies of every tag, the front-run one among them, add nothing.
    let mut flooded = attacked.clone();
    for number in 0..=5 {
        let original = flooded
            .leaves
            .iter()
            .rposition(|leaf| leaf.tag == key_lookup_tag(&victim, number))
            .unwrap();
        let leaf = flooded.leaves[original].clone();
        for _ in 0..4 {
            flooded.copy(leaf.tag, leaf.note, &mut rng);
        }
    }
    let restore = restore_by_lookup(&victim, &mut ScanServer::new(&flooded), &mut rng, SESSION_BUDGET);
    assert_eq!(restore.outcome, Outcome::Current(five));
    assert_eq!(restore.sessions, 2);

    // A copy that front-runs a first commit: the same one extra session.
    let newcomer = key(&mut rng);
    let first = pending(&newcomer, 0, wei_of(0), &mut rng);
    let mut early = chain.clone();
    let early_copy = early.copy(first.leaf.tag, first.leaf.note, &mut rng);
    early.noise(&mut rng);
    let zero = early.land(first);
    let restore = restore_by_lookup(&newcomer, &mut ScanServer::new(&early), &mut rng, SESSION_BUDGET);
    assert_eq!(restore.outcome, Outcome::Current(zero));
    assert_eq!(restore.sessions, 2);
    assert_eq!(restore.passed, vec![(key_lookup_tag(&newcomer, 0), early_copy)]);
    let alone = restore_by_lookup(&newcomer, &mut ScanServer::new(&early), &mut rng, 1);
    assert_eq!(alone.outcome, Outcome::Unknown);
}

#[test]
fn a_second_independent_lookupsource_restores_the_same_result() {
    let mut rng = StdRng::seed_from_u64(0x2_5e_7e);
    let long = key(&mut rng);
    let single = key(&mut rng);
    let front_run = key(&mut rng);
    let never = key(&mut rng);

    let mut chain = Chain::new(&mut rng);
    let long_coins = chain.history(&long, 9, &mut rng);
    let single_coins = chain.history(&single, 0, &mut rng);
    let run_coins = chain.history(&front_run, 2, &mut rng);
    let remainder = pending(&front_run, 3, wei_of(3), &mut rng);
    chain.copy(remainder.leaf.tag, remainder.leaf.note, &mut rng);
    let run_current = chain.reveal(&run_coins[2], remainder);
    for _ in 0..150 {
        chain.noise(&mut rng);
    }

    let cases = [
        (&long, Outcome::Current(long_coins[9]), 1),
        (&single, Outcome::Current(single_coins[0]), 1),
        (&front_run, Outcome::Current(run_current), 2),
        (&never, Outcome::NothingCommitted, 1),
    ];

    let mut scan = ScanServer::new(&chain);
    let mut table = TableServer::new(&chain);
    // The two servers lay out their databases differently: the same key's
    // requests name other records.
    for database in [Database::LookupHints, Database::HintOverflow, Database::MarkerHints, Database::Notes] {
        assert_ne!(scan.records(database), table.records(database), "{database:?}");
    }

    for (index, (wallet, expected, sessions)) in cases.into_iter().enumerate() {
        scan.seen.clear();
        table.seen.clear();
        let first = restore_by_lookup(wallet, &mut scan, &mut StdRng::seed_from_u64(index as u64), SESSION_BUDGET);
        // The second through a trait object: nothing of the server's type
        // reaches the restore.
        let source: &mut dyn LookupSource = &mut table;
        let second = restore_by_lookup(wallet, source, &mut StdRng::seed_from_u64(100 + index as u64), SESSION_BUDGET);

        assert_eq!(first.outcome, expected, "case {index} on the scanning server");
        assert_eq!(second.outcome, expected, "case {index} on the table server");
        assert_eq!((first.sessions, second.sessions), (sessions, sessions), "case {index}");
        assert_eq!(first.passed, second.passed, "case {index}");
        assert_sessions_seen(&scan.seen, sessions);
        assert_sessions_seen(&table.seen, sessions);

        // The probe of number 0 named each server's own bucket of its tag.
        let tag = key_lookup_tag(wallet, 0);
        assert_eq!(scan.seen[0].record, hint_bucket(&tag, scan.records(Database::LookupHints)));
        assert_eq!(table.seen[0].record, hint_bucket(&tag, table.records(Database::LookupHints)));
    }
}
