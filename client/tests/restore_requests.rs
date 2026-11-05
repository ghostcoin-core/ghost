//! The requests of a restore by private lookup (stage 2 design, "Wallet
//! restore volume", "What a wallet does"): every key sends the same 31
//! queries, 22 padded probes then 9 follow-ups, to the same databases in the
//! same order, whatever its coins; two restores of one key use fresh
//! randomness.

use std::collections::HashMap;

use ghost_client::commit::{salted_coin_marker, Amount, Commitment, Rule, Salt};
use ghost_client::lookup::{key_lookup_tag, LookupTag, NO_POSITION, ZERO_TAG};
use ghost_client::note::{
    encrypt_note, encrypt_note_v2, pad_reveal_note, Capsule, NoteContents, NOTE_BYTES, REVEAL_NOTE_BYTES,
};
use ghost_client::restore_requests::{
    hint_bucket, plan, restore_requests, Answer, Database, Exchange, LookupHint, LookupSource, MarkerHint, Probed,
    Query, QueryKind, Request, RestoreRequests, FOLLOW_UPS, MAX_HOPS, MINIPAGE_LEAVES, PAGE_LEAVES, PROBES, QUERIES,
};
use ghost_client::{KeyFormat, PhantomKey};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// A test chain id.
const CHAIN_ID: u64 = 7357;

const LOOKUP_BUCKETS: u64 = 64;
const OVERFLOW_BUCKETS: u64 = 8;
const MARKER_BUCKETS: u64 = 32;

/// One coin of a key on the fake chain.
struct Coin {
    number: u64,
    position: u64,
    salt: Salt,
}

/// A fake restore server: the public tables a full node builds, answered
/// in the clear. It logs what a PIR server sees, the queries without their
/// records.
#[derive(Default)]
struct FakeServer {
    lookup: Vec<LookupHint>,
    overflow: Vec<LookupHint>,
    markers: Vec<MarkerHint>,
    leaves: HashMap<u64, [u8; 32]>,
    notes: HashMap<u64, [u8; NOTE_BYTES]>,
    next_position: u64,
    seen: Vec<Query>,
}

impl FakeServer {
    /// A server whose lookup index starts with its sentinel.
    fn new() -> Self {
        let mut server = Self::default();
        server.lookup.push(LookupHint {
            tag: ZERO_TAG,
            position: NO_POSITION,
            index_position: 0,
        });
        server.markers.push(MarkerHint {
            marker: [0; 32],
            set_position: 0,
        });
        server.next_position = 1;
        server
    }

    /// Appends one leaf carrying `tag`, with a random commitment.
    fn append(&mut self, tag: LookupTag, rng: &mut StdRng) -> (u64, [u8; 32]) {
        let position = self.next_position;
        self.next_position += 1;
        let mut leaf = [0u8; 32];
        rng.fill_bytes(&mut leaf);
        self.leaves.insert(position, leaf);
        let index_position = self.lookup.len() as u64;
        self.lookup.push(LookupHint {
            tag,
            position,
            index_position,
        });
        (position, leaf)
    }

    /// Appends a stranger's leaf.
    fn append_noise(&mut self, rng: &mut StdRng) {
        let mut tag = [0u8; 16];
        rng.fill_bytes(&mut tag);
        self.append(tag, rng);
    }

    /// Appends a key's commitments 0 to `hops`, each but the last spent,
    /// with a stranger's leaf between each two.
    fn add_key(&mut self, key: &PhantomKey, hops: u64, rng: &mut StdRng) -> Vec<Coin> {
        let mut coins = Vec::new();
        for number in 0..=hops {
            self.append_noise(rng);
            let (position, leaf) = self.append(key_lookup_tag(key, number), rng);
            let salt = Salt::random(rng);
            let amount = Amount::new(1000 + u128::from(number)).unwrap();
            let contents = NoteContents::salted_coin(number, amount, Rule::EMPTY, salt);
            let note = encrypt_note(
                &key.note_key(),
                CHAIN_ID,
                &Commitment::from_bytes(leaf),
                &contents,
                &Capsule::empty(),
                rng,
            );
            self.notes.insert(position, note);
            if number < hops {
                self.spend(marker_of(key, number, &salt));
            }
            coins.push(Coin {
                number,
                position,
                salt,
            });
        }
        coins
    }

    fn spend(&mut self, marker: [u8; 32]) {
        let set_position = self.markers.len() as u64;
        self.markers.push(MarkerHint { marker, set_position });
    }

    /// Fills the marker set with strangers' spends.
    fn spend_noise(&mut self, count: usize, rng: &mut StdRng) {
        for _ in 0..count {
            let mut marker = [0u8; 32];
            rng.fill_bytes(&mut marker);
            self.spend(marker);
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

impl LookupSource for FakeServer {
    fn records(&self, database: Database) -> u64 {
        match database {
            Database::LookupHints => LOOKUP_BUCKETS,
            Database::HintOverflow => OVERFLOW_BUCKETS,
            Database::Notes => 1 << 20,
            Database::CoinLeaves | Database::MarkerLeaves | Database::LookupLeaves => (1 << 20) / MINIPAGE_LEAVES,
            Database::CoinPages | Database::MarkerPages | Database::LookupPages => (1 << 20) / PAGE_LEAVES,
            Database::MarkerHints => MARKER_BUCKETS,
        }
    }

    fn fetch(&mut self, request: &Request) -> Answer {
        assert!(request.record < self.records(request.query.database), "record beyond the database");
        self.seen.push(request.query);
        let record = request.record;
        match request.query.database {
            Database::LookupHints => {
                Answer::LookupHints(Self::bucket(&self.lookup, |hint| hint.tag, LOOKUP_BUCKETS, record))
            }
            Database::HintOverflow => {
                Answer::LookupHints(Self::bucket(&self.overflow, |hint| hint.tag, OVERFLOW_BUCKETS, record))
            }
            Database::MarkerHints => {
                Answer::MarkerHints(Self::bucket(&self.markers, |hint| hint.marker, MARKER_BUCKETS, record))
            }
            Database::Notes => {
                Answer::Note(self.notes.get(&record).map_or_else(|| vec![0; NOTE_BYTES], |note| note.to_vec()))
            }
            Database::CoinLeaves => Answer::Leaves(
                (record * MINIPAGE_LEAVES..(record + 1) * MINIPAGE_LEAVES)
                    .map(|position| self.leaves.get(&position).copied().unwrap_or([0; 32]))
                    .collect(),
            ),
            _ => Answer::Record(record.to_be_bytes().to_vec()),
        }
    }
}

fn marker_of(key: &PhantomKey, number: u64, salt: &Salt) -> [u8; 32] {
    *salted_coin_marker(&key.reveal_secret(), &key.blinding(number), salt).as_bytes()
}

/// A chain with the keys' coins, strangers' leaves and spends, and an
/// overflow table.
fn server_with(keys: &[(&PhantomKey, u64)], rng: &mut StdRng) -> (FakeServer, Vec<Vec<Coin>>) {
    let mut server = FakeServer::new();
    let mut coins = Vec::new();
    for (key, hops) in keys {
        coins.push(server.add_key(key, *hops, rng));
        server.spend_noise(40, rng);
    }
    for _ in 0..50 {
        server.append_noise(rng);
    }
    for index_position in 0..24 {
        let mut tag = [0u8; 16];
        rng.fill_bytes(&mut tag);
        server.overflow.push(LookupHint {
            tag,
            position: index_position * 7,
            index_position,
        });
    }
    (server, coins)
}

fn key(rng: &mut StdRng) -> PhantomKey {
    PhantomKey::generate(KeyFormat::Words, rng)
}

fn probes(restore: &RestoreRequests) -> &[Exchange] {
    &restore.exchanges[..PROBES]
}

fn follow_up(restore: &RestoreRequests, kind: QueryKind) -> &Exchange {
    let exchange = restore.exchange(kind).unwrap_or_else(|| panic!("no {kind:?}"));
    assert!(exchange.query.slot as usize >= PROBES);
    exchange
}

/// The databases, kinds and order every restore must send, written out.
fn expected_order() -> Vec<(Database, QueryKind)> {
    let mut order = vec![(Database::LookupHints, QueryKind::Probe); 22];
    order.extend([
        (Database::Notes, QueryKind::Note),
        (Database::CoinLeaves, QueryKind::CoinLeaves),
        (Database::CoinPages, QueryKind::CoinPage),
        (Database::MarkerHints, QueryKind::MarkerHint),
        (Database::MarkerLeaves, QueryKind::MarkerLeaves),
        (Database::MarkerPages, QueryKind::MarkerPage),
        (Database::LookupLeaves, QueryKind::LookupLeaves),
        (Database::LookupPages, QueryKind::LookupPage),
        (Database::HintOverflow, QueryKind::Overflow),
    ]);
    order
}

fn assert_follows_plan(restore: &RestoreRequests, seen: &[Query]) {
    assert_eq!(restore.exchanges.len(), QUERIES);
    assert_eq!(restore.shapes(), plan().to_vec());
    let order: Vec<_> = seen.iter().map(|query| (query.database, query.kind)).collect();
    assert_eq!(order, expected_order());
    let slots: Vec<u8> = seen.iter().map(|query| query.slot).collect();
    assert_eq!(slots, (0..31).collect::<Vec<u8>>());
    assert_eq!(seen, restore.queries().as_slice());
}

fn real_count(exchanges: &[Exchange]) -> usize {
    exchanges.iter().filter(|exchange| !exchange.padding).count()
}

#[test]
fn the_plan_is_22_probes_then_9_follow_ups() {
    assert_eq!((PROBES, FOLLOW_UPS, QUERIES, MAX_HOPS), (22, 9, 31, 1023));
    let order: Vec<_> = plan().iter().map(|shape| (shape.database, shape.kind)).collect();
    assert_eq!(order, expected_order());
    for (slot, shape) in plan().iter().enumerate() {
        assert_eq!(shape.slot as usize, slot);
    }
}

#[test]
fn a_key_of_one_hop_and_a_key_of_500_hops_send_identical_request_sequences() {
    let mut rng = StdRng::seed_from_u64(0x0e_500);
    let short = key(&mut rng);
    let long = key(&mut rng);
    let (mut server, coins) = server_with(&[(&short, 1), (&long, 500)], &mut rng);

    let first = restore_requests(&short, CHAIN_ID, &mut server, &mut rng);
    let seen_short = std::mem::take(&mut server.seen);
    let second = restore_requests(&long, CHAIN_ID, &mut server, &mut rng);
    let seen_long = std::mem::take(&mut server.seen);

    // Different coins: one hop found at its leaf, 500 hops at theirs.
    assert_eq!(
        first.probed,
        Probed::Found {
            number: 1,
            position: coins[0][1].position
        }
    );
    assert_eq!(
        second.probed,
        Probed::Found {
            number: 500,
            position: coins[1][500].position
        }
    );
    // Different work behind the probes: 3 real probes against 19.
    assert_eq!(real_count(probes(&first)), 3);
    assert_eq!(real_count(probes(&second)), 19);

    // The same sequence: 22 probes and 9 follow-ups, 31 in all, the same
    // databases, kinds and slots in the same order.
    assert_follows_plan(&first, &seen_short);
    assert_follows_plan(&second, &seen_long);
    assert_eq!(seen_short.len(), 31);
    assert_eq!(seen_short.iter().filter(|query| query.kind == QueryKind::Probe).count(), 22);
    let shapes = |seen: &[Query]| seen.iter().map(Query::shape).collect::<Vec<_>>();
    assert_eq!(shapes(&seen_short), shapes(&seen_long));
    assert_eq!(first.shapes(), second.shapes());
}

#[test]
fn the_probes_double_then_halve() {
    let mut rng = StdRng::seed_from_u64(0xd0b1e);
    let wallet = key(&mut rng);
    let (mut server, coins) = server_with(&[(&wallet, 500)], &mut rng);
    let restore = restore_requests(&wallet, CHAIN_ID, &mut server, &mut rng);

    let numbers = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 384, 448, 480, 496, 504, 500, 502, 501];
    let probes = probes(&restore);
    for (exchange, number) in probes.iter().zip(numbers) {
        assert!(!exchange.padding, "probe of {number}");
        assert_eq!(exchange.record, hint_bucket(&key_lookup_tag(&wallet, number), LOOKUP_BUCKETS), "probe of {number}");
    }
    assert!(probes[numbers.len()..].iter().all(|exchange| exchange.padding));
    assert_eq!(
        restore.probed,
        Probed::Found {
            number: 500,
            position: coins[0][500].position
        }
    );

    // One hop: 0 and 1 present, 2 absent, nothing to halve.
    let short = key(&mut rng);
    let (mut server, _) = server_with(&[(&short, 1)], &mut rng);
    let restore = restore_requests(&short, CHAIN_ID, &mut server, &mut rng);
    for (exchange, number) in restore.exchanges.iter().zip([0, 1, 2]) {
        assert!(!exchange.padding);
        assert_eq!(exchange.record, hint_bucket(&key_lookup_tag(&short, number), LOOKUP_BUCKETS));
    }
    assert!(restore.exchanges[3..PROBES].iter().all(|exchange| exchange.padding));
}

#[test]
fn the_follow_ups_fetch_the_highest_number_found() {
    let mut rng = StdRng::seed_from_u64(0xf0110);
    let wallet = key(&mut rng);
    let (mut server, coins) = server_with(&[(&wallet, 37)], &mut rng);
    let restore = restore_requests(&wallet, CHAIN_ID, &mut server, &mut rng);
    let current = &coins[0][37];
    assert_eq!(current.number, 37);
    assert_eq!(
        restore.probed,
        Probed::Found {
            number: 37,
            position: current.position
        }
    );

    let real = |kind| {
        let exchange = follow_up(&restore, kind);
        assert!(!exchange.padding, "{kind:?} is padding");
        exchange.record
    };
    assert_eq!(real(QueryKind::Note), current.position);
    assert_eq!(real(QueryKind::CoinLeaves), current.position / MINIPAGE_LEAVES);
    assert_eq!(real(QueryKind::CoinPage), current.position / PAGE_LEAVES);

    // Its unspent marker, from the salt in its note: the hint bucket of the
    // marker, then the low leaf that brackets it.
    let marker = marker_of(&wallet, 37, &current.salt);
    assert!(server.markers.iter().all(|hint| hint.marker != marker));
    assert_eq!(real(QueryKind::MarkerHint), hint_bucket(&marker, MARKER_BUCKETS));
    let low = server
        .markers
        .iter()
        .filter(|hint| hint.marker < marker)
        .max_by_key(|hint| hint.marker)
        .unwrap();
    assert_eq!(real(QueryKind::MarkerLeaves), low.set_position / MINIPAGE_LEAVES);
    assert_eq!(real(QueryKind::MarkerPage), low.set_position / PAGE_LEAVES);

    // Found, so the lookup index's absence leaf is padding; the overflow
    // bucket of the first tag is asked on every restore.
    assert!(follow_up(&restore, QueryKind::LookupLeaves).padding);
    assert!(follow_up(&restore, QueryKind::LookupPage).padding);
    assert_eq!(real(QueryKind::Overflow), hint_bucket(&key_lookup_tag(&wallet, 0), OVERFLOW_BUCKETS));
    let Answer::LookupHints(overflow) = &follow_up(&restore, QueryKind::Overflow).answer else {
        panic!("the overflow answer is a bucket");
    };
    assert!(!overflow.is_empty());

    // A spent marker leads to its own entry: an earlier number, read again
    // with only its first coins on the chain.
    let (mut server, coins) = server_with(&[(&wallet, 37)], &mut rng);
    let spent = &coins[0][36];
    let marker = marker_of(&wallet, 36, &spent.salt);
    let entry = *server.markers.iter().find(|hint| hint.marker == marker).unwrap();
    server.lookup.retain(|hint| hint.tag != key_lookup_tag(&wallet, 37));
    let restore = restore_requests(&wallet, CHAIN_ID, &mut server, &mut rng);
    assert_eq!(
        restore.probed,
        Probed::Found {
            number: 36,
            position: spent.position
        }
    );
    let marker_leaves = follow_up(&restore, QueryKind::MarkerLeaves);
    assert!(!marker_leaves.padding);
    assert_eq!(marker_leaves.record, entry.set_position / MINIPAGE_LEAVES);
}

#[test]
fn a_note_that_does_not_open_pads_the_marker_queries() {
    let mut rng = StdRng::seed_from_u64(0xbad_0);
    let wallet = key(&mut rng);
    let (mut server, coins) = server_with(&[(&wallet, 5)], &mut rng);
    server.notes.insert(coins[0][5].position, [7; NOTE_BYTES]);
    let restore = restore_requests(&wallet, CHAIN_ID, &mut server, &mut rng);
    assert_follows_plan(&restore, &server.seen);
    assert!(!follow_up(&restore, QueryKind::Note).padding);
    for kind in [QueryKind::MarkerHint, QueryKind::MarkerLeaves, QueryKind::MarkerPage] {
        assert!(follow_up(&restore, kind).padding, "{kind:?}");
    }
}

/// Stores a coin's note again as the tree stores a version 1 reveal's
/// remainder: a 156-byte note version 2, zero-padded to 380 bytes.
fn store_as_reveal_remainder(server: &mut FakeServer, key: &PhantomKey, coin: &Coin, rng: &mut StdRng) {
    let leaf = Commitment::from_bytes(server.leaves[&coin.position]);
    let amount = Amount::new(1000 + u128::from(coin.number)).unwrap();
    let contents = NoteContents::salted_coin(coin.number, amount, Rule::EMPTY, coin.salt);
    let short = encrypt_note_v2(&key.note_key(), CHAIN_ID, &leaf, &contents, rng);
    let padded = pad_reveal_note(&short);
    assert!(padded[REVEAL_NOTE_BYTES..].iter().all(|&byte| byte == 0));
    server.notes.insert(coin.position, padded);
}

#[test]
fn a_reveal_remainder_note_still_fetches_its_spent_status() {
    let mut rng = StdRng::seed_from_u64(0x5e_ed2);
    let wallet = key(&mut rng);

    // The same chain twice: the current coin's note as a note version 3,
    // and as a version 1 reveal's padded remainder note.
    let (mut plain, _) = server_with(&[(&wallet, 12)], &mut StdRng::seed_from_u64(0xc4a1));
    let (mut server, coins) = server_with(&[(&wallet, 12)], &mut StdRng::seed_from_u64(0xc4a1));
    let current = &coins[0][12];
    store_as_reveal_remainder(&mut server, &wallet, current, &mut rng);
    let reference = restore_requests(&wallet, CHAIN_ID, &mut plain, &mut rng);
    let restore = restore_requests(&wallet, CHAIN_ID, &mut server, &mut rng);

    // The query shape and order are unchanged.
    assert_follows_plan(&restore, &server.seen);
    assert_eq!(restore.shapes(), reference.shapes());
    assert_eq!(
        restore.probed,
        Probed::Found {
            number: 12,
            position: current.position
        }
    );

    // The marker queries are real, at the unspent marker's bucket and its
    // low leaf, the records the version 3 note leads to.
    let marker = marker_of(&wallet, 12, &current.salt);
    let hint = follow_up(&restore, QueryKind::MarkerHint);
    assert!(!hint.padding);
    assert_eq!(hint.record, hint_bucket(&marker, MARKER_BUCKETS));
    let low = server
        .markers
        .iter()
        .filter(|hint| hint.marker < marker)
        .max_by_key(|hint| hint.marker)
        .unwrap();
    for (kind, record) in [
        (QueryKind::MarkerLeaves, low.set_position / MINIPAGE_LEAVES),
        (QueryKind::MarkerPage, low.set_position / PAGE_LEAVES),
    ] {
        let exchange = follow_up(&restore, kind);
        assert!(!exchange.padding, "{kind:?} is padding");
        assert_eq!(exchange.record, record, "{kind:?}");
    }
    for kind in [QueryKind::MarkerHint, QueryKind::MarkerLeaves, QueryKind::MarkerPage] {
        assert_eq!(follow_up(&restore, kind).record, follow_up(&reference, kind).record, "{kind:?}");
    }

    // A spent remainder leads to its own marker entry.
    let spent = &coins[0][11];
    store_as_reveal_remainder(&mut server, &wallet, spent, &mut rng);
    server.lookup.retain(|hint| hint.tag != key_lookup_tag(&wallet, 12));
    let marker = marker_of(&wallet, 11, &spent.salt);
    let entry = *server.markers.iter().find(|hint| hint.marker == marker).unwrap();
    server.seen.clear();
    let restore = restore_requests(&wallet, CHAIN_ID, &mut server, &mut rng);
    assert_follows_plan(&restore, &server.seen);
    assert_eq!(
        restore.probed,
        Probed::Found {
            number: 11,
            position: spent.position
        }
    );
    let marker_leaves = follow_up(&restore, QueryKind::MarkerLeaves);
    assert!(!marker_leaves.padding);
    assert_eq!(marker_leaves.record, entry.set_position / MINIPAGE_LEAVES);
    let marker_page = follow_up(&restore, QueryKind::MarkerPage);
    assert!(!marker_page.padding);
    assert_eq!(marker_page.record, entry.set_position / PAGE_LEAVES);

    // A remainder note with a byte after its first 156 is not one: padding.
    let mut tampered = server.notes[&spent.position];
    tampered[NOTE_BYTES - 1] = 1;
    server.notes.insert(spent.position, tampered);
    server.seen.clear();
    let restore = restore_requests(&wallet, CHAIN_ID, &mut server, &mut rng);
    assert_follows_plan(&restore, &server.seen);
    for kind in [QueryKind::MarkerHint, QueryKind::MarkerLeaves, QueryKind::MarkerPage] {
        assert!(follow_up(&restore, kind).padding, "{kind:?}");
    }
}

#[test]
fn a_key_that_never_committed_sends_the_same_sequence() {
    let mut rng = StdRng::seed_from_u64(0x0_0e);
    let stranger = key(&mut rng);
    let fresh = key(&mut rng);
    let (mut server, _) = server_with(&[(&stranger, 3)], &mut rng);
    let restore = restore_requests(&fresh, CHAIN_ID, &mut server, &mut rng);
    assert_eq!(restore.probed, Probed::Nothing);
    assert_follows_plan(&restore, &server.seen);
    assert_eq!(real_count(probes(&restore)), 1);
    for kind in [
        QueryKind::Note,
        QueryKind::CoinLeaves,
        QueryKind::CoinPage,
        QueryKind::MarkerHint,
        QueryKind::MarkerLeaves,
        QueryKind::MarkerPage,
    ] {
        assert!(follow_up(&restore, kind).padding, "{kind:?}");
    }

    // The lookup index leaf that proves "no first commitment": the low leaf
    // of the first tag.
    let tag = key_lookup_tag(&fresh, 0);
    let low = server.lookup.iter().filter(|hint| hint.tag < tag).max_by_key(|hint| hint.tag).unwrap();
    let leaves = follow_up(&restore, QueryKind::LookupLeaves);
    assert!(!leaves.padding);
    assert_eq!(leaves.record, low.index_position / MINIPAGE_LEAVES);
    let page = follow_up(&restore, QueryKind::LookupPage);
    assert!(!page.padding);
    assert_eq!(page.record, low.index_position / PAGE_LEAVES);
    assert!(!follow_up(&restore, QueryKind::Overflow).padding);
}

#[test]
fn more_hops_than_the_probes_cover_pads_every_fetch() {
    let mut rng = StdRng::seed_from_u64(0x10_24);
    let wallet = key(&mut rng);
    let mut server = FakeServer::new();
    for number in 0..=MAX_HOPS + 1 {
        server.append(key_lookup_tag(&wallet, number), &mut rng);
    }
    let restore = restore_requests(&wallet, CHAIN_ID, &mut server, &mut rng);
    assert_eq!(restore.probed, Probed::BeyondLimit);
    assert_follows_plan(&restore, &server.seen);
    // Probe 0 and the eleven doubling probes up to 1,024.
    assert_eq!(real_count(probes(&restore)), 12);
    assert_eq!(
        probes(&restore)[11].record,
        hint_bucket(&key_lookup_tag(&wallet, MAX_HOPS + 1), LOOKUP_BUCKETS)
    );
    let follow_ups = &restore.exchanges[PROBES..];
    assert_eq!(real_count(follow_ups), 1);
    assert!(!follow_up(&restore, QueryKind::Overflow).padding);
}

#[test]
fn two_restores_of_one_key_use_fresh_unrelated_randomness() {
    let mut rng = StdRng::seed_from_u64(0x7_0);
    let wallet = key(&mut rng);
    let (mut server, _) = server_with(&[(&wallet, 9)], &mut rng);

    let mut first_rng = StdRng::seed_from_u64(1);
    let mut second_rng = StdRng::seed_from_u64(2);
    let first = restore_requests(&wallet, CHAIN_ID, &mut server, &mut first_rng);
    let second = restore_requests(&wallet, CHAIN_ID, &mut server, &mut second_rng);

    // With the randomness removed the sequences are the same.
    assert_eq!(first.shapes(), second.shapes());
    assert_eq!(first.probed, second.probed);

    // Every query carries its own randomness, unrelated across restores.
    let mut randomness: Vec<[u8; 32]> = first
        .queries()
        .iter()
        .chain(second.queries().iter())
        .map(|query| query.randomness)
        .collect();
    randomness.sort();
    randomness.dedup();
    assert_eq!(randomness.len(), 2 * QUERIES);

    // Padding asks for fresh records; the real records are the same.
    let padded: Vec<(u64, u64)> = first
        .exchanges
        .iter()
        .zip(&second.exchanges)
        .filter(|(a, _)| a.padding)
        .map(|(a, b)| {
            assert!(b.padding);
            (a.record, b.record)
        })
        .collect();
    assert!(padded.len() >= 10);
    assert!(padded.iter().any(|(a, b)| a != b));
    for (a, b) in first.exchanges.iter().zip(&second.exchanges) {
        if !a.padding {
            assert!(!b.padding);
            assert_eq!(a.record, b.record);
        }
    }

    // The same random source gives the same queries: nothing else enters.
    let again = restore_requests(&wallet, CHAIN_ID, &mut server, &mut StdRng::seed_from_u64(1));
    assert_eq!(again.queries(), first.queries());
}
