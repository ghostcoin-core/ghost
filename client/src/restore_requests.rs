//! The requests of a restore by private lookup (stage 2 design, "Wallet
//! restore volume", "What a wallet does", steps 1, 3 and 4; spec 01,
//! section 8, "The lookup path").
//!
//! A coin key's commitments are numbered 0, 1, 2 and on with no gaps, so the
//! wallet derives the lookup tag of every number from the digits alone
//! ([`crate::lookup::key_lookup_tag`], unchanged) and asks for what it needs
//! by single-server PIR. This module plans and sends those requests against a
//! [`LookupSource`], a trait the caller implements (a PIR client in the
//! wallet, a fake server in a test); it has no network code and no PIR
//! scheme of its own.
//!
//! Every restore sends exactly [`QUERIES`] queries, always the same ones in
//! the same order, the fixed [`plan`]:
//!
//! 1. [`PROBES`] probes of the lookup hint table: the tag of number 0, then
//!    numbers 1, 2, 4 and on, doubling until a tag is absent, then halving
//!    between the last number present and the first absent; padded to
//!    exactly [`PROBES`], which covers up to [`MAX_HOPS`] hops.
//! 2. [`FOLLOW_UPS`] fetches for the highest number found: its note, the
//!    coin-tree minipage of 64 leaves that holds its leaf and the page's
//!    witness records, the hint, minipage and page witness of its spent
//!    marker in the coin marker-set tree, the minipage and page witness of
//!    the lookup index (the low leaf that proves "no first commitment" when
//!    nothing was found, padding otherwise), and the hint overflow bucket of
//!    the first tag.
//!
//! A query the key has nothing for is padding: the same database, kind and
//! slot, at a record drawn uniformly from the caller's random source. What a
//! query carries in the clear ([`Query`]: database, kind, slot and fresh
//! randomness for the PIR query) depends only on the fixed plan and on the
//! caller's random source, never on which coins the key has; the record it
//! asks for ([`Request::record`]) is what the PIR query hides.
//!
//! Nothing an answer says is believed here: the hints are unauthenticated,
//! and the notes, witnesses, snapshot header and bulk lists are checked
//! before use elsewhere. The note of the highest number is only opened under
//! the note key to read its salt, from which the commitment's spent marker
//! follows: as a note version 3, or, as restore reads it, as the padded
//! note version 2 remainder of a version 1 reveal. A note that opens neither
//! way makes the marker queries padding.
//!
//! # Hint buckets
//!
//! A hint table is a table of buckets, each a range of consecutive keys: the
//! bucket of a tag or a marker is its first 8 bytes, big-endian, times the
//! number of buckets the server publishes, divided by 2^64
//! ([`hint_bucket`]). A bucket answer holds the entries of the bucket and the
//! entry just before it in key order, so it brackets a key that is absent.
//!
//! # Record indices of the positional databases
//!
//! The note table is indexed by global position; the coin leaves, the
//! marker-set leaves and the lookup index leaves by minipage
//! (`position / 64`); their page witness records by page
//! (`position / 4096`). The number of records of each database is public
//! ([`LookupSource::records`]), and padding draws below it.

use rand_core::CryptoRng;

use crate::commit::{salted_coin_marker, Commitment, COIN_V2};
use crate::lookup::{lookup_tag, LookupTag};
use crate::key::PhantomKey;
use crate::derive::NoteKey;
use crate::note::{decrypt_note, decrypt_note_v2, unpad_reveal_note, NoteContents, NoteError, NOTE_BYTES};
use crate::wipe::wipe;

/// The most hops the probes cover: numbers 0 to 1,023.
pub const MAX_HOPS: u64 = 1023;
/// The probes of every restore, padded: probe 0, eleven doubling probes and
/// ten halving ones, `1 + (10 + 1) + 10` for [`MAX_HOPS`].
pub const PROBES: usize = 22;
/// The fetches after the probes.
pub const FOLLOW_UPS: usize = 9;
/// Every query of one restore.
pub const QUERIES: usize = PROBES + FOLLOW_UPS;
/// Leaves of a minipage, one record of a leaves database.
pub const MINIPAGE_LEAVES: u64 = 64;
/// Leaves of a page, one record of a page witness database.
pub const PAGE_LEAVES: u64 = 4096;

/// The bits of a number up to [`MAX_HOPS`].
const HOP_BITS: usize = 10;

const _: () = assert!(QUERIES == 31);
const _: () = assert!(1u64 << HOP_BITS == MAX_HOPS + 1);
const _: () = assert!(PROBES == 1 + (HOP_BITS + 1) + HOP_BITS);

/// The last number a doubling probe asks for.
const LAST_DOUBLING: u64 = MAX_HOPS + 1;

/// The PIR databases a restore server serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Database {
    /// The coin lookup hint table: buckets of (tag, leaf position, index
    /// position).
    LookupHints,
    /// The overflow table of the lookup hint buckets.
    HintOverflow,
    /// The notes, by global position.
    Notes,
    /// The coin tree's leaves, by minipage.
    CoinLeaves,
    /// The coin tree's page witness records, by page.
    CoinPages,
    /// The coin marker hint table: buckets of (marker, set position).
    MarkerHints,
    /// The coin marker-set tree's leaves, by minipage.
    MarkerLeaves,
    /// The coin marker-set tree's page witness records, by page.
    MarkerPages,
    /// The coin lookup index's leaves, by minipage.
    LookupLeaves,
    /// The coin lookup index's page witness records, by page.
    LookupPages,
}

/// What a query of the plan is for. Every probe has the same kind, so the
/// kind never shows whether a probe doubles, halves or pads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryKind {
    /// A probe of the lookup hint table.
    Probe,
    /// The note of the highest number found.
    Note,
    /// The coin-tree minipage holding its leaf.
    CoinLeaves,
    /// The coin-tree page witness records of its leaf.
    CoinPage,
    /// The marker hint of its spent marker.
    MarkerHint,
    /// The marker-set minipage of its marker's leaf or low leaf.
    MarkerLeaves,
    /// The marker-set page witness records of that leaf.
    MarkerPage,
    /// The lookup index minipage of the first tag's low leaf.
    LookupLeaves,
    /// The lookup index page witness records of that leaf.
    LookupPage,
    /// The hint overflow bucket of the first tag.
    Overflow,
}

impl QueryKind {
    /// The database a query of this kind goes to.
    pub const fn database(self) -> Database {
        match self {
            Self::Probe => Database::LookupHints,
            Self::Note => Database::Notes,
            Self::CoinLeaves => Database::CoinLeaves,
            Self::CoinPage => Database::CoinPages,
            Self::MarkerHint => Database::MarkerHints,
            Self::MarkerLeaves => Database::MarkerLeaves,
            Self::MarkerPage => Database::MarkerPages,
            Self::LookupLeaves => Database::LookupLeaves,
            Self::LookupPage => Database::LookupPages,
            Self::Overflow => Database::HintOverflow,
        }
    }
}

/// The follow-up fetches, in the order every restore sends them.
pub const FOLLOW_UP_KINDS: [QueryKind; FOLLOW_UPS] = [
    QueryKind::Note,
    QueryKind::CoinLeaves,
    QueryKind::CoinPage,
    QueryKind::MarkerHint,
    QueryKind::MarkerLeaves,
    QueryKind::MarkerPage,
    QueryKind::LookupLeaves,
    QueryKind::LookupPage,
    QueryKind::Overflow,
];

/// A query of the fixed plan without its per-restore randomness: its
/// database, its kind and its slot, the query's place in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryShape {
    /// The database queried.
    pub database: Database,
    /// What the query is for.
    pub kind: QueryKind,
    /// The query's place in the plan, 0 to [`QUERIES`] - 1.
    pub slot: u8,
}

/// The fixed plan every restore follows: [`PROBES`] probes, then the
/// [`FOLLOW_UP_KINDS`].
pub fn plan() -> [QueryShape; QUERIES] {
    core::array::from_fn(|slot| {
        let kind = if slot < PROBES {
            QueryKind::Probe
        } else {
            FOLLOW_UP_KINDS[slot - PROBES]
        };
        QueryShape {
            database: kind.database(),
            kind,
            slot: slot as u8,
        }
    })
}

/// What a query shows in the clear: its place in the fixed plan and 32 fresh
/// random bytes from the caller's source, the randomness of its PIR query.
/// Nothing in it depends on the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Query {
    /// The database queried.
    pub database: Database,
    /// What the query is for.
    pub kind: QueryKind,
    /// The query's place in the plan.
    pub slot: u8,
    /// Fresh randomness for this query, drawn from the caller's source.
    pub randomness: [u8; 32],
}

impl Query {
    /// The query without its randomness.
    pub fn shape(&self) -> QueryShape {
        QueryShape {
            database: self.database,
            kind: self.kind,
            slot: self.slot,
        }
    }
}

/// A query and the record it asks for. A PIR client sends the query in the
/// clear and the record only inside the PIR query, under the query's
/// randomness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// What the server sees.
    pub query: Query,
    /// The record index the PIR query hides: real, or uniform padding.
    pub record: u64,
}

/// An entry of a lookup hint bucket. Unauthenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupHint {
    /// The lookup tag.
    pub tag: LookupTag,
    /// The global position of the leaf carrying it.
    pub position: u64,
    /// The position of its leaf in the lookup index.
    pub index_position: u64,
}

/// An entry of a marker hint bucket. Unauthenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkerHint {
    /// A spent marker.
    pub marker: [u8; 32],
    /// The position of its leaf in the coin marker-set tree.
    pub set_position: u64,
}

/// The answer of one query, as the source returns it, unchecked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// A lookup hint or overflow bucket.
    LookupHints(Vec<LookupHint>),
    /// A marker hint bucket.
    MarkerHints(Vec<MarkerHint>),
    /// A note.
    Note(Vec<u8>),
    /// A minipage of leaves.
    Leaves(Vec<[u8; 32]>),
    /// Any other record: page witness records, a minipage's encoded leaves.
    Record(Vec<u8>),
}

/// Where a restore's queries go: a PIR client in the wallet, or a fake
/// server in a test. The source learns the record of each request only
/// through the PIR query.
pub trait LookupSource {
    /// The number of records of a database, which a restore server
    /// publishes with its snapshot.
    fn records(&self, database: Database) -> u64;
    /// The answer to one request.
    fn fetch(&mut self, request: &Request) -> Answer;
}

/// What the probes found. Unauthenticated: a hint table can be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probed {
    /// The tag of number 0 is in no hint.
    Nothing,
    /// The highest number whose tag a hint holds, and the global position
    /// that hint gives.
    Found {
        /// The commitment number.
        number: u64,
        /// The global position of its leaf, by the hint.
        position: u64,
    },
    /// Every doubling probe, up to number [`MAX_HOPS`] + 1, found its tag:
    /// more hops than the probes cover. Every follow-up is padding.
    BeyondLimit,
}

/// One query sent, its record and its answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    /// The query as sent.
    pub query: Query,
    /// The record asked for.
    pub record: u64,
    /// Whether the query was padding: the key had nothing to fetch here.
    pub padding: bool,
    /// The source's answer, unchecked.
    pub answer: Answer,
}

/// Every query of one restore, in order, with its answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreRequests {
    /// What the probes found.
    pub probed: Probed,
    /// The [`QUERIES`] exchanges, in the order of the [`plan`].
    pub exchanges: Vec<Exchange>,
}

impl RestoreRequests {
    /// The queries as sent.
    pub fn queries(&self) -> Vec<Query> {
        self.exchanges.iter().map(|exchange| exchange.query).collect()
    }

    /// The queries without their randomness.
    pub fn shapes(&self) -> Vec<QueryShape> {
        self.exchanges.iter().map(|exchange| exchange.query.shape()).collect()
    }

    /// The exchange of a follow-up kind, or of the first probe for
    /// [`QueryKind::Probe`].
    pub fn exchange(&self, kind: QueryKind) -> Option<&Exchange> {
        self.exchanges.iter().find(|exchange| exchange.query.kind == kind)
    }
}

/// The bucket of a tag or a marker among `buckets`: its first 8 bytes,
/// big-endian, times `buckets`, divided by 2^64, so that every bucket is a
/// range of consecutive keys in key order; 0 when there are none.
pub fn hint_bucket(key: &[u8], buckets: u64) -> u64 {
    let mut first = [0u8; 8];
    let len = key.len().min(8);
    first[..len].copy_from_slice(&key[..len]);
    ((u128::from(u64::from_be_bytes(first)) * u128::from(buckets)) >> 64) as u64
}

/// A uniform value below `bound` from the caller's source, by rejection; 0
/// when `bound` is 0 or 1.
fn random_below<R: CryptoRng + ?Sized>(rng: &mut R, bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    let zone = u64::MAX - u64::MAX % bound;
    loop {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        let value = u64::from_be_bytes(bytes);
        if value < zone {
            return value % bound;
        }
    }
}

/// Sends the queries of the fixed plan in order, each with fresh
/// randomness, and keeps the answers.
struct Sender<'a, S: ?Sized, R: ?Sized> {
    source: &'a mut S,
    rng: &'a mut R,
    exchanges: Vec<Exchange>,
}

impl<S: LookupSource + ?Sized, R: CryptoRng + ?Sized> Sender<'_, S, R> {
    /// Sends the next query of the plan for `record`, or as padding when
    /// `record` is `None`. The kind must be the plan's at this slot.
    fn send(&mut self, kind: QueryKind, record: Option<u64>) -> &Answer {
        let slot = self.exchanges.len();
        let shape = plan()[slot];
        debug_assert_eq!(shape.kind, kind);
        let mut randomness = [0u8; 32];
        self.rng.fill_bytes(&mut randomness);
        let query = Query {
            database: shape.database,
            kind: shape.kind,
            slot: shape.slot,
            randomness,
        };
        let padding = record.is_none();
        let record = match record {
            Some(record) => record,
            None => random_below(self.rng, self.source.records(shape.database)),
        };
        let answer = self.source.fetch(&Request { query, record });
        self.exchanges.push(Exchange {
            query,
            record,
            padding,
            answer,
        });
        &self.exchanges[slot].answer
    }
}

/// The hint for `tag` in a bucket answer: the entry carrying it with the
/// lowest position (a copy of a public tag is appended after the original).
fn hint_for(answer: &Answer, tag: &LookupTag) -> Option<LookupHint> {
    match answer {
        Answer::LookupHints(hints) => hints
            .iter()
            .filter(|hint| &hint.tag == tag)
            .min_by_key(|hint| hint.position)
            .copied(),
        _ => None,
    }
}

/// The low entry of an absent tag in a bucket answer: the largest tag below
/// it, which the bucket's "entry just before" supplies.
fn low_hint_for(answer: &Answer, tag: &LookupTag) -> Option<LookupHint> {
    match answer {
        Answer::LookupHints(hints) => hints.iter().filter(|hint| &hint.tag < tag).max_by_key(|hint| hint.tag).copied(),
        _ => None,
    }
}

/// The set position for a marker in a marker hint answer: its own entry
/// when spent, else the entry of the largest marker below it (its low
/// leaf, for an absence witness).
fn marker_position(answer: &Answer, marker: &[u8; 32]) -> Option<u64> {
    let Answer::MarkerHints(hints) = answer else {
        return None;
    };
    hints
        .iter()
        .find(|hint| &hint.marker == marker)
        .or_else(|| hints.iter().filter(|hint| &hint.marker < marker).max_by_key(|hint| hint.marker))
        .map(|hint| hint.set_position)
}

/// Opens a stored 380-byte note under the note key as [`crate::restore`]
/// reads it: as a note version 3 first; if that does not authenticate and
/// its last 224 bytes are zero, its first 156 bytes as the note version 2
/// remainder note of a version 1 reveal. `None` when neither opens.
fn read_note(note_key: &NoteKey, chain_id: u64, leaf: &Commitment, note: &[u8; NOTE_BYTES]) -> Option<NoteContents> {
    match decrypt_note(note_key, chain_id, leaf, note) {
        Ok(contents) => Some(contents),
        Err(NoteError::Unauthentic) => {
            let short = unpad_reveal_note(note)?;
            decrypt_note_v2(note_key, chain_id, leaf, &short).ok()
        }
        Err(_) => None,
    }
}

/// Sends the [`PROBES`] probes and returns what they found, with the
/// answer of the probe of number 0.
fn probe<S: LookupSource + ?Sized, R: CryptoRng + ?Sized>(
    sender: &mut Sender<'_, S, R>,
    tag_of: &dyn Fn(u64) -> LookupTag,
) -> (Probed, Option<LookupHint>) {
    let buckets = sender.source.records(Database::LookupHints);
    let ask = |sender: &mut Sender<'_, S, R>, number: u64| {
        let tag = tag_of(number);
        let answer = sender.send(QueryKind::Probe, Some(hint_bucket(&tag, buckets)));
        (hint_for(answer, &tag), low_hint_for(answer, &tag))
    };

    let (first, low) = ask(sender, 0);
    let probed = match first {
        None => Probed::Nothing,
        Some(first) => {
            // Doubling: `low` is the last number present, `high` the first
            // absent.
            let (mut low, mut low_position) = (0u64, first.position);
            let mut high = None;
            let mut next = 1u64;
            while next <= LAST_DOUBLING {
                match ask(sender, next).0 {
                    Some(hint) => {
                        (low, low_position) = (next, hint.position);
                        next *= 2;
                    }
                    None => {
                        high = Some(next);
                        break;
                    }
                }
            }
            match high {
                None => Probed::BeyondLimit,
                Some(mut high) => {
                    // Halving between the last present and the first absent.
                    while high - low > 1 {
                        let middle = low + (high - low) / 2;
                        match ask(sender, middle).0 {
                            Some(hint) => (low, low_position) = (middle, hint.position),
                            None => high = middle,
                        }
                    }
                    Probed::Found {
                        number: low,
                        position: low_position,
                    }
                }
            }
        }
    };
    debug_assert!(sender.exchanges.len() <= PROBES);
    while sender.exchanges.len() < PROBES {
        sender.send(QueryKind::Probe, None);
    }
    let absent_low = if matches!(probed, Probed::Nothing) { low } else { None };
    (probed, absent_low)
}

/// Runs the requests of one restore of a coin key against `source`: the
/// [`PROBES`] padded probes, then the [`FOLLOW_UPS`] fetches, the same
/// [`QUERIES`] queries in the order of the [`plan`] whatever the key's
/// coins, each with fresh randomness from `rng`, and padding at a uniform
/// record wherever the key has nothing to fetch.
///
/// Everything is derived from the digits alone: the note key and the
/// lookup tags (the reveal secret and the blinding of the highest number
/// only for its spent marker). `chain_id` is the chain the notes are bound
/// to. Nothing returned is checked; see the module documentation.
pub fn restore_requests<S, R>(key: &PhantomKey, chain_id: u64, source: &mut S, rng: &mut R) -> RestoreRequests
where
    S: LookupSource + ?Sized,
    R: CryptoRng + ?Sized,
{
    let key_bytes = key.key_bytes();
    let note_key = key_bytes.note_key();
    let tag_of = |number: u64| lookup_tag(&note_key, number);
    let first_tag = tag_of(0);

    let mut sender = Sender {
        source,
        rng,
        exchanges: Vec::with_capacity(QUERIES),
    };
    let (probed, absent_low) = probe(&mut sender, &tag_of);

    let found = match probed {
        Probed::Found { number, position } => Some((number, position)),
        Probed::Nothing | Probed::BeyondLimit => None,
    };
    let position = found.map(|(_, position)| position);

    // The note and the coin leaf of the highest number.
    let note = match sender.send(QueryKind::Note, position) {
        Answer::Note(bytes) => <[u8; NOTE_BYTES]>::try_from(bytes.as_slice()).ok(),
        _ => None,
    };
    let leaf = match (sender.send(QueryKind::CoinLeaves, position.map(|p| p / MINIPAGE_LEAVES)), position) {
        (Answer::Leaves(leaves), Some(position)) => leaves.get((position % MINIPAGE_LEAVES) as usize).copied(),
        _ => None,
    };
    sender.send(QueryKind::CoinPage, position.map(|p| p / PAGE_LEAVES));

    // Its spent marker, from the salt its note carries.
    let mut marker = match (found, note, leaf) {
        (Some((number, _)), Some(note), Some(leaf)) => {
            read_note(&note_key, chain_id, &Commitment::from_bytes(leaf), &note)
                .filter(|contents| contents.type_tag == COIN_V2 && contents.number == number)
                .map(|contents| {
                    *salted_coin_marker(&key_bytes.reveal_secret(), &key_bytes.blinding(number), &contents.salt)
                        .as_bytes()
                })
        }
        _ => None,
    };
    let marker_buckets = sender.source.records(Database::MarkerHints);
    let marker_hints = sender.send(QueryKind::MarkerHint, marker.map(|m| hint_bucket(&m, marker_buckets)));
    let set_position = marker.and_then(|marker| marker_position(marker_hints, &marker));
    sender.send(QueryKind::MarkerLeaves, set_position.map(|p| p / MINIPAGE_LEAVES));
    sender.send(QueryKind::MarkerPage, set_position.map(|p| p / PAGE_LEAVES));
    // An unspent marker is known only to its holder.
    if let Some(marker) = marker.as_mut() {
        wipe(marker);
    }

    // The lookup index's low leaf of the first tag, when nothing was found.
    let index_position = absent_low.map(|hint| hint.index_position);
    sender.send(QueryKind::LookupLeaves, index_position.map(|p| p / MINIPAGE_LEAVES));
    sender.send(QueryKind::LookupPage, index_position.map(|p| p / PAGE_LEAVES));

    // The overflow bucket of the first tag, on every restore.
    let overflow_buckets = sender.source.records(Database::HintOverflow);
    sender.send(QueryKind::Overflow, Some(hint_bucket(&first_tag, overflow_buckets)));

    debug_assert_eq!(sender.exchanges.len(), QUERIES);
    RestoreRequests {
        probed,
        exchanges: sender.exchanges,
    }
}
