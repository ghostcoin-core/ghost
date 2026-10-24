//! What one real coin reveal proof costs to enter recursion, as a proxy.
//!
//! A recursive verifier of a Keccak leaf proof has to compute, inside its own
//! trace, every Keccak-f[1600] permutation the native verifier computes. This
//! test counts those permutations for one real reveal proof, then proves that
//! many permutations with the pinned `p3-keccak-air` at the shipped leaf
//! parameters and times it. The proxy is the cost of re-proving a verifier's
//! hash work, not a full recursive verifier: no FRI folding, no constraint
//! evaluation and no binding of the child's statement is in it.
//!
//! The count is modeled: `ghost-proofs` exposes no hook to count permutations
//! while it verifies, so the count is derived from the shipped constants and
//! checked against an independent recount from the decoded proof. The
//! derivation itself is checked against a counted verification of the proxy
//! proofs, whose configuration this test builds with counting permutations.
//!
//! With `GHOST_SCALE_QUICK` set the proxy proves a small number of
//! permutations instead of the counted one, and the figures at the counted
//! size are modeled from it. Records go to `GHOST_SCALE_RECORDS_DIR`, or to
//! the cargo target directory, as `recursion-proxy.jsonl`.

use std::cell::Cell;
use std::time::Instant;

use ghost_proofs::{
    BATCH_POW_BITS, Binding, EXTENSION_DEGREE, LOG_BLOWUP, NUM_QUERIES, QUERY_POW_BITS, RATE_BYTES, Statement,
    shipped_configuration,
};
use ghost_reveal_bench::{BUILD_FLAGS, PLONKY3_REVISION, RUSTC_VERSION, Session, verify};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS, generate_trace_rows};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, CryptographicPermutation, PaddingFreeSponge, Permutation,
    SerializingHasher,
};
use p3_uni_stark::{Proof as StarkProof, StarkConfig};
use rand::SeedableRng;
use rand::rngs::StdRng;

type F = BabyBear;
type Challenge = BinomialExtensionField<F, EXTENSION_DEGREE>;

/// Lanes of the Merkle sponge's rate: 17, Keccak-256's 136 bytes.
const SPONGE_RATE_LANES: usize = RATE_BYTES / 8;
/// Field elements one leaf-sponge permutation absorbs: two to a lane.
const LEAF_BLOCK_ELEMS: usize = 2 * SPONGE_RATE_LANES;
/// Words of a Merkle digest.
const DIGEST_WORDS: usize = 4;
/// Salt elements per leaf (`SALT_ELEMS` of proofs/src/stark.rs); the recount
/// reads them from the proof.
const SALT_ELEMS: usize = 5;
/// Random codewords hiding FRI appends to each committed matrix: as many as
/// the extension degree (`NUM_RANDOM_CODEWORDS` of proofs/src/stark.rs).
const RANDOM_CODEWORDS: usize = EXTENSION_DEGREE;
/// Bytes of one base element and one challenge in the transcript.
const FIELD_BYTES: usize = 4;
const CHALLENGE_BYTES: usize = EXTENSION_DEGREE * FIELD_BYTES;
/// Bytes of a commitment in the transcript: four `u64` words.
const COMMITMENT_BYTES: usize = DIGEST_WORDS * 8;
/// Bytes one transcript flush yields for sampling.
const TRANSCRIPT_OUT_BYTES: usize = 32;
/// The constraint degree of `p3-keccak-air`.
const KECCAK_AIR_DEGREE: usize = 3;
/// Permutations the quick path proves for the conversion layer: 2,040 rows,
/// so a 2,048-row trace.
const QUICK_PERMUTATIONS: usize = 85;

const ARCHITECTURE: &str = "keccak-leaves-keccak-aggregation";
const CONFIGURATION: &str = "keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk";

// Counting permutations. The prover runs on one thread (no `parallel`
// feature), so a thread-local counter sees every permutation of one proof or
// one verification.

thread_local! {
    static COUNTS: [Cell<u64>; 3] = const { [Cell::new(0), Cell::new(0), Cell::new(0)] };
}

const LEAF: usize = 0;
const NODE: usize = 1;
const TRANSCRIPT: usize = 2;

fn bump(role: usize, by: u64) {
    COUNTS.with(|c| c[role].set(c[role].get() + by));
}

fn take_counts() -> [u64; 3] {
    COUNTS.with(|c| [c[0].replace(0), c[1].replace(0), c[2].replace(0)])
}

/// The library's Keccak-f[1600], counting each state it permutes under one
/// role: leaf hashing or two-to-one compression.
#[derive(Clone, Copy, Debug, Default)]
struct CountedKeccakF<const ROLE: usize>;

impl<const ROLE: usize> Permutation<[u64; 25]> for CountedKeccakF<ROLE> {
    fn permute_mut(&self, state: &mut [u64; 25]) {
        bump(ROLE, 1);
        KeccakF.permute_mut(state);
    }
}

impl<const ROLE: usize> CryptographicPermutation<[u64; 25]> for CountedKeccakF<ROLE> {}

impl<const ROLE: usize> Permutation<[[u64; VECTOR_LEN]; 25]> for CountedKeccakF<ROLE> {
    fn permute_mut(&self, state: &mut [[u64; VECTOR_LEN]; 25]) {
        bump(ROLE, VECTOR_LEN as u64);
        KeccakF.permute_mut(state);
    }
}

impl<const ROLE: usize> CryptographicPermutation<[[u64; VECTOR_LEN]; 25]> for CountedKeccakF<ROLE> {}

/// Keccak-256 for the transcript, counting the permutations of each call:
/// one per started 136-byte block, padding included.
#[derive(Clone, Copy, Debug)]
struct CountedKeccak256;

fn keccak256_permutations(len: usize) -> u64 {
    (len / RATE_BYTES + 1) as u64
}

impl CryptographicHasher<u8, [u8; 32]> for CountedKeccak256 {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let bytes: Vec<u8> = input.into_iter().collect();
        self.hash_slice(&bytes)
    }

    fn hash_slice(&self, input: &[u8]) -> [u8; 32] {
        bump(TRANSCRIPT, keccak256_permutations(input.len()));
        Keccak256Hash {}.hash_slice(input)
    }
}

// The shipped configuration rebuilt from the library's own types, with the
// counting permutations. Its proofs serialize exactly as the shipped ones:
// the hashes do not appear in a proof's type.

type LeafHash = SerializingHasher<PaddingFreeSponge<CountedKeccakF<LEAF>, 25, SPONGE_RATE_LANES, DIGEST_WORDS>>;
type NodeHash = PaddingFreeSponge<CountedKeccakF<NODE>, 25, SPONGE_RATE_LANES, DIGEST_WORDS>;
type Compress = CompressionFunctionFromHasher<NodeHash, 2, DIGEST_WORDS>;
type ValMmcs =
    MerkleTreeHidingMmcs<[F; VECTOR_LEN], [u64; VECTOR_LEN], LeafHash, Compress, StdRng, 2, DIGEST_WORDS, SALT_ELEMS>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<F, HashChallenger<u8, CountedKeccak256, 32>>;
type Pcs = HidingFriPcs<F, Radix2DitParallel<F>, ValMmcs, ChallengeMmcs, StdRng>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;
type Proof = StarkProof<Config>;

fn config(dft: &Radix2DitParallel<F>, seed: u64) -> Config {
    let val_mmcs = ValMmcs::new(
        LeafHash::new(PaddingFreeSponge::new(CountedKeccakF)),
        Compress::new(NodeHash::new(CountedKeccakF)),
        0,
        StdRng::seed_from_u64(seed),
    );
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: BATCH_POW_BITS,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_POW_BITS,
        mmcs: ChallengeMmcs::new(val_mmcs.clone()),
    };
    let pcs = Pcs::new(dft.clone(), val_mmcs, fri, RANDOM_CODEWORDS, StdRng::seed_from_u64(seed ^ 0x9e37_79b9));
    Config::new(pcs, Challenger::from_hasher(Vec::new(), CountedKeccak256))
}

// The derivation.

/// What decides the verifier's hash work for one proof of the shipped
/// configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shape {
    queries: usize,
    /// log2 of the committed trace height, zero-knowledge doubling included.
    degree_bits: usize,
    trace_width: usize,
    quotient_chunks: usize,
    /// Folding rounds of FRI, each with its own tree.
    fri_rounds: usize,
    public_values: usize,
}

/// Keccak-f[1600] permutations a verifier performs, by role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Counts {
    /// Two-to-one compressions along the Merkle paths.
    merkle: usize,
    /// Leaf hashes of the opened rows, 34 elements (17 lanes) a permutation.
    leaf: usize,
    /// The Keccak-256 transcript.
    transcript: usize,
}

impl Counts {
    const fn total(self) -> usize {
        self.merkle + self.leaf + self.transcript
    }
}

fn leaf_perms(elems: usize) -> usize {
    elems.div_ceil(LEAF_BLOCK_ELEMS)
}

/// Transcript permutations: every observed byte absorbed at 136 a
/// permutation, and one flush for each 32 sampled bytes. A model: the
/// library's step labels and rejection-sampling retries are not counted.
fn transcript_perms(observed_bytes: usize, sampled_bytes: usize) -> usize {
    observed_bytes / RATE_BYTES + sampled_bytes.div_ceil(TRANSCRIPT_OUT_BYTES)
}

/// Bytes the verifier samples: the constraint batching challenge, the
/// out-of-domain point, the opening batching challenge, one folding challenge
/// a round, one index a query, and a squeezed byte and a 4-byte check for
/// each of the two grinding sites.
fn sampled_bytes(fri_rounds: usize, queries: usize) -> usize {
    (3 + fri_rounds) * CHALLENGE_BYTES + queries * FIELD_BYTES + 2 * (1 + FIELD_BYTES)
}

impl Shape {
    /// The shape from the shipped constants and the statement's trace, as
    /// `ghost-proofs` reports them.
    fn coin_reveal() -> Self {
        let shipped = shipped_configuration().expect("shipped configuration");
        let (statement, est) = shipped.statements[0];
        assert_eq!(statement, Statement::CoinReveal);
        assert_eq!((shipped.log_blowup, shipped.num_queries), (LOG_BLOWUP, NUM_QUERIES));
        assert!(est.trace_height.is_power_of_two());
        // Zero-knowledge doubles the trace before it is committed.
        let degree_bits = est.trace_height.trailing_zeros() as usize + 1;
        Self {
            queries: NUM_QUERIES,
            degree_bits,
            trace_width: est.trace_width,
            // The library's zero-knowledge split: 2 * next_power_of_two(d).
            quotient_chunks: 2 * est.constraint_degree.next_power_of_two(),
            // Binary folding down to one coefficient.
            fri_rounds: degree_bits,
            // The binding fields and their 32-byte digest, one element a byte.
            public_values: Binding::CoinReveal.fields_len() + 32,
        }
    }

    /// The shape of a `p3-keccak-air` proof of `rows` rows.
    fn keccak_air(rows: usize) -> Self {
        assert!(rows.is_power_of_two());
        let degree_bits = rows.trailing_zeros() as usize + 1;
        Self {
            queries: NUM_QUERIES,
            degree_bits,
            trace_width: NUM_KECCAK_COLS,
            quotient_chunks: 2 * KECCAK_AIR_DEGREE.next_power_of_two(),
            fri_rounds: degree_bits,
            public_values: 0,
        }
    }

    /// The shape read back from a decoded proof.
    fn of_proof(proof: &Proof, public_values: usize) -> Self {
        let fri = &proof.opening_proof.1;
        Self {
            queries: fri.input_openings[0].opened_values.len(),
            degree_bits: proof.degree_bits,
            trace_width: proof.opened_values.trace_local.len(),
            quotient_chunks: proof.opened_values.quotient_chunks.len(),
            fri_rounds: fri.commit_phase_commits.len(),
            public_values,
        }
    }

    fn log_codeword(self) -> usize {
        self.degree_bits + LOG_BLOWUP
    }

    /// The permutations a verifier of fixed shape performs, as a recursive
    /// verifier's circuit must: every query's leaves and full paths, with no
    /// sharing between queries.
    fn counts(self) -> Counts {
        let q = self.queries;
        let ext = EXTENSION_DEGREE;
        // The randomization polynomial (one challenge flattened, plus the
        // random codewords), the trace and the quotient chunks, each matrix
        // row followed by its salt; one leaf per batch.
        let random = ext + RANDOM_CODEWORDS + SALT_ELEMS;
        let trace = self.trace_width + RANDOM_CODEWORDS + SALT_ELEMS;
        let quotient = self.quotient_chunks * (ext + RANDOM_CODEWORDS + SALT_ELEMS);
        // A folding round's leaf: the queried value and its sibling, salted.
        let fold = 2 * ext + SALT_ELEMS;
        let per_query =
            leaf_perms(random) + leaf_perms(trace) + leaf_perms(quotient) + self.fri_rounds * leaf_perms(fold);
        let leaf = q * per_query;
        let d = self.log_codeword();
        let fold_paths: usize = (0..self.fri_rounds).map(|i| d - 1 - i).sum();
        let merkle = q * (3 * d + fold_paths);
        let opened = 2 * self.trace_width + self.quotient_chunks * ext + ext;
        let observed = (3 + self.fri_rounds) * COMMITMENT_BYTES
            + self.public_values * FIELD_BYTES
            + opened * CHALLENGE_BYTES
            // The final polynomial and the two grinding witnesses.
            + CHALLENGE_BYTES
            + 2 * FIELD_BYTES;
        Counts {
            merkle,
            leaf,
            transcript: transcript_perms(observed, sampled_bytes(self.fri_rounds, q)),
        }
    }
}

/// The same counts walked from the proof's own vectors: each query's opened
/// rows and salts, each round's siblings, every opened value and commitment.
fn recount(proof: &Proof, public_values: usize) -> Counts {
    let fri = &proof.opening_proof.1;
    let d = proof.degree_bits + LOG_BLOWUP;
    let mut leaf = 0;
    let mut merkle = 0;
    for batch in &fri.input_openings {
        let (salts, pruned) = &batch.opening_proof;
        assert_eq!(salts.len(), batch.opened_values.len());
        for (rows, salts) in batch.opened_values.iter().zip(salts) {
            let elems: usize = rows.iter().zip(salts).map(|(row, salt)| row.len() + salt.len()).sum();
            leaf += leaf_perms(elems);
            merkle += d;
        }
        assert!(pruned.sibling_hashes.len() <= multiproof_bound(batch.opened_values.len(), d));
    }
    for (i, round) in fri.commit_phase_openings.iter().enumerate() {
        let (salts, pruned) = &round.opening_proof;
        for (siblings, salts) in round.sibling_values.iter().zip(salts) {
            let salt: usize = salts.iter().map(Vec::len).sum();
            leaf += leaf_perms((siblings.len() + 1) * EXTENSION_DEGREE + salt);
            merkle += d - 1 - i;
        }
        assert!(pruned.sibling_hashes.len() <= multiproof_bound(round.sibling_values.len(), d - 1 - i));
    }
    let ov = &proof.opened_values;
    let opened = ov.trace_local.len()
        + ov.trace_next.as_ref().map_or(0, Vec::len)
        + ov.quotient_chunks.iter().map(Vec::len).sum::<usize>()
        + ov.random.as_ref().map_or(0, Vec::len);
    let commitments = 2 + usize::from(proof.commitments.random.is_some()) + fri.commit_phase_commits.len();
    let witnesses = usize::from(BATCH_POW_BITS > 0) + usize::from(QUERY_POW_BITS > 0);
    let observed = commitments * COMMITMENT_BYTES
        + public_values * FIELD_BYTES
        + opened * CHALLENGE_BYTES
        + fri.final_poly.len() * CHALLENGE_BYTES
        + witnesses * FIELD_BYTES;
    let queries = fri.input_openings[0].opened_values.len();
    Counts {
        merkle,
        leaf,
        transcript: transcript_perms(observed, sampled_bytes(fri.commit_phase_commits.len(), queries)),
    }
}

/// The most sibling digests a pruned multiproof of `queries` indices can hold
/// in a binary tree of `depth` levels: per level, at most one per query and
/// at most as many as the level has nodes.
fn multiproof_bound(queries: usize, depth: usize) -> usize {
    (0..depth).map(|level| queries.min(1 << level)).sum()
}

/// Rows of a `p3-keccak-air` trace of `permutations` permutations.
fn keccak_rows(permutations: usize) -> usize {
    (permutations * NUM_ROUNDS).next_power_of_two()
}

// The proxy proofs.

/// Deterministic inputs: one state a permutation.
fn inputs(count: usize, seed: u64) -> Vec<[u64; 25]> {
    let mut x = seed;
    let mut next = move || {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    (0..count).map(|_| core::array::from_fn(|_| next())).collect()
}

struct Measured {
    permutations: usize,
    rows: usize,
    proof_bytes: usize,
    seconds: Vec<f64>,
    /// The native verifier's counted permutations on the last proof.
    counted: [u64; 3],
    derived: Counts,
}

/// Prove `permutations` Keccak-f[1600] permutations once untimed, then
/// `repeats` times timed (trace generation and proving), and verify the last
/// proof with the counting permutations.
fn measure(dft: &Radix2DitParallel<F>, permutations: usize, repeats: usize) -> Measured {
    let states = inputs(permutations, permutations as u64);
    let mut seconds = Vec::with_capacity(repeats);
    let mut last = None;
    for run in 0..=repeats {
        let config = config(dft, run as u64 + 1);
        let start = Instant::now();
        let trace = generate_trace_rows::<F>(states.clone(), 0);
        let proof = p3_uni_stark::prove(&config, &KeccakAir {}, trace, &[]).expect("the proxy proves");
        let elapsed = start.elapsed().as_secs_f64();
        if run > 0 {
            seconds.push(elapsed);
        }
        last = Some(proof);
    }
    let proof = last.expect("one proof");
    let bytes = postcard::to_allocvec(&proof).expect("serializes");
    let rows = keccak_rows(permutations);
    assert_eq!(proof.degree_bits, rows.trailing_zeros() as usize + 1);

    take_counts();
    let config = config(dft, 0);
    p3_uni_stark::verify(&config, &KeccakAir {}, &proof, &[]).expect("the proxy verifies");
    let counted = take_counts();

    // The derivation agrees with the proxy proof's own vectors, and bounds
    // the native verifier, which shares path nodes between queries.
    let shape = Shape::keccak_air(rows);
    assert_eq!(Shape::of_proof(&proof, 0), shape);
    let derived = shape.counts();
    assert_eq!(recount(&proof, 0), derived);
    assert!(counted[LEAF] as usize <= derived.leaf, "{counted:?} {derived:?}");
    assert!(counted[NODE] as usize <= derived.merkle, "{counted:?} {derived:?}");
    // The transcript model leaves out the library's step labels and sampling
    // retries, so it stays at or under the counted transcript.
    assert!(derived.transcript as u64 <= counted[TRANSCRIPT], "{counted:?} {derived:?}");
    assert!(counted[LEAF] > 0 && counted[NODE] > 0);
    eprintln!("proxy of {permutations} permutations: counted {counted:?}, derived {derived:?}");

    Measured { permutations, rows, proof_bytes: bytes.len(), seconds, counted, derived }
}

fn median(seconds: &[f64]) -> f64 {
    let mut s = seconds.to_vec();
    s.sort_by(f64::total_cmp);
    let n = s.len();
    if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 }
}

fn slowest(seconds: &[f64]) -> f64 {
    seconds.iter().copied().fold(0.0, f64::max)
}

// The machine.

/// The processor as `/proc/cpuinfo` names it: the model name when there is
/// one, else the architecture with the implementer and part codes.
fn cpu_model() -> String {
    let info = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let field = |name: &str| {
        info.lines()
            .find(|l| l.split(':').next().is_some_and(|k| k.trim() == name))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    if let Some(model) = field("model name").or_else(|| field("Hardware")) {
        return model;
    }
    match (field("CPU implementer"), field("CPU part")) {
        (Some(implementer), Some(part)) => {
            let vendor = match implementer.as_str() {
                "0x41" => " (Arm)",
                "0x61" => " (Apple)",
                "0xc0" => " (Ampere)",
                _ => "",
            };
            format!(
                "{} CPU implementer {implementer}{vendor}, part {part} (no model name in /proc/cpuinfo)",
                std::env::consts::ARCH
            )
        }
        _ => String::new(),
    }
}

fn machine_threads() -> usize {
    std::thread::available_parallelism().map_or(0, usize::from)
}

// Records.

struct Json(String);

impl Json {
    fn new() -> Self {
        Self(String::from("{"))
    }

    fn str(mut self, key: &str, value: &str) -> Self {
        let value = value.replace('\\', "\\\\").replace('"', "\\\"");
        self.0.push_str(&format!("\"{key}\":\"{value}\","));
        self
    }

    fn num(mut self, key: &str, value: impl std::fmt::Display) -> Self {
        self.0.push_str(&format!("\"{key}\":{value},"));
        self
    }

    fn raw(mut self, key: &str, value: &str) -> Self {
        self.0.push_str(&format!("\"{key}\":{value},"));
        self
    }

    fn done(mut self) -> String {
        self.0.pop();
        self.0.push('}');
        self.0
    }
}

fn parameters() -> String {
    format!(
        "{CONFIGURATION}; p3-keccak-air ({NUM_KECCAK_COLS} columns, {NUM_ROUNDS} rows a permutation) over BabyBear; \
         Plonky3 {PLONKY3_REVISION}; one prover thread; {RUSTC_VERSION}; {BUILD_FLAGS}"
    )
}

fn base(layer: &str, permutations: usize, rows: usize, label: &str, quick: bool) -> Json {
    Json::new()
        .str("architecture", ARCHITECTURE)
        .str("layer", layer)
        .num("permutation_count", permutations)
        .num("trace_rows", rows)
        .num("trace_width", NUM_KECCAK_COLS)
        .str("label", label)
        .raw("quick", if quick { "true" } else { "false" })
        .str("cpu_model", &cpu_model())
        .num("threads", machine_threads())
        .num("prover_threads", 1)
        .str("parameters", &parameters())
}

fn with_counts(json: Json, counts: Counts, label: &str) -> Json {
    json.num("merkle_permutations", counts.merkle)
        .num("leaf_permutations", counts.leaf)
        .num("transcript_permutations", counts.transcript)
        .str("count_label", label)
}

fn measured_record(layer: &str, m: &Measured, quick: bool, reveal: Counts, children: &str) -> String {
    let json = base(layer, m.permutations, m.rows, "measured (proxy)", quick)
        .num("proof_bytes", m.proof_bytes)
        .num("median_seconds", format!("{:.6}", median(&m.seconds)))
        .num("slowest_seconds", format!("{:.6}", slowest(&m.seconds)))
        .num("repeats", m.seconds.len())
        .str("children", children);
    // The quick path proves fewer permutations than the children's verifier
    // performs, so the breakdown goes only with the counted size.
    let json = if m.permutations == reveal.total() { with_counts(json, reveal, "modeled") } else { json };
    json.num("proxy_verifier_counted_merkle", m.counted[NODE])
        .num("proxy_verifier_counted_leaf", m.counted[LEAF])
        .num("proxy_verifier_counted_transcript", m.counted[TRANSCRIPT])
        .num("proxy_verifier_derived_total", m.derived.total())
        .done()
}

fn modeled_record(
    layer: &str,
    permutations: usize,
    seconds: f64,
    counts: Counts,
    children: &str,
    anchor: &str,
) -> Json {
    let json = base(layer, permutations, keccak_rows(permutations), "modeled", false)
        .raw("proof_bytes", "null")
        .num("median_seconds", format!("{seconds:.6}"))
        .num("slowest_seconds", format!("{seconds:.6}"))
        .num("repeats", 0)
        .str("children", children)
        .str("model", anchor);
    with_counts(json, counts, "modeled")
}

fn records_path() -> std::path::PathBuf {
    let dir = std::env::var_os("GHOST_SCALE_RECORDS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&dir).expect("records directory");
    dir.join("recursion-proxy.jsonl")
}

// The tests.

#[test]
fn reveal_verifier_hash_work_is_counted_and_proved_as_a_proxy() {
    let quick = std::env::var_os("GHOST_SCALE_QUICK").is_some();

    // One real reveal proof, verified.
    let session = Session::new(11, true);
    let (tx, proof) = session.prove([0x5a; 32]).expect("the reveal proves");
    verify(&tx, &proof).expect("the reveal verifies");

    // Decoded as a proof of the rebuilt configuration, it encodes back to the
    // same bytes, so the types agree with the shipped ones.
    let decoded: Proof = postcard::from_bytes(proof.as_bytes()).expect("decodes");
    assert_eq!(postcard::to_allocvec(&decoded).expect("encodes"), proof.as_bytes());

    // The derivation from the constants and the recount from the proof agree.
    let shape = Shape::coin_reveal();
    let public_values = shape.public_values;
    assert_eq!(Shape::of_proof(&decoded, public_values), shape);
    assert_eq!(decoded.opening_proof.1.final_poly.len(), 1);
    let reveal = shape.counts();
    assert_eq!(recount(&decoded, public_values), reveal);
    let n = reveal.total();
    eprintln!("reveal verifier: {reveal:?}, {n} permutations");

    // The conversion layer re-proves one leaf verifier's permutations, the
    // merge two.
    let (conversion_n, repeats) = if quick { (QUICK_PERMUTATIONS, 5) } else { (n, 3) };
    let dft = Radix2DitParallel::<F>::default();
    let conversion = measure(&dft, conversion_n, repeats);
    let merge = measure(&dft, 2 * conversion_n, repeats);
    assert!(merge.proof_bytes > conversion.proof_bytes);

    let leaf_children = "one coin reveal proof";
    let merge_children = "two coin reveal proofs";
    let doubled = Counts { merkle: 2 * reveal.merkle, leaf: 2 * reveal.leaf, transcript: 2 * reveal.transcript };
    let mut lines = vec![
        measured_record("conversion", &conversion, quick, reveal, leaf_children),
        measured_record("merge", &merge, quick, doubled, merge_children),
    ];

    // Later merges verify two proofs of the merge proxy's own shape.
    let merge_rows = keccak_rows(2 * n);
    let later = Shape::keccak_air(merge_rows).counts();
    let later_n = 2 * later.total();

    if quick {
        // The cost per row past the smaller proof, without what both pay
        // whatever their size, times the rows at the counted size.
        let per_row = (median(&merge.seconds) - median(&conversion.seconds)) / (merge.rows - conversion.rows) as f64;
        assert!(per_row > 0.0, "the larger proxy is not slower");
        let anchor = format!(
            "single-thread seconds per row past the {}-row proxy, {:.9}, from the measured (proxy) medians \
             at {} and {} rows, times the rows",
            conversion.rows, per_row, conversion.rows, merge.rows
        );
        lines.push(
            modeled_record("conversion", n, per_row * keccak_rows(n) as f64, reveal, leaf_children, &anchor).done(),
        );
        lines.push(
            modeled_record("merge", 2 * n, per_row * merge_rows as f64, doubled, merge_children, &anchor)
                .num("later_merge_permutation_count", later_n)
                .num("later_merge_trace_rows", keccak_rows(later_n))
                .done(),
        );
    }

    let path = records_path();
    let mut text = lines.join("\n");
    text.push('\n');
    std::fs::write(&path, &text).expect("records written");
    eprintln!("{}:\n{text}", path.display());
}

#[test]
fn derivation_arithmetic() {
    assert_eq!(leaf_perms(34), 1);
    assert_eq!(leaf_perms(35), 2);
    // A trace row of 3,808 columns with 5 random codewords and 5 salts.
    assert_eq!(leaf_perms(3808 + 10), 113);
    assert_eq!(keccak256_permutations(0), 1);
    assert_eq!(keccak256_permutations(135), 1);
    assert_eq!(keccak256_permutations(136), 2);
    assert_eq!(keccak_rows(85), 2048);
    assert_eq!(keccak_rows(86), 4096);
    assert_eq!(multiproof_bound(43, 6), 63);

    // A 2,048-row proof: 12 rounds over a 2^15 codeword; three input trees of
    // 15 levels and folding trees of 14 down to 3 levels, for each of 43
    // queries.
    let shape = Shape {
        queries: 43,
        degree_bits: 12,
        trace_width: 3808,
        quotient_chunks: 8,
        fri_rounds: 12,
        public_values: 0,
    };
    let counts = shape.counts();
    assert_eq!(counts.merkle, 43 * (45 + 102));
    assert_eq!(counts.leaf, 43 * (1 + 113 + 4 + 12));
    // One more column past a block boundary costs one more leaf permutation a query.
    let wider = Shape { trace_width: 3808 + 34, ..shape }.counts();
    assert_eq!(wider.leaf - counts.leaf, 43);
    // A doubled trace adds a level to each of the 3 input trees, and a round
    // whose tree, the new top one, has 15 levels.
    let taller = Shape { degree_bits: 13, fri_rounds: 13, ..shape }.counts();
    assert_eq!(taller.merkle - counts.merkle, 43 * (3 + 15));
}
