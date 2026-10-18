//! The proof system of decision 0003 and the one place it is configured.
//!
//! BabyBear with a degree-5 extension for challenges, Keccak-256 for every
//! commitment, hiding FRI at blowup 2^2 with 57 queries and 16 bits of
//! grinding on the queries, zero-knowledge mode on, at least 128 conjectured
//! bits by the library's own estimator. The larger trace of the coin reveal
//! also needs 16 bits of grinding before the batching challenge
//! ([`BATCH_POW_BITS`]).
//!
//! Plonky3 makes a proof zero-knowledge with a hiding polynomial commitment
//! scheme (`HidingFriPcs`) paired with a hiding Merkle commitment
//! (`MerkleTreeHidingMmcs`). [`stark_config`] is the only function that builds
//! a configuration, for the prover and the verifier alike. Its types are the
//! hiding ones, there is no other configuration type in this crate, and it
//! refuses to return a configuration the library does not report as
//! zero-knowledge. So there is no way to prove with zero-knowledge off.
//!
//! The zero-knowledge randomness is 32 bytes the caller supplies; this crate
//! never reads the operating system's random source.
//!
//! The proof-size budget of spec 07, section 3 lives here too: no statement's
//! trace may be taller than [`MAX_TRACE_HEIGHT`] or wider than
//! [`MAX_TRACE_WIDTH`], the coin reveal's, and [`proof_length_bound`] shows
//! that a proof of such a trace fits [`PROOF_FIELD_BYTES`].

use alloc::vec::Vec;
use std::sync::OnceLock;

use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{
    AirLayout, ConjecturedSecurity, GrindingSites, OpeningShape, Proof as StarkProof, ProvenSecurity,
    StarkConfig, StarkGenericConfig, StarkSecurityParams, get_max_constraint_degree,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::ProofError;
use crate::air::{F, StatementAir};
use crate::schedule::{Assignment, Schedule, execute};

/// Degree of the challenge field over BabyBear.
pub const EXTENSION_DEGREE: usize = 5;
/// log2 of the challenge field size, rounded down: 5 * log2(2^31 - 2^27 + 1).
pub const CHALLENGE_FIELD_BITS: usize = 154;
/// log2 of the blowup.
pub const LOG_BLOWUP: usize = 2;
/// FRI queries.
pub const NUM_QUERIES: usize = 57;
/// Proof-of-work bits before the FRI queries are drawn.
pub const QUERY_POW_BITS: usize = 16;
/// Proof-of-work bits before the challenge that batches the openings.
///
/// The coin reveal's trace is 2,048 rows of about 3,800 columns, larger than
/// the benchmark statement decision 0003 measured. The estimator's
/// batched-openings term, `|EF| / ((functions - 1) * codeword length)`, comes
/// to about 127 bits for it without grinding, whatever the query count. The
/// decision's security gate allows up to 16 bits at a site and, after the
/// queries, tries the batching challenge next; this is that choice. It costs
/// the prover about 2^16 hashes and the verifier one.
pub const BATCH_POW_BITS: usize = 16;
/// The most grinding allowed at any one site.
pub const MAX_GRINDING_BITS: usize = 16;
const _: () = assert!(QUERY_POW_BITS <= MAX_GRINDING_BITS && BATCH_POW_BITS <= MAX_GRINDING_BITS);
/// The floor: a statement below this many conjectured bits is refused.
pub const TARGET_CONJECTURED_BITS: usize = 128;
/// Collision resistance of Keccak-256 as the commitment hash.
pub const COLLISION_RESISTANCE_BITS: usize = 128;
/// Random columns hiding FRI appends to each committed matrix; the library
/// requires at least the extension degree.
const NUM_RANDOM_CODEWORDS: usize = EXTENSION_DEGREE;
/// Salt elements per Merkle leaf: 5 * 31 = 155 bits of salt.
const SALT_ELEMS: usize = 5;
/// Points at which the main trace is opened (`zeta` and `zeta * g`).
const TRACE_OPENING_POINTS: usize = 2;
/// Words of a Merkle digest: Keccak-256 as four `u64` lanes.
const DIGEST_WORDS: usize = 4;

/// Width of the proof field of a private transaction in version 1, for every
/// reveal kind (spec 07, section 3): 1.25 MiB. A change of width is a new
/// transaction version, never an edit of this one.
pub const PROOF_FIELD_BYTES: usize = 1_310_720;
/// The proof-size budget (spec 07, section 3): the most rows a statement's
/// trace may have before zero-knowledge padding, the coin reveal's.
pub const MAX_TRACE_HEIGHT: usize = 2048;
/// The most columns a statement's trace may have, the coin reveal's.
pub const MAX_TRACE_WIDTH: usize = 3808;

/// The challenge field.
pub(crate) type Challenge = BinomialExtensionField<BabyBear, EXTENSION_DEGREE>;
type Dft = Radix2DitParallel<F>;
type KeccakU64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type KeccakFieldHash = SerializingHasher<KeccakU64Hash>;
type KeccakCompress = CompressionFunctionFromHasher<KeccakU64Hash, 2, 4>;
type ValMmcs = MerkleTreeHidingMmcs<
    [F; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    KeccakFieldHash,
    KeccakCompress,
    StdRng,
    2,
    DIGEST_WORDS,
    SALT_ELEMS,
>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;
type Pcs = HidingFriPcs<F, Dft, ValMmcs, ChallengeMmcs, StdRng>;
/// The one configuration type: hiding commitments only.
pub(crate) type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// The library's minimum trace height for zero-knowledge:
/// `N >= 2 * (num_queries + D * points)` (`HidingFriPcs`).
pub const fn zk_min_trace_height() -> usize {
    2 * (NUM_QUERIES + EXTENSION_DEGREE * TRACE_OPENING_POINTS)
}

fn fri_parameters<M>(mmcs: M) -> FriParameters<M> {
    FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: BATCH_POW_BITS,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_POW_BITS,
        mmcs,
    }
}

/// The configuration the public prove and verify functions use. `zk_seed`
/// must be fresh secure randomness when proving; the verifier draws nothing
/// from it.
pub(crate) fn stark_config(zk_seed: [u8; 32]) -> Result<Config, ProofError> {
    let mut master = StdRng::from_seed(zk_seed);
    let salts = StdRng::from_rng(&mut master);
    let masks = StdRng::from_rng(&mut master);
    let u64_hash = KeccakU64Hash::new(KeccakF {});
    let val_mmcs = ValMmcs::new(KeccakFieldHash::new(u64_hash), KeccakCompress::new(u64_hash), 0, salts);
    let fri = fri_parameters(ChallengeMmcs::new(val_mmcs.clone()));
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri, NUM_RANDOM_CODEWORDS, masks);
    let config = Config::new(pcs, Challenger::from_hasher(Vec::new(), Keccak256Hash {}));
    if config.is_zk() == 1 {
        Ok(config)
    } else {
        Err(ProofError::NotZeroKnowledge)
    }
}

/// Whether the shipped configuration is zero-knowledge, as the library
/// reports it.
pub(crate) fn shipped_is_zero_knowledge() -> bool {
    stark_config([0; 32]).is_ok_and(|config| config.is_zk() == 1)
}

/// The estimator's result for one statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityEstimate {
    /// Conjectured bits, the target regime.
    pub conjectured_bits: usize,
    /// Best proven bits for the same parameters, for the record.
    pub proven_bits: usize,
    /// Trace height before zero-knowledge padding.
    pub trace_height: usize,
    /// Trace width.
    pub trace_width: usize,
    /// Maximum constraint degree.
    pub constraint_degree: usize,
}

/// Apply the library's estimator (`p3-security`, through
/// `StarkSecurityParams`) to the actual parameters of a statement.
fn estimate(air: &StatementAir) -> SecurityEstimate {
    let log_height = air.height().trailing_zeros() as usize;
    let regime = fri_parameters(()).security_regime();
    let mut params = StarkSecurityParams::from_air::<F, Challenge, StatementAir>(
        regime,
        air,
        AirLayout::from_air(air),
        TwoAdicMultiplicativeCoset::new(BabyBear::ONE, log_height).expect("two-adic height"),
        CHALLENGE_FIELD_BITS,
        COLLISION_RESISTANCE_BITS,
        TRACE_OPENING_POINTS,
        OpeningShape::hiding(NUM_RANDOM_CODEWORDS),
        GrindingSites {
            batch_combination: BATCH_POW_BITS,
            ..GrindingSites::NONE
        },
    );
    params.fri_num_queries = NUM_QUERIES;
    params.fri_query_proof_of_work_bits = QUERY_POW_BITS;
    // The committed polynomials are twice as tall after zero-knowledge padding.
    let degree_bits = log_height + 1;
    let constraint_degree = get_max_constraint_degree::<F, StatementAir>(air, AirLayout::from_air(air), air.height())
        .max(<StatementAir as BaseAir<F>>::max_constraint_degree(air).unwrap_or(0));
    SecurityEstimate {
        conjectured_bits: ConjecturedSecurity::compute_from_params(&params, degree_bits).security_bits,
        proven_bits: ProvenSecurity::compute_from_proof(degree_bits, &params).security_bits(),
        trace_height: air.height(),
        trace_width: air.width(),
        constraint_degree,
    }
}

/// The three statements, each with its own fixed shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Statement {
    /// S1, the one-time reveal of a coin.
    CoinReveal,
    /// S2, the one-time reveal of data (reveal or revoke).
    DataReveal,
    /// S3, the proof of holding.
    Hold,
}

impl Statement {
    pub const ALL: [Self; 3] = [Self::CoinReveal, Self::DataReveal, Self::Hold];

    const fn index(self) -> usize {
        match self {
            Self::CoinReveal => 0,
            Self::DataReveal => 1,
            Self::Hold => 2,
        }
    }

    /// The statement's schedule, without any witness.
    pub(crate) fn schedule(self) -> Schedule {
        match self {
            Self::CoinReveal => crate::reveal::schedule(None).0,
            Self::DataReveal => crate::data::schedule(None).0,
            Self::Hold => crate::hold::schedule(None).0,
        }
    }

    pub(crate) fn air(self) -> StatementAir {
        let schedule = self.schedule();
        let height = StatementAir::height_for(&schedule, zk_min_trace_height());
        StatementAir::new(schedule, height)
    }
}

/// The security gate: the estimate of a statement at the shipped
/// parameters, computed once, and refused below the floor.
pub(crate) fn gate(statement: Statement) -> Result<SecurityEstimate, ProofError> {
    static PLANS: [OnceLock<SecurityEstimate>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
    let est = *PLANS[statement.index()].get_or_init(|| estimate(&statement.air()));
    within_budget(&est)?;
    // Zero-knowledge adds one to the quotient degree, so the constraint degree
    // must fit the blowup.
    if est.constraint_degree > 1 << LOG_BLOWUP {
        return Err(ProofError::ConstraintDegreeTooHigh);
    }
    if est.conjectured_bits < TARGET_CONJECTURED_BITS {
        return Err(ProofError::BelowSecurityFloor {
            bits: est.conjectured_bits,
        });
    }
    Ok(est)
}

/// The proof-size budget: a statement whose trace is taller or wider than the
/// coin reveal's could make a proof longer than [`PROOF_FIELD_BYTES`], so it
/// is refused before anything is proved or verified.
fn within_budget(est: &SecurityEstimate) -> Result<(), ProofError> {
    if est.trace_height > MAX_TRACE_HEIGHT || est.trace_width > MAX_TRACE_WIDTH {
        return Err(ProofError::TraceOverBudget {
            height: est.trace_height,
            width: est.trace_width,
        });
    }
    Ok(())
}

// The proof length bound. Every size is the most the encoding can write at
// the pinned Plonky3 revision, through postcard.

/// A BabyBear element: four little-endian bytes, never a varint.
const FIELD_BYTES: usize = 4;
/// A challenge: [`EXTENSION_DEGREE`] base elements, with no length prefix.
const CHALLENGE_BYTES: usize = EXTENSION_DEGREE * FIELD_BYTES;
/// The longest varint postcard writes, for a length prefix or a `usize`.
const VARINT_MAX_BYTES: usize = 10;
/// A digest: [`DIGEST_WORDS`] `u64` words, each a varint.
const DIGEST_MAX_BYTES: usize = DIGEST_WORDS * VARINT_MAX_BYTES;
/// The tag of an `Option`.
const OPTION_TAG_BYTES: usize = 1;
/// A commitment: a Merkle cap of height 0, one digest behind a length prefix.
const CAP_BYTES: usize = VARINT_MAX_BYTES + DIGEST_MAX_BYTES;
/// The most quotient chunks the gate lets through. The gate allows a
/// constraint degree `d` of at most the blowup; the library splits the
/// quotient into `2 * next_power_of_two(d)` chunks in zero-knowledge mode.
const MAX_QUOTIENT_CHUNKS: usize = 2 * (1 << LOG_BLOWUP);
/// Base columns of the quotient chunks and of the randomization polynomial:
/// one challenge flattened, before the hiding columns.
const FLATTENED_CHALLENGE_COLUMNS: usize = EXTENSION_DEGREE;

/// A sequence of `len` items of `item` bytes each, behind its length prefix.
const fn seq(len: usize, item: usize) -> usize {
    VARINT_MAX_BYTES + len * item
}

/// The most sibling digests a pruned multiproof for [`NUM_QUERIES`] indices
/// can carry in a binary tree of `depth` levels: at each level at most one
/// per parent of a queried node, so at most one per query and at most the
/// number of parents at that level.
fn multiproof_digests(depth: usize) -> usize {
    (0..depth).map(|level| NUM_QUERIES.min(1 << level)).sum()
}

/// The longest proof the shipped configuration can serialize for a statement
/// whose trace has `trace_height` rows (before zero-knowledge padding) and
/// `trace_width` columns. It is a bound from the proof's structure, not a
/// sampled length: every term takes its worst case (spec 07, section 3).
pub fn proof_length_bound(trace_height: usize, trace_width: usize) -> usize {
    let h = trace_height.max(zk_min_trace_height()).next_power_of_two();
    // Zero-knowledge doubles the rows, and the blowup gives the codeword.
    let log_codeword = (2 * h).trailing_zeros() as usize + LOG_BLOWUP;
    // Binary folding down to a final polynomial of one coefficient.
    let fri_rounds = log_codeword - LOG_BLOWUP;
    let chunks = MAX_QUOTIENT_CHUNKS;
    let challenges = |n| seq(n, CHALLENGE_BYTES);
    let row = |n| seq(n, FIELD_BYTES);

    // Trace, quotient and the optional randomization commitment.
    let commitments = 3 * CAP_BYTES + OPTION_TAG_BYTES;
    // The trace at zeta and zeta * g, no preprocessed trace (two absent
    // options), each quotient chunk at zeta and the randomization polynomial.
    let opened_values = challenges(trace_width)
        + OPTION_TAG_BYTES
        + challenges(trace_width)
        + 2 * OPTION_TAG_BYTES
        + seq(chunks, challenges(FLATTENED_CHALLENGE_COLUMNS))
        + OPTION_TAG_BYTES
        + challenges(FLATTENED_CHALLENGE_COLUMNS);
    // The hidden columns' openings, per round, matrix and point.
    let hidden = challenges(NUM_RANDOM_CODEWORDS);
    let hidden_openings = VARINT_MAX_BYTES
        + seq(1, seq(1, hidden))
        + seq(1, seq(TRACE_OPENING_POINTS, hidden))
        + seq(chunks, seq(1, hidden));
    // One input batch: every query's rows, every query's salts and one
    // pruned multiproof over the codeword tree.
    let batch = |matrices: usize, width: usize| {
        seq(NUM_QUERIES, seq(matrices, row(width)))
            + seq(NUM_QUERIES, seq(matrices, row(SALT_ELEMS)))
            + seq(multiproof_digests(log_codeword), DIGEST_MAX_BYTES)
    };
    let input_openings = VARINT_MAX_BYTES
        + batch(1, NUM_RANDOM_CODEWORDS + FLATTENED_CHALLENGE_COLUMNS)
        + batch(1, trace_width + NUM_RANDOM_CODEWORDS)
        + batch(chunks, FLATTENED_CHALLENGE_COLUMNS + NUM_RANDOM_CODEWORDS);
    // Each FRI layer: one sibling per query, its salts and its multiproof;
    // layer `i` is a tree of `log_codeword - 1 - i` levels.
    let layers: usize = (0..fri_rounds)
        .map(|i| {
            seq(NUM_QUERIES, challenges(1))
                + seq(NUM_QUERIES, seq(1, row(SALT_ELEMS)))
                + seq(multiproof_digests(log_codeword - 1 - i), DIGEST_MAX_BYTES)
        })
        .sum();
    let fri = FIELD_BYTES
        + seq(fri_rounds, CAP_BYTES)
        + seq(fri_rounds, FIELD_BYTES)
        + input_openings
        + VARINT_MAX_BYTES
        + layers
        + challenges(1)
        + FIELD_BYTES;
    // Then `degree_bits` and the out-of-domain grinding witness.
    commitments + opened_values + hidden_openings + fri + VARINT_MAX_BYTES + FIELD_BYTES
}

fn public_field(public: &[u8]) -> Vec<F> {
    public.iter().map(|&b| F::from_u8(b)).collect()
}

/// Prove an assignment of a statement. The caller has already checked the
/// witness; nothing here does.
pub(crate) fn prove(statement: Statement, a: &Assignment, zk_seed: [u8; 32]) -> Result<Vec<u8>, ProofError> {
    gate(statement)?;
    let air = statement.air();
    let ex = execute(&statement.schedule(), a);
    let trace = air.generate_trace(&ex, a);
    let config = stark_config(zk_seed)?;
    let proof = p3_uni_stark::prove(&config, &air, trace, &public_field(&a.public)).map_err(|_| ProofError::Proving)?;
    postcard::to_allocvec(&proof).map_err(|_| ProofError::Proving)
}

/// Verify a proof of a statement against public values the verifier built.
pub(crate) fn verify(statement: Statement, public: &[u8], proof: &[u8]) -> Result<(), ProofError> {
    gate(statement)?;
    let air = statement.air();
    if public.len() != air.num_public_values() {
        return Err(ProofError::Rejected);
    }
    let config = stark_config([0; 32])?;
    let proof: StarkProof<Config> = postcard::from_bytes(proof).map_err(|_| ProofError::MalformedProof)?;
    let expected_degree_bits = air.height().trailing_zeros() as usize + 1;
    if proof.degree_bits != expected_degree_bits {
        return Err(ProofError::MalformedProof);
    }
    p3_uni_stark::verify(&config, &air, &proof, &public_field(public)).map_err(|_| ProofError::Rejected)
}

/// The length of the one serialized proof at the start of `bytes`, or `None`
/// when no proof of the shipped configuration decodes there.
pub(crate) fn serialized_len(bytes: &[u8]) -> Option<usize> {
    let (_, rest) = postcard::take_from_bytes::<StarkProof<Config>>(bytes).ok()?;
    Some(bytes.len() - rest.len())
}

/// The gate's estimate for every statement, for the shipped configuration
/// report.
pub(crate) fn estimates() -> Result<[(Statement, SecurityEstimate); 3], ProofError> {
    let mut out = [(Statement::CoinReveal, gate(Statement::CoinReveal)?); 3];
    for (slot, statement) in out.iter_mut().zip(Statement::ALL) {
        *slot = (statement, gate(statement)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(trace_height: usize, trace_width: usize) -> SecurityEstimate {
        SecurityEstimate {
            conjectured_bits: TARGET_CONJECTURED_BITS,
            proven_bits: 0,
            trace_height,
            trace_width,
            constraint_degree: 1 << LOG_BLOWUP,
        }
    }

    /// The gate refuses a trace one row or one column over the budget, and
    /// takes the budget trace itself.
    #[test]
    fn budget_refuses_a_trace_over_it() {
        assert_eq!(within_budget(&trace(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH)), Ok(()));
        assert_eq!(
            within_budget(&trace(2 * MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH)),
            Err(ProofError::TraceOverBudget {
                height: 2 * MAX_TRACE_HEIGHT,
                width: MAX_TRACE_WIDTH
            })
        );
        assert_eq!(
            within_budget(&trace(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH + 1)),
            Err(ProofError::TraceOverBudget {
                height: MAX_TRACE_HEIGHT,
                width: MAX_TRACE_WIDTH + 1
            })
        );
    }

    /// Each extra column adds its two out-of-domain challenges and one base
    /// element per query; a doubled height adds a level to every tree.
    #[test]
    fn bound_grows_with_the_trace() {
        let base = proof_length_bound(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH);
        assert_eq!(
            proof_length_bound(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH + 1) - base,
            2 * CHALLENGE_BYTES + NUM_QUERIES * FIELD_BYTES
        );
        assert!(proof_length_bound(2 * MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH) > base);
        assert_eq!(proof_length_bound(1000, 10), proof_length_bound(1024, 10));
    }

    /// A multiproof never needs more than one digest per query per level, nor
    /// more than the level has parents.
    #[test]
    fn multiproof_digests_take_the_worst_level_by_level() {
        assert_eq!(multiproof_digests(1), 1);
        assert_eq!(multiproof_digests(6), 63);
        assert_eq!(multiproof_digests(14), 63 + 8 * NUM_QUERIES);
    }
}
