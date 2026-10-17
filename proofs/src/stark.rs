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
    4,
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

/// The gate's estimate for every statement, for the shipped configuration
/// report.
pub(crate) fn estimates() -> Result<[(Statement, SecurityEstimate); 3], ProofError> {
    let mut out = [(Statement::CoinReveal, gate(Statement::CoinReveal)?); 3];
    for (slot, statement) in out.iter_mut().zip(Statement::ALL) {
        *slot = (statement, gate(statement)?);
    }
    Ok(out)
}
