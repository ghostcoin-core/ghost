//! The scale build's proof configuration: the version 2 coin reveal proven
//! with Poseidon2 commitments and transcript (stage 2 design, "Aggregation
//! cost", leaf, and "Whole-bundle proven security bound").
//!
//! The statement is the one of [`crate::reveal_v2`], unchanged: the same AIR,
//! the same public values and the same Keccak-256 hashes of commitments,
//! markers and the binding inside the trace. Only the proof system around it
//! changes:
//!
//! - every Merkle commitment and the Fiat–Shamir transcript use Poseidon2 over
//!   BabyBear of width 24 ([`SCALE_POSEIDON2_WIDTH`]), as a sponge of rate 15
//!   and capacity 9, with a 9-element digest of 279 bits
//!   ([`SCALE_DIGEST_BITS`]); a Merkle node is the width-24 permutation of its
//!   two children, truncated to 9 elements;
//! - challenges come from the degree-8 binomial extension of BabyBear;
//! - hiding FRI at blowup 2^3 with 96 queries, 16 bits of grinding on the
//!   queries and 16 before the batching challenge; zero-knowledge on.
//!
//! It sits beside the shipped Keccak configuration of [`crate::stark`] and
//! shares nothing with its verify path: a proof of one configuration does not
//! decode or verify as a proof of the other. Nothing here changes
//! [`crate::PROOF_FIELD_BYTES`]; a proof of this configuration is larger than
//! that field (see [`SCALE_MODELED_PROOF_BYTES`]).
//!
//! Like the rest of the crate it uses no thread, clock, file or operating
//! system random source: the zero-knowledge randomness is 32 bytes the caller
//! supplies, so it builds for `wasm32-unknown-unknown` as it is.

use alloc::vec::Vec;
use std::sync::OnceLock;

use p3_air::BaseAir;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_24};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::HidingFriPcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    AirLayout, ConjecturedSecurity, OpeningShape, Proof as StarkProof, ProvenSecurity, StarkConfig,
    StarkGenericConfig, StarkSecurityParams, get_max_constraint_degree,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::ProofError;
use crate::air::{F, StatementAir};
use crate::schedule::{Assignment, Schedule, execute};
use crate::stark::{
    FriShape, MAX_GRINDING_BITS, MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH, MIN_SALT_BITS, MemoDft, SecurityEstimate,
    TARGET_CONJECTURED_BITS, fri_parameters, public_field,
};

/// Width of the Poseidon2 permutation over BabyBear.
pub const SCALE_POSEIDON2_WIDTH: usize = 24;
/// Elements the sponge absorbs per permutation.
pub const SCALE_SPONGE_RATE: usize = 15;
/// Elements of the sponge's state never written by the input.
pub const SCALE_SPONGE_CAPACITY: usize = 9;
const _: () = assert!(SCALE_SPONGE_RATE + SCALE_SPONGE_CAPACITY == SCALE_POSEIDON2_WIDTH);
/// Elements of a Merkle digest.
pub const SCALE_DIGEST_ELEMS: usize = 9;
/// Bits of a digest, rounded down: 9 elements of 31 bits (stage 2 design,
/// "Whole-bundle proven security bound": 279).
pub const SCALE_DIGEST_BITS: usize = SCALE_DIGEST_ELEMS * 31;
/// Collision resistance of the digest: half its bits.
pub const SCALE_COLLISION_RESISTANCE_BITS: usize = SCALE_DIGEST_BITS / 2;
/// Degree of the challenge field over BabyBear.
pub const SCALE_EXTENSION_DEGREE: usize = 8;
/// log2 of the challenge field size, rounded down: 8 * log2(2^31 - 2^27 + 1).
pub const SCALE_CHALLENGE_FIELD_BITS: usize = 247;
/// log2 of the blowup: rate 1/8.
pub const SCALE_LOG_BLOWUP: usize = 3;
/// FRI queries.
pub const SCALE_NUM_QUERIES: usize = 96;
/// Proof-of-work bits before the FRI queries are drawn.
pub const SCALE_QUERY_POW_BITS: usize = 16;
/// Proof-of-work bits before the challenge that batches the openings.
pub const SCALE_BATCH_POW_BITS: usize = 16;
/// The proof length the stage 2 design models for a reveal proof at 96
/// queries ("Aggregation cost", the direct path). A proof longer than this is
/// a finding against the design, not a reason to move the figure.
pub const SCALE_MODELED_PROOF_BYTES: usize = 2_330_908;

/// Salt elements per Merkle leaf: 5 BabyBear elements, 154 bits.
const SALT_ELEMS: usize = 5;
/// Salt bits per opened row, rounded down.
const SALT_BITS: usize = SALT_ELEMS * SCALE_CHALLENGE_FIELD_BITS / SCALE_EXTENSION_DEGREE;
/// Random columns hiding FRI appends to each committed matrix; the library
/// requires at least the extension degree.
const NUM_RANDOM_CODEWORDS: usize = SCALE_EXTENSION_DEGREE;
/// Points at which the main trace is opened (`zeta` and `zeta * g`).
const TRACE_OPENING_POINTS: usize = 2;

/// The FRI settings of the scale configuration.
const SCALE_FRI: FriShape = FriShape {
    log_blowup: SCALE_LOG_BLOWUP,
    num_queries: SCALE_NUM_QUERIES,
    query_pow_bits: SCALE_QUERY_POW_BITS,
    batch_pow_bits: SCALE_BATCH_POW_BITS,
};

type Perm = Poseidon2BabyBear<SCALE_POSEIDON2_WIDTH>;
type Packed = <F as Field>::Packing;
type Challenge = BinomialExtensionField<BabyBear, SCALE_EXTENSION_DEGREE>;
type Challenger = DuplexChallenger<F, Perm, SCALE_POSEIDON2_WIDTH, SCALE_SPONGE_RATE>;

/// The library's width-24 Poseidon2 over BabyBear with its default round
/// constants, built once.
fn perm() -> Perm {
    static PERM: OnceLock<Perm> = OnceLock::new();
    PERM.get_or_init(default_babybear_poseidon2_24).clone()
}

/// The shape of a proof of this configuration that a test may change: the
/// query count and the digest length. [`ScaleShape::SHIPPED`] is the only
/// shape the public prove and verify functions use; the others exist so tests
/// can show a proof of another shape is rejected.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScaleShape {
    pub num_queries: usize,
    /// 9, or 8 for a test of a proof whose digests are one element short.
    pub digest_elems: usize,
}

impl ScaleShape {
    pub const SHIPPED: Self = Self {
        num_queries: SCALE_NUM_QUERIES,
        digest_elems: SCALE_DIGEST_ELEMS,
    };

    const fn fri(self) -> FriShape {
        FriShape {
            num_queries: self.num_queries,
            ..SCALE_FRI
        }
    }
}

/// The configuration types and their prove and verify functions for one
/// digest length. The digest length is a type parameter of the Merkle
/// commitment, so each length is its own set of types.
macro_rules! scale_backend {
    ($name:ident, $digest:expr) => {
        #[allow(dead_code)]
        mod $name {
            use super::*;

            const DIGEST: usize = $digest;
            type Hash = PaddingFreeSponge<Perm, SCALE_POSEIDON2_WIDTH, SCALE_SPONGE_RATE, DIGEST>;
            type Compress = TruncatedPermutation<Perm, 2, DIGEST, SCALE_POSEIDON2_WIDTH>;
            type ValMmcs = MerkleTreeHidingMmcs<Packed, Packed, Hash, Compress, StdRng, 2, DIGEST, SALT_ELEMS>;
            type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
            type Pcs = HidingFriPcs<F, MemoDft, ValMmcs, ChallengeMmcs, StdRng>;
            pub(super) type Config = StarkConfig<Pcs, Challenge, Challenger>;

            pub(super) fn config(zk_seed: [u8; 32], fri: &FriShape) -> Result<Config, ProofError> {
                let mut master = StdRng::from_seed(zk_seed);
                let salts = StdRng::from_rng(&mut master);
                let masks = StdRng::from_rng(&mut master);
                let val_mmcs = ValMmcs::new(Hash::new(perm()), Compress::new(perm()), 0, salts);
                let fri = fri_parameters(fri, ChallengeMmcs::new(val_mmcs.clone()));
                let pcs = Pcs::new(MemoDft::default(), val_mmcs, fri, NUM_RANDOM_CODEWORDS, masks);
                let config = Config::new(pcs, Challenger::new(perm()));
                if config.is_zk() == 1 { Ok(config) } else { Err(ProofError::NotZeroKnowledge) }
            }

            pub(super) fn prove(
                air: &StatementAir,
                trace: RowMajorMatrix<F>,
                public: &[u8],
                zk_seed: [u8; 32],
                fri: &FriShape,
            ) -> Result<Vec<u8>, ProofError> {
                let config = config(zk_seed, fri)?;
                let proof = p3_uni_stark::prove(&config, air, trace, &public_field(public))
                    .map_err(|_| ProofError::Proving)?;
                postcard::to_allocvec(&proof).map_err(|_| ProofError::Proving)
            }

            pub(super) fn verify(
                air: &StatementAir,
                public: &[u8],
                proof: &[u8],
                fri: &FriShape,
            ) -> Result<(), ProofError> {
                if public.len() != air.num_public_values() {
                    return Err(ProofError::Rejected);
                }
                let config = config([0; 32], fri)?;
                let (proof, rest) = postcard::take_from_bytes::<StarkProof<Config>>(proof)
                    .map_err(|_| ProofError::MalformedProof)?;
                if !rest.is_empty() {
                    return Err(ProofError::MalformedProof);
                }
                if proof.degree_bits != air.height().trailing_zeros() as usize + 1 {
                    return Err(ProofError::MalformedProof);
                }
                // The query count, checked on the proof's own shape before the
                // library runs: every input batch and every folding layer opens
                // exactly one row set per query.
                let fri_proof = &proof.opening_proof.1;
                let inputs_ok = fri_proof
                    .input_openings
                    .iter()
                    .all(|batch| batch.opened_values.len() == fri.num_queries);
                let layers_ok = fri_proof
                    .commit_phase_openings
                    .iter()
                    .all(|layer| layer.sibling_values.len() == fri.num_queries);
                if fri_proof.input_openings.is_empty() || !inputs_ok || !layers_ok {
                    return Err(ProofError::MalformedProof);
                }
                p3_uni_stark::verify(&config, air, &proof, &public_field(public)).map_err(|_| ProofError::Rejected)
            }
        }
    };
}

scale_backend!(digest9, SCALE_DIGEST_ELEMS);
scale_backend!(digest8, SCALE_DIGEST_ELEMS - 1);

/// The library's minimum trace height for zero-knowledge at this
/// configuration: `N >= 2 * (num_queries + D * points)` (`HidingFriPcs`).
const fn zk_min_trace_height(num_queries: usize) -> usize {
    2 * (num_queries + SCALE_EXTENSION_DEGREE * TRACE_OPENING_POINTS)
}

/// The statement's AIR, at the height this configuration needs.
fn air_for(schedule: Schedule, num_queries: usize) -> StatementAir {
    let height = StatementAir::height_for(&schedule, zk_min_trace_height(num_queries));
    StatementAir::new(schedule, height)
}

/// The library's estimator applied to the statement at the scale
/// configuration, once with the grinding as it is and once with each site at
/// half its bits. `None` when the estimator cannot be run.
fn estimate(air: &StatementAir, fri: &FriShape) -> Option<SecurityEstimate> {
    let height = air.height();
    if !height.is_power_of_two() {
        return None;
    }
    let log_height = height.trailing_zeros() as usize;
    // The committed polynomials are twice as tall after zero-knowledge padding.
    let degree_bits = log_height + 1;
    let report = |fri: &FriShape| -> Option<(usize, usize)> {
        let fri = fri_parameters(fri, ());
        let params = StarkSecurityParams::from_air::<F, Challenge, StatementAir>(
            fri.security_regime(),
            air,
            AirLayout::from_air(air),
            TwoAdicMultiplicativeCoset::new(BabyBear::ONE, log_height)?,
            SCALE_CHALLENGE_FIELD_BITS,
            SCALE_COLLISION_RESISTANCE_BITS,
            TRACE_OPENING_POINTS,
            OpeningShape::hiding(NUM_RANDOM_CODEWORDS),
            fri.grinding_sites(),
        );
        Some((
            ConjecturedSecurity::compute_from_params(&params, degree_bits).security_bits,
            ProvenSecurity::compute_from_proof(degree_bits, &params).security_bits(),
        ))
    };
    let (conjectured_bits, proven_bits) = report(fri)?;
    let (conjectured_bits_half_grinding, _) = report(&FriShape {
        query_pow_bits: fri.query_pow_bits / 2,
        batch_pow_bits: fri.batch_pow_bits / 2,
        ..*fri
    })?;
    let constraint_degree = get_max_constraint_degree::<F, StatementAir>(air, AirLayout::from_air(air), height)
        .max(<StatementAir as BaseAir<F>>::max_constraint_degree(air).unwrap_or(0));
    Some(SecurityEstimate {
        conjectured_bits,
        conjectured_bits_half_grinding,
        conjectured_quantum_bits: conjectured_bits / 2,
        proven_bits,
        proven_quantum_bits: proven_bits / 2,
        trace_height: height,
        trace_width: air.width(),
        constraint_degree,
    })
}

/// The rule of spec 09, section 4.1 as the scale configuration meets it,
/// item 3 read for Poseidon2: the queries alone reach 128 conjectured bits,
/// no site grinds more than [`MAX_GRINDING_BITS`], the digest is the 9
/// elements of the design, salts are at least [`MIN_SALT_BITS`], the trace is
/// within the budget, the constraint degree fits the blowup, and the
/// estimator, grinding counted at half, reports at least 128 bits.
fn check(air: &StatementAir) -> Result<SecurityEstimate, ProofError> {
    let fri = &SCALE_FRI;
    let query_bits = fri.log_blowup * fri.num_queries;
    if query_bits < TARGET_CONJECTURED_BITS {
        return Err(ProofError::TooFewQueries { bits: query_bits });
    }
    if fri.query_pow_bits > MAX_GRINDING_BITS || fri.batch_pow_bits > MAX_GRINDING_BITS {
        return Err(ProofError::TooMuchGrinding);
    }
    if SALT_BITS < MIN_SALT_BITS {
        return Err(ProofError::SaltTooShort { bits: SALT_BITS });
    }
    if digest9::config([0; 32], fri).is_err() {
        return Err(ProofError::NotZeroKnowledge);
    }
    let est = estimate(air, fri).ok_or(ProofError::EstimateUnavailable)?;
    if est.trace_height > MAX_TRACE_HEIGHT || est.trace_width > MAX_TRACE_WIDTH {
        return Err(ProofError::TraceOverBudget {
            height: est.trace_height,
            width: est.trace_width,
        });
    }
    if est.constraint_degree > 1 << fri.log_blowup {
        return Err(ProofError::ConstraintDegreeTooHigh);
    }
    if est.conjectured_bits_half_grinding < TARGET_CONJECTURED_BITS {
        return Err(ProofError::BelowSecurityFloor {
            bits: est.conjectured_bits_half_grinding,
        });
    }
    Ok(est)
}

/// The gate of the version 2 coin reveal at the scale configuration,
/// computed once.
fn gate() -> Result<SecurityEstimate, ProofError> {
    static PLAN: OnceLock<Result<SecurityEstimate, ProofError>> = OnceLock::new();
    PLAN.get_or_init(|| check(&air_for(crate::reveal_v2::schedule(), SCALE_NUM_QUERIES))).clone()
}

/// The estimator's report for the version 2 coin reveal at the scale
/// configuration, or the item of the rule it breaks.
pub fn scale_coin_reveal_v2_estimate() -> Result<SecurityEstimate, ProofError> {
    gate()
}

/// Prove an assignment of the version 2 coin reveal at `shape`. The caller
/// has already checked the witness; nothing here does.
pub(crate) fn prove(a: &Assignment, zk_seed: [u8; 32], shape: ScaleShape) -> Result<Vec<u8>, ProofError> {
    if shape == ScaleShape::SHIPPED {
        gate()?;
    }
    let schedule = crate::reveal_v2::schedule();
    let ex = execute(&schedule, a);
    let air = air_for(schedule, shape.num_queries);
    let trace = air.generate_trace_with(&ex, a, None);
    match shape.digest_elems {
        SCALE_DIGEST_ELEMS => digest9::prove(&air, trace, &a.public, zk_seed, &shape.fri()),
        8 => digest8::prove(&air, trace, &a.public, zk_seed, &shape.fri()),
        _ => Err(ProofError::Proving),
    }
}

/// Verify a proof of the version 2 coin reveal at `shape` against public
/// values the verifier built.
pub(crate) fn verify(public: &[u8], proof: &[u8], shape: ScaleShape) -> Result<(), ProofError> {
    if shape == ScaleShape::SHIPPED {
        gate()?;
    }
    let air = air_for(crate::reveal_v2::schedule(), shape.num_queries);
    match shape.digest_elems {
        SCALE_DIGEST_ELEMS => digest9::verify(&air, public, proof, &shape.fri()),
        8 => digest8::verify(&air, public, proof, &shape.fri()),
        _ => Err(ProofError::Rejected),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parameters are the design's: width 24 = rate 15 + capacity 9, a
    /// 9-element 279-bit digest, the degree-8 extension, 96 queries at
    /// blowup 2^3, 16 and 16 bits of grinding.
    #[test]
    fn parameters_are_the_designs() {
        assert_eq!((SCALE_POSEIDON2_WIDTH, SCALE_SPONGE_RATE, SCALE_SPONGE_CAPACITY), (24, 15, 9));
        assert_eq!((SCALE_DIGEST_ELEMS, SCALE_DIGEST_BITS), (9, 279));
        assert_eq!(<Challenge as p3_field::BasedVectorSpace<F>>::DIMENSION, 8);
        assert_eq!((SCALE_LOG_BLOWUP, SCALE_NUM_QUERIES), (3, 96));
        assert_eq!((SCALE_QUERY_POW_BITS, SCALE_BATCH_POW_BITS), (16, 16));
        assert!(SALT_BITS >= MIN_SALT_BITS);
        // The statement's own height is kept: 2,048 rows, above the
        // zero-knowledge minimum of 224 at 96 queries.
        let air = air_for(crate::reveal_v2::schedule(), SCALE_NUM_QUERIES);
        assert_eq!(zk_min_trace_height(SCALE_NUM_QUERIES), 224);
        assert_eq!((air.height(), air.width()), (MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH));
    }

    /// The gate takes the scale configuration for the version 2 coin reveal.
    #[test]
    fn the_gate_takes_the_scale_configuration() {
        let est = gate().expect("the scale configuration meets the rule");
        assert!(est.conjectured_bits_half_grinding >= TARGET_CONJECTURED_BITS, "{est:?}");
        assert_eq!((est.trace_height, est.trace_width), (MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH));
    }
}
