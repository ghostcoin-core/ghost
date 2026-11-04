//! The pinned library's security estimator at the real shape of every proof
//! a bundle holds: a reveal (the leaf), a batch, a root and a shrink.
//!
//! The estimator is the one the crate's gates already run:
//! `ProvenSecurity::compute_from_proof` and
//! `ConjecturedSecurity::compute_from_params` of `p3-uni-stark` over a
//! `StarkSecurityParams`. A reveal is one uni-STARK instance, and its
//! parameters come from `StarkSecurityParams::from_air` exactly as
//! [`crate::scale_coin_reveal_v2_estimate`] derives them. A layer is one
//! batch STARK of five tables sharing one transcript, one out-of-domain point
//! and one FRI instance; the library has no batch-STARK entry point, so the
//! shape is folded into one parameter set as follows:
//!
//! - batched functions: the sum over the tables of
//!   `p3_batch_stark::num_batched_openings` (main, preprocessed, quotient,
//!   randomizing and LogUp permutation columns, each at every point it is
//!   opened at), the one count the opening-batching challenge combines;
//! - constraints: the sum over the tables of their AIR and LogUp constraints;
//! - constraint degree and quotient chunks: the largest over the tables;
//! - trace domain: the tallest table, zero-knowledge doubling included;
//! - two out-of-domain points (`zeta` and `zeta * g`), where every LogUp
//!   permutation column is opened.
//!
//! The library caps every proven figure at the commitment hash's collision
//! resistance (139 bits for the 279-bit digest), a term the design counts
//! once for the whole bundle rather than once a proof. So the estimator is
//! also run with every grinding site at half its bits, as the requirement
//! counts grinding, and with that cap lifted
//! ([`ProofEstimate::proven_bits_uncapped`]): the smallest of its algebraic
//! round errors, the figure to set beside the design's per-proof terms.
//!
//! The five tables share one out-of-domain point, so the DEEP term of the
//! batch is at most five times the one of its tallest, highest-degree table:
//! [`ProofEstimate::proven_bits_uncapped_field_less_3`] reruns the uncapped
//! estimator with the challenge field taken 3 bits smaller (`log2(5) < 3`),
//! which charges that factor, and more, to every field-size term at once.

use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_batch_stark::symbolic::get_max_constraint_degree;
use p3_field::PrimeCharacteristicRing;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_lookup::LogUpGadget;
use p3_uni_stark::{AirLayout, ConjecturedSecurity, OpeningShape, ProvenSecurity, StarkSecurityParams};

use super::verifier::{LayerSpec, TableConstraints, table_layout};
use super::{EF, F};
use crate::ProofError;
use crate::air::StatementAir;
use crate::scale::{
    SCALE_CHALLENGE_FIELD_BITS, SCALE_COLLISION_RESISTANCE_BITS, SCALE_EXTENSION_DEGREE, SCALE_RANDOM_CODEWORDS,
    ScaleShape, reveal_air, reveal_fri,
};
use crate::stark::{FriShape, fri_parameters};

/// Out-of-domain points a column is opened at: `zeta` and `zeta * g`.
const OPENING_POINTS: usize = 2;
/// Bits the challenge field is taken smaller by for
/// [`ProofEstimate::proven_bits_uncapped_field_less_3`].
pub const FIELD_MARGIN_BITS: usize = 3;
/// A collision resistance no algebraic term of these proofs reaches: what the
/// estimator is given to lift its collision cap.
pub const UNCAPPED_COLLISION_BITS: usize = 1_000;

/// The estimator's inputs and output for one proof at its real shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofEstimate {
    /// log2 of the FRI blowup.
    pub log_blowup: usize,
    /// FRI queries.
    pub num_queries: usize,
    /// Proof-of-work bits before the queries are drawn.
    pub query_pow_bits: usize,
    /// Proof-of-work bits before the challenge that batches the openings.
    pub batch_pow_bits: usize,
    /// log2 of the length of FRI's final polynomial.
    pub log_final_poly_len: usize,
    /// log2 of FRI's folding arity.
    pub max_log_arity: usize,
    /// AIR instances in the proof: 1 for a reveal, 5 for a layer.
    pub tables: usize,
    /// log2 of the tallest committed trace, zero-knowledge doubling included.
    pub degree_bits: usize,
    /// Constraints, the AIR's and the lookups', over every table.
    pub num_constraints: usize,
    /// The largest constraint degree of any table.
    pub max_constraint_degree: usize,
    /// The most quotient chunks any table commits.
    pub num_quotient_chunks: usize,
    /// Functions the opening-batching challenge combines.
    pub num_batched_functions: usize,
    /// log2 of the challenge field, rounded down, as the estimator takes it.
    pub challenge_field_bits: usize,
    /// Collision resistance of the commitment hash, as the estimator takes it.
    pub collision_resistance_bits: usize,
    /// Conjectured bits, every grinding site at its full bits.
    pub conjectured_bits: usize,
    /// Conjectured bits with each grinding site at half its bits.
    pub conjectured_bits_half_grinding: usize,
    /// Proven bits in the unique-decoding regime.
    pub proven_unique_decoding_bits: usize,
    /// Proven bits in the list-decoding regime, at the library's best `m`.
    pub proven_list_decoding_bits: usize,
    /// The better of the two proven regimes: the library's proven figure.
    pub proven_bits: usize,
    /// [`Self::proven_bits`] with each grinding site at half its bits, the
    /// rule of the requirement.
    pub proven_bits_half_grinding: usize,
    /// [`Self::proven_bits_half_grinding`] with the collision cap lifted: the
    /// smallest of the estimator's algebraic terms in the better regime.
    pub proven_bits_uncapped: usize,
    /// [`Self::proven_bits_uncapped`] with the challenge field taken
    /// [`FIELD_MARGIN_BITS`] smaller.
    pub proven_bits_uncapped_field_less_3: usize,
}

impl ProofEstimate {
    /// FRI folding rounds: the committed degree folded down to the final
    /// polynomial, `2^max_log_arity` to one a round.
    pub fn fri_rounds(&self) -> usize {
        (self.degree_bits - self.log_final_poly_len).div_ceil(self.max_log_arity)
    }

    /// log2 of the codeword FRI tests: the committed degree times the blowup.
    pub fn lde_log(&self) -> usize {
        self.degree_bits + self.log_blowup
    }
}

/// The shape-dependent inputs of one estimate.
#[derive(Clone, Copy)]
struct Shape {
    tables: usize,
    degree_bits: usize,
    num_constraints: usize,
    max_constraint_degree: usize,
    num_quotient_chunks: usize,
    num_batched_functions: usize,
}

fn params(shape: &Shape, fri: &FriShape, field_bits: usize, collision_bits: usize) -> StarkSecurityParams {
    let fri = fri_parameters(fri, ());
    StarkSecurityParams::new(
        fri.security_regime(),
        field_bits,
        collision_bits,
        shape.num_constraints,
        shape.max_constraint_degree,
        OPENING_POINTS,
        shape.num_batched_functions,
        shape.num_quotient_chunks,
    )
    .with_grinding(fri.grinding_sites())
}

fn run(shape: Shape, fri: &FriShape) -> ProofEstimate {
    let (field, collision) = (SCALE_CHALLENGE_FIELD_BITS, SCALE_COLLISION_RESISTANCE_BITS);
    let full = params(&shape, fri, field, collision);
    let half = FriShape {
        query_pow_bits: fri.query_pow_bits / 2,
        batch_pow_bits: fri.batch_pow_bits / 2,
        ..*fri
    };
    let proven = ProvenSecurity::compute_from_proof(shape.degree_bits, &full);
    let half_proven = |field_bits, collision_bits| {
        let p = params(&shape, &half, field_bits, collision_bits);
        ProvenSecurity::compute_from_proof(shape.degree_bits, &p).security_bits()
    };
    let regime = fri_parameters(fri, ());
    ProofEstimate {
        log_blowup: fri.log_blowup,
        num_queries: fri.num_queries,
        query_pow_bits: fri.query_pow_bits,
        batch_pow_bits: fri.batch_pow_bits,
        log_final_poly_len: regime.log_final_poly_len,
        max_log_arity: regime.max_log_arity,
        tables: shape.tables,
        degree_bits: shape.degree_bits,
        num_constraints: shape.num_constraints,
        max_constraint_degree: shape.max_constraint_degree,
        num_quotient_chunks: shape.num_quotient_chunks,
        num_batched_functions: shape.num_batched_functions,
        challenge_field_bits: SCALE_CHALLENGE_FIELD_BITS,
        collision_resistance_bits: SCALE_COLLISION_RESISTANCE_BITS,
        conjectured_bits: ConjecturedSecurity::compute_from_params(&full, shape.degree_bits).security_bits,
        conjectured_bits_half_grinding: ConjecturedSecurity::compute_from_params(
            &params(&shape, &half, field, collision),
            shape.degree_bits,
        )
        .security_bits,
        proven_unique_decoding_bits: proven.unique_decoding_bits,
        proven_list_decoding_bits: proven.list_decoding_bits,
        proven_bits: proven.security_bits(),
        proven_bits_half_grinding: half_proven(field, collision),
        proven_bits_uncapped: half_proven(field, UNCAPPED_COLLISION_BITS),
        proven_bits_uncapped_field_less_3: half_proven(field - FIELD_MARGIN_BITS, UNCAPPED_COLLISION_BITS),
    }
}

/// The estimate of a version 2 coin reveal at the scale configuration: the
/// leaf of a bundle. Its parameters are the ones `StarkSecurityParams::from_air`
/// derives from the reveal's AIR, as the scale gate derives them.
pub fn reveal_estimate() -> Result<ProofEstimate, ProofError> {
    let fri = reveal_fri(ScaleShape::SHIPPED);
    let air: StatementAir = reveal_air(fri.num_queries);
    let height = air.height();
    if !height.is_power_of_two() {
        return Err(ProofError::EstimateUnavailable);
    }
    let log_height = height.trailing_zeros() as usize;
    let domain = TwoAdicMultiplicativeCoset::new(BabyBear::ONE, log_height).ok_or(ProofError::EstimateUnavailable)?;
    let derived = StarkSecurityParams::from_air::<F, EF, StatementAir>(
        fri_parameters(&fri, ()).security_regime(),
        &air,
        AirLayout::from_air(&air),
        domain,
        SCALE_CHALLENGE_FIELD_BITS,
        SCALE_COLLISION_RESISTANCE_BITS,
        OPENING_POINTS,
        OpeningShape::hiding(SCALE_RANDOM_CODEWORDS),
        fri_parameters(&fri, ()).grinding_sites(),
    );
    let shape = Shape {
        tables: 1,
        degree_bits: log_height + 1,
        num_constraints: derived.num_constraints,
        max_constraint_degree: derived.air_max_constraint_degree,
        num_quotient_chunks: derived.num_quotient_chunks,
        num_batched_functions: derived.num_batched_functions,
    };
    Ok(run(shape, &fri))
}

/// The estimate of a layer of `spec`'s tables, with `cons` their constraints.
pub(crate) fn layer_estimate(spec: &LayerSpec, cons: &[TableConstraints]) -> ProofEstimate {
    let gadget = LogUpGadget::new();
    let openings = OpeningShape::hiding(SCALE_RANDOM_CODEWORDS);
    let mut shape = Shape {
        tables: spec.airs.len(),
        degree_bits: 0,
        num_constraints: 0,
        max_constraint_degree: 0,
        num_quotient_chunks: 0,
        num_batched_functions: 0,
    };
    for ((air, lookups), c) in spec.airs.iter().zip(&spec.lookups).zip(cons) {
        let layout = table_layout(air);
        // The batch prover commits `2^(log_chunks + 1)` chunks under
        // zero knowledge (`p3-batch-stark`, prover).
        let chunks = 1usize << (c.log_chunks + 1);
        let degree = get_max_constraint_degree::<F, EF, _, LogUpGadget>(air, layout, air.height(), lookups, &gadget)
            .max(BaseAir::<F>::max_constraint_degree(air).unwrap_or(0));
        shape.degree_bits = shape.degree_bits.max(air.height().trailing_zeros() as usize + 1);
        shape.num_constraints += c.len();
        shape.max_constraint_degree = shape.max_constraint_degree.max(degree);
        shape.num_quotient_chunks = shape.num_quotient_chunks.max(chunks);
        shape.num_batched_functions += p3_batch_stark::num_batched_openings(
            BaseAir::<F>::width(air),
            !BaseAir::<F>::main_next_row_columns(air).is_empty(),
            BaseAir::<F>::preprocessed_width(air),
            !BaseAir::<F>::preprocessed_next_row_columns(air).is_empty(),
            chunks,
            lookups.len(),
            SCALE_EXTENSION_DEGREE,
            openings,
        );
    }
    run(shape, &spec.shape.fri())
}

/// The estimates of a planned pipeline's batch, root and shrink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineEstimate {
    pub plan: super::PipelinePlan,
    pub batch: ProofEstimate,
    pub root: ProofEstimate,
    pub shrink: ProofEstimate,
}
