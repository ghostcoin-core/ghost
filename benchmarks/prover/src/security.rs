//! The security gate.
//!
//! The pinned Plonky3 revision ships its own estimator (`p3-security`, used
//! through `p3_uni_stark::StarkSecurityParams`), so the harness uses it rather
//! than one of its own. It is applied to the actual parameters of each
//! configuration: the FRI queries and folding, every grinding site, the
//! opening batching (all committed columns, quotient chunks, the
//! randomizing codeword and the hiding columns), the constraint composition
//! (the number and degree of the constraints, the DEEP point, the trace
//! height after zero-knowledge padding and the size of the challenge field),
//! and the collision resistance of the commitment hash.
//!
//! The target is 128 bits under the conjectured estimate. The best proven
//! figure for the same parameters is recorded beside it. The number of
//! queries is the smallest that reaches the target; it is never hard-coded.

use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_fri::FriParameters;
use p3_uni_stark::{
    AirLayout, ConjecturedSecurity, GrindingSites, OpeningShape, ProvenSecurity,
    StarkSecurityParams, SymbolicAirBuilder, get_max_constraint_degree,
};

use crate::{BenchError, Challenge, HashCandidate};

/// The floor: a configuration below this many conjectured bits is refused
/// before anything is timed.
pub const TARGET_CONJECTURED_BITS: usize = 128;

/// Grinding is allowed up to 16 bits at a site.
pub const MAX_GRINDING_BITS: usize = 16;

/// Degree of the challenge field over BabyBear.
pub const EXTENSION_DEGREE: usize = 5;

/// log2 of the challenge field size, rounded down: 5 * log2(2^31 - 2^27 + 1).
pub const CHALLENGE_FIELD_BITS: usize = 154;

/// Random columns hiding FRI appends to each committed matrix. The library
/// requires at least the extension degree.
pub const NUM_RANDOM_CODEWORDS: usize = EXTENSION_DEGREE;

/// Points at which the main trace is opened (`zeta` and `zeta * g`).
pub const TRACE_OPENING_POINTS: usize = 2;

/// Upper end of the query search.
pub const MAX_QUERIES: usize = 512;

/// The grinding the search tries, in order: query-phase grinding alone,
/// then also before the batching challenge, then also before the DEEP point.
pub const GRINDING_CHOICES: [Grinding; 3] = [
    Grinding {
        query: MAX_GRINDING_BITS,
        commit: 0,
        batch: 0,
        ood: 0,
    },
    Grinding {
        query: MAX_GRINDING_BITS,
        commit: 0,
        batch: MAX_GRINDING_BITS,
        ood: 0,
    },
    Grinding {
        query: MAX_GRINDING_BITS,
        commit: 0,
        batch: MAX_GRINDING_BITS,
        ood: MAX_GRINDING_BITS,
    },
];

/// Proof-of-work bits at each grinding site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grinding {
    /// Before the FRI queries are sampled.
    pub query: usize,
    /// Before each FRI folding challenge.
    pub commit: usize,
    /// Before the challenge that batches the openings.
    pub batch: usize,
    /// Before the DEEP out-of-domain point.
    pub ood: usize,
}

/// The library's minimum trace height for zero-knowledge: hiding FRI masks
/// each column with as many values as the trace has rows and requires
/// `N >= 2 * (num_queries + D * points)` (`HidingFriPcs`, after Section 4.2 of
/// eprint 2024/1037), with `D` the extension degree and `points` the number
/// of opening points of the trace.
pub const fn zk_min_trace_height(num_queries: usize) -> usize {
    2 * (num_queries + EXTENSION_DEGREE * TRACE_OPENING_POINTS)
}

/// FRI parameters of a configuration. Binary folding down to a constant
/// final polynomial.
pub fn fri_parameters<M>(
    log_blowup: usize,
    num_queries: usize,
    grinding: Grinding,
    mmcs: M,
) -> FriParameters<M> {
    FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries,
        batch_proof_of_work_bits: grinding.batch,
        commit_proof_of_work_bits: grinding.commit,
        query_proof_of_work_bits: grinding.query,
        mmcs,
    }
}

/// Conjectured and best proven estimates, in bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Estimate {
    pub conjectured_bits: usize,
    pub proven_bits: usize,
}

/// Estimator inputs for an AIR at a given trace height, with the grinding
/// and query count filled in by [`estimate`].
pub fn security_params<A>(
    air: &A,
    log_height: usize,
    log_blowup: usize,
    collision_resistance_bits: usize,
) -> StarkSecurityParams
where
    A: BaseAir<BabyBear> + Air<SymbolicAirBuilder<BabyBear, Challenge>>,
{
    let fri = fri_parameters(log_blowup, 1, Grinding { query: 0, commit: 0, batch: 0, ood: 0 }, ());
    StarkSecurityParams::from_air::<BabyBear, Challenge, A>(
        fri.security_regime(),
        air,
        AirLayout::from_air(air),
        TwoAdicMultiplicativeCoset::new(BabyBear::ONE, log_height).expect("two-adic height"),
        CHALLENGE_FIELD_BITS,
        collision_resistance_bits,
        2,
        OpeningShape::hiding(NUM_RANDOM_CODEWORDS),
        GrindingSites::NONE,
    )
}

/// Apply the estimator to the actual parameters.
///
/// `log_height` is the trace height before zero-knowledge padding; the
/// committed polynomials are twice as tall, which is the size the estimator
/// is evaluated at.
pub fn estimate(
    base: &StarkSecurityParams,
    log_height: usize,
    num_queries: usize,
    grinding: Grinding,
) -> Estimate {
    let mut params = base.clone();
    params.fri_num_queries = num_queries;
    params.fri_query_proof_of_work_bits = grinding.query;
    params.fri_commit_proof_of_work_bits = grinding.commit;
    params.grinding = GrindingSites {
        out_of_domain: grinding.ood,
        batch_combination: grinding.batch,
        ..GrindingSites::NONE
    };
    let degree_bits = log_height + 1;
    Estimate {
        conjectured_bits: ConjecturedSecurity::compute_from_params(&params, degree_bits)
            .security_bits,
        proven_bits: ProvenSecurity::compute_from_proof(degree_bits, &params).security_bits(),
    }
}

/// A configuration that passed the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityPlan {
    pub candidate: HashCandidate,
    pub log_blowup: usize,
    pub num_queries: usize,
    pub grinding: Grinding,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
    pub trace_height: usize,
    pub trace_width: usize,
    pub constraint_degree: usize,
    pub zk_min_trace_height: usize,
    pub collision_resistance_bits: usize,
    pub estimate: Estimate,
}

impl SecurityPlan {
    /// A short name for the configuration, recorded with every result.
    pub fn configuration_name(&self) -> String {
        format!(
            "{}/hiding-fri/blowup-2^{}/queries-{}/grinding-q{}-b{}-o{}/ext-{}/zk",
            self.candidate.name(),
            self.log_blowup,
            self.num_queries,
            self.grinding.query,
            self.grinding.batch,
            self.grinding.ood,
            EXTENSION_DEGREE,
        )
    }
}

/// Search for the smallest query count (and least grinding) that reaches the
/// target, refusing the configuration when none does.
pub fn plan_for<A>(
    candidate: HashCandidate,
    log_blowup: usize,
    min_height: usize,
    collision_resistance_bits: usize,
    make_air: impl Fn(usize) -> A,
) -> Result<SecurityPlan, BenchError>
where
    A: BaseAir<BabyBear>
        + Air<SymbolicAirBuilder<BabyBear>>
        + Air<SymbolicAirBuilder<BabyBear, Challenge>>,
{
    if !(1..=3).contains(&log_blowup) {
        return Err(BenchError::UnsupportedBlowup { log_blowup });
    }
    let air = make_air(min_height);
    let trace_width = air.width();
    let constraint_degree = get_max_constraint_degree::<BabyBear, A>(
        &air,
        AirLayout::from_air(&air),
        min_height,
    )
    .max(air.max_constraint_degree().unwrap_or(0));
    // Zero-knowledge mode adds one to the quotient degree, so the quotient
    // only fits in the low-degree extension when the constraint degree is at
    // most the blowup.
    if constraint_degree > 1 << log_blowup {
        return Err(BenchError::ConstraintDegreeTooHigh {
            degree: constraint_degree,
            log_blowup,
        });
    }

    let mut best = 0;
    for grinding in GRINDING_CHOICES {
        let mut cached: Option<(usize, StarkSecurityParams)> = None;
        for num_queries in 1..=MAX_QUERIES {
            let zk_min = zk_min_trace_height(num_queries);
            let height = zk_min.next_power_of_two().max(min_height);
            let log_height = height.trailing_zeros() as usize;
            if cached.as_ref().is_none_or(|(h, _)| *h != height) {
                let air = make_air(height);
                cached = Some((
                    height,
                    security_params(&air, log_height, log_blowup, collision_resistance_bits),
                ));
            }
            let (_, base) = cached.as_ref().expect("filled above");
            let est = estimate(base, log_height, num_queries, grinding);
            best = best.max(est.conjectured_bits);
            if est.conjectured_bits >= TARGET_CONJECTURED_BITS {
                return Ok(SecurityPlan {
                    candidate,
                    log_blowup,
                    num_queries,
                    grinding,
                    log_final_poly_len: 0,
                    max_log_arity: 1,
                    trace_height: height,
                    trace_width,
                    constraint_degree,
                    zk_min_trace_height: zk_min,
                    collision_resistance_bits,
                    estimate: est,
                });
            }
        }
    }
    Err(BenchError::BelowSecurityFloor { best_bits: best })
}

/// Re-check a plan before proving: the estimate is recomputed from the
/// plan's own parameters, so a plan edited after the search cannot slip
/// under the floor.
pub fn check_gate<A>(plan: &SecurityPlan, air: &A) -> Result<Estimate, BenchError>
where
    A: BaseAir<BabyBear> + Air<SymbolicAirBuilder<BabyBear, Challenge>>,
{
    if plan.grinding.query > MAX_GRINDING_BITS
        || plan.grinding.commit > MAX_GRINDING_BITS
        || plan.grinding.batch > MAX_GRINDING_BITS
        || plan.grinding.ood > MAX_GRINDING_BITS
    {
        return Err(BenchError::GrindingAboveLimit);
    }
    let log_height = plan.trace_height.trailing_zeros() as usize;
    let base = security_params(air, log_height, plan.log_blowup, plan.collision_resistance_bits);
    let est = estimate(&base, log_height, plan.num_queries, plan.grinding);
    if est.conjectured_bits < TARGET_CONJECTURED_BITS {
        return Err(BenchError::BelowSecurityFloor {
            best_bits: est.conjectured_bits,
        });
    }
    Ok(est)
}
