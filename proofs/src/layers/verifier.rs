//! Child proofs verified inside a circuit: a uni-STARK proof of the scale
//! configuration (a reveal, or any AIR) and a batch-STARK proof of a layer.
//!
//! Each follows the library's own verifier at the pinned revision
//! (`p3_uni_stark::verify`, `p3_batch_stark::verify_batch`): the same
//! transcript, the same opening claims, the same quotient recomposition and
//! the same constraint fold, with every check a row of the circuit. The shape
//! of the child (its AIR, heights and FRI parameters) is fixed when the
//! circuit is built; a proof of another shape is refused before.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder, capture_symbolic_constraints};
use p3_air::{Air, BaseAir};
use p3_challenger::CanObserve;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_uni_stark::{AirConstraints, StarkShape};

use super::circuit::{Circuit, Wire};
use super::pcs::{CircuitChallenger, ClaimMat, ClaimRound, ExtVal, digest_hint, seed_elements, verify_pcs};
use super::symbolic::{OodValues, fold_constraints};
use super::{EF, F, basis};
use crate::scale::{ScaleChallenger, ScaleConfig, tagged_challenger};
use crate::stark::FriShape;

/// A uni-STARK proof of the scale configuration.
pub(crate) type UniProof = p3_uni_stark::Proof<ScaleConfig>;

/// The first digest of a Merkle cap of height 0.
pub(crate) fn cap_root(cap: &p3_merkle_tree::MerkleCap<F, [F; 9]>) -> Vec<F> {
    cap.roots().first().map(|d| d.to_vec()).unwrap_or_default()
}

/// Selectors of a subgroup of size `2^log_n` at `zeta`, and `zeta^n`.
pub(crate) struct Selectors {
    pub(crate) is_first_row: Wire,
    pub(crate) is_last_row: Wire,
    pub(crate) is_transition: Wire,
    pub(crate) inv_vanishing: Wire,
}

/// The Lagrange selectors of the subgroup of size `2^log_n` (shift one) at
/// `zeta`, as `selectors_at_point` computes them.
pub(crate) fn selectors(c: &mut Circuit, zeta: Wire, log_n: usize) -> Selectors {
    let zeta_n = c.pow2k(zeta, log_n);
    let z_h = c.add_const(zeta_n, -EF::ONE);
    let g_inv = F::two_adic_generator(log_n).inverse();
    let first_den = c.add_const(zeta, -EF::ONE);
    let is_first_row = c.div(z_h, first_den);
    let is_transition = c.add_const(zeta, -EF::from(g_inv));
    let is_last_row = c.div(z_h, is_transition);
    let inv_vanishing = c.inv(z_h);
    Selectors {
        is_first_row,
        is_last_row,
        is_transition,
        inv_vanishing,
    }
}

/// `quotient(zeta)` from its chunks, as `recompose_quotient_from_chunks`
/// computes it: the chunk domains split the disjoint coset of size
/// `2^(log_ext_degree + log_chunks)` into `chunks.len()` cosets of size
/// `2^log_chunk_domain`.
pub(crate) fn recompose_quotient(
    c: &mut Circuit,
    zeta: Wire,
    log_ext_degree: usize,
    log_chunks: usize,
    chunks: &[Vec<ExtVal>],
) -> Wire {
    let num = chunks.len();
    let log_quotient = log_ext_degree + log_chunks;
    let log_chunk_domain = log_quotient - num.trailing_zeros() as usize;
    let h = F::two_adic_generator(log_quotient);
    let shifts: Vec<F> = (0..num).map(|i| F::GENERATOR * h.exp_u64(i as u64)).collect();
    let n = 1u64 << log_chunk_domain;
    // Z_j(x) = (x / shift_j)^n - 1.
    let vanish = |x: F, j: usize| (x * shifts[j].inverse()).exp_u64(n) - F::ONE;
    let zeta_n = c.pow2k(zeta, log_chunk_domain);
    let at_zeta: Vec<Wire> = (0..num)
        .map(|j| {
            let k = EF::from(shifts[j].inverse().exp_u64(n));
            let minus_one = c.constant(-EF::ONE);
            c.mul_const_add(zeta_n, k, minus_one)
        })
        .collect();
    let mut quotient = c.zero();
    for i in 0..num {
        let mut zp = c.one();
        let mut denominator = F::ONE;
        for j in 0..num {
            if j != i {
                zp = c.mul(zp, at_zeta[j]);
                denominator *= vanish(shifts[i], j);
            }
        }
        let zp = c.mul_const(zp, EF::from(denominator.inverse()));
        // The chunk's eight opened values are the coefficients of one value.
        let mut chunk = c.zero();
        for (k, v) in chunks[i].iter().enumerate() {
            chunk = c.mul_const_add(v.ext, basis(k), chunk);
        }
        quotient = c.mul_add(zp, chunk, quotient);
    }
    quotient
}

/// Every periodic column at `zeta`, over the subgroup of size `2^log_n`.
pub(crate) fn periodic_values(c: &mut Circuit, zeta: Wire, log_n: usize, columns: &[Vec<F>]) -> Vec<Wire> {
    // Per period: y = zeta^(n / p) and (y^p - 1) / p; per point: w^k / (y - w^k).
    let mut per_period: BTreeMap<usize, (Wire, Wire)> = BTreeMap::new();
    let mut per_point: BTreeMap<(usize, usize), Wire> = BTreeMap::new();
    let mut out = Vec::with_capacity(columns.len());
    for col in columns {
        let p = col.len();
        let log_p = p.trailing_zeros() as usize;
        let (y, scale) = *per_period.entry(p).or_insert_with(|| {
            let y = c.pow2k(zeta, log_n - log_p);
            let yp = c.pow2k(y, log_p);
            let yp1 = c.add_const(yp, -EF::ONE);
            let scale = c.mul_const(yp1, EF::from(F::from_usize(p).inverse()));
            (y, scale)
        });
        let w = F::two_adic_generator(log_p);
        let mut sum = c.zero();
        for (k, &v) in col.iter().enumerate() {
            if v == F::ZERO {
                continue;
            }
            let term = *per_point.entry((p, k)).or_insert_with(|| {
                let wk = w.exp_u64(k as u64);
                let den = c.add_const(y, -EF::from(wk));
                let inv = c.inv(den);
                c.mul_const(inv, EF::from(wk))
            });
            sum = c.mul_const_add(term, EF::from(v), sum);
        }
        out.push(c.mul(sum, scale));
    }
    out
}

/// What the circuit fixes about a uni-STARK child.
#[derive(Clone, Copy, Debug)]
pub(crate) struct UniShape {
    pub(crate) fri: FriShape,
    /// Log of the trace height, before zero knowledge.
    pub(crate) log_height: usize,
}

/// A native refusal of a child proof whose shape is not the circuit's.
pub(crate) fn uni_shape_ok<A: BaseAir<F>>(air: &A, shape: &UniShape, proof: &UniProof, num_chunks: usize) -> bool {
    let o = &proof.opened_values;
    let width = air.width();
    let opens_next = !air.main_next_row_columns().is_empty();
    proof.degree_bits == shape.log_height + 1
        && o.trace_local.len() == width
        && o.trace_next.as_ref().map_or(!opens_next, |n| opens_next && n.len() == width)
        && o.preprocessed.is_none()
        && o.quotient_chunks.len() == num_chunks
        && o.quotient_chunks.iter().all(|q| q.len() == 8)
        && o.random.as_ref().is_some_and(|r| r.len() == 8)
        && proof.commitments.random.is_some()
        && proof.ood_pow_witness == F::ZERO
}

/// The log of the quotient chunk count of an AIR on a trace of `2^log_height`
/// rows, before the zero-knowledge doubling.
pub(crate) fn log_quotient_chunks<A>(air: &A, log_height: usize) -> usize
where
    A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
{
    let layout = uni_layout(air);
    let domain = TwoAdicMultiplicativeCoset::new(F::ONE, log_height).expect("a two-adic height");
    AirConstraints::<F>::evaluate(air, layout).log_num_quotient_chunks(domain, 1)
}

fn uni_layout<A: BaseAir<F>>(air: &A) -> AirLayout {
    AirLayout {
        preprocessed_width: 0,
        main_width: air.width(),
        num_public_values: air.num_public_values(),
        num_periodic_columns: air.num_periodic_columns(),
        ..Default::default()
    }
}

/// The transcript a uni-STARK child starts from: the library's seed for its
/// shape, absorbed by a fresh challenger of the scale configuration.
fn uni_start<A: BaseAir<F>>(air: &A, shape: &UniShape, num_chunks: usize) -> ScaleChallenger {
    let stark_shape = StarkShape::new::<F, A>(air, 0, shape.log_height + 1, shape.log_height, num_chunks, true, 0);
    let mut native = tagged_challenger(&[]);
    for e in seed_elements(&stark_shape.domain_separator::<F, EF>()) {
        native.observe(e);
    }
    native
}

/// Verify a uni-STARK proof of `air` at `shape` inside the circuit, against
/// public values the circuit already holds. `proof` is `None` when only the
/// rows are wanted.
pub(crate) fn verify_uni<A>(c: &mut Circuit, air: &A, shape: &UniShape, publics: &[Wire], proof: Option<&UniProof>)
where
    A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
{
    let log_n = shape.log_height;
    let log_ext = log_n + 1;
    let log_chunks = log_quotient_chunks(air, log_n);
    let num_chunks = 1usize << (log_chunks + 1);
    let width = air.width();
    let opens_next = !air.main_next_row_columns().is_empty();
    debug_assert_eq!(publics.len(), air.num_public_values());

    let native = uni_start(air, shape, num_chunks);
    let mut ch = CircuitChallenger::from_native(c, &native);

    let trace_commit = digest_hint(c, &proof.map(|p| cap_root(&p.commitments.trace)).unwrap_or_default());
    ch.observe_all(c, &trace_commit);
    ch.observe_all(c, publics);
    let alpha = ch.sample_ext(c);
    let quotient_commit =
        digest_hint(c, &proof.map(|p| cap_root(&p.commitments.quotient_chunks)).unwrap_or_default());
    ch.observe_all(c, &quotient_commit);
    let random_commit = digest_hint(
        c,
        &proof.and_then(|p| p.commitments.random.as_ref().map(cap_root)).unwrap_or_default(),
    );
    ch.observe_all(c, &random_commit);
    let zeta = ch.sample_ext(c);

    let opened = proof.map(|p| &p.opened_values);
    let ext_hints = |c: &mut Circuit, vals: Option<&Vec<EF>>, n: usize| -> Vec<ExtVal> {
        (0..n)
            .map(|i| ExtVal::hint(c, vals.and_then(|v| v.get(i).copied()).unwrap_or(EF::ZERO)))
            .collect()
    };
    let trace_local = ext_hints(c, opened.map(|o| &o.trace_local), width);
    let trace_next = if opens_next {
        ext_hints(c, opened.and_then(|o| o.trace_next.as_ref()), width)
    } else {
        Vec::new()
    };
    let chunks: Vec<Vec<ExtVal>> = (0..num_chunks)
        .map(|i| ext_hints(c, opened.and_then(|o| o.quotient_chunks.get(i)), 8))
        .collect();
    let random = ext_hints(c, opened.and_then(|o| o.random.as_ref()), 8);

    let zeta_next = c.mul_const(zeta.ext, EF::from(F::two_adic_generator(log_n)));
    let mut trace_points = alloc::vec![(zeta.ext, trace_local.clone())];
    if opens_next {
        trace_points.push((zeta_next, trace_next.clone()));
    }
    let rounds = [
        ClaimRound {
            commit: random_commit,
            mats: alloc::vec![ClaimMat {
                log_domain: log_ext,
                points: alloc::vec![(zeta.ext, random)],
            }],
            preprocessed: false,
        },
        ClaimRound {
            commit: trace_commit,
            mats: alloc::vec![ClaimMat {
                log_domain: log_ext,
                points: trace_points,
            }],
            preprocessed: false,
        },
        ClaimRound {
            commit: quotient_commit,
            mats: chunks
                .iter()
                .map(|ch| ClaimMat {
                    log_domain: log_ext,
                    points: alloc::vec![(zeta.ext, ch.clone())],
                })
                .collect(),
            preprocessed: false,
        },
    ];
    verify_pcs(c, &mut ch, &shape.fri, &rounds, proof.map(|p| &p.opening_proof));

    let quotient = recompose_quotient(c, zeta.ext, log_ext, log_chunks, &chunks);
    let sels = selectors(c, zeta.ext, log_n);
    let periodic = periodic_values(c, zeta.ext, log_n, &air.periodic_columns());
    let constraints = capture_symbolic_constraints::<F, F>(uni_layout(air), |b| air.eval(b));
    let layout = constraints.constraint_layout();
    let total = layout.base_indices.len() + layout.ext_indices.len();
    let mut order = alloc::vec![(true, 0usize); total];
    for (i, &g) in layout.base_indices.iter().enumerate() {
        order[g] = (true, i);
    }
    for (i, &g) in layout.ext_indices.iter().enumerate() {
        order[g] = (false, i);
    }
    let zeros = |c: &mut Circuit, n: usize| -> Vec<Wire> { (0..n).map(|_| c.zero()).collect() };
    let main_next = if opens_next {
        trace_next.iter().map(|v| v.ext).collect()
    } else {
        zeros(c, width)
    };
    let values = OodValues {
        main_local: trace_local.iter().map(|v| v.ext).collect(),
        main_next,
        prep_local: Vec::new(),
        prep_next: Vec::new(),
        periodic,
        publics: publics.to_vec(),
        perm_local: Vec::new(),
        perm_next: Vec::new(),
        challenges: Vec::new(),
        perm_values: Vec::new(),
        is_first_row: sels.is_first_row,
        is_last_row: sels.is_last_row,
        is_transition: sels.is_transition,
    };
    // A uni-STARK AIR asserts base constraints only.
    debug_assert!(constraints.extension_constraints().is_empty());
    let folded = fold_constraints(
        c,
        constraints.base_constraints(),
        &[],
        &order,
        &values,
        alpha.ext,
    );
    let lhs = c.mul(folded, sels.inv_vanishing);
    c.assert_eq(lhs, quotient);
}
