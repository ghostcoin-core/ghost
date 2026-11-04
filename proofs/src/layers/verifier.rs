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

use p3_air::symbolic::{
    AirLayout, SymbolicAirBuilder, SymbolicExpression, SymbolicExpressionExt, capture_symbolic_constraints,
};
use p3_air::{Air, BaseAir};
use p3_batch_stark::BatchShape;
use p3_batch_stark::symbolic::{get_constraint_layout, get_log_num_quotient_chunks_for_domain, get_symbolic_constraints};
use p3_challenger::CanObserve;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_lookup::{Kind as LookupKind, LogUpGadget, Lookups, assert_uniform_tuple_width};
use p3_uni_stark::{AirConstraints, StarkShape};

use super::bundle::{LayerKind, NativeDigest};
use super::circuit::{Circuit, Wire};
use super::pcs::{CircuitChallenger, ClaimMat, ClaimRound, Digest, ExtVal, digest_hint, seed_elements, verify_pcs};
use super::symbolic::{OodValues, fold_constraints, fold_constraints_linear};
use super::tables::{TableAir, Table, degree_bits};
use super::{EF, F, LayerShape, basis, coeffs};
use crate::scale::{ScaleChallenger, ScaleConfig, tagged_challenger};
use crate::stark::FriShape;

/// A uni-STARK proof of the scale configuration.
pub(crate) type UniProof = p3_uni_stark::Proof<ScaleConfig>;

/// A batch-STARK proof of a layer.
pub(crate) type LayerProof = p3_batch_stark::BatchProof<ScaleConfig>;

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

/// Grinding bits before the lookup challenges and before the out-of-domain
/// point of a layer proof: the configuration's, none.
const LAYER_LOOKUP_POW_BITS: usize = 0;
const LAYER_OOD_POW_BITS: usize = 0;

/// What a parent circuit fixes about a layer child: its kind and FRI shape,
/// its tables (lanes, heights, public value count), the lookups the library
/// derived for them, its preprocessed commitment, the digest of the key its
/// own tag names, and the digest of its key.
#[derive(Clone)]
pub(crate) struct LayerSpec {
    pub(crate) kind: LayerKind,
    pub(crate) shape: LayerShape,
    pub(crate) airs: Vec<TableAir>,
    pub(crate) lookups: Vec<Lookups<F>>,
    pub(crate) commitment: NativeDigest,
    pub(crate) child_key: NativeDigest,
    pub(crate) key_digest: NativeDigest,
}

/// One table's constraints, the library's symbolic form of them with its
/// LogUp constraints, evaluated once for every slot of a parent circuit.
pub(crate) struct TableConstraints {
    base: Vec<SymbolicExpression<F>>,
    ext: Vec<SymbolicExpressionExt<F, EF>>,
    order: Vec<(bool, usize)>,
    pub(crate) log_chunks: usize,
}

fn table_layout(air: &TableAir) -> AirLayout {
    AirLayout {
        preprocessed_width: BaseAir::<F>::preprocessed_width(air),
        main_width: BaseAir::<F>::width(air),
        num_public_values: BaseAir::<F>::num_public_values(air),
        num_periodic_columns: 0,
        ..Default::default()
    }
}

/// The constraints of each table of a layer child, as `verify_batch` folds
/// them: the AIR's, then its lookups', in the order the gadget emits them.
pub(crate) fn table_constraints(spec: &LayerSpec) -> Vec<TableConstraints> {
    let gadget = LogUpGadget::new();
    spec.airs
        .iter()
        .zip(&spec.lookups)
        .map(|(air, lookups)| {
            let (base, ext) =
                get_symbolic_constraints::<F, EF, TableAir, LogUpGadget>(air, table_layout(air), lookups, &gadget);
            let layout =
                get_constraint_layout::<F, EF, TableAir, LogUpGadget>(air, table_layout(air), lookups, &gadget);
            let total = layout.base_indices.len() + layout.ext_indices.len();
            let mut order = alloc::vec![(true, 0usize); total];
            for (i, &g) in layout.base_indices.iter().enumerate() {
                order[g] = (true, i);
            }
            for (i, &g) in layout.ext_indices.iter().enumerate() {
                order[g] = (false, i);
            }
            let log_n = air.height().trailing_zeros() as usize;
            let domain = TwoAdicMultiplicativeCoset::new(F::ONE, log_n).expect("a two-adic height");
            let log_chunks = get_log_num_quotient_chunks_for_domain::<F, EF, TableAir, LogUpGadget>(
                air,
                table_layout(air),
                domain,
                lookups,
                1,
                &gadget,
            );
            TableConstraints {
                base,
                ext,
                order,
                log_chunks,
            }
        })
        .collect()
}

/// The bus of every lookup of every table, the widest message and the bus
/// count, as the library lays its lookup challenges out.
fn bus_layout(all: &[Lookups<F>]) -> (Vec<Vec<usize>>, usize, usize) {
    let mut names: BTreeMap<alloc::string::String, usize> = BTreeMap::new();
    let mut next = 0usize;
    let mut widest = 1usize;
    let ids = all
        .iter()
        .map(|lookups| {
            lookups
                .iter()
                .map(|l| {
                    widest = widest.max(assert_uniform_tuple_width(&l.elements, "lookup"));
                    match &l.kind {
                        LookupKind::Global(name) => *names.entry(name.clone()).or_insert_with(|| {
                            next += 1;
                            next - 1
                        }),
                        LookupKind::Local => {
                            next += 1;
                            next - 1
                        }
                    }
                })
                .collect()
        })
        .collect();
    (ids, widest, next)
}

/// Columns of a table's permutation trace: an accumulator and one fraction
/// column a lookup, each an extension value of eight base columns.
fn aux_columns(lookups: &Lookups<F>) -> usize {
    if lookups.is_empty() { 0 } else { (lookups.len() + 1) * 8 }
}

/// A native refusal of a layer proof whose shape is not the spec's.
pub(crate) fn layer_shape_ok(spec: &LayerSpec, cons: &[TableConstraints], proof: &LayerProof) -> bool {
    let n = spec.airs.len();
    let any_lookups = spec.lookups.iter().any(|l| !l.is_empty());
    let one_root = |cap: &p3_merkle_tree::MerkleCap<F, [F; 9]>| cap.roots().len() == 1;
    let c = &proof.commitments;
    if proof.degree_bits != degree_bits(&spec.airs)
        || proof.opened_values.instances.len() != n
        || proof.lookup_terminals.len() != n
        || !one_root(&c.main)
        || !one_root(&c.quotient_chunks)
        || !c.random.as_ref().is_some_and(one_root)
        || c.permutation.as_ref().map_or(any_lookups, |p| !any_lookups || !one_root(p))
        || proof.lookup_pow_witness != any_lookups.then_some(F::ZERO)
        || proof.ood_pow_witness != F::ZERO
    {
        return false;
    }
    spec.airs.iter().enumerate().all(|(i, air)| {
        let inst = &proof.opened_values.instances[i];
        let o = &inst.base_opened_values;
        let aux = aux_columns(&spec.lookups[i]);
        let width = BaseAir::<F>::width(air);
        let next_ok = if air.reads_next() {
            o.trace_next.as_ref().is_some_and(|n| n.len() == width)
        } else {
            o.trace_next.is_none()
        };
        o.trace_local.len() == width
            && next_ok
            && o.preprocessed.as_ref().is_some_and(|p| {
                p.local.len() == BaseAir::<F>::preprocessed_width(air) && p.next.is_none()
            })
            && o.quotient_chunks.len() == 1 << (cons[i].log_chunks + 1)
            && o.quotient_chunks.iter().all(|q| q.len() == 8)
            && o.random.as_ref().is_some_and(|r| r.len() == 8)
            && inst.permutation_local.len() == aux
            && inst.permutation_next.len() == aux
            && proof.lookup_terminals[i].is_some() == (aux > 0)
    })
}

/// Verify a layer proof of `spec` inside the circuit, as `verify_batch`
/// verifies it natively, its transcript starting from `tag` and its wire
/// table's public values `publics`. `proof` is `None` when only the rows are
/// wanted.
pub(crate) fn verify_layer(
    c: &mut Circuit,
    spec: &LayerSpec,
    cons: &[TableConstraints],
    tag: &[Wire],
    publics: &[Wire],
    proof: Option<&LayerProof>,
) {
    let fri = spec.shape.fri();
    let airs = &spec.airs;
    let n = airs.len();
    let log_ns: Vec<usize> = airs.iter().map(|a| a.height().trailing_zeros() as usize).collect();
    let has_lookups: Vec<bool> = spec.lookups.iter().map(|l| !l.is_empty()).collect();
    debug_assert_eq!(publics.len(), airs[0].num_publics());

    // The transcript: the tag, the shape's seed, every table's degree bits,
    // the main commitment, the public values, the preprocessed commitment
    // (the child's key, a constant), the lookup challenges, the permutation
    // commitment and terminals, the folding challenge, the quotient and
    // randomization commitments and the out-of-domain point.
    let batch_shape = BatchShape {
        trace_widths: airs.iter().map(BaseAir::<F>::width).collect(),
        public_value_counts: airs.iter().map(BaseAir::<F>::num_public_values).collect(),
        preprocessed_widths: airs.iter().map(BaseAir::<F>::preprocessed_width).collect(),
        has_preprocessed_commitment: true,
        num_lookup_instances: has_lookups.iter().filter(|&&h| h).count(),
        lookup_pow_bits: LAYER_LOOKUP_POW_BITS,
        has_randomization_commitment: true,
        ood_pow_bits: LAYER_OOD_POW_BITS,
    };
    let native = tagged_challenger(&[]);
    let mut ch = CircuitChallenger::from_native(c, &native);
    ch.observe_all(c, tag);
    ch.observe_consts(c, &seed_elements(&batch_shape.domain_separator::<F, EF>()));
    for &log_n in &log_ns {
        ch.observe_consts(c, coeffs(&EF::from(F::from_usize(log_n + 1))));
    }
    let commit = |c: &mut Circuit, cap: Option<&p3_merkle_tree::MerkleCap<F, [F; 9]>>| -> Digest {
        digest_hint(c, &cap.map(cap_root).unwrap_or_default())
    };
    let main_commit = commit(c, proof.map(|p| &p.commitments.main));
    ch.observe_all(c, &main_commit);
    ch.observe_all(c, publics);
    let prep_commit: Digest = core::array::from_fn(|i| c.const_base(spec.commitment[i]));
    ch.observe_all(c, &prep_commit);
    // No lookup grinding: the step absorbs nothing.
    let lookup_alpha = ch.sample_ext(c);
    let lookup_beta = ch.sample_ext(c);
    let perm_commit = commit(c, proof.and_then(|p| p.commitments.permutation.as_ref()));
    ch.observe_all(c, &perm_commit);
    let terminals: Vec<Option<ExtVal>> = (0..n)
        .map(|i| {
            has_lookups[i].then(|| {
                let t = proof.and_then(|p| p.lookup_terminals.get(i)?.as_ref().map(|t| t.0));
                ExtVal::hint(c, t.unwrap_or(EF::ZERO))
            })
        })
        .collect();
    for t in terminals.iter().flatten() {
        ch.observe_all(c, &t.coeffs);
    }
    let alpha = ch.sample_ext(c);
    let quotient_commit = commit(c, proof.map(|p| &p.commitments.quotient_chunks));
    ch.observe_all(c, &quotient_commit);
    let random_commit = commit(c, proof.and_then(|p| p.commitments.random.as_ref()));
    ch.observe_all(c, &random_commit);
    // No out-of-domain grinding: the step absorbs nothing.
    let zeta = ch.sample_ext(c);

    // The opened values.
    let ext_hints = |c: &mut Circuit, vals: Option<&[EF]>, len: usize| -> Vec<ExtVal> {
        (0..len)
            .map(|k| ExtVal::hint(c, vals.and_then(|v| v.get(k).copied()).unwrap_or(EF::ZERO)))
            .collect()
    };
    let opened = |i: usize| proof.and_then(|p| p.opened_values.instances.get(i));
    let mut trace_local = Vec::with_capacity(n);
    let mut trace_next = Vec::with_capacity(n);
    let mut prep_local = Vec::with_capacity(n);
    let mut chunks = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    let mut perm_local = Vec::with_capacity(n);
    let mut perm_next = Vec::with_capacity(n);
    for (i, air) in airs.iter().enumerate() {
        let o = opened(i);
        let base = o.map(|o| &o.base_opened_values);
        trace_local.push(ext_hints(c, base.map(|b| &b.trace_local[..]), BaseAir::<F>::width(air)));
        trace_next.push(if air.reads_next() {
            ext_hints(c, base.and_then(|b| b.trace_next.as_deref()), BaseAir::<F>::width(air))
        } else {
            Vec::new()
        });
        prep_local.push(ext_hints(
            c,
            base.and_then(|b| b.preprocessed.as_ref().map(|p| &p.local[..])),
            BaseAir::<F>::preprocessed_width(air),
        ));
        let num_chunks = 1usize << (cons[i].log_chunks + 1);
        chunks.push(
            (0..num_chunks)
                .map(|k| ext_hints(c, base.and_then(|b| b.quotient_chunks.get(k).map(|q| &q[..])), 8))
                .collect::<Vec<_>>(),
        );
        random.push(ext_hints(c, base.and_then(|b| b.random.as_deref()), 8));
        let aux = aux_columns(&spec.lookups[i]);
        perm_local.push(ext_hints(c, o.map(|o| &o.permutation_local[..]), aux));
        perm_next.push(ext_hints(c, o.map(|o| &o.permutation_next[..]), aux));
    }

    // The opening argument: randomization, main, quotient, preprocessed and
    // permutation rounds, in the library's order.
    let zeta_nexts: Vec<Wire> = log_ns
        .iter()
        .map(|&log_n| c.mul_const(zeta.ext, EF::from(F::two_adic_generator(log_n))))
        .collect();
    let single = |log_n: usize, values: &Vec<ExtVal>| ClaimMat {
        log_domain: log_n + 1,
        points: alloc::vec![(zeta.ext, values.clone())],
    };
    let rounds = [
        ClaimRound {
            commit: random_commit,
            mats: (0..n).map(|i| single(log_ns[i], &random[i])).collect(),
            preprocessed: false,
        },
        ClaimRound {
            commit: main_commit,
            mats: (0..n)
                .map(|i| {
                    let mut mat = single(log_ns[i], &trace_local[i]);
                    if airs[i].reads_next() {
                        mat.points.push((zeta_nexts[i], trace_next[i].clone()));
                    }
                    mat
                })
                .collect(),
            preprocessed: false,
        },
        ClaimRound {
            commit: quotient_commit,
            mats: (0..n)
                .flat_map(|i| chunks[i].iter().map(move |ch| (i, ch)))
                .map(|(i, ch)| single(log_ns[i], ch))
                .collect(),
            preprocessed: false,
        },
        ClaimRound {
            commit: prep_commit,
            mats: (0..n).map(|i| single(log_ns[i], &prep_local[i])).collect(),
            preprocessed: true,
        },
        ClaimRound {
            commit: perm_commit,
            mats: (0..n)
                .filter(|&i| has_lookups[i])
                .map(|i| ClaimMat {
                    log_domain: log_ns[i] + 1,
                    points: alloc::vec![(zeta.ext, perm_local[i].clone()), (zeta_nexts[i], perm_next[i].clone())],
                })
                .collect(),
            preprocessed: false,
        },
    ];
    let rounds: Vec<ClaimRound> = rounds.into_iter().filter(|r| !r.mats.is_empty()).collect();
    verify_pcs(c, &mut ch, &fri, &rounds, proof.map(|p| &p.opening_proof));

    // The lookup challenges: one bus offset and the combiner a lookup.
    let (bus_ids, widest, num_buses) = bus_layout(&spec.lookups);
    let gamma = c.pow_const(lookup_beta.ext, widest as u64);
    let mut prefixes = Vec::with_capacity(num_buses);
    let mut prefix = lookup_alpha.ext;
    for _ in 0..num_buses {
        prefix = c.add(prefix, gamma);
        prefixes.push(prefix);
    }

    // Each table's constraints at zeta against its quotient.
    for (i, air) in airs.iter().enumerate() {
        let log_n = log_ns[i];
        let quotient = recompose_quotient(c, zeta.ext, log_n + 1, cons[i].log_chunks, &chunks[i]);
        let sels = selectors(c, zeta.ext, log_n);
        let recompose = |c: &mut Circuit, flat: &[ExtVal]| -> Vec<Wire> {
            flat.chunks(8)
                .map(|col| {
                    let mut acc = c.zero();
                    for (k, v) in col.iter().enumerate() {
                        acc = c.mul_const_add(v.ext, basis(k), acc);
                    }
                    acc
                })
                .collect()
        };
        let perm_l = recompose(c, &perm_local[i]);
        let perm_n = recompose(c, &perm_next[i]);
        let zero = c.zero();
        let challenges: Vec<Wire> = bus_ids[i].iter().flat_map(|&b| [prefixes[b], lookup_beta.ext]).collect();
        let values = OodValues {
            main_local: trace_local[i].iter().map(|v| v.ext).collect(),
            main_next: if air.reads_next() {
                trace_next[i].iter().map(|v| v.ext).collect()
            } else {
                alloc::vec![zero; BaseAir::<F>::width(air)]
            },
            prep_local: prep_local[i].iter().map(|v| v.ext).collect(),
            prep_next: alloc::vec![zero; BaseAir::<F>::preprocessed_width(air)],
            periodic: Vec::new(),
            publics: if air.table() == Table::Wires { publics.to_vec() } else { Vec::new() },
            perm_local: perm_l,
            perm_next: perm_n,
            challenges,
            perm_values: terminals[i].iter().map(|t| t.ext).collect(),
            is_first_row: sels.is_first_row,
            is_last_row: sels.is_last_row,
            is_transition: sels.is_transition,
        };
        // A chunk proof's ML-DSA tables are folded with linear values, in
        // fewer rows; every other table keeps the fold the layers' keys were
        // built with.
        let folded = if spec.kind == LayerKind::Chunk && matches!(air.table(), Table::Ml(_)) {
            fold_constraints_linear(c, &cons[i].base, &cons[i].ext, &cons[i].order, &values, alpha.ext)
        } else {
            fold_constraints(c, &cons[i].base, &cons[i].ext, &cons[i].order, &values, alpha.ext)
        };
        let lhs = c.mul(folded, sels.inv_vanishing);
        c.assert_eq(lhs, quotient);
    }

    // The terminals of every table sum to zero: every wire read is a wire
    // the wire table holds.
    let mut total = c.zero();
    for t in terminals.iter().flatten() {
        total = c.add(total, t.ext);
    }
    c.assert_zero(total);
}
