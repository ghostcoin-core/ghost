//! The recursion layers of the scale build (stage 2 design, "Aggregation
//! cost", architecture (c)): a batch proof that verifies reveal proofs, a root
//! proof that verifies an aggregator's batches, and a shrink proof that
//! verifies the root and is what a block carries.
//!
//! Every layer is a verifier circuit ([`circuit`]) proven as a batch STARK of
//! five tables routed by LogUp ([`tables`]), at the scale configuration's
//! Poseidon2 commitments and transcript, degree-8 extension and hiding FRI. The
//! circuit replays its children's transcripts, checks their Merkle openings,
//! their FRI folding and their constraints at the out-of-domain point, all in
//! its own rows: a batch's children are uni-STARK proofs (a reveal), a root's
//! and a shrink's are batch-STARK proofs of the layer below, lookups
//! included ([`verifier`]). No elliptic curve is used anywhere.
//!
//! Like the rest of the crate this module reads no clock, file or operating
//! system source and builds for `wasm32-unknown-unknown`; timing is the
//! benchmark's business.

pub(crate) mod bundle;
pub(crate) mod circuit;
pub(crate) mod keys;
pub(crate) mod pcs;
pub(crate) mod poseidon2;
pub(crate) mod security;
pub(crate) mod stream;
pub(crate) mod symbolic;
pub(crate) mod tables;
pub(crate) mod verifier;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_matrix::dense::RowMajorMatrix;

use crate::ProofError;
use crate::stark::FriShape;

/// Proof-of-work bits on the FRI queries of every layer and leaf.
const QUERY_POW_BITS: usize = 16;
/// Proof-of-work bits before the batching challenge of every layer and leaf.
const BATCH_POW_BITS: usize = 16;

/// The FRI parameters of a proof: blowup and queries. Grinding is 16 bits on
/// the queries and 16 before the batching challenge at every shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerShape {
    pub log_blowup: usize,
    pub num_queries: usize,
}

impl LayerShape {
    /// A reveal proof, a batch and a root: blowup 2^3, 96 queries.
    pub const WIDE: Self = Self {
        log_blowup: 3,
        num_queries: 96,
    };
    /// The shrink: blowup 2^5, 56 queries.
    pub const SHRINK: Self = Self {
        log_blowup: 5,
        num_queries: 56,
    };

    pub(crate) const fn fri(self) -> FriShape {
        FriShape {
            log_blowup: self.log_blowup,
            num_queries: self.num_queries,
            query_pow_bits: QUERY_POW_BITS,
            batch_pow_bits: BATCH_POW_BITS,
        }
    }

    /// The smallest trace height a proof at this shape may have: the hiding
    /// budget of the library, `2 * (8 * 2 + num_queries)`, rounded up.
    pub const fn min_height(self) -> usize {
        (2 * (16 + self.num_queries)).next_power_of_two()
    }

    /// Log of the tallest table a layer proof at this shape may have: its
    /// zero-knowledge doubling and blowup stay within the field's two-adic
    /// subgroup of 2^27.
    pub fn max_log_height(self) -> usize {
        tables::max_log_height(&self.fri())
    }
}

/// The positions, among a child's public values, of the chain identifier's
/// eight bytes, the protocol version's two and the statement version: what a
/// batch constrains to its binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingSlots {
    pub chain_id: [usize; 8],
    pub protocol_version: [usize; 2],
    pub statement_version: usize,
}

impl BindingSlots {
    /// Eleven consecutive public values from `first`: the chain identifier,
    /// the protocol version, the statement version.
    pub const fn consecutive(first: usize) -> Self {
        Self {
            chain_id: [first, first + 1, first + 2, first + 3, first + 4, first + 5, first + 6, first + 7],
            protocol_version: [first + 8, first + 9],
            statement_version: first + 10,
        }
    }

    fn positions(&self) -> [usize; bundle::BINDING_ELEMS] {
        let mut out = [0; bundle::BINDING_ELEMS];
        out[..8].copy_from_slice(&self.chain_id);
        out[8..10].copy_from_slice(&self.protocol_version);
        out[10] = self.statement_version;
        out
    }
}

/// An AIR a child proof can be made for: its width, its public values, where
/// they carry the chain and versions, and its constraints, for every builder.
pub trait ChildAir: Sync {
    fn width(&self) -> usize;
    fn num_public_values(&self) -> usize;
    /// Where the public values carry the chain identifier and the protocol
    /// and statement versions a batch's binding names.
    fn binding_slots(&self) -> BindingSlots;
    /// Whether the constraints read the next row.
    fn reads_next_row(&self) -> bool {
        true
    }
    /// The AIR's periodic columns, if any.
    fn periodic_columns(&self) -> Vec<Vec<BabyBear>> {
        Vec::new()
    }
    fn eval<AB: AirBuilder<F = BabyBear>>(&self, builder: &mut AB);
}

/// The version 2 coin reveal of the scale build as a batch child: its AIR at
/// the height the scale configuration gives it for `num_queries` queries.
pub struct RevealChild {
    air: crate::air::StatementAir,
    periodic: Vec<Vec<BabyBear>>,
}

impl RevealChild {
    /// The reveal's AIR at `num_queries` queries (blowup 2^3).
    pub fn new(num_queries: usize) -> Self {
        let air = crate::scale::reveal_air(num_queries);
        let periodic = BaseAir::<F>::periodic_columns(&air).into_owned();
        Self { air, periodic }
    }

    /// The log of the reveal trace's height.
    pub fn log_height(&self) -> usize {
        self.periodic.first().map_or(0, |c| c.len().trailing_zeros() as usize)
    }

    /// The reveal's public values as field elements, one a byte.
    pub fn public_values(params: &crate::ChainParams, tx: &crate::CoinRevealV2) -> Vec<BabyBear> {
        crate::stark::public_field(&crate::coin_reveal_v2_public_values(params, tx))
    }
}

impl ChildAir for RevealChild {
    fn width(&self) -> usize {
        BaseAir::<F>::width(&self.air)
    }

    fn num_public_values(&self) -> usize {
        BaseAir::<F>::num_public_values(&self.air)
    }

    /// The reveal's binding fields: `chain_id`, `version` and
    /// `statement_version`, one public value a byte.
    fn binding_slots(&self) -> BindingSlots {
        let fields = crate::binding::Binding::CoinRevealV2;
        let chain = fields.offset("chain_id");
        let version = fields.offset("version");
        BindingSlots {
            chain_id: core::array::from_fn(|i| chain + i),
            protocol_version: [version, version + 1],
            statement_version: fields.offset("statement_version"),
        }
    }

    fn reads_next_row(&self) -> bool {
        !BaseAir::<F>::main_next_row_columns(&self.air).is_empty()
    }

    fn periodic_columns(&self) -> Vec<Vec<BabyBear>> {
        self.periodic.clone()
    }

    fn eval<AB: AirBuilder<F = BabyBear>>(&self, builder: &mut AB) {
        Air::<AB>::eval(&self.air, builder);
    }
}

/// A [`ChildAir`] as the library's AIR traits.
pub(crate) struct AirOf<'a, A>(pub(crate) &'a A);

impl<A: ChildAir> BaseAir<F> for AirOf<'_, A> {
    fn width(&self) -> usize {
        self.0.width()
    }

    fn num_public_values(&self) -> usize {
        self.0.num_public_values()
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        if self.0.reads_next_row() { (0..self.0.width()).collect() } else { Vec::new() }
    }

    fn num_periodic_columns(&self) -> usize {
        self.0.periodic_columns().len()
    }

    fn periodic_columns(&self) -> alloc::borrow::Cow<'_, [Vec<F>]> {
        alloc::borrow::Cow::Owned(self.0.periodic_columns())
    }
}

impl<A: ChildAir, AB: AirBuilder<F = BabyBear>> Air<AB> for AirOf<'_, A> {
    fn eval(&self, builder: &mut AB) {
        self.0.eval(builder);
    }
}

/// Prove a trace of a [`ChildAir`] with the scale configuration at `shape`:
/// a leaf of the layers, the way a reveal proof is one.
pub fn prove_child<A: ChildAir>(
    air: &A,
    trace: RowMajorMatrix<BabyBear>,
    public_values: &[BabyBear],
    shape: LayerShape,
    zk_seed: [u8; 32],
) -> Result<Vec<u8>, ProofError> {
    let config = crate::scale::layer_config(zk_seed, &shape.fri(), crate::scale::tagged_challenger(&[]))?;
    let proof = p3_uni_stark::prove(&config, &AirOf(air), trace, public_values).map_err(|_| ProofError::Proving)?;
    postcard::to_allocvec(&proof).map_err(|_| ProofError::Proving)
}

/// Verify a proof of [`prove_child`] natively.
pub fn verify_child<A: ChildAir>(
    air: &A,
    public_values: &[BabyBear],
    proof: &[u8],
    shape: LayerShape,
) -> Result<(), ProofError> {
    let config = crate::scale::layer_config([0; 32], &shape.fri(), crate::scale::tagged_challenger(&[]))?;
    let proof: verifier::UniProof = postcard::from_bytes(proof).map_err(|_| ProofError::MalformedProof)?;
    p3_uni_stark::verify(&config, &AirOf(air), &proof, public_values).map_err(|_| ProofError::Rejected)
}

pub use bundle::{LayerKind, LayerTag};
pub use keys::{Binding, Claim, LayerKey};

/// A running digest, as canonical integers.
pub type Digest = [u32; 9];

/// The running digest every bundle starts from.
pub const START_DIGEST: Digest = [0; 9];

fn native(d: &Digest) -> bundle::NativeDigest {
    keys::native_of(d)
}

/// The running digest after `contents` (each child's public values, in
/// order) from `start`.
pub fn running_digest(start: &Digest, contents: &[Vec<BabyBear>]) -> Digest {
    bundle::digest_u32(&bundle::native_running_digest(&native(start), contents))
}

/// The key of a batch of `capacity` [`ChildAir`] children, each proven at
/// `child` over `2^child_log_height` rows; the batch is proven at `shape`.
pub fn batch_key<A: ChildAir>(
    air: &A,
    child: LayerShape,
    child_log_height: usize,
    capacity: usize,
    shape: LayerShape,
) -> Result<LayerKey, ProofError> {
    keys::batch_key_of(&AirOf(air), &air.binding_slots().positions(), child, child_log_height, capacity, shape)
}

/// Prove a batch of child proofs (each with its public values, in order),
/// its running digest starting from `start`, at position `index` under
/// `binding`. Refuses a batch some child does not verify in, and one with a
/// child whose chain identifier or versions are not `binding`'s.
pub fn prove_batch<A: ChildAir>(
    key: &LayerKey,
    air: &A,
    binding: &Binding,
    index: u32,
    start: &Digest,
    children: &[(Vec<u8>, Vec<BabyBear>)],
    zk_seed: [u8; 32],
) -> Result<Vec<u8>, ProofError> {
    let tag = key.tag(binding, index);
    let slots = air.binding_slots().positions();
    keys::prove_batch_of(key, &AirOf(air), &slots, &tag, &native(start), children, zk_seed, false)
}

/// [`prove_batch`] that proves the circuit even when a child breaks it, and
/// under any tag (whose binding the batch's public values then carry): for
/// tests that such a proof is refused.
#[doc(hidden)]
pub fn prove_batch_unchecked<A: ChildAir>(
    key: &LayerKey,
    air: &A,
    tag: &LayerTag,
    start: &Digest,
    children: &[(Vec<u8>, Vec<BabyBear>)],
    zk_seed: [u8; 32],
) -> Result<Vec<u8>, ProofError> {
    let slots = air.binding_slots().positions();
    keys::prove_batch_of(key, &AirOf(air), &slots, tag, &native(start), children, zk_seed, true)
}

/// The public values of a batch under `binding` whose children have
/// `contents` from `start`: the binding, the running digest before and after,
/// the count.
pub fn batch_public_values(binding: &Binding, start: &Digest, contents: &[Vec<BabyBear>]) -> Vec<BabyBear> {
    keys::batch_publics(binding, &native(start), contents)
}

/// Verify a batch proof at position `index` under `binding` against the
/// public values of its children, in order, from `start`.
pub fn verify_batch(
    key: &LayerKey,
    binding: &Binding,
    index: u32,
    start: &Digest,
    contents: &[Vec<BabyBear>],
    proof: &[u8],
) -> Result<(), ProofError> {
    if key.kind != LayerKind::Batch {
        return Err(ProofError::Rejected);
    }
    let publics = keys::batch_publics(binding, &native(start), contents);
    keys::verify_layer(key, &key.tag(binding, index), &publics, proof)
}

/// The key of a root over up to `capacity` batch proofs of `batch`'s key,
/// proven at `shape`.
pub fn root_key(batch: &LayerKey, capacity: usize, shape: LayerShape) -> Result<LayerKey, ProofError> {
    keys::layer_key_of(batch, LayerKind::Root, capacity, shape, shape.max_log_height())
}

/// [`root_key`] with its tables no taller than `2^max_log_height`, packed
/// into more lanes: for tests of packed tables at small shapes.
#[doc(hidden)]
pub fn root_key_within(
    batch: &LayerKey,
    capacity: usize,
    shape: LayerShape,
    max_log_height: usize,
) -> Result<LayerKey, ProofError> {
    keys::layer_key_of(batch, LayerKind::Root, capacity, shape, max_log_height)
}

/// The key of a shrink of one root proof of `root`'s key, proven at `shape`
/// ([`LayerShape::SHRINK`] for the proof a block carries). Its tables are
/// packed into the lanes that make its proof bound smallest
/// ([`keys::smallest_proof_limit`]).
pub fn shrink_key(root: &LayerKey, shape: LayerShape) -> Result<LayerKey, ProofError> {
    if root.kind != LayerKind::Root {
        return Err(ProofError::Proving);
    }
    let spec = root.spec();
    let cons = verifier::table_constraints(&spec);
    let rows = keys::layer_rows(&spec, &cons, 1);
    let (max_log, _) = keys::smallest_proof_limit(LayerKind::Shrink, shape, rows, bundle::LAYER_PUBLICS)?;
    keys::layer_key_of(root, LayerKind::Shrink, 1, shape, max_log)
}

/// Prove a root (over batch proofs) or a shrink (over one root proof) at
/// position `index` under `binding`: `children` are proofs of `child`'s key
/// with their claims, in order, the first at index 0. The layer claims from
/// the first child's start to the last one's end ([`Claim::joined`]).
/// Refuses children that do not verify, or where one does not start where
/// the one before it ended.
pub fn prove_layer(
    key: &LayerKey,
    child: &LayerKey,
    binding: &Binding,
    index: u32,
    children: &[(Vec<u8>, Claim)],
    zk_seed: [u8; 32],
) -> Result<Vec<u8>, ProofError> {
    keys::prove_layer_of(key, child, &key.tag(binding, index), children, zk_seed, false)
}

/// [`prove_layer`] that proves the circuit even when a child breaks it, and
/// under any tag: for tests that such a proof is refused.
#[doc(hidden)]
pub fn prove_layer_unchecked(
    key: &LayerKey,
    child: &LayerKey,
    tag: &LayerTag,
    children: &[(Vec<u8>, Claim)],
    zk_seed: [u8; 32],
) -> Result<Vec<u8>, ProofError> {
    keys::prove_layer_of(key, child, tag, children, zk_seed, true)
}

/// Verify a root or a shrink proof at position `index` under `binding`
/// against its claim.
pub fn verify_layer(
    key: &LayerKey,
    binding: &Binding,
    index: u32,
    claim: &Claim,
    proof: &[u8],
) -> Result<(), ProofError> {
    if key.kind == LayerKind::Batch {
        return Err(ProofError::Rejected);
    }
    keys::verify_layer(key, &key.tag(binding, index), &keys::claim_publics(binding, claim), proof)
}

/// The proof field of spec 07: the most bytes a block carries for a proof,
/// the bound on a shrink proof.
pub const PROOF_FIELD_BYTES: usize = crate::stark::PROOF_FIELD_BYTES;

/// An upper bound on the bytes of any proof of `key`, from its tables, its
/// lookups and its FRI shape.
pub fn proof_size_bound(key: &LayerKey) -> usize {
    keys::key_proof_bytes_bound(key)
}

/// One planned layer: each table's lanes and height, the entries the
/// circuit fills (wires, arithmetic rows, permutation rows, bits rows,
/// packing rows), and a model of the memory its prover holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedLayer {
    pub lanes: Vec<usize>,
    pub heights: Vec<usize>,
    pub entries: [usize; 5],
    /// Bytes the streamed prover holds at its peak, modeled
    /// ([`ProverMemory::peak`]).
    pub modeled_prover_bytes: usize,
    /// The model by part: the circuit, the key, the coefficients of the
    /// committed matrices, each phase, and the largest block of extended
    /// rows evaluated at once.
    pub memory: ProverMemory,
}

/// The memory ceiling of an aggregator machine in the stage 2 design: 128
/// GiB. Every layer of the real pipeline plans its prover within it.
pub const PROVER_CEILING_BYTES: u64 = 128 << 30;

pub use keys::ProverMemory;

/// The batch, root and shrink of a real pipeline, planned without proving:
/// each layer's tables as its circuit fills them, and an upper bound on the
/// shrink proof's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelinePlan {
    pub batch: PlannedLayer,
    pub root: PlannedLayer,
    pub shrink: PlannedLayer,
    pub shrink_bytes_bound: usize,
}

pub(crate) fn planned(spec: &verifier::LayerSpec, cons: &[verifier::TableConstraints], entries: [usize; 5]) -> PlannedLayer {
    let memory = keys::prover_memory(&spec.airs, &spec.lookups, cons, spec.shape, entries);
    PlannedLayer {
        lanes: spec.airs.iter().map(tables::TableAir::lanes).collect(),
        heights: spec.airs.iter().map(tables::TableAir::height).collect(),
        entries,
        modeled_prover_bytes: memory.peak,
        memory,
    }
}

/// [`PlannedLayer::modeled_prover_bytes`] for a layer of a built key.
pub fn modeled_prover_bytes(key: &LayerKey) -> usize {
    let spec = key.spec();
    let cons = verifier::table_constraints(&spec);
    let entries: [usize; 5] = core::array::from_fn(|t| spec.airs[t].height() * spec.airs[t].lanes());
    keys::prover_bytes_model(&spec.airs, &spec.lookups, &cons, spec.shape, entries)
}

/// Plan a batch of `per_batch` children of `air` (each proven at `child`
/// over `2^child_log_height` rows) at `layer`, a root over `batches` such
/// batches at `layer`, and a shrink of that root at `shrink`. The batch and
/// root circuits are built for one, two and three slots and their entries
/// extended slot by slot ([`keys::extrapolate`]); the shrink circuit is
/// built whole. Each layer's tables are planned as its key plans them: the
/// batch's and root's in the fewest lanes within the field's two-adic limit,
/// the shrink's in the lanes that make its proof bound smallest, as
/// [`shrink_key`] does. `Err` when a layer cannot fit the limit.
pub fn plan_pipeline<A: ChildAir>(
    air: &A,
    child: LayerShape,
    child_log_height: usize,
    per_batch: usize,
    batches: usize,
    layer: LayerShape,
    shrink: LayerShape,
) -> Result<PipelinePlan, ProofError> {
    Ok(pipeline_specs(air, child, child_log_height, per_batch, batches, layer, shrink)?.plan())
}

/// The batch, root and shrink of [`plan_pipeline`], each with its
/// constraints and entries.
struct PipelineSpecs {
    layers: [(verifier::LayerSpec, Vec<verifier::TableConstraints>, [usize; 5]); 3],
    shrink_bytes_bound: usize,
}

impl PipelineSpecs {
    fn plan(&self) -> PipelinePlan {
        let [batch, root, shrink] = &self.layers;
        PipelinePlan {
            batch: planned(&batch.0, &batch.1, batch.2),
            root: planned(&root.0, &root.1, root.2),
            shrink: planned(&shrink.0, &shrink.1, shrink.2),
            shrink_bytes_bound: self.shrink_bytes_bound,
        }
    }
}

fn pipeline_specs<A: ChildAir>(
    air: &A,
    child: LayerShape,
    child_log_height: usize,
    per_batch: usize,
    batches: usize,
    layer: LayerShape,
    shrink: LayerShape,
) -> Result<PipelineSpecs, ProofError> {
    let slots = air.binding_slots().positions();
    let air = AirOf(air);
    let np = bundle::LAYER_PUBLICS;
    let batch_entries = keys::extrapolate(|n| keys::batch_rows(&air, &slots, child, child_log_height, n), per_batch);
    let batch = keys::shape_spec(LayerKind::Batch, layer, batch_entries, np)?;
    let batch_cons = verifier::table_constraints(&batch);
    let root_entries = keys::extrapolate(|n| keys::layer_rows(&batch, &batch_cons, n), batches);
    let root = keys::shape_spec(LayerKind::Root, layer, root_entries, np)?;
    let root_cons = verifier::table_constraints(&root);
    let shrink_entries = keys::layer_rows(&root, &root_cons, 1);
    let (max_log, _) = keys::smallest_proof_limit(LayerKind::Shrink, shrink, shrink_entries, np)?;
    let shrink_spec = keys::shape_spec_within(LayerKind::Shrink, shrink, shrink_entries, np, max_log)?;
    let shrink_cons = verifier::table_constraints(&shrink_spec);
    let shrink_bytes_bound =
        keys::proof_bytes_bound(&shrink_spec.airs, &shrink_spec.lookups, &shrink_cons, shrink);
    Ok(PipelineSpecs {
        layers: [
            (batch, batch_cons, batch_entries),
            (root, root_cons, root_entries),
            (shrink_spec, shrink_cons, shrink_entries),
        ],
        shrink_bytes_bound,
    })
}

pub use security::{FIELD_MARGIN_BITS, PipelineEstimate, ProofEstimate, UNCAPPED_COLLISION_BITS, reveal_estimate};

/// The pinned library's security estimator at the real shape of the batch,
/// root and shrink of [`plan_pipeline`] (same arguments), with the plan
/// itself. See [`security`] for how a layer's five tables enter the
/// estimator.
pub fn estimate_pipeline<A: ChildAir>(
    air: &A,
    child: LayerShape,
    child_log_height: usize,
    per_batch: usize,
    batches: usize,
    layer: LayerShape,
    shrink: LayerShape,
) -> Result<PipelineEstimate, ProofError> {
    let specs = pipeline_specs(air, child, child_log_height, per_batch, batches, layer, shrink)?;
    let [batch, root, shrink] = &specs.layers;
    Ok(PipelineEstimate {
        plan: specs.plan(),
        batch: security::layer_estimate(&batch.0, &batch.1),
        root: security::layer_estimate(&root.0, &root.1),
        shrink: security::layer_estimate(&shrink.0, &shrink.1),
    })
}

/// Whether the lookups a key's tables were committed with are the ones the
/// library derives for tables of the same shape: what [`plan_pipeline`]
/// relies on for layers it does not build.
#[doc(hidden)]
pub fn derived_lookups_match(key: &LayerKey) -> bool {
    let spec = key.spec();
    let shapes: Vec<tables::TableAir> = spec
        .airs
        .iter()
        .map(|a| tables::TableAir::shape(a.table(), a.num_publics(), a.lanes(), a.height()))
        .collect();
    let Ok(derived) = tables::lookups_for(&shapes, &key.shape.fri()) else {
        return false;
    };
    alloc::format!("{:?}", derived) == alloc::format!("{:?}", spec.lookups)
}

/// Verify a child proof inside a circuit and report what the circuit found:
/// `Ok(rows)` with the arithmetic and permutation row counts when every row
/// holds, the first broken row otherwise. A test of the in-circuit verifier
/// alone, before any layer is proven.
#[doc(hidden)]
pub fn child_in_circuit_check<A: ChildAir>(
    air: &A,
    public_values: &[BabyBear],
    proof: &[u8],
    shape: LayerShape,
    log_height: usize,
    tamper: usize,
) -> Result<(usize, usize), alloc::string::String> {
    use p3_field::PrimeCharacteristicRing;
    let mut proof: verifier::UniProof =
        postcard::from_bytes(proof).map_err(|_| alloc::string::String::from("malformed proof"))?;
    // Change one part of the proof: an opened row, the final polynomial, an
    // opened trace value, a folding sibling or a quotient chunk.
    let one = EF::ONE;
    match tamper {
        0 => {}
        1 => proof.opening_proof.1.input_openings[1].opened_values[0][0][0] += F::ONE,
        2 => proof.opening_proof.1.final_poly[0] += one,
        3 => proof.opened_values.trace_local[0] += one,
        4 => proof.opening_proof.1.commit_phase_openings[0].sibling_values[0][0] += one,
        5 => proof.opened_values.quotient_chunks[0][0] += one,
        _ => return Err("unknown change".into()),
    }
    let mut c = circuit::Circuit::new();
    let publics: Vec<circuit::Wire> = public_values.iter().map(|&v| c.hint_base(v)).collect();
    let ushape = verifier::UniShape {
        fri: shape.fri(),
        log_height,
    };
    verifier::verify_uni(&mut c, &AirOf(air), &ushape, &publics, Some(&proof));
    match c.failure() {
        None => Ok((c.arith_rows().len(), c.perm_rows().len())),
        Some(f) => Err(f.into()),
    }
}

/// Verify a layer proof of `child`'s key inside a circuit, the way a root or
/// a shrink does, after changing one part of it, and report what the circuit
/// found: `Ok(rows)` with the arithmetic and permutation row counts when
/// every row holds, the first broken row otherwise. A test of the in-circuit
/// batch-STARK verifier alone.
#[doc(hidden)]
pub fn layer_in_circuit_check(
    child: &LayerKey,
    binding: &Binding,
    index: u32,
    claim: &Claim,
    proof: &[u8],
    tamper: usize,
) -> Result<(usize, usize), alloc::string::String> {
    use p3_field::PrimeCharacteristicRing;
    let mut proof: verifier::LayerProof =
        postcard::from_bytes(proof).map_err(|_| alloc::string::String::from("malformed proof"))?;
    let one = EF::ONE;
    // An opened main row, a permutation-trace value, a lookup terminal, a
    // preprocessed value, a folding sibling or a quotient chunk.
    match tamper {
        0 => {}
        1 => proof.opening_proof.1.input_openings[1].opened_values[0][0][0] += F::ONE,
        2 => proof.opened_values.instances[2].permutation_local[0] += one,
        3 => {
            if let Some(t) = proof.lookup_terminals[1].as_mut() {
                t.0 += one;
            }
        }
        4 => {
            if let Some(p) = proof.opened_values.instances[0].base_opened_values.preprocessed.as_mut() {
                p.local[0] += one;
            }
        }
        5 => proof.opening_proof.1.commit_phase_openings[0].sibling_values[0][0] += one,
        6 => proof.opened_values.instances[1].base_opened_values.quotient_chunks[0][0] += one,
        _ => return Err("unknown change".into()),
    }
    let spec = child.spec();
    let cons = verifier::table_constraints(&spec);
    if !verifier::layer_shape_ok(&spec, &cons, &proof) {
        return Err("a proof of another shape".into());
    }
    let mut c = circuit::Circuit::new();
    let publics: Vec<circuit::Wire> =
        keys::claim_publics(binding, claim).iter().map(|&v| c.hint_base(v)).collect();
    let tag: Vec<circuit::Wire> =
        child.tag(binding, index).elements().iter().map(|&v| c.const_base(v)).collect();
    verifier::verify_layer(&mut c, &spec, &cons, &tag, &publics, Some(&proof));
    match c.failure() {
        None => Ok((c.arith_rows().len(), c.perm_rows().len())),
        Some(f) => Err(f.into()),
    }
}

/// The base field.
pub(crate) type F = BabyBear;
/// The challenge field: the degree-8 extension of BabyBear.
pub(crate) type EF = BinomialExtensionField<BabyBear, 8>;

/// The eight base coefficients of an extension value.
pub(crate) fn coeffs(v: &EF) -> &[F] {
    <EF as p3_field::BasedVectorSpace<F>>::as_basis_coefficients_slice(v)
}

/// The `i`-th basis element of the extension.
pub(crate) fn basis(i: usize) -> EF {
    <EF as p3_field::BasedVectorSpace<F>>::ith_basis_element(i).expect("eight basis elements")
}

/// An extension value from its eight base coefficients.
pub(crate) fn from_coeffs(f: impl FnMut(usize) -> F) -> EF {
    <EF as p3_field::BasedVectorSpace<F>>::from_basis_coefficients_fn(f)
}

/// Columns of the width-24 Poseidon2 permutation table: one permutation a
/// row (the stage 2 design models 451, the library AIR's layout with its
/// export flag).
pub const POSEIDON2_PERMUTATION_COLUMNS: usize = poseidon2::PERM_COLS;

/// A small circuit with every kind of row, proven and verified through the
/// five tables with one lane a row and with the wire and arithmetic tables
/// packed into several, then checked to fail with a changed public value and
/// with a changed tag. A test of the tables alone, before any verifier
/// circuit. Returns the lanes of the packed tables.
#[doc(hidden)]
pub fn table_roundtrip_check() -> Result<Vec<usize>, alloc::string::String> {
    use alloc::format;
    use p3_field::PrimeCharacteristicRing;

    let (c, publics, tag, fri) = small_circuit()?;
    let mut lanes = Vec::new();
    // One lane a row, then everything within the smallest height.
    for max_log in [tables::max_log_height(&fri), tables::min_height(&fri).trailing_zeros() as usize] {
        let airs = tables::table_airs_within(&c, &fri, max_log).map_err(|e| format!("tables: {e}"))?;
        lanes = airs.iter().map(tables::TableAir::lanes).collect();
        let key = tables::setup(airs, &fri).map_err(|e| format!("setup: {e}"))?;
        let proof = tables::prove(&key, &c, &fri, &tag, [3; 32]).map_err(|e| format!("prove: {e}"))?;
        tables::verify(&key.airs, key.common(), &proof, &publics, &fri, &tag)
            .map_err(|e| format!("verify with lanes {lanes:?}: {e}"))?;
        let wrong = [publics[0] + F::ONE];
        if tables::verify(&key.airs, key.common(), &proof, &wrong, &fri, &tag).is_ok() {
            return Err(format!("a changed public value verifies with lanes {lanes:?}"));
        }
        if tables::verify(&key.airs, key.common(), &proof, &publics, &fri, &tag[..1]).is_ok() {
            return Err(format!("a changed tag verifies with lanes {lanes:?}"));
        }
    }
    Ok(lanes)
}

/// The small circuit of [`table_roundtrip_check`], with its public value,
/// a tag and a FRI shape of two queries at blowup 2^3.
fn small_circuit() -> Result<(circuit::Circuit, [F; 1], [F; 2], FriShape), alloc::string::String> {
    use alloc::format;
    use p3_field::PrimeCharacteristicRing;

    let fri = FriShape {
        log_blowup: 3,
        num_queries: 2,
        query_pow_bits: 8,
        batch_pow_bits: 8,
    };
    // The public value is the permutation's second output, known first: a
    // circuit's public values are its first wires.
    let y_native = F::from_u32(1234) * F::from_u32(77);
    let input_native: [F; 24] = core::array::from_fn(|i| if i == 0 { y_native } else { F::from_usize(i) });
    let out_native = poseidon2::permute(input_native);
    let mut c = circuit::Circuit::new();
    let public = c.public(out_native[1]);
    let x = c.hint(EF::from(F::from_u32(1234)));
    let y = c.mul_const(x, EF::from(F::from_u32(77)));
    let input: [circuit::Wire; 24] = core::array::from_fn(|i| if i == 0 { y } else { c.const_base(F::from_usize(i)) });
    let out = c.perm(input);
    let bits = c.bits(out[0]);
    let back = c.from_bits(&bits);
    c.assert_eq(back, out[0]);
    c.assert_eq(public, out[1]);
    let e = c.hint(from_coeffs(|i| F::from_usize(i + 3)));
    let inv = c.inv(e);
    let mut acc = c.mul(inv, e);
    // Enough arithmetic for the packed arithmetic table to take lanes.
    for _ in 0..200 {
        acc = c.mul(acc, e);
    }
    if let Some(f) = c.failure() {
        return Err(format!("the honest circuit fails: {f}"));
    }
    let publics = [c.base_value(public)];
    let tag = [F::from_u8(7), F::from_u8(9)];
    Ok((c, publics, tag, fri))
}

/// The streamed prover against the library's: the small circuit of
/// [`table_roundtrip_check`], its tables in one lane a row and packed into
/// lanes, keyed and proven by the library (`ProverData::from_airs_and_degrees`
/// and `prove_batch`, every extension held whole) and by the streamed key
/// and prover with blocks of at most `budget` bytes for each budget given.
/// The keys must agree (lookups and preprocessed commitment), the proofs
/// must be the same bytes, and the streamed proof must verify, and fail
/// with a changed public value. Returns, for each budget, the blocks the
/// main commitment was cut into.
#[doc(hidden)]
pub fn streamed_prover_check(budgets: &[usize]) -> Result<Vec<usize>, alloc::string::String> {
    use alloc::format;
    use p3_field::PrimeCharacteristicRing;

    let (c, publics, tag, fri) = small_circuit()?;
    let mut blocks = Vec::new();
    for max_log in [tables::max_log_height(&fri), tables::min_height(&fri).trailing_zeros() as usize] {
        let airs = tables::table_airs_within(&c, &fri, max_log).map_err(|e| format!("tables: {e}"))?;
        let library_key = tables::library_setup(&airs, &fri).map_err(|e| format!("library setup: {e}"))?;
        let library = tables::library_prove(&airs, &library_key, &c, &fri, &tag, [5; 32])
            .map_err(|e| format!("library prove: {e}"))?;
        let library_bytes = postcard::to_allocvec(&library).map_err(|_| "library proof encodes")?;
        let library_root = library_key.common.preprocessed.as_ref().map(|p| p.commitment.roots().to_vec());
        let mains: Vec<(usize, usize)> = airs
            .iter()
            .map(|a| {
                let log_lde = a.height().trailing_zeros() as usize + 1 + fri.log_blowup;
                (log_lde, BaseAir::<F>::width(a) + crate::scale::SCALE_RANDOM_CODEWORDS)
            })
            .collect();
        for &budget in budgets {
            blocks.push(stream::block_count(&mains, budget));
            let key = tables::setup_within(airs.clone(), &fri, budget).map_err(|e| format!("setup: {e}"))?;
            let root = key.common().preprocessed.as_ref().map(|p| p.commitment.roots().to_vec());
            if root != library_root {
                return Err(format!("the preprocessed commitment differs at {budget} bytes a block"));
            }
            if format!("{:?}", key.common().lookups) != format!("{:?}", library_key.common.lookups) {
                return Err(format!("the lookups differ at {budget} bytes a block"));
            }
            let proof = tables::prove_within(&key, &c, &fri, &tag, [5; 32], budget)
                .map_err(|e| format!("prove at {budget} bytes a block: {e}"))?;
            let bytes = postcard::to_allocvec(&proof).map_err(|_| "proof encodes")?;
            if bytes != library_bytes {
                let at = bytes.iter().zip(&library_bytes).position(|(a, b)| a != b).unwrap_or(bytes.len());
                return Err(format!(
                    "the proof at {budget} bytes a block differs from the library's at byte {at} of {} ({} bytes)",
                    library_bytes.len(),
                    bytes.len()
                ));
            }
            tables::verify(&key.airs, key.common(), &proof, &publics, &fri, &tag)
                .map_err(|e| format!("verify at {budget} bytes a block: {e}"))?;
            if tables::verify(&key.airs, key.common(), &proof, &[publics[0] + F::ONE], &fri, &tag).is_ok() {
                return Err(format!("a changed public value verifies at {budget} bytes a block"));
            }
            // With its prover data released the key still verifies, and
            // refuses to prove.
            let mut key = key;
            key.release();
            tables::verify(&key.airs, key.common(), &proof, &publics, &fri, &tag)
                .map_err(|e| format!("verify with a released key: {e}"))?;
            if tables::prove_within(&key, &c, &fri, &tag, [5; 32], budget).is_ok() {
                return Err("a released key proves".into());
            }
        }
    }
    Ok(blocks)
}

/// The width-24 Poseidon2 permutation as the layers' permutation table
/// computes it, row by row, for a test against the library's
/// `default_babybear_poseidon2_24`. Returns the output and whether the row
/// satisfies the table's constraints.
#[doc(hidden)]
pub fn poseidon2_table_permutation(input: [u32; 24]) -> ([u32; 24], bool) {
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    let input: [F; 24] = core::array::from_fn(|i| F::from_u32(input[i]));
    let row = poseidon2::permute_row(input);
    let mut ok = true;
    poseidon2::eval_row(&row, |e: F| ok &= e == F::ZERO);
    let out: Vec<u32> = row[poseidon2::output_columns()].iter().map(|x| x.as_canonical_u32()).collect();
    (core::array::from_fn(|i| out[i]), ok)
}
