//! Layer keys, proving and verifying each layer, and planning the layers of
//! a shape too large to build here.

use alloc::vec::Vec;

use p3_air::symbolic::SymbolicAirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::StarkGenericConfig;

use super::bundle::{
    BINDING_ELEMS, LAYER_PUBLICS, LayerChild, LayerKind, LayerTag, NativeDigest, UniChild, batch_circuit, digest_u32,
    key_words, layer_circuit, layer_publics, native_hash, native_running_digest, uni_key_digest,
};
use super::circuit::Circuit;
use super::pcs::DIGEST;
use super::tables::{self, CircuitKey, TABLES, TableAir};
use super::verifier::{
    LayerProof, LayerSpec, TableConstraints, UniProof, UniShape, cap_root, layer_shape_ok, log_quotient_chunks,
    table_constraints, uni_shape_ok,
};
use super::{F, LayerShape};
use crate::{ChainParams, ProofError, STATEMENT_VERSION_2};

/// What a bundle is bound to: the chain and the versions every layer's tag
/// names, and every layer's public values carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub chain_id: [u8; 8],
    pub protocol_version: [u8; 2],
    pub statement_version: u8,
}

impl Binding {
    /// The binding of reveals of the version 2 coin reveal on a chain.
    pub fn of(params: &ChainParams) -> Self {
        Self {
            chain_id: params.chain_id,
            protocol_version: params.version,
            statement_version: STATEMENT_VERSION_2,
        }
    }

    /// The binding among a layer's public values: the chain identifier's
    /// bytes, the protocol version's, the statement version.
    pub(crate) fn elements(&self) -> [F; BINDING_ELEMS] {
        let mut out = [F::ZERO; BINDING_ELEMS];
        for (o, &b) in out.iter_mut().zip(self.chain_id.iter().chain(&self.protocol_version)) {
            *o = F::from_u8(b);
        }
        out[BINDING_ELEMS - 1] = F::from_u8(self.statement_version);
        out
    }

    /// The binding a tag names.
    pub(crate) fn of_tag(tag: &LayerTag) -> Self {
        Self {
            chain_id: tag.chain_id,
            protocol_version: tag.protocol_version,
            statement_version: tag.statement_version,
        }
    }
}

/// What a layer proof claims about the reveals under it, in order: the
/// running digest before them, the running digest after them, and their
/// count. A node computes it from the block's ordered reveals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub start: [u32; DIGEST],
    pub end: [u32; DIGEST],
    pub count: u32,
}

impl Claim {
    /// The claim of reveals with public values `contents`, in order, from the
    /// running digest `start`.
    pub fn of(start: &[u32; DIGEST], contents: &[Vec<F>]) -> Self {
        let s = native_of(start);
        Self {
            start: *start,
            end: digest_u32(&native_running_digest(&s, contents)),
            count: u32::try_from(contents.len()).expect("fewer than 2^32 reveals"),
        }
    }

    /// The claim of consecutive layers' claims: from the first one's start
    /// to the last one's end. `None` for no claims.
    pub fn joined(parts: &[Claim]) -> Option<Self> {
        Some(Self {
            start: parts.first()?.start,
            end: parts.last()?.end,
            count: parts.iter().map(|p| p.count).sum(),
        })
    }

    fn publics(&self, binding: &Binding) -> [F; LAYER_PUBLICS] {
        layer_publics(
            &binding.elements(),
            &native_of(&self.start),
            &native_of(&self.end),
            self.count as usize,
        )
    }
}

pub(crate) fn native_of(d: &[u32; DIGEST]) -> NativeDigest {
    core::array::from_fn(|i| F::from_u32(d[i]))
}

/// The verifier key of a layer: its circuit's tables (the preprocessed
/// commitment of the batch STARK), its shape and what its children are.
pub struct LayerKey {
    pub(crate) kind: LayerKind,
    pub(crate) shape: LayerShape,
    pub(crate) capacity: usize,
    pub(crate) child_key: NativeDigest,
    pub(crate) circuit: CircuitKey,
    /// A batch's children: their shape and log trace height.
    pub(crate) leaf: Option<(LayerShape, usize)>,
    /// Log of the tallest table the key allows; below the field's own limit
    /// only for tests that pack tables into several lanes.
    pub(crate) max_log: usize,
}

impl LayerKey {
    pub fn kind(&self) -> LayerKind {
        self.kind
    }

    pub fn shape(&self) -> LayerShape {
        self.shape
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The digest of the children's verifier key this layer fixes.
    pub fn child_key(&self) -> [u32; DIGEST] {
        digest_u32(&self.child_key)
    }

    /// The height of each of the layer's five tables (wires, arithmetic,
    /// permutation, bits, packing).
    pub fn table_heights(&self) -> Vec<usize> {
        self.circuit.airs.iter().map(TableAir::height).collect()
    }

    /// The lanes of each of the layer's five tables.
    pub fn table_lanes(&self) -> Vec<usize> {
        self.circuit.airs.iter().map(TableAir::lanes).collect()
    }

    /// The preprocessed commitment of the layer's tables.
    pub(crate) fn commitment(&self) -> NativeDigest {
        let root = self
            .circuit
            .common()
            .preprocessed
            .as_ref()
            .map(|p| cap_root(&p.commitment))
            .unwrap_or_default();
        core::array::from_fn(|i| root.get(i).copied().unwrap_or(F::ZERO))
    }

    /// The digest of this key, which the layer above fixes: its kind, shape,
    /// public value count, tables, preprocessed commitment and children's key.
    pub fn digest(&self) -> [u32; DIGEST] {
        digest_u32(&self.native_digest())
    }

    pub(crate) fn native_digest(&self) -> NativeDigest {
        let tables: Vec<(usize, usize)> = self.circuit.airs.iter().map(|a| (a.lanes(), a.height())).collect();
        native_hash(&key_words(
            self.kind,
            self.shape,
            LAYER_PUBLICS,
            &tables,
            &self.commitment(),
            &self.child_key,
        ))
    }

    /// The tag of a proof of this layer at position `index` under `binding`.
    pub fn tag(&self, binding: &Binding, index: u32) -> LayerTag {
        LayerTag {
            kind: self.kind,
            index,
            protocol_version: binding.protocol_version,
            statement_version: binding.statement_version,
            chain_id: binding.chain_id,
            child_key: digest_u32(&self.child_key),
        }
    }

    /// What a parent circuit fixes about this layer.
    pub(crate) fn spec(&self) -> LayerSpec {
        LayerSpec {
            kind: self.kind,
            shape: self.shape,
            airs: self.circuit.airs.clone(),
            lookups: self.circuit.common().lookups.clone(),
            commitment: self.commitment(),
            child_key: self.child_key,
            key_digest: self.native_digest(),
        }
    }
}

/// The shape a batch fixes for its children.
fn uni_shape(child: LayerShape, log_height: usize) -> UniShape {
    UniShape {
        fri: child.fri(),
        log_height,
    }
}

/// The layers run no grinding of their own before the lookup challenges or
/// the out-of-domain point, which the in-circuit verifier relies on.
pub(crate) fn check_config(shape: LayerShape) -> Result<(), ProofError> {
    let config = crate::scale::layer_config([0; 32], &shape.fri(), crate::scale::tagged_challenger(&[]))?;
    if config.lookup_proof_of_work_bits() != 0 || config.ood_proof_of_work_bits() != 0 {
        return Err(ProofError::Proving);
    }
    Ok(())
}

/// The key of a batch of `capacity` children of `air`, each proven at
/// `child` over `2^child_log_height` rows, the batch proven at `shape`.
pub(crate) fn batch_key_of<A>(
    air: &A,
    binding_slots: &[usize; BINDING_ELEMS],
    child: LayerShape,
    child_log_height: usize,
    capacity: usize,
    shape: LayerShape,
) -> Result<LayerKey, ProofError>
where
    A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
{
    if capacity == 0 || binding_slots.iter().any(|&s| s >= air.num_public_values()) {
        return Err(ProofError::Proving);
    }
    check_config(shape)?;
    let ushape = uni_shape(child, child_log_height);
    let child_key = uni_key_digest(air, &ushape);
    let mut c = Circuit::new();
    let zeros = [F::ZERO; LAYER_PUBLICS];
    batch_circuit(&mut c, air, &ushape, binding_slots, &child_key, capacity, &zeros, None);
    let max_log = tables::max_log_height(&shape.fri());
    let airs = tables::table_airs_within(&c, &shape.fri(), max_log)?;
    let circuit = tables::setup(airs, &shape.fri())?;
    Ok(LayerKey {
        kind: LayerKind::Batch,
        shape,
        capacity,
        child_key,
        circuit,
        leaf: Some((child, child_log_height)),
        max_log,
    })
}

/// The public values of a batch under `binding` whose children have
/// `contents`, in order, from `start`.
pub(crate) fn batch_publics(binding: &Binding, start: &NativeDigest, contents: &[Vec<F>]) -> Vec<F> {
    let end = native_running_digest(start, contents);
    layer_publics(&binding.elements(), start, &end, contents.len()).to_vec()
}

/// Prove a batch of uni-STARK children under `tag`. Refuses a child of
/// another shape, and, unless `unchecked`, a circuit some child breaks
/// (a child of another chain or version among them); `unchecked` proves it
/// anyway, for tests that the proof is then refused.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_batch_of<A>(
    key: &LayerKey,
    air: &A,
    binding_slots: &[usize; BINDING_ELEMS],
    tag: &LayerTag,
    start: &NativeDigest,
    children: &[(Vec<u8>, Vec<F>)],
    zk_seed: [u8; 32],
    unchecked: bool,
) -> Result<Vec<u8>, ProofError>
where
    A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
{
    let Some((child, child_log_height)) = key.leaf else {
        return Err(ProofError::Proving);
    };
    if children.is_empty() || children.len() > key.capacity || key.kind != LayerKind::Batch {
        return Err(ProofError::Proving);
    }
    let ushape = uni_shape(child, child_log_height);
    let num_chunks = 1usize << (log_quotient_chunks(air, child_log_height) + 1);
    let proofs: Vec<UniProof> = children
        .iter()
        .map(|(bytes, _)| postcard::from_bytes(bytes).map_err(|_| ProofError::MalformedProof))
        .collect::<Result<_, _>>()?;
    for (proof, (_, publics)) in proofs.iter().zip(children) {
        if !uni_shape_ok(air, &ushape, proof, num_chunks) || publics.len() != air.num_public_values() {
            return Err(ProofError::MalformedProof);
        }
    }
    let kids: Vec<UniChild<'_>> = proofs
        .iter()
        .zip(children)
        .map(|(proof, (_, publics))| UniChild { proof, publics })
        .collect();
    let contents: Vec<Vec<F>> = children.iter().map(|(_, p)| p.clone()).collect();
    let publics = batch_publics(&Binding::of_tag(tag), start, &contents);
    let publics: [F; LAYER_PUBLICS] = core::array::from_fn(|i| publics[i]);
    let mut c = Circuit::new();
    batch_circuit(
        &mut c,
        air,
        &ushape,
        binding_slots,
        &key.child_key,
        key.capacity,
        &publics,
        Some(&kids),
    );
    finish(key, &c, tag, zk_seed, unchecked)
}

/// The key of a layer of `kind` (a root over batches, or a shrink over one
/// root) with `capacity` children of `child`'s key, proven at `shape`, its
/// tables no taller than `2^max_log` (the field's limit, or less).
pub(crate) fn layer_key_of(
    child: &LayerKey,
    kind: LayerKind,
    capacity: usize,
    shape: LayerShape,
    max_log: usize,
) -> Result<LayerKey, ProofError> {
    let fits = match kind {
        LayerKind::Root => child.kind == LayerKind::Batch && capacity > 0,
        LayerKind::Shrink => child.kind == LayerKind::Root && capacity == 1,
        // A batch of chunk proofs; a batch of uni-STARK children has its own
        // key ([`batch_key_of`]).
        LayerKind::Batch => child.kind == LayerKind::Chunk && capacity > 0,
        LayerKind::Chunk => false,
    };
    if !fits {
        return Err(ProofError::Proving);
    }
    check_config(shape)?;
    let spec = child.spec();
    let cons = table_constraints(&spec);
    let mut c = Circuit::new();
    layer_circuit(&mut c, &spec, &cons, capacity, &[F::ZERO; LAYER_PUBLICS], None);
    let max_log = max_log.min(tables::max_log_height(&shape.fri()));
    let airs = tables::table_airs_within(&c, &shape.fri(), max_log)?;
    let circuit = tables::setup(airs, &shape.fri())?;
    Ok(LayerKey {
        kind,
        shape,
        capacity,
        child_key: spec.key_digest,
        circuit,
        leaf: None,
        max_log,
    })
}

/// Prove a root or a shrink over `children`, each a proof of `child`'s key
/// with its claim, in order, under `tag`. The layer claims from the first
/// child's start to the last one's end. Refuses a child of another shape,
/// and, unless `unchecked`, a circuit some child breaks (one that does not
/// verify, or does not start where the one before it ended).
pub(crate) fn prove_layer_of(
    key: &LayerKey,
    child: &LayerKey,
    tag: &LayerTag,
    children: &[(Vec<u8>, Claim)],
    zk_seed: [u8; 32],
    unchecked: bool,
) -> Result<Vec<u8>, ProofError> {
    let layer_children = match key.kind {
        LayerKind::Batch => child.kind == LayerKind::Chunk,
        LayerKind::Root | LayerKind::Shrink => true,
        LayerKind::Chunk => false,
    };
    if !layer_children
        || key.child_key != child.native_digest()
        || children.is_empty()
        || children.len() > key.capacity
    {
        return Err(ProofError::Proving);
    }
    let spec = child.spec();
    let cons = table_constraints(&spec);
    let proofs: Vec<LayerProof> = children
        .iter()
        .map(|(bytes, _)| postcard::from_bytes(bytes).map_err(|_| ProofError::MalformedProof))
        .collect::<Result<_, _>>()?;
    if !proofs.iter().all(|p| layer_shape_ok(&spec, &cons, p)) {
        return Err(ProofError::MalformedProof);
    }
    let binding = Binding::of_tag(tag);
    let child_publics: Vec<[F; LAYER_PUBLICS]> = children.iter().map(|(_, claim)| claim.publics(&binding)).collect();
    let claims: Vec<Claim> = children.iter().map(|(_, claim)| *claim).collect();
    let claim = Claim::joined(&claims).ok_or(ProofError::Proving)?;
    let kids: Vec<LayerChild<'_>> = proofs
        .iter()
        .zip(&child_publics)
        .enumerate()
        .map(|(i, (proof, publics))| LayerChild {
            proof,
            index: i as u32,
            publics,
        })
        .collect();
    let mut c = Circuit::new();
    layer_circuit(&mut c, &spec, &cons, key.capacity, &claim.publics(&binding), Some(&kids));
    finish(key, &c, tag, zk_seed, unchecked)
}

/// The public values of a layer under `binding` claiming `claim`.
pub(crate) fn claim_publics(binding: &Binding, claim: &Claim) -> Vec<F> {
    claim.publics(binding).to_vec()
}

/// Check the circuit holds (unless `unchecked`), then prove its tables
/// under `tag`.
pub(crate) fn finish(
    key: &LayerKey,
    c: &Circuit,
    tag: &LayerTag,
    zk_seed: [u8; 32],
    unchecked: bool,
) -> Result<Vec<u8>, ProofError> {
    if c.failure().is_some() && !unchecked {
        return Err(ProofError::Rejected);
    }
    let airs = tables::table_airs_within(c, &key.shape.fri(), key.max_log)?;
    let same =airs.len() == key.circuit.airs.len()
        && airs
            .iter()
            .zip(&key.circuit.airs)
            .all(|(a, b)| a.height() == b.height() && a.lanes() == b.lanes());
    if !same {
        return Err(ProofError::Proving);
    }
    let proof = tables::prove(&key.circuit, c, &key.shape.fri(), &tag.elements(), zk_seed)?;
    postcard::to_allocvec(&proof).map_err(|_| ProofError::Proving)
}

/// Verify a layer proof against its key, tag and public values.
pub(crate) fn verify_layer(key: &LayerKey, tag: &LayerTag, publics: &[F], proof: &[u8]) -> Result<(), ProofError> {
    let proof: LayerProof = postcard::from_bytes(proof).map_err(|_| ProofError::MalformedProof)?;
    tables::verify(
        &key.circuit.airs,
        key.circuit.common(),
        &proof,
        publics,
        &key.shape.fri(),
        &tag.elements(),
    )
}

/// A layer known by its tables' entries alone, at `shape`: its lanes and
/// heights as a key would plan them, the lookups the library derives for
/// them, and no commitment. Enough to build the circuit of the layer above
/// it, row for row, without proving anything.
pub(crate) fn shape_spec(
    kind: LayerKind,
    shape: LayerShape,
    rows: [usize; 5],
    num_publics: usize,
) -> Result<LayerSpec, ProofError> {
    shape_spec_within(kind, shape, rows, num_publics, tables::max_log_height(&shape.fri()))
}

/// [`shape_spec`] with every table no taller than `2^max_log`.
pub(crate) fn shape_spec_within(
    kind: LayerKind,
    shape: LayerShape,
    rows: [usize; 5],
    num_publics: usize,
    max_log: usize,
) -> Result<LayerSpec, ProofError> {
    let fri = shape.fri();
    let plans = tables::plan(rows, &fri, max_log.min(tables::max_log_height(&fri)))?;
    let airs: Vec<TableAir> = TABLES
        .into_iter()
        .zip(plans)
        .map(|(t, (lanes, height))| TableAir::shape(t, num_publics, lanes, height))
        .collect();
    let lookups = tables::lookups_for(&airs, &fri)?;
    let zero = [F::ZERO; DIGEST];
    let tables: Vec<(usize, usize)> = plans.to_vec();
    let key_digest = native_hash(&key_words(kind, shape, num_publics, &tables, &zero, &zero));
    Ok(LayerSpec {
        kind,
        shape,
        airs,
        lookups,
        commitment: zero,
        child_key: zero,
        key_digest,
    })
}

/// The entries of each table of a batch circuit of `capacity` children.
pub(crate) fn batch_rows<A>(
    air: &A,
    binding_slots: &[usize; BINDING_ELEMS],
    child: LayerShape,
    child_log_height: usize,
    capacity: usize,
) -> [usize; 5]
where
    A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
{
    let ushape = uni_shape(child, child_log_height);
    let mut c = Circuit::new();
    let zeros = [F::ZERO; LAYER_PUBLICS];
    batch_circuit(&mut c, air, &ushape, binding_slots, &[F::ZERO; DIGEST], capacity, &zeros, None);
    tables::table_rows(&c)
}

/// The entries of each table of a layer circuit of `capacity` children of
/// `child`.
pub(crate) fn layer_rows(child: &LayerSpec, cons: &[TableConstraints], capacity: usize) -> [usize; 5] {
    let mut c = Circuit::new();
    layer_circuit(&mut c, child, cons, capacity, &[F::ZERO; LAYER_PUBLICS], None);
    tables::table_rows(&c)
}

/// The entries of each table at `capacity` slots, from circuits of one, two
/// and three slots: every slot past the first adds the same rows, and at
/// most one new constant (its index), counted for each slot.
pub(crate) fn extrapolate(mut rows: impl FnMut(usize) -> [usize; 5], capacity: usize) -> [usize; 5] {
    if capacity <= 3 {
        return rows(capacity);
    }
    let (r1, r2, r3) = (rows(1), rows(2), rows(3));
    core::array::from_fn(|t| {
        let step = (r2[t] - r1[t]).max(r3[t] - r2[t]);
        let margin = if t == 0 { capacity } else { 0 };
        r1[t] + (capacity - 1) * step + margin
    })
}

/// An upper bound on the bytes of a layer proof with these tables, lookups
/// and constraints at `shape`, as the library serializes it: every opened
/// value, every hiding opening, every input row with its salt, every
/// Merkle sibling a pruned multiproof can hold (at most one a node pair
/// level by level, and at most one a query), every folding step, every
/// commitment, and every length as the varint postcard writes for it.
pub(crate) fn proof_bytes_bound(
    airs: &[TableAir],
    lookups: &[p3_lookup::Lookups<F>],
    cons: &[TableConstraints],
    shape: LayerShape,
) -> usize {
    const FE: usize = 4;
    const EF: usize = 32;
    const DIG: usize = 4 * DIGEST;
    // A length (or a degree) as a varint: seven bits a byte.
    let len = |n: usize| -> usize { (usize::BITS as usize - n.leading_zeros() as usize).div_ceil(7).max(1) };
    let cap = len(1) + DIG;
    let salt = crate::scale::SCALE_SALT_ELEMS;
    let hiding = crate::scale::SCALE_RANDOM_CODEWORDS;
    let q = shape.num_queries;
    let siblings = |depth: usize| -> usize { (0..depth).map(|k| q.min(1usize << k.min(40))).sum() };

    struct Mat {
        log_lde: usize,
        width: usize,
        points: usize,
        hiding: usize,
    }
    let n = airs.len();
    let log_ext: Vec<usize> = airs.iter().map(|a| a.height().trailing_zeros() as usize + 1).collect();
    let aux: Vec<usize> = lookups.iter().map(|l| if l.is_empty() { 0 } else { (l.len() + 1) * 8 }).collect();
    let chunks: Vec<usize> = cons.iter().map(|c| 1usize << (c.log_chunks + 1)).collect();
    let mat = |i: usize, width: usize, points: usize, hiding: usize| Mat {
        log_lde: log_ext[i] + shape.log_blowup,
        width,
        points,
        hiding,
    };
    let rounds: Vec<Vec<Mat>> = alloc::vec![
        (0..n).map(|i| mat(i, 8, 1, hiding)).collect(),
        (0..n)
            .map(|i| mat(i, BaseAir::<F>::width(&airs[i]), 1 + usize::from(airs[i].reads_next()), hiding))
            .collect(),
        (0..n)
            .flat_map(|i| (0..chunks[i]).map(move |_| i))
            .map(|i| mat(i, 8, 1, hiding))
            .collect(),
        (0..n).map(|i| mat(i, BaseAir::<F>::preprocessed_width(&airs[i]), 1, 0)).collect(),
        (0..n).filter(|&i| aux[i] > 0).map(|i| mat(i, aux[i], 2, hiding)).collect(),
    ];

    let mut bytes = 0;
    // Commitments: main, permutation, quotient, randomization.
    bytes += 4 * cap + 2;
    // Opened values at zeta (and zeta next for the permutation trace).
    bytes += len(n);
    for i in 0..n {
        let w = BaseAir::<F>::width(&airs[i]);
        let pw = BaseAir::<F>::preprocessed_width(&airs[i]);
        bytes += len(w) + w * EF + 1;
        if airs[i].reads_next() {
            bytes += len(w) + w * EF;
        }
        bytes += 1 + len(pw) + pw * EF + 1;
        bytes += len(chunks[i]) + chunks[i] * (len(8) + 8 * EF);
        bytes += 1 + len(8) + 8 * EF;
        bytes += 2 * (len(aux[i]) + aux[i] * EF);
    }
    // The hiding openings: per round, matrix and point.
    bytes += len(rounds.len());
    for round in &rounds {
        bytes += len(round.len());
        for m in round {
            bytes += len(m.points) + m.points * (len(m.hiding) + m.hiding * EF);
        }
    }
    // FRI: the input openings of every round, with salts and paths.
    let log_max = rounds.iter().flatten().map(|m| m.log_lde).max().unwrap_or(0);
    let num_folds = log_max.saturating_sub(shape.log_blowup);
    bytes += FE + len(num_folds) + num_folds * cap + len(num_folds) + num_folds * FE;
    bytes += len(rounds.len());
    for round in &rounds {
        let depth = round.iter().map(|m| m.log_lde).max().unwrap_or(0);
        let rows: usize = round.iter().map(|m| len(m.width + m.hiding) + (m.width + m.hiding) * FE).sum();
        bytes += len(q) + q * (len(round.len()) + rows);
        bytes += len(q) + q * (len(round.len()) + round.len() * (len(salt) + salt * FE));
        bytes += len(siblings(depth)) + siblings(depth) * DIG;
    }
    // FRI: the folding steps, each a sibling a query, its salt and paths.
    bytes += len(num_folds);
    for r in 0..num_folds {
        let depth = log_max - r - 1;
        bytes += len(q) + q * (len(1) + EF);
        bytes += len(q) + q * (len(1) + len(salt) + salt * FE);
        bytes += len(siblings(depth)) + siblings(depth) * DIG;
    }
    // The final polynomial and the query grinding witness.
    bytes += len(1) + EF + FE;
    // Lookup terminals, degree bits, the two grinding witnesses.
    bytes += len(n) + n * (1 + EF) + len(n) + log_ext.iter().map(|&d| len(d)).sum::<usize>() + 1 + FE + FE;
    bytes
}

/// The height limit, from the field's own down to six levels below it, whose
/// lane plan gives a layer of `kind` with these entries at `shape` the
/// smallest proof bound: packing a tall table into lanes widens its rows
/// but shortens every Merkle path and the folding, which a shrink proof,
/// the one a block carries, is mostly made of. Ties keep the taller limit.
pub(crate) fn smallest_proof_limit(
    kind: LayerKind,
    shape: LayerShape,
    rows: [usize; 5],
    num_publics: usize,
) -> Result<(usize, usize), ProofError> {
    let top = tables::max_log_height(&shape.fri());
    let mut best: Option<(usize, usize)> = None;
    for max_log in (top.saturating_sub(6)..=top).rev() {
        let Ok(spec) = shape_spec_within(kind, shape, rows, num_publics, max_log) else {
            continue;
        };
        let cons = table_constraints(&spec);
        let bound = proof_bytes_bound(&spec.airs, &spec.lookups, &cons, shape);
        if best.is_none_or(|(_, b)| bound < b) {
            best = Some((max_log, bound));
        }
    }
    best.ok_or(ProofError::Proving)
}

/// A model of the bytes a layer's prover holds at its peak: the circuit (a
/// 32-byte value a wire, a 16-byte arithmetic row, a permutation row's 24
/// inputs, outputs and values) and every committed matrix (main with its
/// hiding columns, preprocessed, permutation trace, quotient chunks,
/// randomization) over its extended domain, four bytes a cell, with a
/// Merkle tree of two digests a row beside it.
pub(crate) fn prover_bytes_model(
    airs: &[TableAir],
    lookups: &[p3_lookup::Lookups<F>],
    cons: &[TableConstraints],
    shape: LayerShape,
    entries: [usize; 5],
) -> usize {
    let hiding = crate::scale::SCALE_RANDOM_CODEWORDS;
    let circuit =
        entries[0] * 32 + entries[1] * 16 + entries[2] * (24 * 4 * 3 + 32) + entries[3] * 132 + entries[4] * 36;
    let committed: usize = airs
        .iter()
        .zip(lookups)
        .zip(cons)
        .map(|((air, l), c)| {
            let rows = air.height() << (1 + shape.log_blowup);
            let aux = if l.is_empty() { 0 } else { (l.len() + 1) * 8 };
            let chunks = 1usize << (c.log_chunks + 1);
            let cols = BaseAir::<F>::width(air)
                + hiding
                + BaseAir::<F>::preprocessed_width(air)
                + aux
                + hiding
                + chunks * (8 + hiding)
                + 8
                + hiding;
            rows * (cols * 4 + 5 * 2 * 4 * DIGEST)
        })
        .sum();
    circuit + committed
}

/// [`proof_bytes_bound`] for a key's own proofs.
pub(crate) fn key_proof_bytes_bound(key: &LayerKey) -> usize {
    let spec = key.spec();
    let cons = table_constraints(&spec);
    proof_bytes_bound(&spec.airs, &spec.lookups, &cons, key.shape)
}
