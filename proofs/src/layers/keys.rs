//! Layer keys, and proving and verifying each layer.

use alloc::vec::Vec;

use p3_air::symbolic::SymbolicAirBuilder;
use p3_air::{Air, BaseAir};
use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;

use super::bundle::{
    LayerKind, LayerTag, NativeDigest, UniChild, batch_circuit, digest_u32, native_hash, uni_key_digest,
};
use super::circuit::Circuit;
use super::pcs::DIGEST;
use super::tables::{self, CircuitKey, TableAir};
use super::verifier::{UniProof, UniShape, cap_root, log_quotient_chunks, uni_shape_ok};
use super::{F, LayerShape};
use crate::scale::ScaleConfig;
use crate::{ChainParams, ProofError, STATEMENT_VERSION_2};

/// A proof of a layer.
pub(crate) type LayerProof = BatchProof<ScaleConfig>;

/// What a bundle is bound to: the chain and the versions every layer's tag
/// names.
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
}

/// The verifier key of a layer: its circuit's tables (the preprocessed
/// commitment of the batch STARK), its shape and what its children are.
pub struct LayerKey {
    pub(crate) kind: LayerKind,
    pub(crate) shape: LayerShape,
    pub(crate) capacity: usize,
    pub(crate) child_key: NativeDigest,
    pub(crate) circuit: CircuitKey,
    pub(crate) num_publics: usize,
    /// A batch's children: their shape and log trace height.
    pub(crate) leaf: Option<(LayerShape, usize)>,
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

    /// The height of each of the layer's four tables (wires, arithmetic,
    /// permutation, bits).
    pub fn table_heights(&self) -> Vec<usize> {
        self.circuit.airs.iter().map(TableAir::height).collect()
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
    /// table heights, public value count and preprocessed commitment.
    pub fn digest(&self) -> [u32; DIGEST] {
        digest_u32(&self.native_digest())
    }

    pub(crate) fn native_digest(&self) -> NativeDigest {
        let mut words: Vec<F> = alloc::vec![
            F::from_u32(self.kind as u32),
            F::from_usize(self.shape.log_blowup),
            F::from_usize(self.shape.num_queries),
            F::from_usize(self.num_publics),
        ];
        words.extend(self.table_heights().into_iter().map(F::from_usize));
        words.extend(self.commitment());
        native_hash(&words)
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
}

/// The shape a batch fixes for its children.
fn uni_shape(child: LayerShape, log_height: usize) -> UniShape {
    UniShape {
        fri: child.fri(),
        log_height,
    }
}

/// The key of a batch of `capacity` children of `air`, each proven at
/// `child` over `2^child_log_height` rows, the batch proven at `shape`.
pub(crate) fn batch_key_of<A>(
    air: &A,
    child: LayerShape,
    child_log_height: usize,
    capacity: usize,
    shape: LayerShape,
) -> Result<LayerKey, ProofError>
where
    A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
{
    if capacity == 0 {
        return Err(ProofError::Proving);
    }
    let ushape = uni_shape(child, child_log_height);
    let mut c = Circuit::new();
    batch_circuit(&mut c, air, &ushape, capacity, &[F::ZERO; DIGEST], None);
    let airs = tables::table_airs(&c, &shape.fri());
    let num_publics = c.publics().len();
    let circuit = tables::setup(airs, &shape.fri())?;
    Ok(LayerKey {
        kind: LayerKind::Batch,
        shape,
        capacity,
        child_key: uni_key_digest(air, &ushape),
        circuit,
        num_publics,
        leaf: Some((child, child_log_height)),
    })
}

/// The public values of a batch: the starting and ending digests and the
/// count.
pub(crate) fn batch_publics(start: &NativeDigest, contents: &[Vec<F>]) -> Vec<F> {
    let end = super::bundle::native_running_digest(start, contents);
    let mut out = start.to_vec();
    out.extend(end);
    out.push(F::from_usize(contents.len()));
    out
}

/// Prove a batch of uni-STARK children. Refuses a child of another shape,
/// and, unless `unchecked`, a circuit some child breaks; `unchecked` proves
/// it anyway, for tests that the proof is then refused.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_batch_of<A>(
    key: &LayerKey,
    air: &A,
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
    let mut c = Circuit::new();
    batch_circuit(&mut c, air, &ushape, key.capacity, start, Some(&kids));
    finish(key, &c, tag, zk_seed, unchecked)
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
    if tables::table_airs(c, &key.shape.fri()).iter().map(TableAir::height).collect::<Vec<_>>() != key.table_heights() {
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
