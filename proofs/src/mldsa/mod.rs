//! Public signatures of the scale build (stage 2 design, "Public signature
//! size"): ML-DSA-44 verifications (FIPS 204) proven in chunks, and the chunk
//! proofs folded by the batch, root and shrink layers of [`crate::layers`]
//! into one public root proof.
//!
//! A chunk is a batch STARK of the five layer tables (wires, arithmetic,
//! Poseidon2 permutation, bits, packing) and ten ML-DSA tables
//! ([`tables`]): Keccak-f\[1600\] rounds of the pinned `p3_keccak_air` AIR
//! for SHAKE-128 and SHAKE-256, and arithmetic modulo 8,380,417 over BabyBear
//! in limbs. The tables are laid out for the batch layer that verifies a
//! chunk proof: no wide table reads its next row, and values cross rows
//! through wires and packed wires. Its public values are a layer's: the
//! binding, the running digest (Poseidon2) of its transactions' public values
//! before and after, and their count. Each transaction's public values are its account (20 bytes), its
//! key identity (the first 32 bytes of `SHAKE256(pk, 64)`) and its message
//! (the transaction hash), a byte a value, in block order.
//!
//! A batch of chunk proofs is a layer over chunk keys
//! ([`chunk_batch_key`]); roots and shrinks over it are the layers' own
//! ([`crate::layers::root_key`], [`crate::layers::shrink_key`]).

pub(crate) mod chunk;
pub mod native;
pub(crate) mod tables;

use alloc::vec::Vec;

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

use crate::ProofError;
use crate::layers::bundle::{LAYER_PUBLICS, LayerKind};
use crate::layers::circuit::Circuit;
use crate::layers::keys::{self, Binding, Claim, LayerKey};
use crate::layers::{Digest, F, LayerShape};

/// The context every transaction signature is made under (FIPS 204,
/// `ML-DSA.Sign` with `ctx`).
pub const TX_CONTEXT: &[u8] = b"ghost/tx/v1";
/// Bytes of an account.
pub const ACCOUNT_BYTES: usize = 20;
/// Bytes of a key identity.
pub const KEY_ID_BYTES: usize = 32;
/// Bytes of a transaction hash, the message a transaction signs.
pub const TX_HASH_BYTES: usize = 32;
/// Verifications a chunk of the design proves.
pub const DESIGN_CHUNK: usize = 32;

/// A transaction's public values: account, key identity, message, a byte a
/// value.
pub(crate) fn tx_content(account: &[u8; ACCOUNT_BYTES], key_id: &[u8; KEY_ID_BYTES], message: &[u8]) -> Vec<F> {
    account.iter().chain(key_id).chain(message).map(|&b| F::from_u8(b)).collect()
}

/// A signed transaction as a chunk sees it: who it is from, the key and
/// signature, and the message signed (its hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    pub account: [u8; ACCOUNT_BYTES],
    pub key_id: [u8; KEY_ID_BYTES],
    pub message: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedTx {
    /// A transaction from `account` under `public_key`, with the key's own
    /// identity.
    pub fn new(account: [u8; ACCOUNT_BYTES], public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> Self {
        let key_id = public_key
            .as_slice()
            .try_into()
            .map(native::key_identity)
            .unwrap_or([0; KEY_ID_BYTES]);
        Self {
            account,
            key_id,
            message,
            public_key,
            signature,
        }
    }

    /// The public values a chunk carries for it, in its running digest.
    pub fn public_values(&self) -> Vec<BabyBear> {
        tx_content(&self.account, &self.key_id, &self.message)
    }

    /// Whether the signature verifies natively (FIPS 204, `ML-DSA.Verify`
    /// under [`TX_CONTEXT`]) and the key identity is the key's.
    pub fn verifies(&self) -> bool {
        self.witness().is_some_and(|(w, ok)| ok && w.key_id == self.key_id)
    }

    /// The slot witness, and whether every check of the verification holds.
    /// `None` when the key or signature has the wrong length or does not
    /// decode.
    fn witness(&self) -> Option<(chunk::SlotWitness, bool)> {
        let pk: &[u8; native::PUBLIC_KEY_BYTES] = self.public_key.as_slice().try_into().ok()?;
        let sig: &[u8; native::SIGNATURE_BYTES] = self.signature.as_slice().try_into().ok()?;
        let (v, refusal) = native::compute(pk, &self.message, sig, TX_CONTEXT).ok()?;
        let ok = refusal.is_none() && native::key_identity(pk) == self.key_id;
        let w = chunk::SlotWitness {
            account: self.account,
            key_id: self.key_id,
            message: self.message.clone(),
            pk: *pk,
            c_tilde: v.sig.c_tilde,
            z: v.sig.z,
            h: v.sig.h,
            w_approx: v.w_approx,
        };
        Some((w, ok))
    }
}

/// The verifier key of a chunk: its circuit's tables, its slots and the
/// message length every slot signs.
pub struct ChunkKey {
    key: LayerKey,
    message_len: usize,
}

impl ChunkKey {
    /// The layer key a batch of chunks fixes ([`chunk_batch_key`]).
    pub fn layer_key(&self) -> &LayerKey {
        &self.key
    }

    /// Verifications a chunk proves.
    pub fn slots(&self) -> usize {
        self.key.capacity
    }

    pub fn message_len(&self) -> usize {
        self.message_len
    }

    /// The height of each table: the five layer tables, then the ten
    /// ML-DSA tables (keccak, xor, butterfly, mac, expand, ball step, ball
    /// position, t1, z, hint).
    pub fn table_heights(&self) -> Vec<usize> {
        self.key.table_heights()
    }

    /// A model of the bytes the chunk's prover holds at its peak: every
    /// committed matrix over its extended domain with its Merkle tree
    /// ([`crate::layers::modeled_prover_bytes`]'s model, the circuit left
    /// out).
    pub fn modeled_prover_bytes(&self) -> usize {
        let spec = self.key.spec();
        let cons = crate::layers::verifier::table_constraints(&spec);
        keys::prover_bytes_model(&spec.airs, &spec.lookups, &cons, self.key.shape, [0; 5])
    }

    /// An upper bound on the bytes of a chunk proof.
    pub fn proof_size_bound(&self) -> usize {
        keys::key_proof_bytes_bound(&self.key)
    }
}

fn blank_circuit(slots: usize, message_len: usize) -> Circuit {
    let mut c = Circuit::new();
    let blank = alloc::vec![chunk::SlotWitness::blank(message_len); slots];
    chunk::chunk_circuit(&mut c, &[F::ZERO; LAYER_PUBLICS], &blank, slots);
    c
}

/// The key of a chunk of `slots` verifications of messages of
/// `message_len` bytes, proven at `shape`.
pub fn chunk_key(slots: usize, message_len: usize, shape: LayerShape) -> Result<ChunkKey, ProofError> {
    chunk_key_for(slots, message_len, shape, keys::KeyUse::Prove)
}

/// [`chunk_key`] built for `key_use`.
fn chunk_key_for(
    slots: usize,
    message_len: usize,
    shape: LayerShape,
    key_use: keys::KeyUse,
) -> Result<ChunkKey, ProofError> {
    if slots == 0 {
        return Err(ProofError::Proving);
    }
    keys::check_config(shape)?;
    let max_log = shape.max_log_height();
    let circuit = keys::circuit_key(blank_circuit(slots, message_len), shape, max_log, true, key_use)?;
    Ok(ChunkKey {
        key: LayerKey {
            kind: LayerKind::Chunk,
            shape,
            capacity: slots,
            child_key: [F::ZERO; crate::layers::pcs::DIGEST],
            circuit,
            leaf: None,
            max_log,
        },
        message_len,
    })
}

fn prove_chunk_of(
    key: &ChunkKey,
    binding: &Binding,
    index: u32,
    start: &Digest,
    txs: &[SignedTx],
    zk_seed: [u8; 32],
    unchecked: bool,
) -> Result<Vec<u8>, ProofError> {
    if txs.is_empty() || txs.len() > key.slots() || txs.iter().any(|t| t.message.len() != key.message_len) {
        return Err(ProofError::Proving);
    }
    let mut slots = Vec::with_capacity(key.slots());
    for tx in txs {
        let (w, ok) = tx.witness().ok_or(ProofError::Rejected)?;
        if !ok && !unchecked {
            return Err(ProofError::Rejected);
        }
        slots.push(w);
    }
    while slots.len() < key.slots() {
        let last = slots.last().expect("one slot").clone();
        slots.push(last);
    }
    let contents: Vec<Vec<F>> = txs.iter().map(SignedTx::public_values).collect();
    let claim = Claim::of(start, &contents);
    let publics = keys::claim_publics(binding, &claim);
    let publics: [F; LAYER_PUBLICS] = core::array::from_fn(|i| publics[i]);
    let mut c = Circuit::new();
    chunk::chunk_circuit(&mut c, &publics, &slots, txs.len());
    if c.failure().is_some() && !unchecked {
        return Err(ProofError::Rejected);
    }
    let fri = key.key.shape.fri();
    let airs = crate::layers::tables::table_airs_with_ml(&c, &fri, key.key.max_log)?;
    let same = airs.len() == key.key.circuit.airs.len()
        && airs
            .iter()
            .zip(&key.key.circuit.airs)
            .all(|(a, b)| a.height() == b.height() && a.lanes() == b.lanes());
    if !same {
        return Err(ProofError::Proving);
    }
    let tag = key.key.tag(binding, index);
    let proof = crate::layers::tables::prove(&key.key.circuit, &c, &fri, &tag.elements(), zk_seed)?;
    postcard::to_allocvec(&proof).map_err(|_| ProofError::Proving)
}

/// Prove a chunk of `txs` (at most the key's slots, in block order) at
/// position `index` under `binding`, its running digest from `start`.
/// Refuses a transaction whose signature does not verify, or whose key
/// identity is not its key's.
pub fn prove_chunk(
    key: &ChunkKey,
    binding: &Binding,
    index: u32,
    start: &Digest,
    txs: &[SignedTx],
    zk_seed: [u8; 32],
) -> Result<Vec<u8>, ProofError> {
    prove_chunk_of(key, binding, index, start, txs, zk_seed, false)
}

/// [`prove_chunk`] that proves the circuit even when a verification breaks
/// it: for tests that such a proof is refused.
#[doc(hidden)]
pub fn prove_chunk_unchecked(
    key: &ChunkKey,
    binding: &Binding,
    index: u32,
    start: &Digest,
    txs: &[SignedTx],
    zk_seed: [u8; 32],
) -> Result<Vec<u8>, ProofError> {
    prove_chunk_of(key, binding, index, start, txs, zk_seed, true)
}

/// The claim of a chunk (or of any layer) over transactions with these
/// public values, in order, from `start`.
pub fn claim_of(start: &Digest, txs: &[Vec<BabyBear>]) -> Claim {
    Claim::of(start, txs)
}

/// Verify a chunk proof at position `index` under `binding` against the
/// public values of its transactions, in order, from `start`.
pub fn verify_chunk(
    key: &ChunkKey,
    binding: &Binding,
    index: u32,
    start: &Digest,
    txs: &[Vec<BabyBear>],
    proof: &[u8],
) -> Result<(), ProofError> {
    if txs.is_empty() || txs.len() > key.slots() {
        return Err(ProofError::Rejected);
    }
    let claim = Claim::of(start, txs);
    keys::verify_layer(&key.key, &key.key.tag(binding, index), &keys::claim_publics(binding, &claim), proof)
}

/// The key of a batch over up to `capacity` chunk proofs of `chunk`'s key,
/// proven at `shape`: prove it with [`crate::layers::prove_layer`] (the chunk
/// key's [`ChunkKey::layer_key`] as the child), verify it with
/// [`crate::layers::verify_batch`] over every transaction's public values.
pub fn chunk_batch_key(chunk: &ChunkKey, capacity: usize, shape: LayerShape) -> Result<LayerKey, ProofError> {
    chunk_batch_key_for(chunk, capacity, shape, keys::KeyUse::Prove)
}

/// [`chunk_batch_key`] built for `key_use`.
fn chunk_batch_key_for(
    chunk: &ChunkKey,
    capacity: usize,
    shape: LayerShape,
    key_use: keys::KeyUse,
) -> Result<LayerKey, ProofError> {
    keys::layer_key_of(&chunk.key, LayerKind::Batch, capacity, shape, shape.max_log_height(), key_use)
}

/// The entries a batch circuit over `capacity` chunk proofs of `chunk`'s key
/// fills (wires, arithmetic rows, permutation rows, bits rows, packing rows),
/// counted by building it without proving: what the batch's tables and its
/// prover's memory follow from.
pub fn batch_entries(chunk: &ChunkKey, capacity: usize) -> [usize; 5] {
    let spec = chunk.key.spec();
    let cons = crate::layers::verifier::table_constraints(&spec);
    keys::layer_rows(&spec, &cons, capacity)
}

/// Chunk proofs a production batch of the public root verifies: the stage 2
/// design folds the chunks by the private bundles' layers, whose batches
/// take the same slots ([`crate::layers::REVEALS_PER_BATCH`]).
pub const DESIGN_CHUNKS_PER_BATCH: usize = crate::layers::REVEALS_PER_BATCH;
/// Batches a production public root verifies: the private bundles' root
/// ([`crate::layers::BATCHES_PER_ROOT`]).
pub const DESIGN_BATCHES_PER_ROOT: usize = crate::layers::BATCHES_PER_ROOT;

/// The entries of a blank chunk of `slots` verifications: the five layer
/// tables' and the ten ML-DSA tables'.
fn chunk_entries(slots: usize, message_len: usize) -> ([usize; 5], Vec<usize>) {
    let c = blank_circuit(slots, message_len);
    let ml = tables::ML_TABLES.iter().map(|&t| c.ml.entries(t)).collect();
    (crate::layers::tables::table_rows(&c), ml)
}

/// The tables of a chunk of `slots` verifications at `shape` as
/// [`chunk_key`] lays them out, from its entries counted for one, two and
/// three slots (every slot past the first adds the same rows), with its blank
/// circuit's entries in the five layer tables and the bytes of its ML-DSA
/// rows beside them (modeled: one main-trace row an entry).
fn chunk_spec(
    slots: usize,
    message_len: usize,
    shape: LayerShape,
) -> Result<(crate::layers::verifier::LayerSpec, [usize; 5], usize), ProofError> {
    use crate::layers::tables::{self as lt, TABLES, Table, TableAir};
    let base = keys::extrapolate(|n| chunk_entries(n, message_len).0, slots);
    let ml: Vec<usize> = if slots <= 3 {
        chunk_entries(slots, message_len).1
    } else {
        let (r1, r2, r3) =
            (chunk_entries(1, message_len).1, chunk_entries(2, message_len).1, chunk_entries(3, message_len).1);
        (0..r1.len())
            .map(|t| r1[t] + (slots - 1) * (r2[t] - r1[t]).max(r3[t] - r2[t]))
            .collect()
    };
    let fri = shape.fri();
    let max_log = shape.max_log_height();
    let mut airs: Vec<TableAir> = TABLES
        .into_iter()
        .zip(lt::plan(base, &fri, max_log)?)
        .map(|(t, (lanes, height))| TableAir::shape(t, LAYER_PUBLICS, lanes, height))
        .collect();
    for (&t, &n) in tables::ML_TABLES.iter().zip(&ml) {
        let height = n.next_power_of_two().max(lt::min_height(&fri));
        if height.trailing_zeros() as usize > max_log {
            return Err(ProofError::Proving);
        }
        airs.push(TableAir::shape(Table::Ml(t), LAYER_PUBLICS, 1, height));
    }
    let ml_bytes = tables::ML_TABLES.iter().zip(&ml).map(|(&t, &n)| n * tables::main_width(t) * 4).sum::<usize>();
    Ok((keys::airs_spec(LayerKind::Chunk, shape, airs)?, base, ml_bytes))
}

/// The entries (wires, arithmetic rows, permutation rows, bits rows, packing
/// rows) a batch circuit over `capacity` chunk proofs of the design's chunk
/// (a chunk of [`DESIGN_CHUNK`] verifications of [`TX_HASH_BYTES`]-byte
/// messages at [`LayerShape::WIDE`]) fills, planned from the chunk's tables
/// without building its key: what decides whether the batch's tables fit.
pub fn design_batch_entries(capacity: usize) -> Result<[usize; 5], ProofError> {
    let (chunk, _, _) = chunk_spec(DESIGN_CHUNK, TX_HASH_BYTES, LayerShape::WIDE)?;
    let cons = crate::layers::verifier::table_constraints(&chunk);
    Ok(keys::extrapolate(|n| keys::layer_rows(&chunk, &cons, n), capacity))
}

/// The plan of [`production_public_root_key`]: a chunk of [`DESIGN_CHUNK`]
/// ML-DSA-44 verifications of [`TX_HASH_BYTES`]-byte messages, a batch of
/// [`DESIGN_CHUNKS_PER_BATCH`] chunks and a root of
/// [`DESIGN_BATCHES_PER_ROOT`] batches, all at [`LayerShape::WIDE`], and the
/// root's shrink at [`LayerShape::SHRINK`].
pub fn public_root_key_plan() -> Result<crate::layers::KeyPlan, ProofError> {
    public_root_key_plan_of(DESIGN_CHUNKS_PER_BATCH, DESIGN_BATCHES_PER_ROOT)
}

/// [`public_root_key_plan`] with `chunks_per_batch` chunks a batch and
/// `batches_per_root` batches a root, the chunk and the shapes unchanged.
pub fn public_root_key_plan_of(
    chunks_per_batch: usize,
    batches_per_root: usize,
) -> Result<crate::layers::KeyPlan, ProofError> {
    use crate::layers::verifier::table_constraints;
    let wide = LayerShape::WIDE;
    let (chunk, chunk_entries, chunk_ml_bytes) = chunk_spec(DESIGN_CHUNK, TX_HASH_BYTES, wide)?;
    let chunk_cons = table_constraints(&chunk);
    let batch_entries = keys::extrapolate(|n| keys::layer_rows(&chunk, &chunk_cons, n), chunks_per_batch);
    let batch = keys::shape_spec(LayerKind::Batch, wide, batch_entries, LAYER_PUBLICS)?;
    let batch_cons = table_constraints(&batch);
    let [root, shrink] =
        crate::layers::root_and_shrink_specs(&batch, &batch_cons, batches_per_root, wide, LayerShape::SHRINK)?;
    let chunk_stage = crate::layers::KeyStage::of(&chunk, chunk_entries, chunk_ml_bytes);
    Ok(crate::layers::KeyPlan::of(alloc::vec![chunk_stage], &[(batch, batch_cons, batch_entries), root, shrink]))
}

/// The production public root key: the shrink key of the stage 2 design's
/// real block shape, derived from the circuits alone, deterministically, as
/// [`public_root_key_plan`] plans it. Each key is built for verifying alone
/// (`keys::KeyUse::Verify`), with the commitment the prover's key has, and
/// the key below it is dropped once it is made. Nothing is proven. A shape
/// whose tables do not lay out is refused by its plan before anything is
/// built.
pub fn production_public_root_key() -> Result<LayerKey, ProofError> {
    public_root_key_plan()?;
    let wide = LayerShape::WIDE;
    let verify = keys::KeyUse::Verify;
    let chunk = chunk_key_for(DESIGN_CHUNK, TX_HASH_BYTES, wide, verify)?;
    let batch = chunk_batch_key_for(&chunk, DESIGN_CHUNKS_PER_BATCH, wide, verify)?;
    drop(chunk);
    let root = crate::layers::root_key_for(&batch, DESIGN_BATCHES_PER_ROOT, wide, verify)?;
    drop(batch);
    crate::layers::shrink_key_for(&root, LayerShape::SHRINK, verify)
}

/// What one verification costs in the chunk circuit, counted from the built
/// tables: the difference between circuits of two slots and of one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationCost {
    /// Keccak-f\[1600\] permutations.
    pub permutations: usize,
    /// Rows a verification fills in each of the fifteen tables.
    pub rows: Vec<usize>,
    /// Main-trace cells: rows times each table's main width (one lane).
    pub cells: usize,
}

/// The cost of one verification of a `message_len`-byte message.
pub fn verification_cost(message_len: usize) -> VerificationCost {
    let one = blank_circuit(1, message_len);
    let two = blank_circuit(2, message_len);
    let entries = |c: &Circuit| -> Vec<usize> {
        let base = crate::layers::tables::table_rows(c);
        let mut out: Vec<usize> = base.to_vec();
        out.extend(tables::ML_TABLES.iter().map(|&t| c.ml.entries(t)));
        out
    };
    let (e1, e2) = (entries(&one), entries(&two));
    let rows: Vec<usize> = e1.iter().zip(&e2).map(|(a, b)| b - a).collect();
    let widths: Vec<usize> = crate::layers::tables::TABLES
        .iter()
        .map(|&t| crate::layers::tables::main_width(t, 1))
        .chain(tables::ML_TABLES.iter().map(|&t| tables::main_width(t)))
        .collect();
    let cells = rows.iter().zip(&widths).map(|(r, w)| r * w).sum();
    VerificationCost {
        permutations: two.ml.keccak.len() - one.ml.keccak.len(),
        rows,
        cells,
    }
}
