//! A C interface to the coin reveal verifiers and the root proof verifiers,
//! so a node written in another language links the same
//! [`verify_salted_coin_reveal`] and [`verify_coin_reveal_v2`] the provers
//! are checked against, and the same verifier of the recursion layers' shrink
//! (see "Root proofs" below).
//!
//! [`ghost_verify_coin_reveal`] takes the chain parameters, the public
//! statement and the proof as pointer and length, and returns a status code.
//! The proof is verified as a salted (version 2) reveal of statement S1
//! version 1. [`ghost_verify_coin_reveal_v2`] does the same for the coin
//! reveal of the ordinary class, statement S1 version 2 (spec 10, section 4),
//! whose statement has no `rule` and a 380-byte note. Nothing unwinds into
//! the caller: a panic inside becomes
//! [`GHOST_PROOFS_PANICKED`], which needs the library built with the default
//! `panic = "unwind"`. Only [`GHOST_PROOFS_ACCEPTED`] accepts; every other
//! status rejects.
//!
//! The header for C is `include/ghost_proofs.h` beside this crate; the two
//! must agree on every constant below.
//!
//! **Chain parameters**, [`CHAIN_PARAMS_BYTES`] bytes: `chain_id` (8),
//! `version` (2), `domain` (32), in that order.
//!
//! **Statement**, [`COIN_REVEAL_BYTES`] bytes: `root` (32), `marker` (32),
//! `remainder` (32), `remainder_note` ([`NOTE_BYTES`]), `recipient` (20),
//! `out` (32), `fee` (32), `rule` (32), in that order.
//!
//! **Version 2 statement**, [`COIN_REVEAL_V2_BYTES`] bytes: `root` (32),
//! `marker` (32), `remainder` (32), `remainder_note` ([`NOTE_V3_BYTES`]),
//! `recipient` (20), `out` (32), `fee` (32), in that order.
//!
//! **Proof**, 1 to [`PROOF_MAX_BYTES`] bytes: one serialized proof, which may
//! be followed by zero bytes, so a zero-padded proof field can be passed as it
//! is. A non-zero byte after the serialization is malformed, so one proof has
//! one encoding.
//!
//! # Root proofs
//!
//! [`ghost_verify_bundle_root`] verifies the proof a block carries for a
//! bundle of private reveals: the shrink of the root over the bundle's batches
//! ([`crate::layers`]). [`ghost_verify_public_root`] verifies the public root
//! proof, the shrink over the ML-DSA-44 chunk proofs of the public
//! transactions ([`crate::mldsa`]). Each takes the shrink's verifier key, the
//! root inputs and the proof field, and accepts only a shrink proof at index 0
//! made under that key for exactly those inputs: their chain identifier and
//! versions, and every item's public values in order, which fix the running
//! digest from [`crate::layers::START_DIGEST`] and the count the proof claims.
//!
//! **Root key**, [`ROOT_KEY_BYTES`] bytes, 31 words of four bytes little
//! endian: the path ([`ROOT_KEY_BUNDLE`] or [`ROOT_KEY_PUBLIC`]), the
//! shrink's `log_blowup` and `num_queries`, each of its five tables' lanes and
//! height (wires, arithmetic, permutation, bits, packing), the nine elements
//! of its preprocessed commitment, the nine of its children's key digest.
//! [`root_key_to_bytes`] writes it from a built shrink key. The key of spec
//! 07's shapes is built once, where its memory is available, and the node
//! pins its bytes; the verifier only rebuilds what it reads from them, so a
//! call costs one verification, not a key build. A key of the other path is a
//! bad argument.
//!
//! **Root inputs**, [`ROOT_BINDING_BYTES`] bytes and then one or more items:
//! `chain_id` (8), `protocol_version` (2), `statement_version` (1), then the
//! items in block order, each its public values one byte a value. A bundle's
//! item is a version 2 coin reveal's public values, [`REVEAL_PUBLIC_BYTES`]
//! bytes (its 607 binding fields and its 32-byte digest, spec 10, section
//! 4.2); a public transaction's is its account, key identity and transaction
//! hash, [`PUBLIC_TX_BYTES`] bytes.
//!
//! **Root proof field**, exactly [`crate::PROOF_FIELD_BYTES`] bytes: one
//! serialized shrink proof followed by zero bytes. Any other length, a field
//! that does not decode, or a non-zero byte after the proof is malformed.

use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_air::BaseAir;
use p3_batch_stark::CommonData;
use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_merkle_tree::MerkleCap;

use crate::layers::bundle::LAYER_PUBLICS;
use crate::layers::keys::{check_config, claim_publics};
use crate::layers::pcs::DIGEST;
use crate::layers::tables::{self, TABLES, Table, TableAir};
use crate::layers::verifier::{LayerProof, cap_root};
use crate::layers::{self, Claim, F, LayerKey, LayerKind, LayerShape, LayerTag};
use crate::mldsa::{ACCOUNT_BYTES, KEY_ID_BYTES, TX_HASH_BYTES};
use crate::scale::ScaleConfig;
use crate::{
    COIN_REVEAL_V2_LAYOUT, ChainParams, CoinReveal, CoinRevealV2, NOTE_BYTES, NOTE_V3_BYTES, PROOF_FIELD_BYTES, Proof,
    ProofError, stark, verify_coin_reveal_v2, verify_salted_coin_reveal,
};

/// The proof verifies against the statement and the chain parameters.
pub const GHOST_PROOFS_ACCEPTED: i32 = 0;
/// The input is well formed and the verifier rejects it.
pub const GHOST_PROOFS_REJECTED: i32 = 1;
/// The proof is empty, too long, does not decode or has non-zero padding.
pub const GHOST_PROOFS_MALFORMED_INPUT: i32 = 2;
/// A null pointer, or parameters or a statement of the wrong length.
pub const GHOST_PROOFS_BAD_ARGUMENT: i32 = 3;
/// The verifier panicked; the panic was caught.
pub const GHOST_PROOFS_PANICKED: i32 = 4;

/// Length of the chain parameters.
pub const CHAIN_PARAMS_BYTES: usize = 8 + 2 + 32;
/// Length of the coin reveal statement.
pub const COIN_REVEAL_BYTES: usize = 32 + 32 + 32 + NOTE_BYTES + 20 + 32 + 32 + 32;
/// Length of the version 2 coin reveal statement: no `rule`, the 380-byte
/// note.
pub const COIN_REVEAL_V2_BYTES: usize = 32 + 32 + 32 + NOTE_V3_BYTES + 20 + 32 + 32;
/// The longest proof buffer accepted, 2 MiB: room above a coin reveal proof
/// (about 1.19 MB) and a bound on what one call reads.
pub const PROOF_MAX_BYTES: usize = 2 * 1024 * 1024;

/// The chain parameters in the layout of the C interface.
pub fn chain_params_to_bytes(params: &ChainParams) -> [u8; CHAIN_PARAMS_BYTES] {
    let mut out = [0u8; CHAIN_PARAMS_BYTES];
    out[..8].copy_from_slice(&params.chain_id);
    out[8..10].copy_from_slice(&params.version);
    out[10..].copy_from_slice(&params.domain);
    out
}

/// Chain parameters from the layout of the C interface.
pub fn chain_params_from_bytes(bytes: &[u8; CHAIN_PARAMS_BYTES]) -> ChainParams {
    let mut r = Reader(bytes);
    ChainParams {
        chain_id: r.take(),
        version: r.take(),
        domain: r.take(),
    }
}

/// The coin reveal statement in the layout of the C interface.
pub fn coin_reveal_to_bytes(tx: &CoinReveal) -> [u8; COIN_REVEAL_BYTES] {
    let mut out = [0u8; COIN_REVEAL_BYTES];
    let fields: [&[u8]; 8] = [
        &tx.root,
        &tx.marker,
        &tx.remainder,
        &tx.remainder_note,
        &tx.recipient,
        &tx.out,
        &tx.fee,
        &tx.rule,
    ];
    let mut at = 0;
    for field in fields {
        out[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
    out
}

/// A coin reveal statement from the layout of the C interface.
pub fn coin_reveal_from_bytes(bytes: &[u8; COIN_REVEAL_BYTES]) -> CoinReveal {
    let mut r = Reader(bytes);
    CoinReveal {
        root: r.take(),
        marker: r.take(),
        remainder: r.take(),
        remainder_note: r.take(),
        recipient: r.take(),
        out: r.take(),
        fee: r.take(),
        rule: r.take(),
    }
}

/// The version 2 coin reveal statement in the layout of the C interface.
pub fn coin_reveal_v2_to_bytes(tx: &CoinRevealV2) -> [u8; COIN_REVEAL_V2_BYTES] {
    let mut out = [0u8; COIN_REVEAL_V2_BYTES];
    let fields: [&[u8]; 7] = [
        &tx.root,
        &tx.marker,
        &tx.remainder,
        &tx.remainder_note,
        &tx.recipient,
        &tx.out,
        &tx.fee,
    ];
    let mut at = 0;
    for field in fields {
        out[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
    out
}

/// A version 2 coin reveal statement from the layout of the C interface.
pub fn coin_reveal_v2_from_bytes(bytes: &[u8; COIN_REVEAL_V2_BYTES]) -> CoinRevealV2 {
    let mut r = Reader(bytes);
    CoinRevealV2 {
        root: r.take(),
        marker: r.take(),
        remainder: r.take(),
        remainder_note: r.take(),
        recipient: r.take(),
        out: r.take(),
        fee: r.take(),
    }
}

/// Reads fixed-width fields in order from a buffer of exactly their total
/// length.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        head.try_into().expect("split_at gives N bytes")
    }
}

/// The safe core of [`ghost_verify_coin_reveal`], over slices.
pub fn verify_coin_reveal_bytes(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    catch_unwind(AssertUnwindSafe(|| verify_unguarded(params, statement, proof))).unwrap_or(GHOST_PROOFS_PANICKED)
}

fn verify_unguarded(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    verify_statement::<COIN_REVEAL_BYTES>(params, statement, proof, |params, statement, proof| {
        verify_salted_coin_reveal(params, &coin_reveal_from_bytes(statement), proof)
    })
}

/// The safe core of [`ghost_verify_coin_reveal_v2`], over slices.
pub fn verify_coin_reveal_v2_bytes(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    catch_unwind(AssertUnwindSafe(|| verify_v2_unguarded(params, statement, proof))).unwrap_or(GHOST_PROOFS_PANICKED)
}

fn verify_v2_unguarded(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    verify_statement::<COIN_REVEAL_V2_BYTES>(params, statement, proof, |params, statement, proof| {
        verify_coin_reveal_v2(params, &coin_reveal_v2_from_bytes(statement), proof)
    })
}

/// What both statements share: the lengths of the parameters and the
/// statement, the proof's size, encoding and zero padding, then `verify` on
/// the decoded parameters, the statement bytes and the proof, mapped to a
/// status.
fn verify_statement<const N: usize>(
    params: &[u8],
    statement: &[u8],
    proof: &[u8],
    verify: impl FnOnce(&ChainParams, &[u8; N], &Proof) -> Result<(), ProofError>,
) -> i32 {
    let (Ok(params), Ok(statement)) = (<&[u8; CHAIN_PARAMS_BYTES]>::try_from(params), <&[u8; N]>::try_from(statement))
    else {
        return GHOST_PROOFS_BAD_ARGUMENT;
    };
    if proof.is_empty() || proof.len() > PROOF_MAX_BYTES {
        return GHOST_PROOFS_MALFORMED_INPUT;
    }
    let Some(len) = stark::serialized_len(proof) else {
        return GHOST_PROOFS_MALFORMED_INPUT;
    };
    let (proof, padding) = proof.split_at(len);
    if padding.iter().any(|&b| b != 0) {
        return GHOST_PROOFS_MALFORMED_INPUT;
    }
    let params = chain_params_from_bytes(params);
    let proof = Proof::from_bytes(proof.to_vec());
    match verify(&params, statement, &proof) {
        Ok(()) => GHOST_PROOFS_ACCEPTED,
        Err(ProofError::MalformedProof) => GHOST_PROOFS_MALFORMED_INPUT,
        Err(_) => GHOST_PROOFS_REJECTED,
    }
}

/// The pointer checks of both C functions, then `core` on the slices.
///
/// # Safety
///
/// As [`ghost_verify_coin_reveal`].
#[allow(clippy::too_many_arguments)]
unsafe fn verify_raw(
    params: *const u8,
    params_len: usize,
    statement: *const u8,
    statement_len: usize,
    expected_statement_len: usize,
    proof: *const u8,
    proof_len: usize,
    core: fn(&[u8], &[u8], &[u8]) -> i32,
) -> i32 {
    catch_unwind(|| {
        if params.is_null() || statement.is_null() || proof.is_null() {
            return GHOST_PROOFS_BAD_ARGUMENT;
        }
        if params_len != CHAIN_PARAMS_BYTES || statement_len != expected_statement_len {
            return GHOST_PROOFS_BAD_ARGUMENT;
        }
        if proof_len == 0 || proof_len > PROOF_MAX_BYTES {
            return GHOST_PROOFS_MALFORMED_INPUT;
        }
        // SAFETY: non-null, and the caller guarantees each length is readable.
        let (params, statement, proof) = unsafe {
            (
                std::slice::from_raw_parts(params, params_len),
                std::slice::from_raw_parts(statement, statement_len),
                std::slice::from_raw_parts(proof, proof_len),
            )
        };
        core(params, statement, proof)
    })
    .unwrap_or(GHOST_PROOFS_PANICKED)
}

/// Verifies a coin reveal proof against the statement and the chain
/// parameters.
///
/// # Safety
///
/// Each non-null pointer must point to at least its length of readable bytes
/// for the duration of the call. A null pointer is refused with
/// [`GHOST_PROOFS_BAD_ARGUMENT`], and a buffer of the wrong length is refused
/// before it is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_verify_coin_reveal(
    params: *const u8,
    params_len: usize,
    statement: *const u8,
    statement_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    // SAFETY: the caller's guarantees are passed on unchanged.
    unsafe {
        verify_raw(
            params,
            params_len,
            statement,
            statement_len,
            COIN_REVEAL_BYTES,
            proof,
            proof_len,
            verify_coin_reveal_bytes,
        )
    }
}

/// Verifies a version 2 coin reveal proof (statement S1 version 2, the
/// ordinary class) against the statement and the chain parameters.
///
/// # Safety
///
/// As [`ghost_verify_coin_reveal`]: each non-null pointer must point to at
/// least its length of readable bytes for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_verify_coin_reveal_v2(
    params: *const u8,
    params_len: usize,
    statement: *const u8,
    statement_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    // SAFETY: the caller's guarantees are passed on unchanged.
    unsafe {
        verify_raw(
            params,
            params_len,
            statement,
            statement_len,
            COIN_REVEAL_V2_BYTES,
            proof,
            proof_len,
            verify_coin_reveal_v2_bytes,
        )
    }
}

/// The path word of a root key that verifies bundles of private reveals.
pub const ROOT_KEY_BUNDLE: u32 = 1;
/// The path word of a root key that verifies the public root.
pub const ROOT_KEY_PUBLIC: u32 = 2;
/// Words of a root key: the path, the shape, five tables' lanes and heights,
/// the preprocessed commitment, the children's key digest.
const ROOT_KEY_WORDS: usize = 3 + 2 * TABLES.len() + 2 * DIGEST;
/// Where the commitment and the children's key digest start, in words.
const ROOT_KEY_COMMITMENT: usize = 3 + 2 * TABLES.len();
const ROOT_KEY_CHILD: usize = ROOT_KEY_COMMITMENT + DIGEST;
/// Length of a root key.
pub const ROOT_KEY_BYTES: usize = 4 * ROOT_KEY_WORDS;
/// Length of the binding that starts the root inputs: `chain_id`,
/// `protocol_version`, `statement_version`.
pub const ROOT_BINDING_BYTES: usize = 8 + 2 + 1;
/// Length of a bundle's item: the public values of a version 2 coin reveal,
/// its binding fields and then its 32-byte binding digest.
pub const REVEAL_PUBLIC_BYTES: usize = {
    let last = COIN_REVEAL_V2_LAYOUT[COIN_REVEAL_V2_LAYOUT.len() - 1];
    last.offset + last.width + 32
};
/// Length of a public transaction's item: account, key identity,
/// transaction hash.
pub const PUBLIC_TX_BYTES: usize = ACCOUNT_BYTES + KEY_ID_BYTES + TX_HASH_BYTES;

/// Bounds a root key is held to before anything is built from it, so a
/// key's bytes cannot ask for an unbounded table or shape.
const MAX_KEY_LOG_BLOWUP: u32 = 8;
const MAX_KEY_QUERIES: u32 = 256;
const MAX_KEY_LANES: usize = 64;

/// Which root a key verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootPath {
    /// A bundle of private reveals; each item is a coin reveal's public
    /// values.
    Bundle,
    /// The public root over the ML-DSA-44 chunks; each item is a public
    /// transaction's account, key identity and hash.
    Public,
}

impl RootPath {
    /// The path word of the key.
    pub const fn code(self) -> u32 {
        match self {
            Self::Bundle => ROOT_KEY_BUNDLE,
            Self::Public => ROOT_KEY_PUBLIC,
        }
    }

    /// The bytes of one item of the root inputs.
    pub const fn item_bytes(self) -> usize {
        match self {
            Self::Bundle => REVEAL_PUBLIC_BYTES,
            Self::Public => PUBLIC_TX_BYTES,
        }
    }
}

/// What the verifier of a shrink reads from its root key.
struct RootVerifierKey {
    shape: LayerShape,
    airs: Vec<TableAir>,
    common: CommonData<ScaleConfig>,
    child_key: [u32; DIGEST],
}

/// The five tables known by their lanes and heights.
fn shape_airs(sizes: &[(usize, usize); 5]) -> Vec<TableAir> {
    TABLES
        .into_iter()
        .zip(sizes)
        .map(|(table, &(lanes, height))| TableAir::shape(table, LAYER_PUBLICS, lanes, height))
        .collect()
}

/// The verifier's common data of tables of these shapes under a
/// preprocessed commitment of one root: each table's preprocessed matrix in
/// table order, as the library's setup lays them out, and the lookups it
/// derives for the tables.
fn verifier_common(airs: &[TableAir], shape: LayerShape, root: [F; DIGEST]) -> Result<CommonData<ScaleConfig>, ProofError> {
    let degree_bits = tables::degree_bits(airs);
    let mut instances = Vec::with_capacity(airs.len());
    let mut matrix_to_instance = Vec::new();
    for (i, air) in airs.iter().enumerate() {
        let width = BaseAir::<F>::preprocessed_width(air);
        if width == 0 {
            instances.push(None);
            continue;
        }
        instances.push(Some(PreprocessedInstanceMeta {
            matrix_index: matrix_to_instance.len(),
            width,
            degree_bits: degree_bits[i],
        }));
        matrix_to_instance.push(i);
    }
    let lookups = tables::lookups_for(airs, &shape.fri())?;
    let preprocessed = GlobalPreprocessed {
        commitment: MerkleCap::new(vec![root]),
        instances,
        matrix_to_instance,
    };
    Ok(CommonData::new(Some(preprocessed), lookups))
}

/// Whether two common data are the same: commitment, preprocessed layout and
/// lookups.
fn same_common(a: &CommonData<ScaleConfig>, b: &CommonData<ScaleConfig>) -> bool {
    let (Some(pa), Some(pb)) = (&a.preprocessed, &b.preprocessed) else {
        return false;
    };
    let meta = |m: &Option<PreprocessedInstanceMeta>| m.as_ref().map(|m| (m.matrix_index, m.width, m.degree_bits));
    pa.commitment == pb.commitment
        && pa.matrix_to_instance == pb.matrix_to_instance
        && pa.instances.iter().map(meta).eq(pb.instances.iter().map(meta))
        && format!("{:?}", a.lookups) == format!("{:?}", b.lookups)
}

/// The root key of a shrink key, for `path`. Refuses a key that is not a
/// shrink, and one whose verifier data the bytes would not rebuild exactly.
pub fn root_key_to_bytes(key: &LayerKey, path: RootPath) -> Result<[u8; ROOT_KEY_BYTES], ProofError> {
    let airs = &key.circuit.airs;
    if key.kind() != LayerKind::Shrink || airs.len() != TABLES.len() {
        return Err(ProofError::Proving);
    }
    let common = key.circuit.common();
    let one_root = common.preprocessed.as_ref().is_some_and(|p| p.commitment.roots().len() == 1);
    if !one_root {
        return Err(ProofError::Proving);
    }
    let root = cap_root(&common.preprocessed.as_ref().expect("checked above").commitment);
    let shape = key.shape();
    let mut words = Vec::with_capacity(ROOT_KEY_WORDS);
    words.push(path.code());
    words.push(u32::try_from(shape.log_blowup).map_err(|_| ProofError::Proving)?);
    words.push(u32::try_from(shape.num_queries).map_err(|_| ProofError::Proving)?);
    for air in airs {
        words.push(u32::try_from(air.lanes()).map_err(|_| ProofError::Proving)?);
        words.push(u32::try_from(air.height()).map_err(|_| ProofError::Proving)?);
    }
    words.extend(root.iter().map(PrimeField32::as_canonical_u32));
    words.extend(key.child_key());
    if words.len() != ROOT_KEY_WORDS {
        return Err(ProofError::Proving);
    }
    let mut out = [0u8; ROOT_KEY_BYTES];
    for (bytes, word) in out.chunks_exact_mut(4).zip(&words) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    let back = decode_root_key(&out, path).map_err(|_| ProofError::Proving)?;
    if !same_common(&back.common, common) {
        return Err(ProofError::Proving);
    }
    Ok(out)
}

/// A root key's verifier data, or [`GHOST_PROOFS_BAD_ARGUMENT`] for a key of
/// the wrong length or path, a shape or table outside the bounds, or a digest
/// element that is not canonical.
fn decode_root_key(bytes: &[u8], path: RootPath) -> Result<RootVerifierKey, i32> {
    let bad = GHOST_PROOFS_BAD_ARGUMENT;
    let bytes: &[u8; ROOT_KEY_BYTES] = bytes.try_into().map_err(|_| bad)?;
    let words: [u32; ROOT_KEY_WORDS] =
        core::array::from_fn(|i| u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]));
    if words[0] != path.code() {
        return Err(bad);
    }
    if !(1..=MAX_KEY_LOG_BLOWUP).contains(&words[1]) || !(1..=MAX_KEY_QUERIES).contains(&words[2]) {
        return Err(bad);
    }
    let shape = LayerShape {
        log_blowup: words[1] as usize,
        num_queries: words[2] as usize,
    };
    let fri = shape.fri();
    let (min_height, max_log) = (tables::min_height(&fri), tables::max_log_height(&fri));
    let mut sizes = [(0usize, 0usize); 5];
    for (i, table) in TABLES.into_iter().enumerate() {
        let (lanes, height) = (words[3 + 2 * i] as usize, words[4 + 2 * i] as usize);
        let most_lanes = if matches!(table, Table::Wires | Table::Arith) { MAX_KEY_LANES } else { 1 };
        let lanes_ok = lanes.is_power_of_two() && lanes <= most_lanes;
        let height_ok =
            height.is_power_of_two() && height >= min_height && height.trailing_zeros() as usize <= max_log;
        if !lanes_ok || !height_ok {
            return Err(bad);
        }
        sizes[i] = (lanes, height);
    }
    let digest = |at: usize| -> Result<[u32; DIGEST], i32> {
        let d: [u32; DIGEST] = core::array::from_fn(|j| words[at + j]);
        if d.iter().all(|&x| x < F::ORDER_U32) { Ok(d) } else { Err(bad) }
    };
    let root = digest(ROOT_KEY_COMMITMENT)?;
    let child_key = digest(ROOT_KEY_CHILD)?;
    check_config(shape).map_err(|_| bad)?;
    let airs = shape_airs(&sizes);
    let common = verifier_common(&airs, shape, root.map(F::from_u32)).map_err(|_| bad)?;
    Ok(RootVerifierKey {
        shape,
        airs,
        common,
        child_key,
    })
}

/// The root inputs in the layout of the C interface: the binding, then each
/// item's public values in order, one byte a value.
pub fn root_inputs_to_bytes(binding: &layers::Binding, items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ROOT_BINDING_BYTES + items.iter().map(Vec::len).sum::<usize>());
    out.extend_from_slice(&binding.chain_id);
    out.extend_from_slice(&binding.protocol_version);
    out.push(binding.statement_version);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// The binding and the items of root inputs, each item `item_bytes` long;
/// `None` for inputs shorter than the binding, without an item, or not a
/// whole number of items.
fn decode_root_inputs(inputs: &[u8], item_bytes: usize) -> Option<(layers::Binding, Vec<Vec<F>>)> {
    if inputs.len() < ROOT_BINDING_BYTES {
        return None;
    }
    let (head, items) = inputs.split_at(ROOT_BINDING_BYTES);
    if items.is_empty() || items.len() % item_bytes != 0 || u32::try_from(items.len() / item_bytes).is_err() {
        return None;
    }
    let binding = layers::Binding {
        chain_id: head[..8].try_into().ok()?,
        protocol_version: head[8..10].try_into().ok()?,
        statement_version: head[10],
    };
    let contents = items
        .chunks_exact(item_bytes)
        .map(|item| item.iter().map(|&b| F::from_u8(b)).collect())
        .collect();
    Some((binding, contents))
}

/// The safe core of [`ghost_verify_bundle_root`], over slices.
pub fn verify_bundle_root_bytes(key: &[u8], inputs: &[u8], proof: &[u8]) -> i32 {
    verify_root_bytes(RootPath::Bundle, key, inputs, proof)
}

/// The safe core of [`ghost_verify_public_root`], over slices.
pub fn verify_public_root_bytes(key: &[u8], inputs: &[u8], proof: &[u8]) -> i32 {
    verify_root_bytes(RootPath::Public, key, inputs, proof)
}

fn verify_root_bytes(path: RootPath, key: &[u8], inputs: &[u8], proof: &[u8]) -> i32 {
    catch_unwind(AssertUnwindSafe(|| verify_root_unguarded(path, key, inputs, proof))).unwrap_or(GHOST_PROOFS_PANICKED)
}

/// The lengths, the key, the proof field's encoding and padding, then the
/// shrink's verification at index 0 under the key, the tag the inputs' binding
/// and the key's children name, and the claim the items give from the start
/// digest.
fn verify_root_unguarded(path: RootPath, key: &[u8], inputs: &[u8], proof: &[u8]) -> i32 {
    if key.len() != ROOT_KEY_BYTES {
        return GHOST_PROOFS_BAD_ARGUMENT;
    }
    let Some((binding, contents)) = decode_root_inputs(inputs, path.item_bytes()) else {
        return GHOST_PROOFS_BAD_ARGUMENT;
    };
    if proof.len() != PROOF_FIELD_BYTES {
        return GHOST_PROOFS_MALFORMED_INPUT;
    }
    let key = match decode_root_key(key, path) {
        Ok(key) => key,
        Err(status) => return status,
    };
    let Ok((decoded, padding)) = postcard::take_from_bytes::<LayerProof>(proof) else {
        return GHOST_PROOFS_MALFORMED_INPUT;
    };
    if padding.iter().any(|&b| b != 0) {
        return GHOST_PROOFS_MALFORMED_INPUT;
    }
    let claim = Claim::of(&layers::START_DIGEST, &contents);
    let publics = claim_publics(&binding, &claim);
    let tag = LayerTag {
        kind: LayerKind::Shrink,
        index: 0,
        protocol_version: binding.protocol_version,
        statement_version: binding.statement_version,
        chain_id: binding.chain_id,
        child_key: key.child_key,
    };
    match tables::verify(&key.airs, &key.common, &decoded, &publics, &key.shape.fri(), &tag.elements()) {
        Ok(()) => GHOST_PROOFS_ACCEPTED,
        Err(ProofError::MalformedProof) => GHOST_PROOFS_MALFORMED_INPUT,
        Err(_) => GHOST_PROOFS_REJECTED,
    }
}

/// The pointer checks of both root functions, then `core` on the slices.
///
/// # Safety
///
/// As [`ghost_verify_bundle_root`].
unsafe fn root_raw(
    key: *const u8,
    key_len: usize,
    inputs: *const u8,
    inputs_len: usize,
    proof: *const u8,
    proof_len: usize,
    core: fn(&[u8], &[u8], &[u8]) -> i32,
) -> i32 {
    catch_unwind(|| {
        if key.is_null() || inputs.is_null() || proof.is_null() {
            return GHOST_PROOFS_BAD_ARGUMENT;
        }
        if key_len != ROOT_KEY_BYTES || inputs_len <= ROOT_BINDING_BYTES || inputs_len > isize::MAX as usize {
            return GHOST_PROOFS_BAD_ARGUMENT;
        }
        if proof_len != PROOF_FIELD_BYTES {
            return GHOST_PROOFS_MALFORMED_INPUT;
        }
        // SAFETY: non-null, and the caller guarantees each length is readable.
        let (key, inputs, proof) = unsafe {
            (
                std::slice::from_raw_parts(key, key_len),
                std::slice::from_raw_parts(inputs, inputs_len),
                std::slice::from_raw_parts(proof, proof_len),
            )
        };
        core(key, inputs, proof)
    })
    .unwrap_or(GHOST_PROOFS_PANICKED)
}

/// Verifies a bundle's root proof: the shrink at index 0 under the bundle
/// root key `key`, for the root inputs `inputs` (the binding and the ordered
/// coin reveals' public values), from the proof field `proof`.
///
/// # Safety
///
/// Each non-null pointer must point to at least its length of readable bytes
/// for the duration of the call. A null pointer, a key of the wrong length,
/// or inputs of no item are refused with [`GHOST_PROOFS_BAD_ARGUMENT`] before
/// a buffer is read, and a proof field of the wrong length with
/// [`GHOST_PROOFS_MALFORMED_INPUT`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_verify_bundle_root(
    key: *const u8,
    key_len: usize,
    inputs: *const u8,
    inputs_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    // SAFETY: the caller's guarantees are passed on unchanged.
    unsafe { root_raw(key, key_len, inputs, inputs_len, proof, proof_len, verify_bundle_root_bytes) }
}

/// Verifies the public root proof: the shrink at index 0 under the public
/// root key `key`, for the root inputs `inputs` (the binding and the ordered
/// public transactions' account, key identity and hash), from the proof field
/// `proof`.
///
/// # Safety
///
/// As [`ghost_verify_bundle_root`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_verify_public_root(
    key: *const u8,
    key_len: usize,
    inputs: *const u8,
    inputs_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    // SAFETY: the caller's guarantees are passed on unchanged.
    unsafe { root_raw(key, key_len, inputs, inputs_len, proof, proof_len, verify_public_root_bytes) }
}
