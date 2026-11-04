//! The recursion layers of the scale build (stage 2 design, "Aggregation
//! cost", architecture (c)): a batch proof that verifies reveal proofs, a root
//! proof that verifies an aggregator's batches, and a shrink proof that
//! verifies the root and is what a block carries.
//!
//! Every layer is a verifier circuit ([`circuit`]) proven as a batch STARK of
//! four tables routed by LogUp ([`tables`]), at the scale configuration's
//! Poseidon2 commitments and transcript, degree-8 extension and hiding FRI. The
//! circuit replays its children's transcripts, checks their Merkle openings,
//! their FRI folding and their constraints at the out-of-domain point, all in
//! its own rows. No elliptic curve is used anywhere.
//!
//! Like the rest of the crate this module reads no clock, file or operating
//! system source and builds for `wasm32-unknown-unknown`; timing is the
//! benchmark's business.

pub(crate) mod bundle;
pub(crate) mod circuit;
pub(crate) mod keys;
pub(crate) mod pcs;
pub(crate) mod poseidon2;
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
}

/// An AIR a child proof can be made for: its width, its public values and
/// its constraints, for every builder.
pub trait ChildAir: Sync {
    fn width(&self) -> usize;
    fn num_public_values(&self) -> usize;
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
pub use keys::{Binding, LayerKey};

/// A running digest, as canonical integers.
pub type Digest = [u32; 9];

/// The running digest every bundle starts from.
pub const START_DIGEST: Digest = [0; 9];

fn native(d: &Digest) -> bundle::NativeDigest {
    use p3_field::PrimeCharacteristicRing;
    core::array::from_fn(|i| F::from_u32(d[i]))
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
    keys::batch_key_of(&AirOf(air), child, child_log_height, capacity, shape)
}

/// Prove a batch of child proofs (each with its public values, in order),
/// its running digest starting from `start`, at position `index` under
/// `binding`. Refuses a batch some child does not verify in.
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
    keys::prove_batch_of(key, &AirOf(air), &tag, &native(start), children, zk_seed, false)
}

/// [`prove_batch`] that proves the circuit even when a child breaks it, and
/// under any tag: for tests that such a proof is refused.
#[doc(hidden)]
pub fn prove_batch_unchecked<A: ChildAir>(
    key: &LayerKey,
    air: &A,
    tag: &LayerTag,
    start: &Digest,
    children: &[(Vec<u8>, Vec<BabyBear>)],
    zk_seed: [u8; 32],
) -> Result<Vec<u8>, ProofError> {
    keys::prove_batch_of(key, &AirOf(air), tag, &native(start), children, zk_seed, true)
}

/// The public values of a batch whose children have `contents` from `start`.
pub fn batch_public_values(start: &Digest, contents: &[Vec<BabyBear>]) -> Vec<BabyBear> {
    keys::batch_publics(&native(start), contents)
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
    let publics = keys::batch_publics(&native(start), contents);
    keys::verify_layer(key, &key.tag(binding, index), &publics, proof)
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
/// four tables, then checked to fail with a changed public value and with a
/// changed tag. A test of the tables alone, before any verifier circuit.
#[doc(hidden)]
pub fn table_roundtrip_check() -> Result<(), alloc::string::String> {
    use alloc::format;
    use p3_field::PrimeCharacteristicRing;

    use crate::stark::FriShape;
    let fri = FriShape {
        log_blowup: 3,
        num_queries: 2,
        query_pow_bits: 8,
        batch_pow_bits: 8,
    };
    let mut c = circuit::Circuit::new();
    let x = c.hint(EF::from(F::from_u32(1234)));
    let y = c.mul_const(x, EF::from(F::from_u32(77)));
    let input: [circuit::Wire; 24] = core::array::from_fn(|i| if i == 0 { y } else { c.const_base(F::from_usize(i)) });
    let out = c.perm(input);
    let bits = c.bits(out[0]);
    let back = c.from_bits(&bits);
    c.assert_eq(back, out[0]);
    let public = c.public(c.base_value(out[1]));
    c.assert_eq(public, out[1]);
    let e = c.hint(from_coeffs(|i| F::from_usize(i + 3)));
    let inv = c.inv(e);
    let _ = c.mul(inv, e);
    if let Some(f) = c.failure() {
        return Err(format!("the honest circuit fails: {f}"));
    }
    let airs = tables::table_airs(&c, &fri);
    let key = tables::setup(airs, &fri).map_err(|e| format!("setup: {e}"))?;
    let tag = [F::from_u8(7), F::from_u8(9)];
    let proof = tables::prove(&key, &c, &fri, &tag, [3; 32]).map_err(|e| format!("prove: {e}"))?;
    let publics = [c.base_value(public)];
    tables::verify(&key.airs, key.common(), &proof, &publics, &fri, &tag).map_err(|e| format!("verify: {e}"))?;
    let wrong = [publics[0] + F::ONE];
    if tables::verify(&key.airs, key.common(), &proof, &wrong, &fri, &tag).is_ok() {
        return Err(format!("a changed public value verifies"));
    }
    if tables::verify(&key.airs, key.common(), &proof, &publics, &fri, &tag[..1]).is_ok() {
        return Err(format!("a changed tag verifies"));
    }
    Ok(())
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
