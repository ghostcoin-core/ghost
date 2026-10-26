//! The proof system of decision 0003 and the one place it is configured.
//!
//! BabyBear with a degree-5 extension for challenges, Keccak-256 for every
//! commitment, hiding FRI at blowup 2^3 (rate 1/8) with 43 queries and 16 bits
//! of grinding on the queries and before the batching challenge
//! ([`BATCH_POW_BITS`]), zero-knowledge mode on.
//!
//! The security gate holds the configuration to the rule of spec 09,
//! section 4.1, so the proof meets the post-quantum target (about half the
//! classical bits against a quantum attacker on the Fiat–Shamir hash). It
//! refuses a configuration unless:
//!
//! 1. the queries alone reach 128 conjectured bits: `LOG_BLOWUP * NUM_QUERIES`
//!    is at least 128, before any grinding;
//! 2. for every statement, the library's estimator, run with the grinding at
//!    each site counted at half its bits, reports at least 128 bits: it reports
//!    the smallest of its terms, so every term reaches 128, the extension-field
//!    ones (DEEP, batching, folding) included;
//! 3. the hash is Keccak-256 with 256-bit digests, in the Merkle commitments and
//!    in the transcript;
//! 4. zero-knowledge is on, with salts of at least 128 bits.
//!
//! An estimate the library cannot compute is a refusal, never a pass.
//!
//! Plonky3 makes a proof zero-knowledge with a hiding polynomial commitment
//! scheme (`HidingFriPcs`) paired with a hiding Merkle commitment
//! (`MerkleTreeHidingMmcs`). [`stark_config`] is the only function that builds
//! a configuration, for the prover and the verifier alike. Its types are the
//! hiding ones, there is no other configuration type in this crate, and it
//! refuses to return a configuration the library does not report as
//! zero-knowledge. So there is no way to prove with zero-knowledge off.
//!
//! The zero-knowledge randomness is 32 bytes the caller supplies; this crate
//! never reads the operating system's random source.
//!
//! The proof-size budget of spec 07, section 3 lives here too: no statement's
//! trace may be taller than [`MAX_TRACE_HEIGHT`] or wider than
//! [`MAX_TRACE_WIDTH`], the coin reveal's, the salted one's included, and
//! [`proof_length_bound`] shows
//! that a proof of such a trace fits [`PROOF_FIELD_BYTES`].

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::{Layout, Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::bitrev::BitReversedMatrixView;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView, RowMajorMatrixViewMut};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, CryptographicPermutation, PaddingFreeSponge, Permutation,
    SerializingHasher,
};
use p3_uni_stark::{
    AirLayout, ConjecturedSecurity, OpeningShape, Proof as StarkProof, ProvenSecurity,
    StarkConfig, StarkGenericConfig, StarkSecurityParams, get_max_constraint_degree,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::ProofError;
use crate::air::{F, StatementAir};
use crate::hash::{keccak_f, keccak_f_inline};
use crate::schedule::{Assignment, Schedule, execute};

/// Degree of the challenge field over BabyBear.
pub const EXTENSION_DEGREE: usize = 5;
/// log2 of the challenge field size, rounded down: 5 * log2(2^31 - 2^27 + 1).
pub const CHALLENGE_FIELD_BITS: usize = 154;
/// log2 of the blowup: rate 1/8, so each query is worth 3 conjectured bits.
pub const LOG_BLOWUP: usize = 3;
/// FRI queries: 3 * 43 = 129 conjectured bits from the queries alone.
pub const NUM_QUERIES: usize = 43;
/// Proof-of-work bits before the FRI queries are drawn: margin, counted at
/// half by the gate.
pub const QUERY_POW_BITS: usize = 16;
/// Proof-of-work bits before the challenge that batches the openings.
///
/// The coin reveal's trace is 2,048 rows of about 3,800 columns. The
/// estimator's batched-openings term, `|EF| / ((functions - 1) * codeword
/// length)`, comes to about 126 bits for it at blowup 2^3 without grinding,
/// whatever the query count; the 8 bits the gate counts of these 16 lift it
/// over 128. It costs the prover about 2^16 hashes and the verifier one.
pub const BATCH_POW_BITS: usize = 16;
/// The most grinding allowed at any one site.
pub const MAX_GRINDING_BITS: usize = 16;
const _: () = assert!(QUERY_POW_BITS <= MAX_GRINDING_BITS && BATCH_POW_BITS <= MAX_GRINDING_BITS);
/// The floor of the rule of spec 09, section 4.1, classical and conjectured:
/// for the queries alone, and for every estimator term with grinding counted
/// at half. A quantum attacker gets about half, the 64 bits of NIST
/// Category 1.
pub const TARGET_CONJECTURED_BITS: usize = 128;
/// Collision resistance of Keccak-256 as the commitment hash.
pub const COLLISION_RESISTANCE_BITS: usize = 128;
/// Bits of every digest the rule accepts: a Merkle node and the transcript
/// hash, Keccak-256 at its full output.
pub const DIGEST_BITS: usize = 256;
/// The fewest salt bits per opened row the rule accepts.
pub const MIN_SALT_BITS: usize = 128;
/// Random columns hiding FRI appends to each committed matrix; the library
/// requires at least the extension degree.
const NUM_RANDOM_CODEWORDS: usize = EXTENSION_DEGREE;
/// Salt elements per Merkle leaf.
const SALT_ELEMS: usize = 5;
/// Salt bits per opened row, rounded down: 5 BabyBear elements, as many bits
/// as the 5 coordinates of a challenge, 154.
pub const SALT_BITS: usize = SALT_ELEMS * CHALLENGE_FIELD_BITS / EXTENSION_DEGREE;
/// Points at which the main trace is opened (`zeta` and `zeta * g`).
const TRACE_OPENING_POINTS: usize = 2;
/// Words of a Merkle digest: Keccak-256 as four `u64` lanes.
const DIGEST_WORDS: usize = 4;
/// Lanes the Merkle sponge absorbs per Keccak-f[1600] permutation: 17, the
/// 136-byte rate of Keccak-256, so its 512-bit capacity.
const SPONGE_RATE_LANES: usize = 17;
/// Bytes of the transcript hash's output.
const TRANSCRIPT_DIGEST_BYTES: usize = 32;

/// Width of the proof field of a private transaction in version 1, for every
/// reveal kind (spec 07, section 3): 1.25 MiB. A change of width is a new
/// transaction version, never an edit of this one.
pub const PROOF_FIELD_BYTES: usize = 1_310_720;
/// The proof-size budget (spec 07, section 3): the most rows a statement's
/// trace may have before zero-knowledge padding, the coin reveal's.
pub const MAX_TRACE_HEIGHT: usize = 2048;
/// The most columns a statement's trace may have, the salted coin reveal's:
/// 3,808 without the salt and its 16 carried columns.
pub const MAX_TRACE_WIDTH: usize = 3824;

/// The challenge field.
pub(crate) type Challenge = BinomialExtensionField<BabyBear, EXTENSION_DEGREE>;
type Dft = MemoDft;
type KeccakU64Hash = PaddingFreeSponge<MerkleKeccak, 25, SPONGE_RATE_LANES, DIGEST_WORDS>;
type KeccakCompress = CompressionFunctionFromHasher<KeccakU64Hash, 2, DIGEST_WORDS>;
type ValMmcs = MerkleTreeHidingMmcs<
    [F; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    MerkleLeafHash,
    KeccakCompress,
    StdRng,
    2,
    DIGEST_WORDS,
    SALT_ELEMS,
>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, TRANSCRIPT_DIGEST_BYTES>>;
type Pcs = HidingFriPcs<F, Dft, ValMmcs, ChallengeMmcs, StdRng>;
/// The one configuration type: hiding commitments only.
pub(crate) type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// States the Merkle trees permute at once: the width of the library's
/// vector Keccak-f[1600] on this target.
const MERKLE_LANES: usize = p3_keccak::VECTOR_LEN;

/// Keccak-f[1600] for the Merkle trees. One state takes [`keccak_f`]. A packed
/// state takes the library's vector permutation (SHA3 instructions, AVX2,
/// AVX-512, wasm SIMD), except on aarch64 without the SHA3 instructions, where
/// [`keccak_f`] run on each lane in turn is the faster: 131 against 147 ns a
/// state on the build machine.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MerkleKeccak;

/// Whether a packed state is permuted one lane at a time with [`keccak_f`]:
/// on aarch64 without the SHA3 instructions.
const SCALAR_MERKLE_LANES: bool = cfg!(all(target_arch = "aarch64", not(target_feature = "sha3")));

impl Permutation<[u64; 25]> for MerkleKeccak {
    fn permute_mut(&self, state: &mut [u64; 25]) {
        keccak_f(state);
    }
}

impl CryptographicPermutation<[u64; 25]> for MerkleKeccak {}

impl Permutation<[[u64; MERKLE_LANES]; 25]> for MerkleKeccak {
    fn permute_mut(&self, state: &mut [[u64; MERKLE_LANES]; 25]) {
        if SCALAR_MERKLE_LANES {
            for lane in 0..MERKLE_LANES {
                let mut one = core::array::from_fn(|i| state[i][lane]);
                keccak_f(&mut one);
                for (word, value) in state.iter_mut().zip(one) {
                    word[lane] = value;
                }
            }
        } else {
            KeccakF.permute_mut(state);
        }
    }
}

impl CryptographicPermutation<[[u64; MERKLE_LANES]; 25]> for MerkleKeccak {}

/// Field elements per block of the leaf sponge: two to a lane.
const LEAF_BLOCK_ELEMS: usize = 2 * SPONGE_RATE_LANES;

/// The Merkle leaf hash: the digest `SerializingHasher<KeccakU64Hash>` gives
/// a row of field elements, computed from the row itself rather than through
/// a stream of bytes. Elements are read in their internal (Montgomery) form,
/// two to a 64-bit lane with the first in the low half; each block of
/// [`LEAF_BLOCK_ELEMS`] elements overwrites the rate and is permuted, and a
/// last, shorter block overwrites only the lanes it fills (the odd element
/// alone in its lane) and is permuted. An empty row hashes to zero. The gate
/// checks it against the library's hasher.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MerkleLeafHash;

/// The rate lane of two elements, the first in the low half.
#[inline(always)]
fn leaf_lane(low: F, high: F) -> u64 {
    u64::from(low.to_unique_u32()) | u64::from(high.to_unique_u32()) << 32
}

/// Overwrite the rate with one block of at most [`LEAF_BLOCK_ELEMS`]
/// elements, through `set(word, value)`.
#[inline(always)]
fn overwrite_leaf_block(block: &[F], mut set: impl FnMut(usize, u64)) {
    if let Ok(full) = <&[F; LEAF_BLOCK_ELEMS]>::try_from(block) {
        for (word, pair) in full.as_chunks::<2>().0.iter().enumerate() {
            set(word, leaf_lane(pair[0], pair[1]));
        }
    } else {
        for (word, pair) in block.chunks(2).enumerate() {
            set(word, leaf_lane(pair[0], pair.get(1).copied().unwrap_or(F::ZERO)));
        }
    }
}

/// Absorb one block of at most [`LEAF_BLOCK_ELEMS`] elements and permute.
#[inline(always)]
fn absorb_leaf_block(state: &mut [u64; 25], block: &[F]) {
    overwrite_leaf_block(block, |word, value| state[word] = value);
    keccak_f(state);
}

/// The leaf digest of one row, the state passed from permutation to
/// permutation by value ([`keccak_f_inline`]) and only the rate lanes read
/// from the row.
fn leaf_digest(row: &[F]) -> [u64; DIGEST_WORDS] {
    let mut state = [0; 25];
    let (blocks, last) = row.as_chunks::<LEAF_BLOCK_ELEMS>();
    for block in blocks {
        for (word, pair) in block.as_chunks::<2>().0.iter().enumerate() {
            state[word] = leaf_lane(pair[0], pair[1]);
        }
        state = keccak_f_inline(state);
    }
    if !last.is_empty() {
        absorb_leaf_block(&mut state, last);
    }
    core::array::from_fn(|i| state[i])
}

/// The leaf digests of [`MERKLE_LANES`] rows of one length, one row to a lane
/// of a packed state.
fn leaf_digests(rows: [&[F]; MERKLE_LANES]) -> [[u64; DIGEST_WORDS]; MERKLE_LANES] {
    let mut state = [[0; MERKLE_LANES]; 25];
    for start in (0..rows[0].len()).step_by(LEAF_BLOCK_ELEMS) {
        for (lane, row) in rows.iter().enumerate() {
            let block = &row[start..row.len().min(start + LEAF_BLOCK_ELEMS)];
            overwrite_leaf_block(block, |word, value| state[word][lane] = value);
        }
        MerkleKeccak.permute_mut(&mut state);
    }
    core::array::from_fn(|lane| core::array::from_fn(|word| state[word][lane]))
}

/// The leaf sponge fed one element at a time.
#[derive(Clone, Copy)]
struct LeafSponge {
    state: [u64; 25],
    block: [F; LEAF_BLOCK_ELEMS],
    len: usize,
}

impl LeafSponge {
    const fn new() -> Self {
        Self {
            state: [0; 25],
            block: [F::ZERO; LEAF_BLOCK_ELEMS],
            len: 0,
        }
    }

    fn absorb(&mut self, x: F) {
        self.block[self.len] = x;
        self.len += 1;
        if self.len == LEAF_BLOCK_ELEMS {
            absorb_leaf_block(&mut self.state, &self.block);
            self.len = 0;
        }
    }

    fn finish(mut self) -> [u64; DIGEST_WORDS] {
        if self.len > 0 {
            absorb_leaf_block(&mut self.state, &self.block[..self.len]);
        }
        core::array::from_fn(|i| self.state[i])
    }
}

impl CryptographicHasher<F, [u64; DIGEST_WORDS]> for MerkleLeafHash {
    /// More than one, so the tree hands whole rows to [`Self::hash_many`].
    const LANES: usize = if MERKLE_LANES > 1 { MERKLE_LANES } else { 2 };

    fn hash_iter<I>(&self, input: I) -> [u64; DIGEST_WORDS]
    where
        I: IntoIterator<Item = F>,
    {
        let mut sponge = LeafSponge::new();
        input.into_iter().for_each(|x| sponge.absorb(x));
        sponge.finish()
    }

    fn hash_slice(&self, input: &[F]) -> [u64; DIGEST_WORDS] {
        leaf_digest(input)
    }

    fn hash_many(&self, input: &[F], out: &mut [[u64; DIGEST_WORDS]]) {
        if out.is_empty() {
            return;
        }
        assert!(input.len().is_multiple_of(out.len()), "rows of unequal length");
        let len = input.len() / out.len();
        if len == 0 {
            out.fill([0; DIGEST_WORDS]);
            return;
        }
        if SCALAR_MERKLE_LANES {
            for (digest, row) in out.iter_mut().zip(input.chunks_exact(len)) {
                *digest = leaf_digest(row);
            }
            return;
        }
        let mut rows = input.chunks_exact(len);
        let (groups, rest) = out.as_chunks_mut::<MERKLE_LANES>();
        for digests in groups {
            *digests = leaf_digests(core::array::from_fn(|_| rows.next().expect("one row per digest")));
        }
        for (digest, row) in rest.iter_mut().zip(rows) {
            *digest = leaf_digest(row);
        }
    }
}

impl<const N: usize> CryptographicHasher<[F; N], [[u64; N]; DIGEST_WORDS]> for MerkleLeafHash {
    fn hash_iter<I>(&self, input: I) -> [[u64; N]; DIGEST_WORDS]
    where
        I: IntoIterator<Item = [F; N]>,
    {
        let mut sponges = [LeafSponge::new(); N];
        for packed in input {
            for (sponge, x) in sponges.iter_mut().zip(packed) {
                sponge.absorb(x);
            }
        }
        let digests = sponges.map(LeafSponge::finish);
        core::array::from_fn(|word| core::array::from_fn(|lane| digests[lane][word]))
    }
}

/// Most field elements [`MemoDft`] keeps, inputs and LDEs together: 64 MiB.
/// The coin reveal's periodic columns take at most a third of it (290 columns
/// of 2,048 rows and their 16,384-row LDEs; equal columns share one entry),
/// the salted coin reveal's as much again.
const LDE_MEMO_ELEMS: usize = 1 << 24;

/// The single-column LDEs [`MemoDft`] has computed, keyed by the added bits,
/// the shift and the column, with the elements they hold.
struct LdeMemo {
    ldes: BTreeMap<(usize, F, Vec<F>), Vec<F>>,
    elems: usize,
}

static LDE_MEMO: Mutex<LdeMemo> = Mutex::new(LdeMemo {
    ldes: BTreeMap::new(),
    elems: 0,
});

/// The library's DFT (`Radix2DitParallel`), whose twiddles every
/// configuration shares, and which remembers the LDE of a single column.
///
/// The quotient reads the statement's periodic columns (selectors and
/// constants, several hundred of them) on the quotient domain, and the
/// library extends each one with its own LDE on every proof: about 57 ms of
/// a coin reveal on the build machine. They depend on the statement alone,
/// so each is computed once, by the library, and the same values are handed
/// back after that, up to [`LDE_MEMO_ELEMS`]. Every batch transform is the
/// library's own, so the commitments and the proof are unchanged.
#[derive(Clone, Debug)]
pub(crate) struct MemoDft(Radix2DitParallel<F>);

impl Default for MemoDft {
    fn default() -> Self {
        static SHARED: OnceLock<Radix2DitParallel<F>> = OnceLock::new();
        Self(SHARED.get_or_init(Radix2DitParallel::default).clone())
    }
}

fn lde_memo() -> MutexGuard<'static, LdeMemo> {
    LDE_MEMO.lock().unwrap_or_else(PoisonError::into_inner)
}

impl TwoAdicSubgroupDft<F> for MemoDft {
    type Evaluations = <Radix2DitParallel<F> as TwoAdicSubgroupDft<F>>::Evaluations;

    fn dft_batch(&self, mat: RowMajorMatrix<F>) -> Self::Evaluations {
        self.0.dft_batch(mat)
    }

    fn coset_dft_batch(&self, mat: RowMajorMatrix<F>, shift: F) -> Self::Evaluations {
        self.0.coset_dft_batch(mat, shift)
    }

    fn idft_batch(&self, mat: RowMajorMatrix<F>) -> RowMajorMatrix<F> {
        self.0.idft_batch(mat)
    }

    fn coset_idft_batch(&self, mat: RowMajorMatrix<F>, shift: F) -> RowMajorMatrix<F> {
        self.0.coset_idft_batch(mat, shift)
    }

    fn coset_lde_batch_with_transform<T>(
        &self,
        mat: RowMajorMatrix<F>,
        added_bits: usize,
        shift: F,
        transform: T,
    ) -> Self::Evaluations
    where
        T: FnOnce(&mut RowMajorMatrixViewMut<'_, F>, Layout),
    {
        self.0.coset_lde_batch_with_transform(mat, added_bits, shift, transform)
    }

    fn coset_lde_batch_with_blocks<T, K, C>(
        &self,
        mat: RowMajorMatrix<F>,
        added_bits: usize,
        shift: F,
        transform: T,
        make_consumer: K,
    ) -> BitReversedMatrixView<RowMajorMatrix<F>>
    where
        T: FnOnce(&mut RowMajorMatrixViewMut<'_, F>, Layout),
        K: FnOnce(usize) -> C,
        C: Fn(usize, RowMajorMatrixView<'_, F>) + Sync,
    {
        self.0.coset_lde_batch_with_blocks(mat, added_bits, shift, transform, make_consumer)
    }

    fn coset_lde(&self, vec: Vec<F>, added_bits: usize, shift: F) -> Vec<F> {
        let key = (added_bits, shift, vec);
        if let Some(lde) = lde_memo().ldes.get(&key) {
            return lde.clone();
        }
        let lde = self.0.coset_lde(key.2.clone(), added_bits, shift);
        let mut memo = lde_memo();
        let elems = key.2.len() + lde.len();
        if memo.elems + elems <= LDE_MEMO_ELEMS && memo.ldes.insert(key, lde.clone()).is_none() {
            memo.elems += elems;
        }
        lde
    }
}

/// The library's minimum trace height for zero-knowledge:
/// `N >= 2 * (num_queries + D * points)` (`HidingFriPcs`).
pub const fn zk_min_trace_height() -> usize {
    2 * (NUM_QUERIES + EXTENSION_DEGREE * TRACE_OPENING_POINTS)
}

/// The FRI settings the gate judges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FriShape {
    pub(crate) log_blowup: usize,
    pub(crate) num_queries: usize,
    pub(crate) query_pow_bits: usize,
    pub(crate) batch_pow_bits: usize,
}

/// The FRI settings that ship.
pub(crate) const SHIPPED_FRI: FriShape = FriShape {
    log_blowup: LOG_BLOWUP,
    num_queries: NUM_QUERIES,
    query_pow_bits: QUERY_POW_BITS,
    batch_pow_bits: BATCH_POW_BITS,
};

fn fri_parameters<M>(fri: &FriShape, mmcs: M) -> FriParameters<M> {
    FriParameters {
        log_blowup: fri.log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: fri.num_queries,
        batch_proof_of_work_bits: fri.batch_pow_bits,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: fri.query_pow_bits,
        mmcs,
    }
}

/// The configuration the public prove and verify functions use. `zk_seed`
/// must be fresh secure randomness when proving; the verifier draws nothing
/// from it.
pub(crate) fn stark_config(zk_seed: [u8; 32]) -> Result<Config, ProofError> {
    let mut master = StdRng::from_seed(zk_seed);
    let salts = StdRng::from_rng(&mut master);
    let masks = StdRng::from_rng(&mut master);
    let val_mmcs = ValMmcs::new(MerkleLeafHash, KeccakCompress::new(KeccakU64Hash::new(MerkleKeccak)), 0, salts);
    let fri = fri_parameters(&SHIPPED_FRI, ChallengeMmcs::new(val_mmcs.clone()));
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri, NUM_RANDOM_CODEWORDS, masks);
    let config = Config::new(pcs, Challenger::from_hasher(Vec::new(), Keccak256Hash {}));
    if config.is_zk() == 1 {
        Ok(config)
    } else {
        Err(ProofError::NotZeroKnowledge)
    }
}

/// Whether the shipped configuration is zero-knowledge, as the library
/// reports it.
pub(crate) fn shipped_is_zero_knowledge() -> bool {
    stark_config([0; 32]).is_ok_and(|config| config.is_zk() == 1)
}

/// The hash of the commitments and the transcript, recognised by what it
/// computes rather than by its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitmentHash {
    /// Keccak-256 with its original padding, the hash of spec 01.
    Keccak256,
    /// Anything else.
    Other,
}

/// The library's leaf hash, which [`MerkleLeafHash`] computes faster: field
/// elements serialized to 64-bit words for a padding-free sponge over the
/// library's Keccak-f[1600].
type LibraryLeafHash = SerializingHasher<PaddingFreeSponge<KeccakF, 25, SPONGE_RATE_LANES, DIGEST_WORDS>>;

/// The transcript hash is Keccak-256 when it agrees with spec 01's Keccak-256
/// on a message longer than one block, and the Merkle sponge runs
/// Keccak-f[1600] at Keccak-256's rate: this crate's permutation and leaf
/// hash agree with the library's on a probe longer than two blocks.
fn commitment_hash() -> CommitmentHash {
    const PROBE: &[u8; 200] = &[0x47; 200];
    let transcript = Keccak256Hash {}.hash_iter(PROBE.iter().copied());
    let mut state: [u64; 25] = core::array::from_fn(|i| 0x0123_4567_89ab_cdef_u64.rotate_left(7 * i as u32));
    let mut library_state = state;
    keccak_f(&mut state);
    KeccakF.permute_mut(&mut library_state);
    let row: Vec<F> = (0..2 * LEAF_BLOCK_ELEMS + 3)
        .map(|i| F::from_u32(u32::from(PROBE[i]) << (i % 24)))
        .collect();
    let leaf = MerkleLeafHash.hash_slice(&row);
    let library_leaf: [u64; DIGEST_WORDS] = LibraryLeafHash::new(PaddingFreeSponge::new(KeccakF)).hash_slice(&row);
    if transcript == crate::hash::keccak256(PROBE)
        && state == library_state
        && leaf == library_leaf
        && SPONGE_RATE_LANES * 8 == crate::hash::RATE_BYTES
    {
        CommitmentHash::Keccak256
    } else {
        CommitmentHash::Other
    }
}

/// Everything the rule of spec 09, section 4.1 is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Parameters {
    pub(crate) fri: FriShape,
    pub(crate) hash: CommitmentHash,
    /// Bits of a Merkle digest.
    pub(crate) merkle_digest_bits: usize,
    /// Bits of the transcript hash's output.
    pub(crate) transcript_digest_bits: usize,
    /// Whether the library reports the configuration as zero-knowledge.
    pub(crate) zero_knowledge: bool,
    /// Salt bits per opened row.
    pub(crate) salt_bits: usize,
}

/// The parameters that ship, as the library and the hash report them.
pub(crate) fn shipped_parameters() -> Parameters {
    Parameters {
        fri: SHIPPED_FRI,
        hash: commitment_hash(),
        merkle_digest_bits: DIGEST_WORDS * u64::BITS as usize,
        transcript_digest_bits: TRANSCRIPT_DIGEST_BYTES * 8,
        zero_knowledge: shipped_is_zero_knowledge(),
        salt_bits: SALT_BITS,
    }
}

/// The estimator's result for one statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityEstimate {
    /// Conjectured bits, classical, with every grinding site at its full
    /// bits.
    pub conjectured_bits: usize,
    /// Conjectured bits, classical, with the grinding at each site counted at
    /// half its bits: the smallest term the estimator reports, the figure the
    /// gate holds to [`TARGET_CONJECTURED_BITS`] (spec 09, section 4.1).
    pub conjectured_bits_half_grinding: usize,
    /// Conjectured bits against a quantum attacker: half the classical figure
    /// (spec 09, section 4.1, the quantum Fiat–Shamir bound).
    pub conjectured_quantum_bits: usize,
    /// Best proven bits for the same parameters, classical, for the record.
    pub proven_bits: usize,
    /// Proven bits against a quantum attacker, half the classical figure: a
    /// goal, not gated (spec 09, question 3).
    pub proven_quantum_bits: usize,
    /// Trace height before zero-knowledge padding.
    pub trace_height: usize,
    /// Trace width.
    pub trace_width: usize,
    /// Maximum constraint degree.
    pub constraint_degree: usize,
}

/// Apply the library's estimator (`p3-security`, through
/// `StarkSecurityParams`) to a statement at the FRI settings of `p`, once with
/// the grinding as it is and once with each site at half its bits. `None` when
/// the estimator cannot be run on the statement.
fn estimate(p: &Parameters, air: &StatementAir) -> Option<SecurityEstimate> {
    let height = air.height();
    if !height.is_power_of_two() {
        return None;
    }
    let log_height = height.trailing_zeros() as usize;
    // The committed polynomials are twice as tall after zero-knowledge padding.
    let degree_bits = log_height + 1;
    let report = |fri: &FriShape| -> Option<(usize, usize)> {
        let fri = fri_parameters(fri, ());
        let params = StarkSecurityParams::from_air::<F, Challenge, StatementAir>(
            fri.security_regime(),
            air,
            AirLayout::from_air(air),
            TwoAdicMultiplicativeCoset::new(BabyBear::ONE, log_height)?,
            CHALLENGE_FIELD_BITS,
            COLLISION_RESISTANCE_BITS,
            TRACE_OPENING_POINTS,
            OpeningShape::hiding(NUM_RANDOM_CODEWORDS),
            fri.grinding_sites(),
        );
        Some((
            ConjecturedSecurity::compute_from_params(&params, degree_bits).security_bits,
            ProvenSecurity::compute_from_proof(degree_bits, &params).security_bits(),
        ))
    };
    let (conjectured_bits, proven_bits) = report(&p.fri)?;
    let (conjectured_bits_half_grinding, _) = report(&FriShape {
        query_pow_bits: p.fri.query_pow_bits / 2,
        batch_pow_bits: p.fri.batch_pow_bits / 2,
        ..p.fri
    })?;
    let constraint_degree = get_max_constraint_degree::<F, StatementAir>(air, AirLayout::from_air(air), height)
        .max(<StatementAir as BaseAir<F>>::max_constraint_degree(air).unwrap_or(0));
    Some(SecurityEstimate {
        conjectured_bits,
        conjectured_bits_half_grinding,
        conjectured_quantum_bits: conjectured_bits / 2,
        proven_bits,
        proven_quantum_bits: proven_bits / 2,
        trace_height: height,
        trace_width: air.width(),
        constraint_degree,
    })
}

/// The statements, each with its own fixed shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Statement {
    /// S1, the one-time reveal of a salted (version 2) coin, type `0x02 0x01`:
    /// the salt is a private witness in 16 carried columns.
    SaltedCoinReveal,
    /// S2, the one-time reveal of salted (version 2) data, type `0x02 0x02`:
    /// the salt is a private witness in 16 carried columns.
    SaltedDataReveal,
    /// S3, the proof of holding of salted (version 2) data, type `0x02 0x02`:
    /// the salt is a private witness in 16 carried columns.
    SaltedHold,
}

impl Statement {
    pub const ALL: [Self; 3] = [Self::SaltedCoinReveal, Self::SaltedDataReveal, Self::SaltedHold];

    /// The coin reveal, [`Self::SaltedCoinReveal`], under the name of the
    /// version 1 statement that is gone. Kept, hidden, only for the reveal
    /// benchmark's recursion test, which reads the coin reveal's shape from
    /// the first entry of the report; remove it with that use.
    #[doc(hidden)]
    #[allow(non_upper_case_globals)]
    pub const CoinReveal: Self = Self::SaltedCoinReveal;

    const fn index(self) -> usize {
        match self {
            Self::SaltedCoinReveal => 0,
            Self::SaltedDataReveal => 1,
            Self::SaltedHold => 2,
        }
    }

    /// The statement's schedule, without any witness.
    pub(crate) fn schedule(self) -> Schedule {
        match self {
            Self::SaltedCoinReveal => crate::reveal::schedule(),
            Self::SaltedDataReveal => crate::data::schedule(),
            Self::SaltedHold => crate::hold::schedule(),
        }
    }

    pub(crate) fn air(self) -> StatementAir {
        let schedule = self.schedule();
        let height = StatementAir::height_for(&schedule, zk_min_trace_height());
        StatementAir::new(schedule, height)
    }
}

/// Items 1, 3 and 4 of the rule of spec 09, section 4.1: what the parameters
/// alone decide, before any statement is estimated.
fn check_parameters(p: &Parameters) -> Result<(), ProofError> {
    // 1. The queries alone, before grinding.
    let query_bits = p.fri.log_blowup * p.fri.num_queries;
    if query_bits < TARGET_CONJECTURED_BITS {
        return Err(ProofError::TooFewQueries { bits: query_bits });
    }
    if p.fri.query_pow_bits > MAX_GRINDING_BITS || p.fri.batch_pow_bits > MAX_GRINDING_BITS {
        return Err(ProofError::TooMuchGrinding);
    }
    // 3. Keccak-256 at its full output, in the commitments and the transcript.
    if p.hash != CommitmentHash::Keccak256
        || p.merkle_digest_bits != DIGEST_BITS
        || p.transcript_digest_bits != DIGEST_BITS
    {
        return Err(ProofError::NotKeccak256);
    }
    // 4. Hiding on, with long enough salts.
    if !p.zero_knowledge {
        return Err(ProofError::NotZeroKnowledge);
    }
    if p.salt_bits < MIN_SALT_BITS {
        return Err(ProofError::SaltTooShort { bits: p.salt_bits });
    }
    Ok(())
}

/// The budget, the constraint degree and item 2 of the rule: the estimate of
/// one statement.
fn check_estimate(p: &Parameters, est: &SecurityEstimate) -> Result<(), ProofError> {
    within_budget(est)?;
    // Zero-knowledge adds one to the quotient degree, so the constraint degree
    // must fit the blowup.
    if est.constraint_degree > 1 << p.fri.log_blowup {
        return Err(ProofError::ConstraintDegreeTooHigh);
    }
    // 2. The estimator reports its smallest term, so this holds every term,
    // the extension-field ones included, to the floor.
    if est.conjectured_bits_half_grinding < TARGET_CONJECTURED_BITS {
        return Err(ProofError::BelowSecurityFloor {
            bits: est.conjectured_bits_half_grinding,
        });
    }
    Ok(())
}

/// The whole rule for one statement at the parameters `p`: its estimate, or
/// the first item it breaks. An estimate that cannot be computed is a
/// refusal.
fn check(p: &Parameters, air: &StatementAir) -> Result<SecurityEstimate, ProofError> {
    check_parameters(p)?;
    let est = estimate(p, air).ok_or(ProofError::EstimateUnavailable)?;
    check_estimate(p, &est)?;
    Ok(est)
}

/// The security gate: the rule checked for a statement at the shipped
/// parameters, computed once.
pub(crate) fn gate(statement: Statement) -> Result<SecurityEstimate, ProofError> {
    static PLANS: [OnceLock<Result<SecurityEstimate, ProofError>>; Statement::ALL.len()] =
        [const { OnceLock::new() }; Statement::ALL.len()];
    PLANS[statement.index()]
        .get_or_init(|| check(&shipped_parameters(), &statement.air()))
        .clone()
}

/// The proof-size budget: a statement whose trace is taller or wider than the
/// coin reveal's could make a proof longer than [`PROOF_FIELD_BYTES`], so it
/// is refused before anything is proved or verified.
fn within_budget(est: &SecurityEstimate) -> Result<(), ProofError> {
    if est.trace_height > MAX_TRACE_HEIGHT || est.trace_width > MAX_TRACE_WIDTH {
        return Err(ProofError::TraceOverBudget {
            height: est.trace_height,
            width: est.trace_width,
        });
    }
    Ok(())
}

// The proof length bound. Every size is the most the encoding can write at
// the pinned Plonky3 revision, through postcard.

/// A BabyBear element: four little-endian bytes, never a varint.
const FIELD_BYTES: usize = 4;
/// A challenge: [`EXTENSION_DEGREE`] base elements, with no length prefix.
const CHALLENGE_BYTES: usize = EXTENSION_DEGREE * FIELD_BYTES;
/// The longest varint postcard writes, for a length prefix or a `usize`.
const VARINT_MAX_BYTES: usize = 10;
/// A digest: [`DIGEST_WORDS`] `u64` words, each a varint.
const DIGEST_MAX_BYTES: usize = DIGEST_WORDS * VARINT_MAX_BYTES;
/// The tag of an `Option`.
const OPTION_TAG_BYTES: usize = 1;
/// A commitment: a Merkle cap of height 0, one digest behind a length prefix.
const CAP_BYTES: usize = VARINT_MAX_BYTES + DIGEST_MAX_BYTES;
/// The most quotient chunks the gate lets through. The gate allows a
/// constraint degree `d` of at most the blowup; the library splits the
/// quotient into `2 * next_power_of_two(d)` chunks in zero-knowledge mode.
const MAX_QUOTIENT_CHUNKS: usize = 2 * (1 << LOG_BLOWUP);
/// Base columns of the quotient chunks and of the randomization polynomial:
/// one challenge flattened, before the hiding columns.
const FLATTENED_CHALLENGE_COLUMNS: usize = EXTENSION_DEGREE;

/// A sequence of `len` items of `item` bytes each, behind its length prefix.
const fn seq(len: usize, item: usize) -> usize {
    VARINT_MAX_BYTES + len * item
}

/// The most sibling digests a pruned multiproof for [`NUM_QUERIES`] indices
/// can carry in a binary tree of `depth` levels: at each level at most one
/// per parent of a queried node, so at most one per query and at most the
/// number of parents at that level.
fn multiproof_digests(depth: usize) -> usize {
    (0..depth).map(|level| NUM_QUERIES.min(1 << level)).sum()
}

/// The longest proof the shipped configuration can serialize for a statement
/// whose trace has `trace_height` rows (before zero-knowledge padding) and
/// `trace_width` columns. It is a bound from the proof's structure, not a
/// sampled length: every term takes its worst case (spec 07, section 3).
pub fn proof_length_bound(trace_height: usize, trace_width: usize) -> usize {
    let h = trace_height.max(zk_min_trace_height()).next_power_of_two();
    // Zero-knowledge doubles the rows, and the blowup gives the codeword.
    let log_codeword = (2 * h).trailing_zeros() as usize + LOG_BLOWUP;
    // Binary folding down to a final polynomial of one coefficient.
    let fri_rounds = log_codeword - LOG_BLOWUP;
    let chunks = MAX_QUOTIENT_CHUNKS;
    let challenges = |n| seq(n, CHALLENGE_BYTES);
    let row = |n| seq(n, FIELD_BYTES);

    // Trace, quotient and the optional randomization commitment.
    let commitments = 3 * CAP_BYTES + OPTION_TAG_BYTES;
    // The trace at zeta and zeta * g, no preprocessed trace (two absent
    // options), each quotient chunk at zeta and the randomization polynomial.
    let opened_values = challenges(trace_width)
        + OPTION_TAG_BYTES
        + challenges(trace_width)
        + 2 * OPTION_TAG_BYTES
        + seq(chunks, challenges(FLATTENED_CHALLENGE_COLUMNS))
        + OPTION_TAG_BYTES
        + challenges(FLATTENED_CHALLENGE_COLUMNS);
    // The hidden columns' openings, per round, matrix and point.
    let hidden = challenges(NUM_RANDOM_CODEWORDS);
    let hidden_openings = VARINT_MAX_BYTES
        + seq(1, seq(1, hidden))
        + seq(1, seq(TRACE_OPENING_POINTS, hidden))
        + seq(chunks, seq(1, hidden));
    // One input batch: every query's rows, every query's salts and one
    // pruned multiproof over the codeword tree.
    let batch = |matrices: usize, width: usize| {
        seq(NUM_QUERIES, seq(matrices, row(width)))
            + seq(NUM_QUERIES, seq(matrices, row(SALT_ELEMS)))
            + seq(multiproof_digests(log_codeword), DIGEST_MAX_BYTES)
    };
    let input_openings = VARINT_MAX_BYTES
        + batch(1, NUM_RANDOM_CODEWORDS + FLATTENED_CHALLENGE_COLUMNS)
        + batch(1, trace_width + NUM_RANDOM_CODEWORDS)
        + batch(chunks, FLATTENED_CHALLENGE_COLUMNS + NUM_RANDOM_CODEWORDS);
    // Each FRI layer: one sibling per query, its salts and its multiproof;
    // layer `i` is a tree of `log_codeword - 1 - i` levels.
    let layers: usize = (0..fri_rounds)
        .map(|i| {
            seq(NUM_QUERIES, challenges(1))
                + seq(NUM_QUERIES, seq(1, row(SALT_ELEMS)))
                + seq(multiproof_digests(log_codeword - 1 - i), DIGEST_MAX_BYTES)
        })
        .sum();
    let fri = FIELD_BYTES
        + seq(fri_rounds, CAP_BYTES)
        + seq(fri_rounds, FIELD_BYTES)
        + input_openings
        + VARINT_MAX_BYTES
        + layers
        + challenges(1)
        + FIELD_BYTES;
    // Then `degree_bits` and the out-of-domain grinding witness.
    commitments + opened_values + hidden_openings + fri + VARINT_MAX_BYTES + FIELD_BYTES
}

fn public_field(public: &[u8]) -> Vec<F> {
    public.iter().map(|&b| F::from_u8(b)).collect()
}

/// Prove an assignment of a statement. The caller has already checked the
/// witness; nothing here does.
pub(crate) fn prove(statement: Statement, a: &Assignment, zk_seed: [u8; 32]) -> Result<Vec<u8>, ProofError> {
    prove_with(statement, a, zk_seed, None)
}

/// [`prove`], with the ordering test's `zero_next` flag forced when given
/// (see [`StatementAir::generate_trace_with`]), for tests of a lying prover.
pub(crate) fn prove_with(
    statement: Statement,
    a: &Assignment,
    zk_seed: [u8; 32],
    zero_next: Option<bool>,
) -> Result<Vec<u8>, ProofError> {
    gate(statement)?;
    let air = statement.air();
    let ex = execute(&statement.schedule(), a);
    let trace = air.generate_trace_with(&ex, a, zero_next);
    let config = stark_config(zk_seed)?;
    let proof = p3_uni_stark::prove(&config, &air, trace, &public_field(&a.public)).map_err(|_| ProofError::Proving)?;
    postcard::to_allocvec(&proof).map_err(|_| ProofError::Proving)
}

/// Verify a proof of a statement against public values the verifier built.
pub(crate) fn verify(statement: Statement, public: &[u8], proof: &[u8]) -> Result<(), ProofError> {
    gate(statement)?;
    let air = statement.air();
    if public.len() != air.num_public_values() {
        return Err(ProofError::Rejected);
    }
    let config = stark_config([0; 32])?;
    let proof: StarkProof<Config> = postcard::from_bytes(proof).map_err(|_| ProofError::MalformedProof)?;
    let expected_degree_bits = air.height().trailing_zeros() as usize + 1;
    if proof.degree_bits != expected_degree_bits {
        return Err(ProofError::MalformedProof);
    }
    p3_uni_stark::verify(&config, &air, &proof, &public_field(public)).map_err(|_| ProofError::Rejected)
}

/// The length of the one serialized proof at the start of `bytes`, or `None`
/// when no proof of the shipped configuration decodes there.
pub(crate) fn serialized_len(bytes: &[u8]) -> Option<usize> {
    let (_, rest) = postcard::take_from_bytes::<StarkProof<Config>>(bytes).ok()?;
    Some(bytes.len() - rest.len())
}

/// The gate's estimate for every statement, for the shipped configuration
/// report.
pub(crate) fn estimates() -> Result<[(Statement, SecurityEstimate); Statement::ALL.len()], ProofError> {
    let mut out = [(Statement::SaltedCoinReveal, gate(Statement::SaltedCoinReveal)?); Statement::ALL.len()];
    for (slot, statement) in out.iter_mut().zip(Statement::ALL) {
        *slot = (statement, gate(statement)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(trace_height: usize, trace_width: usize) -> SecurityEstimate {
        SecurityEstimate {
            conjectured_bits: TARGET_CONJECTURED_BITS,
            conjectured_bits_half_grinding: TARGET_CONJECTURED_BITS,
            conjectured_quantum_bits: TARGET_CONJECTURED_BITS / 2,
            proven_bits: 0,
            proven_quantum_bits: 0,
            trace_height,
            trace_width,
            constraint_degree: 1 << LOG_BLOWUP,
        }
    }

    /// The gate refuses a trace one row or one column over the budget, and
    /// takes the budget trace itself.
    #[test]
    fn budget_refuses_a_trace_over_it() {
        assert_eq!(within_budget(&trace(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH)), Ok(()));
        assert_eq!(
            within_budget(&trace(2 * MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH)),
            Err(ProofError::TraceOverBudget {
                height: 2 * MAX_TRACE_HEIGHT,
                width: MAX_TRACE_WIDTH
            })
        );
        assert_eq!(
            within_budget(&trace(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH + 1)),
            Err(ProofError::TraceOverBudget {
                height: MAX_TRACE_HEIGHT,
                width: MAX_TRACE_WIDTH + 1
            })
        );
    }

    /// Each extra column adds its two out-of-domain challenges and one base
    /// element per query; a doubled height adds a level to every tree.
    #[test]
    fn bound_grows_with_the_trace() {
        let base = proof_length_bound(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH);
        assert_eq!(
            proof_length_bound(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH + 1) - base,
            2 * CHALLENGE_BYTES + NUM_QUERIES * FIELD_BYTES
        );
        assert!(proof_length_bound(2 * MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH) > base);
        assert_eq!(proof_length_bound(1000, 10), proof_length_bound(1024, 10));
    }

    /// QS-12: the gate takes the shipped parameters and refuses each item of
    /// the rule of spec 09, section 4.1 broken on its own: too few queries, an
    /// estimate short only because grinding counts at half, a hash or digest
    /// that is not Keccak-256's, hiding off, short salts.
    #[test]
    fn gate_refuses_a_configuration_below_the_quantum_rule() {
        let air = Statement::SaltedCoinReveal.air();
        let shipped = shipped_parameters();
        assert_eq!(shipped.hash, CommitmentHash::Keccak256);
        assert_eq!((shipped.merkle_digest_bits, shipped.transcript_digest_bits), (256, 256));
        assert!(shipped.zero_knowledge);
        assert_eq!(shipped.salt_bits, 154);
        let est = check(&shipped, &air).expect("the shipped parameters meet the rule");
        assert!(est.conjectured_bits_half_grinding >= TARGET_CONJECTURED_BITS);
        assert_eq!(gate(Statement::SaltedCoinReveal), Ok(est));

        let with_fri = |fri: FriShape| Parameters { fri, ..shipped };

        // Item 1: 42 queries at rate 1/8 are 126 bits, refused before the
        // estimator runs, however much grinding there is.
        let too_few = with_fri(FriShape {
            num_queries: 42,
            ..SHIPPED_FRI
        });
        assert_eq!(check(&too_few, &air), Err(ProofError::TooFewQueries { bits: 126 }));
        // So is rate 1/4 with the 57 queries of the earlier configuration: 114.
        let earlier = with_fri(FriShape {
            log_blowup: 2,
            num_queries: 57,
            ..SHIPPED_FRI
        });
        assert_eq!(check(&earlier, &air), Err(ProofError::TooFewQueries { bits: 114 }));

        // Item 2: one bit of query grinding passes the queries' own rule (129)
        // and an estimate with grinding at full value, but not with grinding
        // counted at half.
        let short = with_fri(FriShape {
            query_pow_bits: 1,
            ..SHIPPED_FRI
        });
        let short_est = estimate(&short, &air).expect("the estimator runs");
        assert!(short_est.conjectured_bits >= TARGET_CONJECTURED_BITS, "{short_est:?}");
        assert!(short_est.conjectured_bits_half_grinding < TARGET_CONJECTURED_BITS, "{short_est:?}");
        assert_eq!(
            check(&short, &air),
            Err(ProofError::BelowSecurityFloor {
                bits: short_est.conjectured_bits_half_grinding
            })
        );
        // The batching term needs its grinding too: without it the estimate is
        // short, whatever the queries give.
        let no_batch_grinding = with_fri(FriShape {
            batch_pow_bits: 0,
            ..SHIPPED_FRI
        });
        assert!(matches!(
            check(&no_batch_grinding, &air),
            Err(ProofError::BelowSecurityFloor { bits }) if bits < TARGET_CONJECTURED_BITS
        ));
        // More grinding than a site allows is refused, not counted.
        let ground = with_fri(FriShape {
            num_queries: 30,
            query_pow_bits: 40,
            ..SHIPPED_FRI
        });
        assert_eq!(check(&ground, &air), Err(ProofError::TooFewQueries { bits: 90 }));
        let over = with_fri(FriShape {
            query_pow_bits: MAX_GRINDING_BITS + 1,
            ..SHIPPED_FRI
        });
        assert_eq!(check(&over, &air), Err(ProofError::TooMuchGrinding));

        // Item 3: another hash, or a shorter digest in either place.
        for broken in [
            Parameters {
                hash: CommitmentHash::Other,
                ..shipped
            },
            Parameters {
                merkle_digest_bits: 160,
                ..shipped
            },
            Parameters {
                transcript_digest_bits: 128,
                ..shipped
            },
        ] {
            assert_eq!(check(&broken, &air), Err(ProofError::NotKeccak256), "{broken:?}");
        }

        // Item 4: hiding off, or salts under 128 bits.
        let open = Parameters {
            zero_knowledge: false,
            ..shipped
        };
        assert_eq!(check(&open, &air), Err(ProofError::NotZeroKnowledge));
        let salted = Parameters {
            salt_bits: MIN_SALT_BITS - 1,
            ..shipped
        };
        assert_eq!(
            check(&salted, &air),
            Err(ProofError::SaltTooShort {
                bits: MIN_SALT_BITS - 1
            })
        );
    }

    /// Field elements from a counter, spread over the field.
    fn elements(seed: u32, len: usize) -> Vec<F> {
        (0..len as u32).map(|i| F::from_u32(seed.wrapping_mul(0x9e37_79b9) ^ i.wrapping_mul(0x85eb_ca6b))).collect()
    }

    /// The Merkle permutation is the library's Keccak-f[1600], on one state
    /// and on a packed state.
    #[test]
    fn merkle_permutation_is_the_library_permutation() {
        for seed in 0..4u64 {
            let state: [u64; 25] =
                core::array::from_fn(|i| (seed * 25 + i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let (mut ours, mut library) = (state, state);
            MerkleKeccak.permute_mut(&mut ours);
            KeccakF.permute_mut(&mut library);
            assert_eq!(ours, library);

            let packed: [[u64; MERKLE_LANES]; 25] =
                core::array::from_fn(|i| core::array::from_fn(|lane| state[i].rotate_left(lane as u32 * 9)));
            let (mut ours, mut library) = (packed, packed);
            MerkleKeccak.permute_mut(&mut ours);
            KeccakF.permute_mut(&mut library);
            assert_eq!(ours, library);
        }
    }

    /// The leaf hash gives the library's digest for rows of every shape: empty,
    /// one element, part blocks of odd and even length, whole blocks, and the
    /// width of the salted coin reveal's committed rows; one row at a time, a
    /// batch of rows (whole lane groups and a remainder) and packed rows.
    #[test]
    fn leaf_hash_is_the_library_leaf_hash() {
        let library = LibraryLeafHash::new(PaddingFreeSponge::new(KeccakF));
        let lengths = [0, 1, 2, 3, 33, 34, 35, 67, 68, 69, 101, MAX_TRACE_WIDTH + NUM_RANDOM_CODEWORDS + SALT_ELEMS];
        for len in lengths {
            let count = 2 * MERKLE_LANES + 1;
            let rows: Vec<Vec<F>> = (0..count as u32).map(|seed| elements(seed + 1, len)).collect();
            let expected: Vec<[u64; DIGEST_WORDS]> = rows.iter().map(|row| library.hash_slice(row)).collect();

            for (row, want) in rows.iter().zip(&expected) {
                assert_eq!(&MerkleLeafHash.hash_slice(row), want, "length {len}");
                assert_eq!(&MerkleLeafHash.hash_iter(row.iter().copied()), want, "length {len}");
            }

            let mut batch = vec![[0; DIGEST_WORDS]; count];
            MerkleLeafHash.hash_many(&rows.concat(), &mut batch);
            assert_eq!(batch, expected, "length {len}");

            let packed: [[u64; MERKLE_LANES]; DIGEST_WORDS] =
                MerkleLeafHash.hash_iter((0..len).map(|i| core::array::from_fn(|lane| rows[lane][i])));
            for (lane, want) in expected.iter().take(MERKLE_LANES).enumerate() {
                let digest: [u64; DIGEST_WORDS] = core::array::from_fn(|word| packed[word][lane]);
                assert_eq!(&digest, want, "length {len}, lane {lane}");
            }
        }
    }

    /// A commitment with this crate's hashes is the one the library's hashes
    /// make from the same rows and salts, and its openings verify.
    #[test]
    fn commitments_match_the_library_trees() {
        use p3_commit::Mmcs;
        use p3_matrix::Matrix;
        use p3_matrix::dense::RowMajorMatrix;

        type LibraryU64Hash = PaddingFreeSponge<KeccakF, 25, SPONGE_RATE_LANES, DIGEST_WORDS>;
        type LibraryMmcs = MerkleTreeHidingMmcs<
            [F; p3_keccak::VECTOR_LEN],
            [u64; p3_keccak::VECTOR_LEN],
            LibraryLeafHash,
            CompressionFunctionFromHasher<LibraryU64Hash, 2, DIGEST_WORDS>,
            StdRng,
            2,
            DIGEST_WORDS,
            SALT_ELEMS,
        >;
        let compress = KeccakCompress::new(KeccakU64Hash::new(MerkleKeccak));
        let ours = ValMmcs::new(MerkleLeafHash, compress, 0, StdRng::seed_from_u64(9));
        let u64_hash = LibraryU64Hash::new(KeccakF);
        let library_compress = CompressionFunctionFromHasher::new(u64_hash);
        let library = LibraryMmcs::new(LibraryLeafHash::new(u64_hash), library_compress, 0, StdRng::seed_from_u64(9));

        for (height, width) in [(64, 77), (37, 3), (8, 1)] {
            let matrix = RowMajorMatrix::new(elements(height as u32, height * width), width);
            let (commitment, data) = ours.commit_matrix(matrix.clone());
            let (library_commitment, _) = library.commit_matrix(matrix.clone());
            assert_eq!(commitment, library_commitment, "{height} by {width}");

            let index = height / 3;
            let opening = ours.open_batch(index, &data);
            assert_eq!(opening.opened_values[0], matrix.row_slice(index).unwrap().to_vec());
            assert!(ours.verify_batch(&commitment, &[matrix.dimensions()], index, (&opening).into()).is_ok());
        }
    }

    /// The periodic tables built with the memoizing DFT are the library's, cell
    /// for cell, for the coin reveal and the data reveal, at two shifts and two
    /// blowups, on the first build (computed) and the second (remembered); and
    /// a single column gets the library's LDE at each shift, not one
    /// remembered for another.
    #[test]
    fn memoized_periodic_ldes_are_the_library_ones() {
        use p3_field::Field;
        use p3_fri::build_periodic_lde_table_two_adic;

        let library = Radix2DitParallel::<F>::default();
        for statement in [Statement::SaltedCoinReveal, Statement::SaltedDataReveal] {
            let air = statement.air();
            let columns = air.periodic_columns();
            let log_height = air.height().trailing_zeros() as usize;
            let trace_domain = TwoAdicMultiplicativeCoset::new(F::ONE, log_height).unwrap();
            for (shift, added_bits) in [(F::GENERATOR, 2), (F::GENERATOR.square(), 3)] {
                let lde = TwoAdicMultiplicativeCoset::new(shift, log_height + added_bits).unwrap();
                let expected = build_periodic_lde_table_two_adic(&library, &*columns, &trace_domain, &lde);
                for _ in 0..2 {
                    let table = build_periodic_lde_table_two_adic(&Dft::default(), &*columns, &trace_domain, &lde);
                    assert_eq!((table.width(), table.height()), (expected.width(), expected.height()));
                    for row in 0..expected.height() {
                        for col in 0..expected.width() {
                            assert_eq!(table.get(row, col), expected.get(row, col), "{statement:?} {row} {col}");
                        }
                    }
                }
            }
        }

        let column = elements(7, 64);
        for shift in [F::GENERATOR, F::GENERATOR.square(), F::ONE] {
            for added_bits in [1, 3] {
                let expected = library.coset_lde(column.clone(), added_bits, shift);
                assert_eq!(Dft::default().coset_lde(column.clone(), added_bits, shift), expected);
                assert_eq!(Dft::default().coset_lde(column.clone(), added_bits, shift), expected);
            }
        }
    }

    /// A multiproof never needs more than one digest per query per level, nor
    /// more than the level has parents.
    #[test]
    fn multiproof_digests_take_the_worst_level_by_level() {
        assert_eq!(multiproof_digests(1), 1);
        assert_eq!(multiproof_digests(6), 63);
        assert_eq!(multiproof_digests(14), 63 + 8 * NUM_QUERIES);
    }
}
