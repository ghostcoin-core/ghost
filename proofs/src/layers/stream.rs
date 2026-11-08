//! The layers' prover, streamed: a batch STARK of the layer tables proven
//! the way the pinned library's `prove_batch` under the scale configuration
//! proves it, transcript for transcript and byte for byte, without ever
//! holding a matrix over its extended domain whole.
//!
//! The library extends every committed matrix (main, permutation trace,
//! quotient chunks, randomization, and the key's preprocessed columns) by the
//! zero-knowledge doubling and the blowup, and keeps each extension with its
//! Merkle tree and salts until the last opening: sixteen times the doubled
//! matrix at blowup 2^3, and two digests and a salt a row. Here each matrix is
//! kept as its polynomials' coefficients over the doubled domain, and its
//! extension is evaluated one block of rows at a time, three times over:
//!
//! - to commit: each block's rows, salted, are hashed into the block's Merkle
//!   subtree, and only the block roots and the levels above them are kept;
//! - to batch the openings: each block's rows are folded into the batched
//!   quotient `sum alpha^i (y_i - p_i(x)) / (z - x)` of its height;
//! - to answer the queries: each block a query falls in is evaluated again,
//!   its subtree rebuilt, and the query's rows, salt and path read from it.
//!
//! The rows of a bit-reversed extension that one block holds are the values
//! on one coset of a smaller subgroup, so a block is one coset transform of
//! the coefficients folded to the block's size. The salts of a block are
//! read again from the salt stream at the word it started at: the stream is
//! the ChaCha12 keystream `StdRng` draws from, so a block's salts are the
//! library's. The quotient is computed one chunk at a time on that chunk's
//! own coset, which is the size of the trace; the library's own quotient
//! evaluation, folding, Merkle trees, transcripts and opening checks are
//! used throughout, so every commitment, challenge and opened value is the
//! library's, and its verifier, unchanged, accepts the proof.

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::marker::PhantomData;

use p3_air::BaseAir;
use p3_air::symbolic::AirLayout;
use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
use p3_batch_stark::proof::OpenedValuesWithLookups;
use p3_batch_stark::prover::quotient_values;
use p3_batch_stark::{
    BatchCommitments, BatchOpenedValues, BatchProof, BatchProverTranscript, BatchShape, CommonData,
};
use p3_commit::{ExtensionMmcs, Mmcs, OpenedValues as PcsOpenedValues, PolynomialSpace};
use p3_dft::{Radix2DFTSmallBatch, Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, TwoAdicField, batch_multiplicative_inverse};
use p3_fri::{
    BatchMultiOpening, CommitPhaseMultiStep, FriFoldingStrategy, FriParameters, FriProof, PcsProverTranscript,
    PcsShape, ProverTranscript, TwoAdicFriFolding,
};
use p3_lookup::{LogUpGadget, LookupProtocol, LookupTerminal, Lookups, check_multiplicity_height_bound};
use p3_matrix::Matrix;
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::util::reverse_matrix_index_bits;
use p3_merkle_tree::{MerkleCap, MerkleTreeHidingMmcs, MerkleTreeMmcs, PrunedMerklePaths};
use p3_symmetric::{PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation};
use p3_uni_stark::{OpenedValues, PreprocessedOpenedValues, StarkGenericConfig};
use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng, TryRng};

use super::tables::TableAir;
use super::{EF, F};
use crate::ProofError;
use crate::scale::{ScaleChallenger, ScaleConfig};
use crate::stark::FriShape;

/// Salt elements of a Merkle leaf.
const SALT: usize = crate::scale::SCALE_SALT_ELEMS;
/// Elements of a digest.
const DIGEST_ELEMS: usize = super::pcs::DIGEST;
/// Random codewords hiding FRI appends to each committed matrix.
const RANDOM: usize = crate::scale::SCALE_RANDOM_CODEWORDS;
/// Coefficients of an extension value.
const D: usize = 8;

/// The most bytes one block of extended rows may take with its salts and
/// its Merkle subtree, unless a commitment's smallest matrix allows no more
/// blocks.
pub(crate) const BLOCK_BYTES: usize = 1 << 31;

/// A commitment whose extension fits one block of at most this many bytes
/// keeps that block and its Merkle tree from the commitment to the last
/// opening instead of evaluating it again: a small layer proves as fast as
/// the library's prover would.
pub(crate) const KEEP_BYTES: usize = 1 << 30;

/// Bytes of one block of a commitment of matrices `(log extended height,
/// width)` cut into `blocks` blocks: every matrix's rows in the block with
/// their salts, and the block's Merkle subtree (two digests a row of the
/// tallest).
pub(crate) fn block_bytes(mats: &[(usize, usize)], blocks: usize) -> usize {
    let log_max = mats.iter().map(|m| m.0).max().unwrap_or(0);
    let rows: usize = mats.iter().map(|&(l, w)| ((1usize << l) / blocks) * (w + SALT) * 4).sum();
    rows + ((1usize << log_max) / blocks) * 2 * 4 * DIGEST_ELEMS
}

/// The most bytes evaluating one block holds: the block ([`block_bytes`])
/// and the widest matrix's rows of it before they are salted.
pub(crate) fn block_peak(mats: &[(usize, usize)], blocks: usize) -> usize {
    block_bytes(mats, blocks) + mats.iter().map(|&(l, w)| ((1usize << l) / blocks) * w * 4).max().unwrap_or(0)
}

/// The fewest blocks (a power of two) whose block takes at most `budget`
/// bytes, and never more blocks than the commitment's smallest matrix has
/// rows.
pub(crate) fn block_count(mats: &[(usize, usize)], budget: usize) -> usize {
    let most = mats.iter().map(|m| 1usize << m.0).min().unwrap_or(1);
    let mut blocks = 1;
    while blocks < most && block_bytes(mats, blocks) > budget {
        blocks *= 2;
    }
    blocks
}

/// Bytes a commitment of these matrices keeps whole ([`KEEP_BYTES`]): its
/// one block, when it has only one.
pub(crate) fn kept_bytes(mats: &[(usize, usize)], budget: usize) -> usize {
    let bytes = block_bytes(mats, 1);
    if block_count(mats, budget) == 1 && bytes <= KEEP_BYTES { bytes } else { 0 }
}

type Perm = p3_baby_bear::Poseidon2BabyBear<24>;
type Hash = PaddingFreeSponge<Perm, 24, 15, DIGEST_ELEMS>;
type Compress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, 24>;
type Packed = <F as Field>::Packing;
type PlainMmcs = MerkleTreeMmcs<Packed, Packed, Hash, Compress, 2, DIGEST_ELEMS>;
type ValMmcs = MerkleTreeHidingMmcs<Packed, Packed, Hash, Compress, StdRng, 2, DIGEST_ELEMS, SALT>;
type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;
type PlainTree = <PlainMmcs as Mmcs<F>>::ProverData<RowMajorMatrix<F>>;
type Digest = [F; DIGEST_ELEMS];
type Com = MerkleCap<F, Digest>;
type Dft = Radix2DitParallel<F>;
type PcsProof = p3_batch_stark::PcsProof<ScaleConfig>;

fn plain_mmcs() -> PlainMmcs {
    let perm = crate::scale::scale_permutation();
    PlainMmcs::new(Hash::new(perm.clone()), Compress::new(perm), 0)
}

fn log2(n: usize) -> usize {
    debug_assert!(n.is_power_of_two());
    n.trailing_zeros() as usize
}

/// `i` with its low `bits` bits reversed.
fn rev(i: usize, bits: usize) -> usize {
    if bits == 0 { 0 } else { i.reverse_bits() >> (usize::BITS as usize - bits) }
}

fn reverse_slice_bits<T>(v: &mut [T]) {
    let bits = log2(v.len());
    for i in 0..v.len() {
        let j = rev(i, bits);
        if i < j {
            v.swap(i, j);
        }
    }
}

// ---------------------------------------------------------------------------
// The salt stream.

const CHACHA_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// Block `counter` of the ChaCha12 keystream under `key`, stream zero.
fn chacha12_block(key: &[u32; 8], counter: u64) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&CHACHA_CONSTANTS);
    s[4..12].copy_from_slice(key);
    s[12] = counter as u32;
    s[13] = (counter >> 32) as u32;
    let mut x = s;
    for _ in 0..6 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }
    for (o, i) in x.iter_mut().zip(s) {
        *o = o.wrapping_add(i);
    }
    x
}

/// The words `StdRng::from_seed(seed)` draws, from any word on: the ChaCha12
/// keystream, read one 32-bit word at a time.
#[derive(Clone, Debug)]
pub(crate) struct SaltStream {
    key: [u32; 8],
    word: u64,
    cached: u64,
    block: [u32; 16],
}

impl SaltStream {
    pub(crate) fn new(seed: &[u8; 32], word: u64) -> Self {
        Self {
            key: core::array::from_fn(|i| {
                u32::from_le_bytes([seed[4 * i], seed[4 * i + 1], seed[4 * i + 2], seed[4 * i + 3]])
            }),
            word,
            cached: u64::MAX,
            block: [0; 16],
        }
    }

    /// The word the next draw reads.
    pub(crate) fn position(&self) -> u64 {
        self.word
    }

    fn next_word(&mut self) -> u32 {
        let b = self.word >> 4;
        if b != self.cached {
            self.block = chacha12_block(&self.key, b);
            self.cached = b;
        }
        let w = self.block[(self.word & 15) as usize];
        self.word += 1;
        w
    }
}

impl TryRng for SaltStream {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.next_word())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let lo = u64::from(self.next_word());
        let hi = u64::from(self.next_word());
        Ok((hi << 32) | lo)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(4) {
            let w = self.next_word().to_le_bytes();
            chunk.copy_from_slice(&w[..chunk.len()]);
        }
        Ok(())
    }
}

/// Where the next commitment's salts start: the stream's seed and word.
struct SaltCursor {
    seed: [u8; 32],
    word: u64,
}

/// The randomness of a proof at `zk_seed`, derived as the scale
/// configuration derives it: the master generator seeds the salts of the
/// input commitments, then the masks; the salts' first draw seeds the salts
/// of the folding commitments.
struct Randomness {
    salts: SaltCursor,
    masks: StdRng,
    fri_salts: StdRng,
}

impl Randomness {
    fn of(zk_seed: [u8; 32]) -> Self {
        let mut master = StdRng::from_seed(zk_seed);
        let mut salt_seed = [0u8; 32];
        master.fill_bytes(&mut salt_seed);
        let masks = StdRng::from_rng(&mut master);
        // The folding commitments' scheme is a clone of the input one, which
        // reseeds from the input salts' first eight words.
        let fri_salts = StdRng::from_rng(&mut StdRng::from_seed(salt_seed));
        Self {
            salts: SaltCursor {
                seed: salt_seed,
                word: 8,
            },
            masks,
            fri_salts,
        }
    }
}

/// The salts of `rows` rows, read from `stream`.
fn salts(stream: &mut SaltStream, rows: usize) -> Vec<F> {
    (0..rows * SALT).map(|_| stream.random()).collect()
}

// ---------------------------------------------------------------------------
// Matrices kept as coefficients, evaluated a block at a time.

/// One committed matrix, as the coefficients (in `x`, row `j` the
/// coefficients of `x^j`) of the polynomials whose evaluations on the coset
/// `g K` (`|K| = 2^log_lde`, bit-reversed) it commits to.
pub(crate) struct Poly {
    coeffs: RowMajorMatrix<F>,
    log_lde: usize,
}

impl Poly {
    fn width(&self) -> usize {
        self.coeffs.width()
    }

    /// The first `cols` columns' coefficients reduced modulo `x^size -
    /// t`: their values on a coset of size `size` whose points' `size`-th
    /// power is `t`.
    fn fold(&self, size: usize, t: F, cols: usize) -> RowMajorMatrix<F> {
        let w = self.coeffs.width();
        let d = self.coeffs.height();
        let mut out = F::zero_vec(size * cols);
        let mut factor = F::ONE;
        let mut start = 0;
        while start < d {
            for k in 0..size.min(d - start) {
                let src = &self.coeffs.values[(start + k) * w..(start + k) * w + cols];
                let dst = &mut out[k * cols..(k + 1) * cols];
                if start == 0 {
                    dst.copy_from_slice(src);
                } else {
                    for (o, &c) in dst.iter_mut().zip(src) {
                        *o += factor * c;
                    }
                }
            }
            factor *= t;
            start += size;
        }
        RowMajorMatrix::new(out, cols)
    }

    /// The first `cols` columns on the coset `shift <w>` of size
    /// `2^log_size`, in bit-reversed order.
    fn on_coset_bitrev(&self, dft: &Dft, shift: F, log_size: usize, cols: usize) -> RowMajorMatrix<F> {
        let folded = self.fold(1 << log_size, shift.exp_power_of_2(log_size), cols);
        dft.coset_dft_batch(folded, shift).bit_reverse_rows()
    }

    /// The first `cols` columns on the coset `shift <w>` of size
    /// `2^log_size`, in natural order.
    fn on_coset(&self, dft: &Dft, shift: F, log_size: usize, cols: usize) -> RowMajorMatrix<F> {
        let mut m = self.on_coset_bitrev(dft, shift, log_size, cols);
        reverse_matrix_index_bits(&mut m);
        m
    }

    /// The shift of block `b` of `blocks`: rows `[b L, (b + 1) L)` of the
    /// bit-reversed extension are the coset `g w_N^rev(b)` of the subgroup
    /// of size `L = N / blocks`, bit-reversed.
    fn block_shift(&self, blocks: usize, b: usize) -> F {
        F::GENERATOR * F::two_adic_generator(self.log_lde).exp_u64(rev(b, log2(blocks)) as u64)
    }

    /// Rows `[b L, (b + 1) L)` of the bit-reversed extension.
    fn block(&self, dft: &Dft, blocks: usize, b: usize) -> RowMajorMatrix<F> {
        self.on_coset_bitrev(dft, self.block_shift(blocks, b), self.log_lde - log2(blocks), self.width())
    }

    /// The points of block `b`, in the order its rows hold them.
    fn block_points(&self, blocks: usize, b: usize) -> Vec<F> {
        let log_l = self.log_lde - log2(blocks);
        let shift = self.block_shift(blocks, b);
        let natural: Vec<F> = F::two_adic_generator(log_l).shifted_powers(shift).take(1 << log_l).collect();
        (0..1usize << log_l).map(|t| natural[rev(t, log_l)]).collect()
    }

    /// Each column's polynomial at each of `points`.
    fn eval(&self, points: &[EF]) -> Vec<Vec<EF>> {
        let w = self.width();
        let mut acc = vec![EF::zero_vec(w); points.len()];
        let mut pows = vec![EF::ONE; points.len()];
        for row in self.coeffs.values.chunks(w) {
            for ((a, p), &z) in acc.iter_mut().zip(pows.iter_mut()).zip(points) {
                for (o, &c) in a.iter_mut().zip(row) {
                    *o += *p * c;
                }
                *p *= z;
            }
        }
        acc
    }
}

/// The coefficients of evaluations over the subgroup of their height.
fn coefficients(dft: &Dft, evals: RowMajorMatrix<F>, log_lde: usize) -> Poly {
    Poly {
        coeffs: dft.idft_batch(evals),
        log_lde,
    }
}

/// One commitment: its matrices as coefficients, the word of the salt
/// stream each block's salts start at, and its Merkle tree from the block
/// roots up (the root last).
pub(crate) struct Committed {
    polys: Vec<Poly>,
    blocks: usize,
    seed: [u8; 32],
    salt_words: Vec<Vec<u64>>,
    upper: Vec<Vec<Digest>>,
    kept: Option<PlainTree>,
}

impl Committed {
    fn log_max(&self) -> usize {
        self.polys.iter().map(|p| p.log_lde).max().unwrap_or(0)
    }

    /// Every matrix's rows in block `b`, each followed by its salt.
    fn salted_block(&self, dft: &Dft, b: usize) -> Vec<RowMajorMatrix<F>> {
        self.polys
            .iter()
            .zip(&self.salt_words)
            .map(|(p, words)| {
                let evals = p.block(dft, self.blocks, b);
                let (rows, w) = (evals.height(), evals.width());
                let mut stream = SaltStream::new(&self.seed, words[b]);
                let salt = salts(&mut stream, rows);
                let mut out = Vec::with_capacity(rows * (w + SALT));
                for r in 0..rows {
                    out.extend_from_slice(&evals.values[r * w..(r + 1) * w]);
                    out.extend_from_slice(&salt[r * SALT..(r + 1) * SALT]);
                }
                RowMajorMatrix::new(out, w + SALT)
            })
            .collect()
    }

    /// Block `b`'s Merkle subtree over its salted rows.
    fn block_tree(&self, dft: &Dft, b: usize) -> Cow<'_, PlainTree> {
        match &self.kept {
            Some(tree) => Cow::Borrowed(tree),
            None => Cow::Owned(plain_mmcs().commit(self.salted_block(dft, b)).1),
        }
    }

    /// Matrix `j`'s rows in block `b`, its first `width` columns being the
    /// values (a kept block's rows carry their salts after them).
    fn block_rows<'a>(&'a self, dft: &Dft, j: usize, b: usize) -> Cow<'a, RowMajorMatrix<F>> {
        match &self.kept {
            Some(tree) => Cow::Borrowed(plain_mmcs().get_matrices(tree)[j]),
            None => Cow::Owned(self.polys[j].block(dft, self.blocks, b)),
        }
    }

    /// The openings of every matrix at `indices` (of the tallest), with
    /// their salts and the pruned multiproof, as the hiding Merkle scheme
    /// of the scale configuration opens them.
    fn open(&self, dft: &Dft, indices: &[usize]) -> BatchMultiOpening<F, ValMmcs> {
        let log_max = self.log_max();
        let log_blocks = log2(self.blocks);
        let log_l = log_max - log_blocks;
        let mut sorted = indices.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mmcs = plain_mmcs();
        let mut rows_of: BTreeMap<usize, Vec<Vec<F>>> = BTreeMap::new();
        let mut paths: BTreeMap<usize, Vec<Digest>> = BTreeMap::new();
        let mut i = 0;
        while i < sorted.len() {
            let b = sorted[i] >> log_l;
            let tree = self.block_tree(dft, b);
            while i < sorted.len() && sorted[i] >> log_l == b {
                let index = sorted[i];
                let (rows, mut siblings) = mmcs.open_batch(index & ((1 << log_l) - 1), &*tree).unpack();
                for level in 0..log_blocks {
                    siblings.push(self.upper[level][(b >> level) ^ 1]);
                }
                rows_of.insert(index, rows);
                paths.insert(index, siblings);
                i += 1;
            }
        }
        // The boundary digests of the frontier, level by level, as
        // `open_batch_pruned` emits them: a group's missing child is the
        // sibling on its lead's path.
        let mut nodes: Vec<(usize, usize)> = sorted.iter().map(|&i| (i, i)).collect();
        let mut sibling_hashes = Vec::new();
        for level in 0..log_max {
            let mut parents = Vec::with_capacity(nodes.len());
            let mut k = 0;
            while k < nodes.len() {
                let (index, lead) = nodes[k];
                let pair = index % 2 == 0 && k + 1 < nodes.len() && nodes[k + 1].0 == index + 1;
                if !pair {
                    sibling_hashes.push(paths[&lead][level]);
                }
                parents.push((index / 2, lead));
                k += if pair { 2 } else { 1 };
            }
            nodes = parents;
        }
        let (opened_values, salts): (Vec<Vec<Vec<F>>>, Vec<Vec<Vec<F>>>) = indices
            .iter()
            .map(|q| {
                rows_of[q]
                    .iter()
                    .map(|row| {
                        let (a, s) = row.split_at(row.len() - SALT);
                        (a.to_vec(), s.to_vec())
                    })
                    .unzip()
            })
            .unzip();
        BatchMultiOpening {
            opened_values,
            opening_proof: (salts, PrunedMerklePaths { sibling_hashes }),
        }
    }
}

/// Commit to `polys`, in order, with salts from `cursor`, a block of at
/// most `budget` bytes at a time.
fn commit(dft: &Dft, polys: Vec<Poly>, cursor: &mut SaltCursor, budget: usize) -> (Com, Committed) {
    let mats: Vec<(usize, usize)> = polys.iter().map(|p| (p.log_lde, p.width())).collect();
    let blocks = block_count(&mats, budget);
    let keep = kept_bytes(&mats, budget) > 0;
    // The library draws every matrix's salts in turn, row by row: note the
    // word each block's salts start at.
    let mut stream = SaltStream::new(&cursor.seed, cursor.word);
    let salt_words: Vec<Vec<u64>> = polys
        .iter()
        .map(|p| {
            let rows = (1usize << p.log_lde) / blocks;
            (0..blocks)
                .map(|_| {
                    let at = stream.position();
                    for _ in 0..rows * SALT {
                        let _: F = stream.random();
                    }
                    at
                })
                .collect()
        })
        .collect();
    cursor.word = stream.position();
    let mut c = Committed {
        polys,
        blocks,
        seed: cursor.seed,
        salt_words,
        upper: Vec::new(),
        kept: None,
    };
    let mmcs = plain_mmcs();
    let mut roots = Vec::with_capacity(blocks);
    for b in 0..blocks {
        let (cap, tree) = mmcs.commit(c.salted_block(dft, b));
        roots.push(cap.roots()[0]);
        if keep {
            c.kept = Some(tree);
        }
    }
    let perm = crate::scale::scale_permutation();
    let compress = Compress::new(perm);
    let mut upper = vec![roots];
    while upper.last().is_some_and(|l| l.len() > 1) {
        let next: Vec<Digest> = upper
            .last()
            .map(|l| {
                l.chunks(2)
                    .map(|p| PseudoCompressionFunction::<Digest, 2>::compress(&compress, [p[0], p[1]]))
                    .collect()
            })
            .unwrap_or_default();
        upper.push(next);
    }
    let root = upper.last().map_or([F::ZERO; DIGEST_ELEMS], |l| l[0]);
    c.upper = upper;
    (MerkleCap::new(vec![root]), c)
}

/// Evaluations over the doubled domain, hiding as `HidingFriPcs::commit`
/// hides them: each row followed by random columns, then a random row.
fn randomized(mat: &RowMajorMatrix<F>, rng: &mut StdRng) -> RowMajorMatrix<F> {
    let w = mat.width();
    let mut r = mat.with_random_cols(w + 2 * RANDOM, &mut *rng);
    r.width = w + RANDOM;
    r
}

// ---------------------------------------------------------------------------
// The opening argument.

/// One commitment of an opening: its data and each matrix's points.
struct Round<'a> {
    data: &'a Committed,
    points: Vec<Vec<EF>>,
}

fn alpha_powers(alpha: EF, n: usize) -> Vec<EF> {
    alpha.powers().take(n).collect()
}

/// Open `rounds` the way `HidingFriPcs::open_with_preprocessing` opens them,
/// on the transcript `ch`. Returns the opened values without the hiding
/// columns, and the proof.
fn open_pcs(
    dft: &Dft,
    rounds: &[Round<'_>],
    preprocessed: Option<usize>,
    ch: &mut ScaleChallenger,
    params: &FriParameters<ChallengeMmcs>,
) -> (PcsOpenedValues<EF>, PcsProof) {
    // Every matrix at every point, its hiding columns included.
    let all: PcsOpenedValues<EF> = rounds
        .iter()
        .map(|round| round.data.polys.iter().zip(&round.points).map(|(p, points)| p.eval(points)).collect())
        .collect();
    let mut transcript =
        PcsProverTranscript::<ScaleChallenger, F, EF>::new(ch, PcsShape::from_opened_values(params, &all));
    transcript.claimed_openings(&all);
    let (alpha, batch_pow) = transcript.batch_phase();
    let batch_pow = batch_pow.unwrap_or(F::ZERO);

    // The batched quotients, one a height: sum alpha^(offset + i)
    // (y_i - p_i(x)) / (z - x) over every matrix of that height and point.
    let widest = rounds.iter().flat_map(|r| r.data.polys.iter().map(Poly::width)).max().unwrap_or(0);
    let pows = alpha_powers(alpha, widest);
    let mut reduced: BTreeMap<usize, Vec<EF>> = BTreeMap::new();
    let mut num_reduced = [0usize; 33];
    for (round, opened) in rounds.iter().zip(&all) {
        let data = round.data;
        for (j, (p, points)) in data.polys.iter().zip(&round.points).enumerate() {
            let lh = p.log_lde;
            let w = p.width();
            let weighted: Vec<(EF, EF)> = points
                .iter()
                .zip(&opened[j])
                .map(|(_, values)| {
                    let offset = alpha.exp_u64(num_reduced[lh] as u64);
                    num_reduced[lh] += w;
                    let y: EF = values.iter().zip(&pows).map(|(&v, &a)| v * a).sum();
                    (offset, offset * y)
                })
                .collect();
            let ro = reduced.entry(lh).or_insert_with(|| EF::zero_vec(1 << lh));
            let rows = (1usize << lh) / data.blocks;
            for b in 0..data.blocks {
                let block = data.block_rows(dft, j, b);
                let stride = block.width();
                let xs = p.block_points(data.blocks, b);
                let compressed: Vec<EF> = block
                    .values
                    .chunks(stride)
                    .map(|row| row[..w].iter().zip(&pows).map(|(&v, &a)| a * v).sum())
                    .collect();
                for (&z, &(offset, weighted_y)) in points.iter().zip(&weighted) {
                    let denoms: Vec<EF> = xs.iter().map(|&x| z - x).collect();
                    let inv = batch_multiplicative_inverse(&denoms);
                    for (t, (&c, &d)) in compressed.iter().zip(&inv).enumerate() {
                        ro[b * rows + t] += (weighted_y - offset * c) * d;
                    }
                }
            }
        }
    }
    let log_max = reduced.keys().copied().max().unwrap_or(0);
    let inputs: Vec<Vec<EF>> = reduced.into_values().rev().collect();
    let fri_proof = transcript.delegate(|ch| prove_fri(dft, params, inputs, ch, log_max, rounds, batch_pow));
    transcript.finish();

    // The hiding columns' values travel in the proof, apart.
    let mut opened = all;
    let random: PcsOpenedValues<EF> = opened
        .iter_mut()
        .enumerate()
        .map(|(r, round)| {
            let extra = if preprocessed == Some(r) { 0 } else { RANDOM };
            round
                .iter_mut()
                .map(|mat| {
                    mat.iter_mut()
                        .map(|values| {
                            let split = values.len() - extra;
                            values.drain(split..).collect()
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    (opened, (random, fri_proof))
}

/// `prove_fri` of the pinned library over `inputs` (tallest first), with
/// the input openings read from the streamed commitments.
fn prove_fri(
    dft: &Dft,
    params: &FriParameters<ChallengeMmcs>,
    inputs: Vec<Vec<EF>>,
    ch: &mut ScaleChallenger,
    log_max: usize,
    rounds: &[Round<'_>],
    batch_pow: F,
) -> FriProof<EF, ChallengeMmcs, F, Vec<BatchMultiOpening<F, ValMmcs>>> {
    let folding: TwoAdicFriFolding<Vec<BatchMultiOpening<F, ValMmcs>>, <ValMmcs as Mmcs<F>>::Error> =
        TwoAdicFriFolding(PhantomData);
    let heights: Vec<usize> = inputs.iter().map(|v| log2(v.len())).collect();
    let index_bits = log_max + FriFoldingStrategy::<F, EF>::extra_query_index_bits(&folding);
    let shape = p3_fri::FriShape::new(params, &heights, index_bits);
    let log_arities = shape.log_arities.clone();
    let mut transcript = ProverTranscript::<ScaleChallenger, F, EF>::new(ch, shape);

    let mut inputs = inputs.into_iter().peekable();
    let mut folded = inputs.next().unwrap_or_default();
    let mut commits = Vec::new();
    let mut data = Vec::new();
    let mut pow_witnesses = Vec::new();
    for &log_arity in &log_arities {
        let leaves = RowMajorMatrix::new(folded, 1 << log_arity);
        let (commit, prover_data) = params.mmcs.commit_matrix(leaves);
        let (beta, witness) = transcript.commit_round(commit.clone());
        commits.push(commit);
        pow_witnesses.push(witness.unwrap_or(F::ZERO));
        let leaves = params.mmcs.get_matrices(&prover_data).pop().expect("one matrix a round");
        folded = FriFoldingStrategy::<F, EF>::fold_matrix(&folding, beta, log_arity, leaves.as_view());
        data.push(prover_data);
        if let Some(v) = inputs.next_if(|v| v.len() == folded.len()) {
            let beta_pow = beta.exp_power_of_2(log_arity);
            for (c, &x) in folded.iter_mut().zip(&v) {
                *c += beta_pow * x;
            }
        }
    }
    folded.truncate(params.final_poly_len());
    reverse_slice_bits(&mut folded);
    let final_poly = Radix2DFTSmallBatch::<F>::default().idft_algebra(folded);
    let (indices, query_pow) = transcript.query_phase(&final_poly);
    transcript.finish();

    let input_openings = rounds
        .iter()
        .map(|round| {
            let shift = log_max - round.data.log_max();
            let reduced: Vec<usize> = indices.iter().map(|&i| i >> shift).collect();
            round.data.open(dft, &reduced)
        })
        .collect();
    let mut current = indices;
    let commit_phase_openings = data
        .iter()
        .zip(&log_arities)
        .map(|(prover_data, &log_arity)| {
            let arity = 1usize << log_arity;
            let groups: Vec<usize> = current.iter().map(|&i| i >> log_arity).collect();
            let (opened_rows, opening_proof) = params.mmcs.open_multi_batch(&groups, prover_data);
            let sibling_values = current
                .iter()
                .zip(opened_rows)
                .map(|(&index, mut rows)| {
                    let row = rows.pop().unwrap_or_default();
                    row.into_iter()
                        .enumerate()
                        .filter(|(j, _)| *j != index % arity)
                        .map(|(_, v)| v)
                        .collect()
                })
                .collect();
            current = groups;
            CommitPhaseMultiStep {
                sibling_values,
                opening_proof,
            }
        })
        .collect();
    FriProof {
        batch_pow_witness: batch_pow,
        commit_phase_commits: commits,
        commit_pow_witnesses: pow_witnesses,
        input_openings,
        commit_phase_openings,
        final_poly,
        query_pow_witness: query_pow.unwrap_or(F::ZERO),
    }
}

// ---------------------------------------------------------------------------
// Keys and proofs.

/// The lookups the library's key generation derives for `air`: its
/// interactions, those of one bus packed as far as its quotient degree
/// allows.
fn lookups_of(air: &TableAir) -> Result<Lookups<F>, ProofError> {
    let gadget = LogUpGadget::new();
    let domain = TwoAdicMultiplicativeCoset::new(F::ONE, log2(air.height())).ok_or(ProofError::Proving)?;
    let unpacked = Lookups::<F>::from_air::<EF, TableAir>(air).map_err(|_| ProofError::Proving)?;
    let log_chunks = p3_batch_stark::symbolic::get_log_num_quotient_chunks_for_domain::<F, EF, TableAir, LogUpGadget>(
        air,
        AirLayout::from_air(air),
        domain,
        &unpacked,
        1,
        &gadget,
    );
    let budget = 1usize << log_chunks;
    Ok(unpacked.pack_same_bus_with_degree(budget, |lookup| {
        gadget.constraint_degree_with_transition(lookup, domain.transition_degree_multiple())
    }))
}

/// A circuit's committed preprocessed columns, as the prover keeps them.
pub(crate) struct Preprocessed {
    pub(crate) common: CommonData<ScaleConfig>,
    committed: Option<Committed>,
    released: bool,
}

impl Preprocessed {
    /// Drop the coefficients; the commitment and lookups stay.
    pub(crate) fn release(&mut self) {
        self.committed = None;
        self.released = true;
    }
}

/// Commit to the preprocessed columns of `airs` at `fri` as the library's
/// key generation does (zero rows interleaved, salts from the all-zero
/// seed), a block of at most `budget` bytes at a time.
pub(crate) fn setup(airs: &[TableAir], fri: &FriShape, budget: usize) -> Result<Preprocessed, ProofError> {
    let dft = Dft::default();
    let mut instances = Vec::with_capacity(airs.len());
    let mut matrix_to_instance = Vec::new();
    let mut polys = Vec::new();
    for (i, air) in airs.iter().enumerate() {
        let Some(prep) = air.preprocessed_trace().filter(|p| p.width() > 0) else {
            instances.push(None);
            continue;
        };
        if prep.height() != air.height() {
            return Err(ProofError::Proving);
        }
        let log_ext = log2(air.height()) + 1;
        let width = prep.width();
        let mut padded = prep.with_zero_cols(width);
        padded.width = width;
        instances.push(Some(PreprocessedInstanceMeta {
            matrix_index: polys.len(),
            width,
            degree_bits: log_ext,
        }));
        matrix_to_instance.push(i);
        polys.push(coefficients(&dft, padded, log_ext + fri.log_blowup));
    }
    let lookups = airs.iter().map(lookups_of).collect::<Result<Vec<_>, _>>()?;
    if polys.is_empty() {
        return Ok(Preprocessed {
            common: CommonData::new(None, lookups),
            committed: None,
            released: false,
        });
    }
    let mut cursor = Randomness::of([0; 32]).salts;
    let (commitment, committed) = commit(&dft, polys, &mut cursor, budget);
    Ok(Preprocessed {
        common: CommonData::new(
            Some(GlobalPreprocessed {
                commitment,
                instances,
                matrix_to_instance,
            }),
            lookups,
        ),
        committed: Some(committed),
        released: false,
    })
}

/// Prove `traces` of `airs` with public values `publics` under the key
/// `prep` at `fri`, the transcript seeded with `tag`: the proof
/// `p3_batch_stark::prove_batch` makes at the scale configuration with
/// `zk_seed`, extended a block of at most `budget` bytes at a time.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove(
    airs: &[TableAir],
    prep: &Preprocessed,
    traces: Vec<RowMajorMatrix<F>>,
    publics: &[Vec<F>],
    fri: &FriShape,
    tag: &[F],
    zk_seed: [u8; 32],
    budget: usize,
) -> Result<BatchProof<ScaleConfig>, ProofError> {
    let n = airs.len();
    // A key whose prover data was released proves nothing.
    if n == 0 || traces.len() != n || publics.len() != n || prep.released {
        return Err(ProofError::Proving);
    }
    let config = crate::scale::layer_config(zk_seed, fri, crate::scale::tagged_challenger(tag))?;
    let dft = Dft::default();
    let common = &prep.common;
    let gadget = LogUpGadget::new();
    let mut rand = Randomness::of(zk_seed);
    let params = crate::stark::fri_parameters(fri, ChallengeMmcs::new(ValMmcs::new(
        Hash::new(crate::scale::scale_permutation()),
        Compress::new(crate::scale::scale_permutation()),
        0,
        rand.fri_salts,
    )));

    let degrees: Vec<usize> = traces.iter().map(Matrix::height).collect();
    if degrees.iter().zip(airs).any(|(&h, a)| h != a.height() || !h.is_power_of_two()) {
        return Err(ProofError::Proving);
    }
    let log_ext: Vec<usize> = degrees.iter().map(|&d| log2(d) + 1).collect();
    let log_lde: Vec<usize> = log_ext.iter().map(|&l| l + fri.log_blowup).collect();
    check_multiplicity_height_bound(&common.lookups, &degrees).map_err(|_| ProofError::Proving)?;
    let all_lookups: Vec<&[p3_lookup::Lookup<F>]> = common.lookups.iter().map(|l| &**l).collect();
    let trace_domains: Vec<TwoAdicMultiplicativeCoset<F>> = degrees
        .iter()
        .map(|&d| TwoAdicMultiplicativeCoset::new(F::ONE, log2(d)).ok_or(ProofError::Proving))
        .collect::<Result<_, _>>()?;
    let ext_domains: Vec<TwoAdicMultiplicativeCoset<F>> = log_ext
        .iter()
        .map(|&l| TwoAdicMultiplicativeCoset::new(F::ONE, l).ok_or(ProofError::Proving))
        .collect::<Result<_, _>>()?;
    let prep_widths: Vec<usize> = (0..n)
        .map(|i| {
            common
                .preprocessed
                .as_ref()
                .and_then(|g| g.instances[i].as_ref().map(|m| m.width))
                .unwrap_or(0)
        })
        .collect();
    let layouts: Vec<AirLayout> = airs
        .iter()
        .zip(&prep_widths)
        .map(|(air, &pw)| AirLayout {
            preprocessed_width: pw,
            main_width: BaseAir::<F>::width(air),
            num_public_values: BaseAir::<F>::num_public_values(air),
            num_periodic_columns: BaseAir::<F>::num_periodic_columns(air),
            ..Default::default()
        })
        .collect();
    let log_chunks: Vec<usize> = (0..n)
        .map(|i| {
            p3_batch_stark::symbolic::get_log_num_quotient_chunks_for_domain::<F, EF, TableAir, LogUpGadget>(
                &airs[i],
                layouts[i],
                trace_domains[i],
                all_lookups[i],
                1,
                &gadget,
            )
        })
        .collect();
    let widths: Vec<usize> = airs.iter().map(BaseAir::<F>::width).collect();

    let shape = BatchShape {
        trace_widths: widths.clone(),
        public_value_counts: publics.iter().map(Vec::len).collect(),
        preprocessed_widths: prep_widths.clone(),
        has_preprocessed_commitment: common.preprocessed.is_some(),
        num_lookup_instances: all_lookups.iter().filter(|l| !l.is_empty()).count(),
        lookup_pow_bits: config.lookup_proof_of_work_bits(),
        has_randomization_commitment: true,
        ood_pow_bits: config.ood_proof_of_work_bits(),
    };
    let mut challenger = config.initialise_challenger();
    let mut transcript = BatchProverTranscript::<ScaleChallenger, F, EF, Com>::new(&mut challenger, shape);
    transcript.instance_bindings(&log_ext);

    // The main traces.
    let mut fork = StdRng::from_rng(&mut rand.masks);
    let main_polys: Vec<Poly> = traces
        .iter()
        .zip(&log_lde)
        .map(|(t, &l)| coefficients(&dft, randomized(t, &mut fork), l))
        .collect();
    let (main_commit, main_data) = commit(&dft, main_polys, &mut rand.salts, budget);
    transcript.main_phase(main_commit.clone(), publics);
    transcript.preprocessed_phase(common.preprocessed.as_ref().map(|g| g.commitment.clone()));

    // The lookup challenges and the permutation traces.
    let (challenges, lookup_pow_witness) = transcript.lookup_phase(&all_lookups, &gadget);
    let mut terminals: Vec<Option<LookupTerminal<EF>>> = vec![None; n];
    // The library's permutation commitment, and its draw of masks, happen
    // only when some table has lookups.
    let mut fork = all_lookups
        .iter()
        .any(|l| !l.is_empty())
        .then(|| StdRng::from_rng(&mut rand.masks));
    let mut perm_polys = Vec::new();
    for i in 0..n {
        let Some(fork) = fork.as_mut().filter(|_| !all_lookups[i].is_empty()) else {
            continue;
        };
        let (perm, terminal) = gadget.generate_permutation::<F, EF>(
            &traces[i],
            &airs[i].preprocessed_trace(),
            &BaseAir::<F>::periodic_columns(&airs[i]),
            &publics[i],
            all_lookups[i],
            &challenges[i],
        );
        terminals[i] = terminal;
        let flat = perm.flatten_to_base();
        perm_polys.push(coefficients(&dft, randomized(&flat, fork), log_lde[i]));
    }
    drop(traces);
    let perm_commit = if perm_polys.is_empty() {
        None
    } else {
        Some(commit(&dft, perm_polys, &mut rand.salts, budget))
    };
    let terminal_values: Vec<EF> = terminals.iter().flatten().map(|t| t.0).collect();
    let alpha = transcript.permutation_phase(perm_commit.as_ref().map(|(c, _)| c.clone()), &terminal_values);

    // The quotient, chunk by chunk: chunk `c` of the quotient domain is its
    // own coset of the trace's size, on which the main, preprocessed and
    // permutation polynomials are evaluated and the constraints folded.
    let mut perm_index = 0;
    let mut quotient_polys = Vec::new();
    let mut chunk_ranges = Vec::with_capacity(n);
    for i in 0..n {
        let num_chunks = 1usize << (log_chunks[i] + 1);
        let quotient_domain = ext_domains[i].create_disjoint_domain(1 << (log_ext[i] + log_chunks[i]));
        let chunk_domains = quotient_domain.split_domains(num_chunks);
        let log_h = log2(degrees[i]);
        let perm_poly = match &perm_commit {
            Some((_, d)) if !all_lookups[i].is_empty() => {
                perm_index += 1;
                Some(&d.polys[perm_index - 1])
            }
            _ => None,
        };
        let prep_poly = common
            .preprocessed
            .as_ref()
            .and_then(|g| g.instances[i].as_ref())
            .and_then(|meta| prep.committed.as_ref().map(|c| &c.polys[meta.matrix_index]));
        let perm_vals: Vec<EF> = terminals[i].iter().map(|t| t.0).collect();
        let mut fork = StdRng::from_rng(&mut rand.masks);
        let mut chunks: Vec<RowMajorMatrix<F>> = Vec::with_capacity(num_chunks);
        for domain in &chunk_domains {
            let main = main_data.polys[i].on_coset(&dft, domain.shift(), log_h, widths[i]);
            let perm = perm_poly.map(|p| p.on_coset(&dft, domain.shift(), log_h, p.width() - RANDOM));
            let pre = prep_poly.map(|p| p.on_coset(&dft, domain.shift(), log_h, p.width()));
            let values = quotient_values::<ScaleConfig, TableAir, RowMajorMatrix<F>, LogUpGadget>(
                config.pcs(),
                &airs[i],
                &publics[i],
                layouts[i],
                trace_domains[i],
                *domain,
                &main,
                perm.as_ref(),
                all_lookups[i],
                &perm_vals,
                &gadget,
                &challenges[i],
                pre.as_ref(),
                alpha,
            );
            let evals = RowMajorMatrix::new_col(values).flatten_to_base::<F>();
            chunks.push(evals.with_random_cols(RANDOM, &mut fork));
        }
        let start = quotient_polys.len();
        quotient_polys.extend(quotient_chunk_polys(&dft, &chunk_domains, chunks, &mut fork, log_lde[i]));
        chunk_ranges.push((start, quotient_polys.len()));
    }
    let (quotient_commit, quotient_data) = commit(&dft, quotient_polys, &mut rand.salts, budget);

    // The randomization polynomials.
    let random_polys: Vec<Poly> = ext_domains
        .iter()
        .zip(&log_lde)
        .map(|(d, &l)| {
            let m = RowMajorMatrix::<F>::rand(&mut rand.masks, d.size(), RANDOM + D);
            coefficients(&dft, m, l)
        })
        .collect();
    let (random_commit, random_data) = commit(&dft, random_polys, &mut rand.salts, budget);
    transcript.quotient_phase(quotient_commit.clone(), Some(random_commit.clone()));
    let (zeta, ood_pow_witness) = transcript.ood_phase();

    // The openings: randomization, main, quotient, preprocessed,
    // permutation, as the library orders its rounds.
    let next = |i: usize| zeta * trace_domains[i].subgroup_generator();
    let mut rounds = vec![
        Round {
            data: &random_data,
            points: (0..n).map(|_| vec![zeta]).collect(),
        },
        Round {
            data: &main_data,
            points: (0..n)
                .map(|i| {
                    if BaseAir::<F>::main_next_row_columns(&airs[i]).is_empty() {
                        vec![zeta]
                    } else {
                        vec![zeta, next(i)]
                    }
                })
                .collect(),
        },
        Round {
            data: &quotient_data,
            points: (0..quotient_data.polys.len()).map(|_| vec![zeta]).collect(),
        },
    ];
    let preprocessed_round = match (&common.preprocessed, &prep.committed) {
        (Some(global), Some(data)) => {
            rounds.push(Round {
                data,
                points: global
                    .matrix_to_instance
                    .iter()
                    .map(|&i| {
                        if BaseAir::<F>::preprocessed_next_row_columns(&airs[i]).is_empty() {
                            vec![zeta]
                        } else {
                            vec![zeta, next(i)]
                        }
                    })
                    .collect(),
            });
            Some(rounds.len() - 1)
        }
        _ => None,
    };
    if let Some((_, data)) = &perm_commit {
        rounds.push(Round {
            data,
            points: (0..n).filter(|&i| !all_lookups[i].is_empty()).map(|i| vec![zeta, next(i)]).collect(),
        });
    }
    let (opened, opening_proof) =
        transcript.delegate(|ch| open_pcs(&dft, &rounds, preprocessed_round, ch, &params));
    transcript.finish();

    // The opened values of each instance, as `prove_batch` lays them out.
    let mut perm_values = perm_commit.as_ref().map(|_| opened[rounds.len() - 1].iter());
    let mut quotient_opened = opened[2].iter();
    let instances = (0..n)
        .map(|i| {
            let tv = &opened[1][i];
            let (s, e) = chunk_ranges[i];
            let quotient_chunks = (s..e)
                .map(|_| quotient_opened.next().map(|v| v[0].clone()).unwrap_or_default())
                .collect();
            let preprocessed = match (&common.preprocessed, preprocessed_round) {
                (Some(global), Some(r)) => global.instances[i].as_ref().map(|meta| {
                    let vals = &opened[r][meta.matrix_index];
                    PreprocessedOpenedValues {
                        local: vals[0].clone(),
                        next: vals.get(1).cloned(),
                    }
                }),
                _ => None,
            };
            let (permutation_local, permutation_next) = if all_lookups[i].is_empty() {
                (Vec::new(), Vec::new())
            } else {
                let v = perm_values.as_mut().and_then(Iterator::next).cloned().unwrap_or_default();
                (v.first().cloned().unwrap_or_default(), v.get(1).cloned().unwrap_or_default())
            };
            OpenedValuesWithLookups {
                base_opened_values: OpenedValues {
                    trace_local: tv[0].clone(),
                    trace_next: tv.get(1).cloned(),
                    preprocessed,
                    quotient_chunks,
                    random: Some(opened[0][i][0].clone()),
                },
                permutation_local,
                permutation_next,
            }
        })
        .collect();
    Ok(BatchProof {
        commitments: BatchCommitments {
            main: main_commit,
            quotient_chunks: quotient_commit,
            random: Some(random_commit),
            permutation: perm_commit.map(|(c, _)| c),
        },
        opened_values: BatchOpenedValues { instances },
        opening_proof,
        lookup_terminals: terminals,
        degree_bits: log_ext,
        lookup_pow_witness,
        ood_pow_witness,
    })
}

/// The quotient chunks of one instance, masked as
/// `HidingFriPcs::get_quotient_ldes` masks them, as coefficients: chunk `i`
/// becomes `q_i + v_(H_i) t_i`, the last chunk `q_d - v_(H_d) c sum t_i`,
/// the masks `t_i` drawn from `rng` after every chunk's hiding columns.
fn quotient_chunk_polys(
    dft: &Dft,
    domains: &[TwoAdicMultiplicativeCoset<F>],
    chunks: Vec<RowMajorMatrix<F>>,
    rng: &mut StdRng,
    log_lde: usize,
) -> Vec<Poly> {
    let num = domains.len();
    let last = num - 1;
    let cis = batch_multiplicative_inverse(
        &(0..num)
            .map(|i| {
                (0..num)
                    .filter(|&j| j != i)
                    .map(|j| domains[j].vanishing_poly_at_point(domains[i].first_point()))
                    .product::<F>()
            })
            .collect::<Vec<_>>(),
    );
    let last_inv = cis[last].inverse();
    let h = chunks[0].height();
    let w = chunks[0].width();
    let mut last_mask = F::zero_vec(h * w);
    let mut out = Vec::with_capacity(num);
    let mut chunks = chunks.into_iter();
    for i in 0..num {
        let evals = chunks.next().expect("one chunk a domain");
        let mask: Vec<F> = if i < last {
            let mask: Vec<F> = (0..h * w).map(|_| rng.random()).collect();
            let mul = cis[i] * last_inv;
            for (l, &t) in last_mask.iter_mut().zip(&mask) {
                *l -= t * mul;
            }
            mask
        } else {
            core::mem::take(&mut last_mask)
        };
        out.push(masked_chunk(dft, &domains[i], evals, &mask, log_lde));
    }
    out
}

/// One quotient chunk's coefficients (in `x`) with its mask added, as the
/// library extends it.
fn masked_chunk(
    dft: &Dft,
    domain: &TwoAdicMultiplicativeCoset<F>,
    evals: RowMajorMatrix<F>,
    mask: &[F],
    log_lde: usize,
) -> Poly {
    let h = evals.height();
    let w = evals.width();
    let shift = F::GENERATOR / domain.shift();
    let mut c = dft.coset_idft_batch(evals, shift.inverse()).values;
    c.resize(2 * h * w, F::ZERO);
    let p = shift.exp_u64(h as u64);
    for (i, p_i) in F::GENERATOR.powers().take(h).enumerate() {
        for j in 0..w {
            let m = p_i * mask[i * w + j];
            c[i * w + j] -= m;
            c[(h + i) * w + j] += p * m;
        }
    }
    // The library commits `c` evaluated on the subgroup itself; in `x`
    // over the coset `g K` the coefficient of `x^j` is `c_j g^-j`.
    let g_inv = F::GENERATOR.inverse();
    for (row, s) in c.chunks_mut(w).zip(g_inv.powers()) {
        for v in row {
            *v *= s;
        }
    }
    Poly {
        coeffs: RowMajorMatrix::new(c, w),
        log_lde,
    }
}

/// The extension field's dimension, which the hiding columns are counted
/// against.
const _: () = assert!(<EF as BasedVectorSpace<F>>::DIMENSION == D && RANDOM >= D);

#[cfg(test)]
mod tests {
    use super::*;

    /// The salt stream is the keystream `StdRng` draws from, from its first
    /// word and from any word.
    #[test]
    fn the_salt_stream_is_std_rng() {
        for seed in [[0u8; 32], [7u8; 32]] {
            let mut reference = StdRng::from_seed(seed);
            let words: Vec<u32> = (0..300).map(|_| reference.next_u32()).collect();
            let mut s = SaltStream::new(&seed, 0);
            for &w in &words {
                assert_eq!(s.next_word(), w);
            }
            let mut s = SaltStream::new(&seed, 77);
            assert_eq!(s.next_word(), words[77]);
        }
    }
}
