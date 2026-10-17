//! The zero-knowledge configurations.
//!
//! Plonky3 makes a proof zero-knowledge with a hiding polynomial commitment
//! scheme (`HidingFriPcs`) paired with a hiding Merkle commitment
//! (`MerkleTreeHidingMmcs`). Both must be selected, and the library does not
//! check at compile time that they are. Each candidate therefore has exactly
//! one function that builds its configuration, used by the prover and the
//! verifier alike, and that function refuses to return a configuration the
//! library does not report as zero-knowledge.
//!
//! The commitment hash is the candidate's own hash, the same one the
//! statement uses for the coin tree.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_fri::HidingFriPcs;
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher, TruncatedPermutation,
};
use p3_uni_stark::{StarkConfig, StarkGenericConfig};
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::security::{NUM_RANDOM_CODEWORDS, SecurityPlan, fri_parameters};
use crate::{BenchError, Challenge};

type F = BabyBear;
type Dft = Radix2DitParallel<F>;

/// Salt elements per Merkle leaf: 5 * 31 = 155 bits of salt, above the
/// 128-bit target.
pub const SALT_ELEMS: usize = 5;

// Candidate A: Poseidon2 over BabyBear, width 24.
//
// Commitment digests are 9 elements (279 bits) with a capacity of 9: an
// 8-element digest gives only about 124 bits of collision resistance. The
// permutation itself is specified for 128 bits, so the commitment hash is
// credited with 128.
pub const POSEIDON2_DIGEST_ELEMS: usize = 9;
pub const POSEIDON2_COLLISION_BITS: usize = 128;
type Poseidon2Perm = Poseidon2BabyBear<24>;
type Poseidon2Hash = PaddingFreeSponge<Poseidon2Perm, 24, 15, POSEIDON2_DIGEST_ELEMS>;
type Poseidon2Compress = TruncatedPermutation<Poseidon2Perm, 2, POSEIDON2_DIGEST_ELEMS, 24>;
type Poseidon2ValMmcs = MerkleTreeHidingMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    Poseidon2Hash,
    Poseidon2Compress,
    StdRng,
    2,
    POSEIDON2_DIGEST_ELEMS,
    SALT_ELEMS,
>;
type Poseidon2ChallengeMmcs = ExtensionMmcs<F, Challenge, Poseidon2ValMmcs>;
type Poseidon2Challenger = DuplexChallenger<F, Poseidon2Perm, 24, 15>;
type Poseidon2Pcs = HidingFriPcs<F, Dft, Poseidon2ValMmcs, Poseidon2ChallengeMmcs, StdRng>;
pub type Poseidon2Config = StarkConfig<Poseidon2Pcs, Challenge, Poseidon2Challenger>;

// Candidate B: Keccak-256. Digests are the full 256-bit output.
pub const KECCAK_COLLISION_BITS: usize = 128;
type KeccakU64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type KeccakFieldHash = SerializingHasher<KeccakU64Hash>;
type KeccakCompress = CompressionFunctionFromHasher<KeccakU64Hash, 2, 4>;
type KeccakValMmcs = MerkleTreeHidingMmcs<
    [F; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    KeccakFieldHash,
    KeccakCompress,
    StdRng,
    2,
    4,
    SALT_ELEMS,
>;
type KeccakChallengeMmcs = ExtensionMmcs<F, Challenge, KeccakValMmcs>;
type KeccakChallenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;
type KeccakPcs = HidingFriPcs<F, Dft, KeccakValMmcs, KeccakChallengeMmcs, StdRng>;
pub type KeccakConfig = StarkConfig<KeccakPcs, Challenge, KeccakChallenger>;

/// Two independent generators from one seed: one salts the Merkle leaves,
/// the other draws the polynomial masks.
fn generators(zk_seed: [u8; 32]) -> (StdRng, StdRng) {
    let mut master = StdRng::from_seed(zk_seed);
    let salts = StdRng::from_rng(&mut master);
    let masks = StdRng::from_rng(&mut master);
    (salts, masks)
}

fn require_zk<SC: StarkGenericConfig>(config: SC) -> Result<SC, BenchError> {
    if config.is_zk() == 1 {
        Ok(config)
    } else {
        Err(BenchError::NotZeroKnowledge)
    }
}

/// The one function that builds candidate A's configuration, for the prover
/// and the verifier. `zk_seed` must come from a secure random source when
/// proving; the verifier draws nothing from it.
pub fn poseidon2_config(plan: &SecurityPlan, zk_seed: [u8; 32]) -> Result<Poseidon2Config, BenchError> {
    let (salts, masks) = generators(zk_seed);
    let perm = crate::poseidon2::permutation();
    let val_mmcs = Poseidon2ValMmcs::new(
        Poseidon2Hash::new(perm.clone()),
        Poseidon2Compress::new(perm.clone()),
        0,
        salts,
    );
    let fri = fri_parameters(
        plan.log_blowup,
        plan.num_queries,
        plan.grinding,
        Poseidon2ChallengeMmcs::new(val_mmcs.clone()),
    );
    let pcs = Poseidon2Pcs::new(Dft::default(), val_mmcs, fri, NUM_RANDOM_CODEWORDS, masks);
    let config = Poseidon2Config::new(pcs, Poseidon2Challenger::new(perm))
        .with_ood_proof_of_work_bits(plan.grinding.ood);
    require_zk(config)
}

/// The one function that builds candidate B's configuration, for the prover
/// and the verifier.
pub fn keccak_config(plan: &SecurityPlan, zk_seed: [u8; 32]) -> Result<KeccakConfig, BenchError> {
    let (salts, masks) = generators(zk_seed);
    let u64_hash = KeccakU64Hash::new(KeccakF {});
    let val_mmcs = KeccakValMmcs::new(
        KeccakFieldHash::new(u64_hash),
        KeccakCompress::new(u64_hash),
        0,
        salts,
    );
    let fri = fri_parameters(
        plan.log_blowup,
        plan.num_queries,
        plan.grinding,
        KeccakChallengeMmcs::new(val_mmcs.clone()),
    );
    let pcs = KeccakPcs::new(Dft::default(), val_mmcs, fri, NUM_RANDOM_CODEWORDS, masks);
    let config = KeccakConfig::new(pcs, KeccakChallenger::from_hasher(vec![], Keccak256Hash {}))
        .with_ood_proof_of_work_bits(plan.grinding.ood);
    require_zk(config)
}
