//! Browser proof benchmark: the representative coin-reveal statement in
//! Plonky3, for two hash candidates, in zero-knowledge mode only.
//!
//! Soundness comes first. A configuration is built only after it passes the
//! security gate ([`security`]), and every configuration is built by the one
//! zero-knowledge function of its candidate ([`zk`]), used by the prover and
//! the verifier alike. Speed decides among the configurations that pass,
//! never the other way round.
//!
//! - Candidate A ([`poseidon2`]): Poseidon2 over BabyBear, width 24.
//! - Candidate B ([`keccak`]): Keccak-256 on Plonky3's Keccak-f circuit.
//!
//! The candidate's hash is used for the coin tree inside the statement and
//! for the proof's own commitments.

extern crate alloc;

use core::fmt;
use core::ops::RangeInclusive;

use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_uni_stark::Proof;

pub mod json;
pub mod keccak;
pub mod poseidon2;
pub mod security;
pub mod witness;
pub mod zk;

pub use security::{Estimate, Grinding, SecurityPlan, TARGET_CONJECTURED_BITS, zk_min_trace_height};
pub use witness::Witness;

/// Library and pinned revision, recorded in every result.
pub const LIBRARY: &str = "Plonky3";
pub const PLONKY3_REPOSITORY: &str = "https://github.com/Plonky3/Plonky3";
pub const PLONKY3_REVISION: &str = "f98331687e47106a64ab82a77e2e1d0d66c9161b";

/// Compiler version and build flags of this build.
pub const RUSTC_VERSION: &str = env!("GHOST_BENCH_RUSTC_VERSION");
pub const BUILD_FLAGS: &str = env!("GHOST_BENCH_BUILD_FLAGS");

/// The challenge field: the degree-5 extension of BabyBear.
pub type Challenge = BinomialExtensionField<BabyBear, { security::EXTENSION_DEGREE }>;

/// Hash-use tags. Every use of the hash carries its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Tag {
    Commitment = 1,
    Marker = 2,
    TreeNode = 3,
    Binding = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashCandidate {
    /// Candidate A: Poseidon2 over BabyBear, width 24.
    Poseidon2,
    /// Candidate B: Keccak-256.
    Keccak256,
}

impl HashCandidate {
    pub const ALL: [Self; 2] = [Self::Poseidon2, Self::Keccak256];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Poseidon2 => "poseidon2-babybear-w24",
            Self::Keccak256 => "keccak-256",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Poseidon2 => "A",
            Self::Keccak256 => "B",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "a" | "poseidon2" | "poseidon2-babybear-w24" => Some(Self::Poseidon2),
            "b" | "keccak" | "keccak256" | "keccak-256" => Some(Self::Keccak256),
            _ => None,
        }
    }

    /// Public-input groups, for reporting and for the tests that change each
    /// public input in turn.
    pub fn public_input_groups(self) -> [(&'static str, core::ops::Range<usize>); 7] {
        match self {
            Self::Poseidon2 => {
                use poseidon2::*;
                [
                    ("tree root", PI_ROOT..PI_MARKER),
                    ("marker", PI_MARKER..PI_REMAINDER),
                    ("remainder commitment", PI_REMAINDER..PI_OUT),
                    ("amount out", PI_OUT..PI_FEE),
                    ("fee", PI_FEE..PI_BINDING),
                    ("binding digest", PI_BINDING..PI_TYPE),
                    ("type tag", PI_TYPE..NUM_PUBLIC),
                ]
            }
            Self::Keccak256 => {
                use keccak::*;
                [
                    ("tree root", PI_ROOT..PI_MARKER),
                    ("marker", PI_MARKER..PI_REMAINDER),
                    ("remainder commitment", PI_REMAINDER..PI_OUT),
                    ("amount out", PI_OUT..PI_FEE),
                    ("fee", PI_FEE..PI_BINDING),
                    ("binding digest", PI_BINDING..PI_TYPE),
                    ("type tag", PI_TYPE..NUM_PUBLIC),
                ]
            }
        }
    }
}

impl fmt::Display for HashCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BenchError {
    UnsupportedBlowup { log_blowup: usize },
    /// Zero-knowledge mode needs the constraint degree to be at most the blowup.
    ConstraintDegreeTooHigh { degree: usize, log_blowup: usize },
    BelowSecurityFloor { best_bits: usize },
    GrindingAboveLimit,
    NotZeroKnowledge,
    MalformedPublicInputs,
    MalformedProof(String),
    Proving(String),
    Rejected(String),
}

impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedBlowup { log_blowup } => {
                write!(f, "blowup 2^{log_blowup} is not one of 2^1, 2^2, 2^3")
            }
            Self::ConstraintDegreeTooHigh { degree, log_blowup } => write!(
                f,
                "constraint degree {degree} does not fit blowup 2^{log_blowup} in zero-knowledge mode (needs degree <= {})",
                1usize << log_blowup
            ),
            Self::BelowSecurityFloor { best_bits } => write!(
                f,
                "refused: best conjectured estimate {best_bits} bits is below {TARGET_CONJECTURED_BITS}"
            ),
            Self::GrindingAboveLimit => write!(f, "refused: grinding above 16 bits"),
            Self::NotZeroKnowledge => {
                write!(f, "refused: the library reports the configuration is not zero-knowledge")
            }
            Self::MalformedPublicInputs => write!(f, "public inputs rejected"),
            Self::MalformedProof(e) => write!(f, "malformed proof: {e}"),
            Self::Proving(e) => write!(f, "proving failed: {e}"),
            Self::Rejected(e) => write!(f, "proof rejected: {e}"),
        }
    }
}

impl std::error::Error for BenchError {}

pub(crate) fn fill_periodic(column: &mut [BabyBear], rows: RangeInclusive<usize>, value: BabyBear) {
    for row in rows {
        column[row] = value;
    }
}

/// Run the security gate for a configuration.
pub fn plan(candidate: HashCandidate, log_blowup: usize) -> Result<SecurityPlan, BenchError> {
    match candidate {
        HashCandidate::Poseidon2 => security::plan_for(
            candidate,
            log_blowup,
            poseidon2::MIN_HEIGHT,
            zk::POSEIDON2_COLLISION_BITS,
            poseidon2::RevealAir::new,
        ),
        HashCandidate::Keccak256 => security::plan_for(
            candidate,
            log_blowup,
            keccak::MIN_HEIGHT,
            zk::KECCAK_COLLISION_BITS,
            keccak::RevealAir::new,
        ),
    }
}

/// The honest public inputs for a witness, as canonical `u32` values.
pub fn public_inputs(candidate: HashCandidate, witness: &Witness) -> Vec<u32> {
    let pis = match candidate {
        HashCandidate::Poseidon2 => poseidon2::public_inputs(witness),
        HashCandidate::Keccak256 => keccak::public_inputs(witness),
    };
    pis.iter().map(PrimeField32::as_canonical_u32).collect()
}

fn to_field(pis: &[u32]) -> Result<Vec<BabyBear>, BenchError> {
    pis.iter()
        .map(|&x| {
            if x < BabyBear::ORDER_U32 {
                Ok(BabyBear::from_u32(x))
            } else {
                Err(BenchError::MalformedPublicInputs)
            }
        })
        .collect()
}

/// Prove a statement after re-checking the security gate.
pub fn prove(
    plan: &SecurityPlan,
    witness: &Witness,
    public_inputs: &[u32],
    zk_seed: [u8; 32],
) -> Result<Vec<u8>, BenchError> {
    match plan.candidate {
        HashCandidate::Poseidon2 => {
            security::check_gate(plan, &poseidon2::RevealAir::new(plan.trace_height))?;
        }
        HashCandidate::Keccak256 => {
            security::check_gate(plan, &keccak::RevealAir::new(plan.trace_height))?;
        }
    }
    prove_gated(plan, witness, public_inputs, zk_seed)
}

/// Prove without re-running the gate; [`Instance`] runs it once up front so
/// it is never inside a timed region.
fn prove_gated(
    plan: &SecurityPlan,
    witness: &Witness,
    public_inputs: &[u32],
    zk_seed: [u8; 32],
) -> Result<Vec<u8>, BenchError> {
    let pis = to_field(public_inputs)?;
    let proving = |e: &dyn fmt::Debug| BenchError::Proving(format!("{e:?}"));
    let encode = |e: postcard::Error| BenchError::Proving(e.to_string());
    match plan.candidate {
        HashCandidate::Poseidon2 => {
            let config = zk::poseidon2_config(plan, zk_seed)?;
            let air = poseidon2::RevealAir::new(plan.trace_height);
            let trace = poseidon2::generate_trace(witness, plan.trace_height);
            let proof = p3_uni_stark::prove(&config, &air, trace, &pis).map_err(|e| proving(&e))?;
            postcard::to_allocvec(&proof).map_err(encode)
        }
        HashCandidate::Keccak256 => {
            let config = zk::keccak_config(plan, zk_seed)?;
            let air = keccak::RevealAir::new(plan.trace_height);
            let trace = keccak::generate_trace(witness, plan.trace_height);
            let proof = p3_uni_stark::prove(&config, &air, trace, &pis).map_err(|e| proving(&e))?;
            postcard::to_allocvec(&proof).map_err(encode)
        }
    }
}

/// Verify a proof against public inputs. The verifier rebuilds the
/// configuration with the same function the prover used.
pub fn verify(plan: &SecurityPlan, public_inputs: &[u32], proof: &[u8]) -> Result<(), BenchError> {
    let pis = to_field(public_inputs)?;
    let expected_degree_bits = plan.trace_height.trailing_zeros() as usize + 1;
    let decode = |e: postcard::Error| BenchError::MalformedProof(e.to_string());
    let rejected = |e: &dyn fmt::Debug| BenchError::Rejected(format!("{e:?}"));
    match plan.candidate {
        HashCandidate::Poseidon2 => {
            if !poseidon2::check_public_inputs(&pis) {
                return Err(BenchError::MalformedPublicInputs);
            }
            let config = zk::poseidon2_config(plan, [0; 32])?;
            let proof: Proof<zk::Poseidon2Config> = postcard::from_bytes(proof).map_err(decode)?;
            if proof.degree_bits != expected_degree_bits {
                return Err(BenchError::MalformedProof("trace height".into()));
            }
            let air = poseidon2::RevealAir::new(plan.trace_height);
            p3_uni_stark::verify(&config, &air, &proof, &pis).map_err(|e| rejected(&e))
        }
        HashCandidate::Keccak256 => {
            if !keccak::check_public_inputs(&pis) {
                return Err(BenchError::MalformedPublicInputs);
            }
            let config = zk::keccak_config(plan, [0; 32])?;
            let proof: Proof<zk::KeccakConfig> = postcard::from_bytes(proof).map_err(decode)?;
            if proof.degree_bits != expected_degree_bits {
                return Err(BenchError::MalformedProof("trace height".into()));
            }
            let air = keccak::RevealAir::new(plan.trace_height);
            p3_uni_stark::verify(&config, &air, &proof, &pis).map_err(|e| rejected(&e))
        }
    }
}

/// The encoded trace commitment of a proof, for comparing two proofs.
pub fn trace_commitment(plan: &SecurityPlan, proof: &[u8]) -> Result<Vec<u8>, BenchError> {
    let decode = |e: postcard::Error| BenchError::MalformedProof(e.to_string());
    match plan.candidate {
        HashCandidate::Poseidon2 => {
            let proof: Proof<zk::Poseidon2Config> = postcard::from_bytes(proof).map_err(decode)?;
            postcard::to_allocvec(&proof.commitments.trace).map_err(decode)
        }
        HashCandidate::Keccak256 => {
            let proof: Proof<zk::KeccakConfig> = postcard::from_bytes(proof).map_err(decode)?;
            postcard::to_allocvec(&proof.commitments.trace).map_err(decode)
        }
    }
}

/// Fresh zero-knowledge randomness from the operating system. The browser
/// build takes its seed from `crypto.getRandomValues` instead.
#[cfg(not(target_arch = "wasm32"))]
pub fn os_seed() -> [u8; 32] {
    use std::io::Read;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .expect("the operating system's random source");
    seed
}

/// One statement ready to prove: the gate has passed, the witness is drawn
/// and the public inputs are computed. Nothing here is timed.
#[derive(Clone, Debug)]
pub struct Instance {
    pub plan: SecurityPlan,
    pub witness: Witness,
    pub public_inputs: Vec<u32>,
    pub same_key: bool,
}

impl Instance {
    pub fn new(
        candidate: HashCandidate,
        log_blowup: usize,
        witness_seed: u64,
        same_key: bool,
    ) -> Result<Self, BenchError> {
        let plan = plan(candidate, log_blowup)?;
        let witness = Witness::primary(witness_seed, same_key);
        let public_inputs = public_inputs(candidate, &witness);
        Ok(Self {
            plan,
            witness,
            public_inputs,
            same_key,
        })
    }

    /// Proving, from receiving the witness to the finished proof bytes:
    /// trace generation, zero-knowledge randomness, commitments, FRI and
    /// grinding.
    pub fn prove(&self, zk_seed: [u8; 32]) -> Result<Vec<u8>, BenchError> {
        prove_gated(&self.plan, &self.witness, &self.public_inputs, zk_seed)
    }

    pub fn verify(&self, proof: &[u8]) -> Result<(), BenchError> {
        verify(&self.plan, &self.public_inputs, proof)
    }

    /// Public inputs as encoded for the verifier: four bytes per element.
    pub fn public_inputs_bytes(&self) -> usize {
        4 * self.public_inputs.len()
    }

    /// The configuration fields of a result record, as a JSON object body.
    pub fn record_fields(&self) -> json::Object {
        let p = &self.plan;
        let mut o = json::Object::new();
        o.str("library", LIBRARY)
            .str("library_repository", PLONKY3_REPOSITORY)
            .str("library_revision", PLONKY3_REVISION)
            .str("rustc_version", RUSTC_VERSION)
            .str("build_flags", BUILD_FLAGS)
            .str("hash_candidate", p.candidate.name())
            .str("hash_candidate_label", p.candidate.label())
            .str("configuration", &p.configuration_name())
            .bool("zero_knowledge", true)
            .num("log_blowup", p.log_blowup as u64)
            .num("blowup", 1 << p.log_blowup)
            .num("num_queries", p.num_queries as u64)
            .num("query_pow_bits", p.grinding.query as u64)
            .num("commit_pow_bits", p.grinding.commit as u64)
            .num("batch_pow_bits", p.grinding.batch as u64)
            .num("ood_pow_bits", p.grinding.ood as u64)
            .num("max_log_arity", p.max_log_arity as u64)
            .num("log_final_poly_len", p.log_final_poly_len as u64)
            .num("extension_degree", security::EXTENSION_DEGREE as u64)
            .num("challenge_field_bits", security::CHALLENGE_FIELD_BITS as u64)
            .num("collision_resistance_bits", p.collision_resistance_bits as u64)
            .num("trace_height", p.trace_height as u64)
            .num("trace_width", p.trace_width as u64)
            .num("zk_min_trace_height", p.zk_min_trace_height as u64)
            .num("constraint_degree", p.constraint_degree as u64)
            .num("conjectured_security_bits", p.estimate.conjectured_bits as u64)
            .num("proven_security_bits", p.estimate.proven_bits as u64)
            .num("security_target_bits", TARGET_CONJECTURED_BITS as u64)
            .str("security_target_regime", "conjectured")
            .str("security_estimator", "library: p3-uni-stark StarkSecurityParams (p3-security)")
            .num("witness_seed", self.witness.seed)
            .bool("same_key", self.same_key)
            .num("public_inputs_bytes", self.public_inputs_bytes() as u64);
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The revision recorded in results is the one the workspace pins.
    #[test]
    fn recorded_revision_matches_the_manifest() {
        let manifest = include_str!("../../Cargo.toml");
        let pins: Vec<&str> = manifest
            .lines()
            .filter(|l| l.starts_with("p3-"))
            .collect();
        assert!(!pins.is_empty());
        for line in pins {
            assert!(line.contains(PLONKY3_REVISION), "{line}");
        }
    }
}
