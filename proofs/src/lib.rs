//! The proof statements of Ghost (spec 02), with a native prover and verifier.
//!
//! Every statement opens a salted (format version 2) commitment of spec 01,
//! section 3, the only commitment format.
//!
//! - S1, the one-time reveal of a coin: [`prove_salted_coin_reveal`] and
//!   [`verify_salted_coin_reveal`].
//! - S2, the one-time reveal of data: [`verify_salted_data_reveal`], which
//!   rejects every data reveal until its fee is settled.
//! - S3, the proof of holding: [`verify_hold`], for `DATA_V2` commitments,
//!   which rejects every proof until the spent-marker set is settled, and the
//!   verifier's [`ChallengeBook`].
//!
//! The module [`ffi`] is a C interface to [`verify_salted_coin_reveal`], with
//! its header in `include/ghost_proofs.h`.
//!
//! S2 and S3 are written in full, and are built and verified only by the
//! functions compiled under the `unsettled-points-test` feature, for tests.
//! The public verifiers reject them whether or not the feature is on.
//!
//! **Proof system** (decision 0003): Plonky3's uni-STARK over BabyBear with a
//! degree-5 extension, hiding FRI at blowup 2^3 (rate 1/8) with 43 queries,
//! 16 bits of grinding on the queries and 16 before the batching challenge,
//! Keccak-256 for every commitment, zero-knowledge on. The security gate holds
//! it to the post-quantum rule of spec 09, section 4.1: 129 conjectured bits
//! from the queries alone, and at least 128 for every term of the library's
//! estimator with grinding counted at half, so about 64 against a quantum
//! attacker. It is transparent and the proof is verified as it is, never
//! wrapped in an elliptic-curve proof. Inside the proofs the only hash is
//! Keccak-256 with the original padding, the hash of spec 01.
//!
//! **What stays private.** No public input is `s`, `r`, `b`, a salt, `v`,
//! `v'`, a position or a path. The types that hold them implement neither `Debug`
//! nor `Display` nor any serialization, so they cannot leave by accident. The
//! content fingerprint `cf` is public in S2 and S3 by design: it is what
//! revealed bytes are checked against.
//!
//! **Chain constants** (`chain_id`, `version`, `domain`) are parameters of
//! the verifier, [`ChainParams`], never constants of this crate. Every
//! binding digest is computed by the verifier from its own values and the
//! transaction's fields; no verify function takes a digest from a prover.
//!
//! **Randomness.** The prover takes its zero-knowledge randomness, and the
//! challenge book its challenges, as bytes the caller supplies from a secure
//! random source. The crate never reads the operating system's random source
//! or clock, so it builds for `wasm32-unknown-unknown` as it is.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

mod air;
mod amount;
mod binding;
mod data;
mod hash;
mod hold;
mod reveal;
mod schedule;
mod stark;

pub mod ffi;

pub use amount::{
    AMOUNT_HIGH_BYTES, AMOUNT_LIMBS, V_MAX, amount_is_valid, amount_limbs, amount_value, amount_word,
    conservation_carries, conservation_holds,
};
pub use binding::{
    Binding, COIN_REVEAL_LAYOUT, ChainParams, DATA_REVEAL_LAYOUT, HOLD_LAYOUT, LayoutField, PROTOCOL_VERSION_1,
    PURPOSE_HOLD, PURPOSE_REVEAL, PURPOSE_REVOKE, PURPOSE_SPEND, STATEMENT_COIN_REVEAL, STATEMENT_DATA_REVEAL,
    STATEMENT_HOLD, STATEMENT_VERSION_1,
};
pub use data::{DataPurpose, DataReveal, SaltedDataOpening, salted_data_reveal_binding, verify_salted_data_reveal};
#[cfg(feature = "unsettled-points-test")]
pub use data::{DataRevealRequest, prove_salted_data_reveal, verify_salted_data_reveal_unsettled};
#[cfg(feature = "unsettled-points-test")]
#[doc(hidden)]
pub use data::prove_salted_data_reveal_claiming;
pub use hash::{
    COIN_V2, DATA_V2, EMPTY_RULE, RATE_BYTES, SALT_BYTES, TREE_DEPTH, Tree, coin_commitment_v2, coin_fingerprint_v2,
    coin_marker_v2, data_commitment_v2, data_fingerprint_v2, data_marker_v2, empty_leaf, keccak256, merkle_root,
    permutations, tag_bytes, tagged, tree_node,
};
pub use hold::{ChallengeBook, HoldContext, SaltedHoldOpening, hold_binding, verify_hold};
#[cfg(feature = "unsettled-points-test")]
pub use hold::{prove_salted_hold, verify_hold_unsettled, verify_hold_unsettled_with_book};
#[cfg(feature = "unsettled-points-test")]
#[doc(hidden)]
pub use hold::prove_salted_hold_claiming;
pub use reveal::{
    CoinReveal, NOTE_BYTES, RevealRequest, SaltedCoinOpening, SaltedCoinRemainder, prove_salted_coin_reveal,
    salted_coin_reveal_binding, verify_salted_coin_reveal,
};
#[doc(hidden)]
pub use reveal::prove_salted_coin_reveal_claiming;

/// There is no version 1 coin reveal statement any more: this verifies
/// nothing and rejects every proof with [`ProofError::Rejected`]. Kept,
/// hidden, only because the client crate's restore test still checks that a
/// salted reveal does not pass as version 1; remove it with that check.
#[doc(hidden)]
pub fn verify_coin_reveal(params: &ChainParams, tx: &CoinReveal, proof: &Proof) -> Result<(), ProofError> {
    let _ = (params, tx, proof);
    Err(ProofError::Rejected)
}
pub use stark::{
    BATCH_POW_BITS, COLLISION_RESISTANCE_BITS, DIGEST_BITS, EXTENSION_DEGREE, LOG_BLOWUP, MAX_GRINDING_BITS,
    MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH, MIN_SALT_BITS, NUM_QUERIES, PROOF_FIELD_BYTES, QUERY_POW_BITS, SALT_BITS,
    SecurityEstimate, Statement, TARGET_CONJECTURED_BITS, proof_length_bound,
};

/// Why a proof was not made or not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofError {
    /// A rule other than the empty rule (spec 02, section 13, item 4).
    RuleNotEmpty,
    /// An amount word with any of its first 20 bytes set.
    AmountOutOfRange,
    /// `v != out + v' + fee`.
    ConservationFails,
    /// A remainder with the input's blinding: it would publish the input's
    /// marker when revealed.
    ReusedBlinding,
    /// The commitment is not the leaf at the position under the root.
    NotInTree,
    /// A type tag version 1 does not know.
    UnknownType,
    /// A purpose code other than the statement's.
    UnknownPurpose,
    /// A proof of holding asked for a content fingerprint that is not the
    /// opened commitment's.
    WrongContentFingerprint,
    /// A proof of holding for `COIN_V2` (spec 02, section 13, item 3).
    HoldCoinUnsettled,
    /// Every proof of holding, until the spent-marker set and its header root
    /// are settled (spec 02, section 13, item 2).
    HoldUnsettled,
    /// Every data reveal, until its fee is settled (spec 02, section 13,
    /// item 1).
    DataFeeUnsettled,
    /// A challenge the verifier never issued.
    ChallengeUnknown,
    /// A challenge already accepted once.
    ChallengeUsed,
    /// A challenge past its lifetime.
    ChallengeExpired,
    /// A challenge value already in the book.
    ChallengeAlreadyIssued,
    /// The library does not report the configuration as zero-knowledge.
    NotZeroKnowledge,
    /// The constraint degree does not fit the blowup in zero-knowledge mode.
    ConstraintDegreeTooHigh,
    /// The estimate, with grinding counted at half, is below 128 conjectured
    /// bits (spec 09, section 4.1, item 2).
    BelowSecurityFloor { bits: usize },
    /// `log2(blowup) * queries` is below 128: the queries alone do not reach
    /// the floor (spec 09, section 4.1, item 1).
    TooFewQueries { bits: usize },
    /// A grinding site over [`MAX_GRINDING_BITS`].
    TooMuchGrinding,
    /// The commitments or the transcript do not use Keccak-256 with 256-bit
    /// digests (spec 09, section 4.1, item 3).
    NotKeccak256,
    /// Salts shorter than [`MIN_SALT_BITS`] (spec 09, section 4.1, item 4).
    SaltTooShort { bits: usize },
    /// The library's estimator could not be run on the statement; an
    /// uncertain estimate is a refusal.
    EstimateUnavailable,
    /// A statement's trace is taller or wider than the proof-size budget
    /// (spec 07, section 3), so its proof might not fit the proof field.
    TraceOverBudget { height: usize, width: usize },
    /// Proof bytes that do not decode, or a proof of the wrong shape.
    MalformedProof,
    /// The proving library failed.
    Proving,
    /// The proof does not verify against the verifier's public values.
    Rejected,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuleNotEmpty => f.write_str("only the empty rule is accepted in version 1"),
            Self::AmountOutOfRange => f.write_str("amount word above 2^96 - 1"),
            Self::ConservationFails => f.write_str("v is not out + remainder + fee"),
            Self::ReusedBlinding => f.write_str("the remainder reuses the input's blinding"),
            Self::NotInTree => f.write_str("the commitment is not under the root"),
            Self::UnknownType => f.write_str("unknown type tag"),
            Self::UnknownPurpose => f.write_str("unknown purpose code"),
            Self::WrongContentFingerprint => {
                f.write_str("the content fingerprint is not the one of the commitment opened")
            }
            Self::HoldCoinUnsettled => f.write_str("proof of holding for coins is not settled"),
            Self::HoldUnsettled => f.write_str("proof of holding is not settled: no spent-marker set"),
            Self::DataFeeUnsettled => f.write_str("the fee of a data reveal is not settled"),
            Self::ChallengeUnknown => f.write_str("challenge never issued"),
            Self::ChallengeUsed => f.write_str("challenge already accepted"),
            Self::ChallengeExpired => f.write_str("challenge expired"),
            Self::ChallengeAlreadyIssued => f.write_str("challenge already issued"),
            Self::NotZeroKnowledge => f.write_str("configuration is not zero-knowledge"),
            Self::ConstraintDegreeTooHigh => f.write_str("constraint degree too high for the blowup"),
            Self::BelowSecurityFloor { bits } => write!(
                f,
                "{bits} conjectured bits with grinding counted at half, below {TARGET_CONJECTURED_BITS}"
            ),
            Self::TooFewQueries { bits } => {
                write!(f, "the queries alone give {bits} conjectured bits, below {TARGET_CONJECTURED_BITS}")
            }
            Self::TooMuchGrinding => write!(f, "a grinding site over {MAX_GRINDING_BITS} bits"),
            Self::NotKeccak256 => f.write_str("commitments or transcript not Keccak-256 with 256-bit digests"),
            Self::SaltTooShort { bits } => write!(f, "{bits}-bit salts, below {MIN_SALT_BITS}"),
            Self::EstimateUnavailable => f.write_str("the security estimate could not be computed"),
            Self::TraceOverBudget { height, width } => write!(
                f,
                "trace of {height} rows by {width} columns is over the budget of \
                 {MAX_TRACE_HEIGHT} by {MAX_TRACE_WIDTH}"
            ),
            Self::MalformedProof => f.write_str("malformed proof"),
            Self::Proving => f.write_str("proving failed"),
            Self::Rejected => f.write_str("proof rejected"),
        }
    }
}

impl std::error::Error for ProofError {}

/// A proof, as the bytes that travel. It holds nothing secret: the
/// configuration is zero-knowledge.
#[derive(Clone, PartialEq, Eq)]
pub struct Proof(Vec<u8>);

impl Proof {
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Proof({} bytes)", self.0.len())
    }
}

/// The configuration the public prove and verify functions use, as the
/// library reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShippedConfiguration {
    /// Whether the library reports the configuration as zero-knowledge.
    pub zero_knowledge: bool,
    pub log_blowup: usize,
    pub num_queries: usize,
    pub query_pow_bits: usize,
    pub batch_pow_bits: usize,
    pub extension_degree: usize,
    pub commitment_collision_bits: usize,
    /// `log_blowup * num_queries`: the conjectured bits of the queries alone,
    /// before grinding (spec 09, section 4.1, item 1).
    pub query_bits: usize,
    /// Whether the commitments and the transcript hash are recognised as
    /// Keccak-256.
    pub commitment_hash_is_keccak256: bool,
    /// Bits of a Merkle digest.
    pub merkle_digest_bits: usize,
    /// Bits of the transcript hash's output.
    pub transcript_digest_bits: usize,
    /// Salt bits per opened row.
    pub salt_bits: usize,
    /// The estimator's result for each statement at these parameters:
    /// conjectured and proven, classical and quantum.
    pub statements: [(Statement, SecurityEstimate); Statement::ALL.len()],
}

/// Build the shipped configuration and report it. Fails when the security
/// gate refuses any statement.
pub fn shipped_configuration() -> Result<ShippedConfiguration, ProofError> {
    let p = stark::shipped_parameters();
    Ok(ShippedConfiguration {
        zero_knowledge: p.zero_knowledge,
        log_blowup: p.fri.log_blowup,
        num_queries: p.fri.num_queries,
        query_pow_bits: p.fri.query_pow_bits,
        batch_pow_bits: p.fri.batch_pow_bits,
        extension_degree: EXTENSION_DEGREE,
        commitment_collision_bits: COLLISION_RESISTANCE_BITS,
        query_bits: p.fri.log_blowup * p.fri.num_queries,
        commitment_hash_is_keccak256: p.hash == stark::CommitmentHash::Keccak256,
        merkle_digest_bits: p.merkle_digest_bits,
        transcript_digest_bits: p.transcript_digest_bits,
        salt_bits: p.salt_bits,
        statements: stark::estimates()?,
    })
}
