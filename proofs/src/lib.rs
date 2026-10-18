//! The proof statements of Ghost (spec 02), with a native prover and verifier.
//!
//! - S1, the one-time reveal of a coin: [`prove_coin_reveal`],
//!   [`verify_coin_reveal`].
//! - S2, the one-time reveal of data: [`verify_data_reveal`], which rejects
//!   every data reveal until its fee is settled.
//! - S3, the proof of holding: [`verify_hold`], which rejects every proof until
//!   the spent-marker set is settled, and the verifier's [`ChallengeBook`].
//!
//! The module [`ffi`] is a C interface to [`verify_coin_reveal`], with its
//! header in `include/ghost_proofs.h`.
//!
//! S2 and S3 are written in full, and are built and verified only by the
//! functions compiled under the `unsettled-points-test` feature, for tests.
//! The public verifiers reject them whether or not the feature is on.
//!
//! **Proof system** (decision 0003): Plonky3's uni-STARK over BabyBear with a
//! degree-5 extension, hiding FRI at blowup 2^2 with 57 queries, 16 bits of
//! grinding on the queries and 16 before the batching challenge, Keccak-256
//! for every commitment, zero-knowledge on, at least 128 conjectured bits. It
//! is transparent and the proof is verified as it is. Inside the proofs the
//! only hash is Keccak-256 with the original padding, the hash of spec 01.
//!
//! **What stays private.** No public input is `s`, `r`, `b`, `cf`, `v`, `v'`,
//! a position or a path. The types that hold them implement neither `Debug`
//! nor `Display` nor any serialization, so they cannot leave by accident.
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

#[doc(hidden)]
pub mod adversary;
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
pub use data::{DataOpening, DataPurpose, DataReveal, data_reveal_binding, verify_data_reveal};
#[cfg(feature = "unsettled-points-test")]
pub use data::{DataRevealRequest, prove_data_reveal, verify_data_reveal_unsettled};
pub use hash::{
    COIN, DATA, EMPTY_RULE, RATE_BYTES, TREE_DEPTH, Tree, coin_commitment, coin_fingerprint, coin_marker,
    data_commitment, data_fingerprint, data_marker, empty_leaf, keccak256, merkle_root, permutations, tag_bytes,
    tagged, tree_node,
};
pub use hold::{ChallengeBook, HoldContext, HoldOpening, hold_binding, verify_hold};
#[cfg(feature = "unsettled-points-test")]
pub use hold::{prove_hold, verify_hold_unsettled, verify_hold_unsettled_with_book};
pub use reveal::{
    CoinOpening, CoinRemainder, CoinReveal, NOTE_BYTES, RevealRequest, coin_reveal_binding, prove_coin_reveal,
    verify_coin_reveal,
};
pub use stark::{
    BATCH_POW_BITS, COLLISION_RESISTANCE_BITS, EXTENSION_DEGREE, LOG_BLOWUP, MAX_GRINDING_BITS, NUM_QUERIES,
    QUERY_POW_BITS, SecurityEstimate, Statement, TARGET_CONJECTURED_BITS,
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
    /// A proof of holding for `COIN` (spec 02, section 13, item 3).
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
    /// The estimate is below 128 conjectured bits.
    BelowSecurityFloor { bits: usize },
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
            Self::HoldCoinUnsettled => f.write_str("proof of holding for coins is not settled"),
            Self::HoldUnsettled => f.write_str("proof of holding is not settled: no spent-marker set"),
            Self::DataFeeUnsettled => f.write_str("the fee of a data reveal is not settled"),
            Self::ChallengeUnknown => f.write_str("challenge never issued"),
            Self::ChallengeUsed => f.write_str("challenge already accepted"),
            Self::ChallengeExpired => f.write_str("challenge expired"),
            Self::ChallengeAlreadyIssued => f.write_str("challenge already issued"),
            Self::NotZeroKnowledge => f.write_str("configuration is not zero-knowledge"),
            Self::ConstraintDegreeTooHigh => f.write_str("constraint degree too high for the blowup"),
            Self::BelowSecurityFloor { bits } => write!(f, "{bits} conjectured bits, below {TARGET_CONJECTURED_BITS}"),
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
    /// The estimator's result for each statement at these parameters.
    pub statements: [(Statement, SecurityEstimate); 3],
}

/// Build the shipped configuration and report it.
pub fn shipped_configuration() -> Result<ShippedConfiguration, ProofError> {
    Ok(ShippedConfiguration {
        zero_knowledge: stark::shipped_is_zero_knowledge(),
        log_blowup: LOG_BLOWUP,
        num_queries: NUM_QUERIES,
        query_pow_bits: QUERY_POW_BITS,
        batch_pow_bits: BATCH_POW_BITS,
        extension_degree: EXTENSION_DEGREE,
        commitment_collision_bits: COLLISION_RESISTANCE_BITS,
        statements: stark::estimates()?,
    })
}
