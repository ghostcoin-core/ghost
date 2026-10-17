//! Witness data for the benchmark runs.
//!
//! The tree is conceptual: its 2^32 leaves are never built. A run draws
//! pseudo-random secrets, a random leaf position and pseudo-random sibling
//! digests from a recorded seed, and the consistent root follows from them.
//! Sibling values and direction bits do not change the cost, but they differ
//! between runs so nothing degenerate (such as all-empty subtrees) is
//! measured. The seed only fixes the statement; the zero-knowledge randomness
//! is drawn separately and is never seeded from it.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Depth of the coin tree: room for about four billion commitments.
pub const TREE_DEPTH: usize = 32;

/// Base units per whole GHOST (18 decimals).
pub const UNITS_PER_GHOST: u128 = 1_000_000_000_000_000_000;

/// Amounts are 96 bits, held as four limbs of 24 bits.
pub const AMOUNT_LIMBS: usize = 4;
pub const AMOUNT_LIMB_BITS: usize = 24;
pub const AMOUNT_BITS: usize = AMOUNT_LIMBS * AMOUNT_LIMB_BITS;

/// Primary measurement: 1,000 GHOST in.
pub const PRIMARY_INPUT: u128 = 1_000 * UNITS_PER_GHOST;
/// Primary measurement: 250 GHOST to the public destination.
pub const PRIMARY_OUT: u128 = 250 * UNITS_PER_GHOST;
/// Primary measurement: a fee of 0.001 GHOST.
pub const PRIMARY_FEE: u128 = UNITS_PER_GHOST / 1_000;

/// Version and type of a coin commitment (type 1, version 1), one byte.
pub const COIN_TYPE_TAG: u32 = 0x11;

/// Everything the prover knows, in candidate-neutral form.
///
/// Secrets, blinding values and digests are 32 bytes. Candidate A reads a
/// 32-byte value as eight field elements (four bytes each, reduced); candidate
/// B uses the bytes as they are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    /// Seed the witness was drawn from, recorded with every result.
    pub seed: u64,
    /// Secret `s` of the commitment being opened.
    pub secret: [u8; 32],
    /// Reveal secret `r` of the commitment being opened.
    pub reveal_secret: [u8; 32],
    /// Blinding `b` of the commitment being opened.
    pub blinding: [u8; 32],
    /// Version and type of both commitments.
    pub type_tag: u32,
    /// Content fingerprint, shared by both commitments.
    pub fingerprint: [u8; 32],
    /// Rule field, shared by both commitments.
    pub rule: [u8; 16],
    /// Amount `v` held by the commitment being opened.
    pub amount: u128,
    /// Secret `s'` of the remainder commitment.
    pub remainder_secret: [u8; 32],
    /// Reveal secret `r'` of the remainder commitment.
    pub remainder_reveal_secret: [u8; 32],
    /// Fresh blinding `b'` of the remainder commitment.
    pub remainder_blinding: [u8; 32],
    /// Remainder amount `v'`.
    pub remainder_amount: u128,
    /// Public amount out.
    pub amount_out: u128,
    /// Total fee, as set by the chain's formula.
    pub fee: u128,
    /// Leaf position in the tree; bit `i` is the direction bit at level `i`
    /// (1 when the current node is the right child).
    pub leaf_index: u32,
    /// Sibling digests from the leaf level up.
    pub siblings: [[u8; 32]; TREE_DEPTH],
    /// Inputs to the binding digest, which the verifier computes itself.
    pub binding: BindingInputs,
}

/// What the binding digest covers besides the remainder commitment and root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingInputs {
    pub chain_id: u64,
    pub transaction_type: u8,
    pub transaction_version: u8,
    pub destination: [u8; 20],
}

impl Witness {
    /// Draw a witness for the primary measurement from `seed`.
    ///
    /// With `same_key` the remainder keeps the input's `s` and `r` (the
    /// outline's default); without it the remainder gets new, independent
    /// values, as in a claim to a new key. The cost is the same.
    pub fn primary(seed: u64, same_key: bool) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut bytes32 = || {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            b
        };
        let secret = bytes32();
        let reveal_secret = bytes32();
        let blinding = bytes32();
        let fingerprint = bytes32();
        let remainder_blinding = bytes32();
        let (remainder_secret, remainder_reveal_secret) = if same_key {
            (secret, reveal_secret)
        } else {
            (bytes32(), bytes32())
        };
        let siblings = core::array::from_fn(|_| bytes32());
        let mut rule = [0u8; 16];
        rng.fill_bytes(&mut rule);
        let mut destination = [0u8; 20];
        rng.fill_bytes(&mut destination);
        let leaf_index = rng.next_u32();
        Self {
            seed,
            secret,
            reveal_secret,
            blinding,
            type_tag: COIN_TYPE_TAG,
            fingerprint,
            rule,
            amount: PRIMARY_INPUT,
            remainder_secret,
            remainder_reveal_secret,
            remainder_blinding,
            remainder_amount: PRIMARY_INPUT - PRIMARY_OUT - PRIMARY_FEE,
            amount_out: PRIMARY_OUT,
            fee: PRIMARY_FEE,
            leaf_index,
            siblings,
            binding: BindingInputs {
                chain_id: 0x6768_6f73_74,
                transaction_type: 1,
                transaction_version: 1,
                destination,
            },
        }
    }

    /// Direction bit at `level`: true when the current node is the right child.
    pub fn direction(&self, level: usize) -> bool {
        (self.leaf_index >> level) & 1 == 1
    }
}

/// Split a 96-bit amount into four little-endian 24-bit limbs.
///
/// Bits above 96 are dropped, which is how a wrapped (negative) remainder
/// shows up in the tests: as an amount whose limbs do not add up.
pub fn amount_limbs(amount: u128) -> [u32; AMOUNT_LIMBS] {
    core::array::from_fn(|i| ((amount >> (AMOUNT_LIMB_BITS * i)) & 0xff_ffff) as u32)
}

/// The amount as 12 little-endian bytes (four 24-bit limbs, three bytes each).
pub fn amount_bytes(amount: u128) -> [u8; 12] {
    let mut out = [0u8; 12];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (amount >> (8 * i)) as u8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_amounts_conserve_value_and_fit_96_bits() {
        let w = Witness::primary(7, true);
        assert_eq!(w.amount, w.amount_out + w.remainder_amount + w.fee);
        assert!(w.amount < 1u128 << AMOUNT_BITS);
        // The amounts use the full width of the limbs.
        assert!(amount_limbs(w.amount).iter().filter(|&&l| l > 0).count() >= 3);
    }

    #[test]
    fn same_key_controls_the_remainder_secrets() {
        let same = Witness::primary(3, true);
        assert_eq!(same.remainder_secret, same.secret);
        assert_eq!(same.remainder_reveal_secret, same.reveal_secret);
        let fresh = Witness::primary(3, false);
        assert_ne!(fresh.remainder_secret, fresh.secret);
        assert_ne!(fresh.remainder_reveal_secret, fresh.reveal_secret);
    }

    #[test]
    fn different_seeds_give_different_paths() {
        let a = Witness::primary(1, true);
        let b = Witness::primary(2, true);
        assert_ne!(a.siblings, b.siblings);
        assert_ne!(a.leaf_index, b.leaf_index);
    }

    #[test]
    fn limbs_and_bytes_round_trip() {
        let v = PRIMARY_INPUT - PRIMARY_OUT - PRIMARY_FEE;
        let limbs = amount_limbs(v);
        let back: u128 = limbs
            .iter()
            .enumerate()
            .map(|(i, &l)| u128::from(l) << (24 * i))
            .sum();
        assert_eq!(back, v);
        let bytes = amount_bytes(v);
        let back: u128 = bytes
            .iter()
            .enumerate()
            .map(|(i, &b)| u128::from(b) << (8 * i))
            .sum();
        assert_eq!(back, v);
    }
}
