//! Building a coin reveal: a partial reveal, a full reveal and a claim to a new
//! key (spec 01, section 8; spec 02, section 4), and the proving call.
//!
//! ```text
//! input      number i of the key, amount v, at its position under root
//! partial    remainder: same key, number i + 1, b_{i+1}, v' = v - out - fee
//! full       remainder: same key, number i + 1, b_{i+1}, v' = 0, out = v - fee
//! claim      remainder: the new key's s' and r', its number 0, b'_0,
//!            v' = v - out - fee, the note under the new key's note key
//! ```
//!
//! Every reveal creates exactly one remainder commitment with its note, even
//! a full reveal, so a full reveal looks like any other on the chain. The
//! remainder number is always one above the number spent, so a retry of a
//! dropped reveal takes the same number again and numbers have no gaps.
//!
//! The root is the caller's: the tree state chosen by
//! [`choose_tree_state`](crate::tree_state::choose_tree_state), never the root
//! of the block that added the leaf.
//!
//! Every coin is salted (version 2) and is proved by
//! [`ghost_proofs::prove_salted_coin_reveal`]: its salt and a fresh salt for
//! the remainder, drawn from the caller's generator, are private witnesses,
//! and the remainder's note is note version 2, carrying that fresh salt.
//! Every builder refuses what the prover refuses.

use core::fmt;

pub use ghost_proofs::{
    ChainParams, CoinReveal, Proof, ProofError, RevealRequest, SaltedCoinOpening,
    SaltedCoinRemainder, TREE_DEPTH,
};
use rand_core::CryptoRng;

use crate::commit::{Amount, Commitment, Marker, Rule, Salt};
use crate::key::PhantomKey;
use crate::note::{encrypt_note, NoteContents};
use crate::wipe::wipe;

/// Why a reveal was not built.
#[derive(Clone, PartialEq, Eq)]
pub enum RevealError {
    /// The proofs crate refused the reveal or failed to prove it. An amount
    /// left below zero (`out + fee > v`) is refused as
    /// [`ProofError::ConservationFails`].
    Proof(ProofError),
    /// The coin's number is the last a key has, so no remainder number is left.
    NumbersExhausted,
    /// A claim to the key that already holds the coin: the remainder would
    /// take number 0 a second time.
    ClaimToSameKey,
}

impl fmt::Debug for RevealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof(error) => write!(f, "Proof({error:?})"),
            Self::NumbersExhausted => f.write_str("NumbersExhausted"),
            Self::ClaimToSameKey => f.write_str("ClaimToSameKey"),
        }
    }
}

impl fmt::Display for RevealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof(error) => write!(f, "the reveal was refused: {error}"),
            Self::NumbersExhausted => f.write_str("the key has no commitment number left"),
            Self::ClaimToSameKey => f.write_str("a claim must go to a new key"),
        }
    }
}

impl std::error::Error for RevealError {}

impl From<ProofError> for RevealError {
    fn from(error: ProofError) -> Self {
        Self::Proof(error)
    }
}

/// The key's coin being revealed, as restore found it and the wallet's own
/// tree data placed it.
///
/// It holds the coin's number, amount and position, so it has no `Debug`.
pub struct OwnedCoin {
    /// The commitment number `i` (spec 01, section 8).
    pub number: u64,
    /// The amount `v`.
    pub amount: Amount,
    /// The rule; only the empty rule is accepted.
    pub rule: Rule,
    /// The coin's salt.
    pub salt: Salt,
    /// The position of the coin's leaf in the coin tree, read from the chain.
    pub position: u32,
    /// The 32 sibling hashes from the leaf up to `root`, computed by the
    /// wallet from its bulk tree data, never asked of an endpoint.
    pub path: [[u8; 32]; TREE_DEPTH],
}

/// The public choices of a reveal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RevealTerms {
    /// The tree state to prove against (spec 02, section 8).
    pub root: [u8; 32],
    /// The address that receives `out`.
    pub recipient: [u8; 20],
    /// The fee.
    pub fee: Amount,
}

/// The remainder commitment a reveal creates. Its position is the one the
/// chain gives the leaf when the reveal is included.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RemainderCoin {
    /// Its number under the key that holds it.
    pub number: u64,
    /// The amount left, `v'`.
    pub amount: Amount,
    /// The rule, the input's.
    pub rule: Rule,
    /// Its fresh salt, carried in its note.
    pub salt: Salt,
    /// `C'`, the new leaf.
    pub commitment: Commitment,
    /// The marker it publishes when it is revealed in turn.
    pub marker: Marker,
}

/// A built reveal: the public fields, the proof, and what the wallet tracks.
pub struct BuiltReveal {
    /// The public fields the transaction carries.
    pub reveal: CoinReveal,
    /// The proof.
    pub proof: Proof,
    /// The remainder the reveal creates.
    pub remainder: RemainderCoin,
}

/// Runs the prover for one coin reveal of a salted coin, as the builders do.
///
/// It is what a background worker runs. It starts no thread, reads no
/// operating system random source or clock and uses no file or network, so
/// it builds for `wasm32-unknown-unknown`; `zk_randomness` must be 32 fresh
/// bytes from the caller's secure random source. It refuses what
/// [`ghost_proofs::prove_salted_coin_reveal`] refuses.
pub fn prove_reveal(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    remainder: &SaltedCoinRemainder,
    request: &RevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(CoinReveal, Proof), ProofError> {
    ghost_proofs::prove_salted_coin_reveal(params, opening, remainder, request, zk_randomness)
}

/// A partial reveal: pays `out` to the recipient and keeps `v - out - fee`
/// under the same key as number `i + 1`, with a fresh blinding and its note.
pub fn partial_reveal<R: CryptoRng + ?Sized>(
    params: &ChainParams,
    key: &PhantomKey,
    coin: &OwnedCoin,
    terms: &RevealTerms,
    out: Amount,
    rng: &mut R,
    zk_randomness: [u8; 32],
) -> Result<BuiltReveal, RevealError> {
    let number = next_number(coin)?;
    build(params, key, coin, terms, out, key, number, rng, zk_randomness)
}

/// A full reveal: pays `v - fee` to the recipient. It still creates a
/// remainder, of amount zero, number `i + 1` under the same key, with its
/// note.
pub fn full_reveal<R: CryptoRng + ?Sized>(
    params: &ChainParams,
    key: &PhantomKey,
    coin: &OwnedCoin,
    terms: &RevealTerms,
    rng: &mut R,
    zk_randomness: [u8; 32],
) -> Result<BuiltReveal, RevealError> {
    let out = coin
        .amount
        .wei()
        .checked_sub(terms.fee.wei())
        .and_then(|wei| Amount::new(wei).ok())
        .ok_or(RevealError::Proof(ProofError::ConservationFails))?;
    let number = next_number(coin)?;
    build(params, key, coin, terms, out, key, number, rng, zk_randomness)
}

/// A claim to a new key: pays `out` to the recipient and moves
/// `v - out - fee` to `new_key`, as that key's commitment number 0, with the
/// note under the new key's note key. The caller generates the new key.
#[allow(clippy::too_many_arguments)]
pub fn claim_to_new_key<R: CryptoRng + ?Sized>(
    params: &ChainParams,
    key: &PhantomKey,
    coin: &OwnedCoin,
    new_key: &PhantomKey,
    terms: &RevealTerms,
    out: Amount,
    rng: &mut R,
    zk_randomness: [u8; 32],
) -> Result<BuiltReveal, RevealError> {
    if key.key_bytes().as_bytes() == new_key.key_bytes().as_bytes() {
        return Err(RevealError::ClaimToSameKey);
    }
    build(params, key, coin, terms, out, new_key, 0, rng, zk_randomness)
}

fn next_number(coin: &OwnedCoin) -> Result<u64, RevealError> {
    coin.number.checked_add(1).ok_or(RevealError::NumbersExhausted)
}

#[allow(clippy::too_many_arguments)]
fn build<R: CryptoRng + ?Sized>(
    params: &ChainParams,
    key: &PhantomKey,
    coin: &OwnedCoin,
    terms: &RevealTerms,
    out: Amount,
    holder: &PhantomKey,
    number: u64,
    rng: &mut R,
    zk_randomness: [u8; 32],
) -> Result<BuiltReveal, RevealError> {
    let left = coin
        .amount
        .wei()
        .checked_sub(out.wei())
        .and_then(|wei| wei.checked_sub(terms.fee.wei()))
        .and_then(|wei| Amount::new(wei).ok())
        .ok_or(RevealError::Proof(ProofError::ConservationFails))?;

    // The remainder is salted under a fresh salt.
    let remainder_salt = Salt::random(rng);
    let commit = holder
        .coin_commit_with_salt(number, left, coin.rule, remainder_salt)
        .map_err(|_| RevealError::Proof(ProofError::RuleNotEmpty))?;
    let remainder = RemainderCoin {
        number,
        amount: left,
        rule: coin.rule,
        salt: remainder_salt,
        commitment: commit.commitment,
        marker: commit.marker,
    };
    let contents = NoteContents::salted_coin(number, left, coin.rule, remainder_salt);
    let chain_id = u64::from_be_bytes(params.chain_id);
    let remainder_note = encrypt_note(
        &holder.note_key(),
        chain_id,
        &remainder.commitment,
        &contents,
        rng,
    );

    let input = key.key_bytes();
    let output = holder.key_bytes();
    let request = RevealRequest {
        root: terms.root,
        recipient: terms.recipient,
        out: out.to_bytes(),
        fee: terms.fee.to_bytes(),
        rule: *coin.rule.as_bytes(),
        remainder_note,
    };
    let mut opening = SaltedCoinOpening {
        s: *input.secret().as_bytes(),
        r: *input.reveal_secret().as_bytes(),
        b: *input.blinding(coin.number).as_bytes(),
        salt: *coin.salt.as_bytes(),
        v: coin.amount.to_bytes(),
        position: coin.position,
        path: coin.path,
    };
    let mut new_coin = SaltedCoinRemainder {
        s: *output.secret().as_bytes(),
        r: *output.reveal_secret().as_bytes(),
        b: *output.blinding(number).as_bytes(),
        salt: *remainder_salt.as_bytes(),
        v: left.to_bytes(),
    };
    let proved = prove_reveal(params, &opening, &new_coin, &request, zk_randomness);
    for secret in [&mut opening.s, &mut opening.r, &mut opening.b, &mut opening.v] {
        wipe(secret);
    }
    for secret in [&mut new_coin.s, &mut new_coin.r, &mut new_coin.b, &mut new_coin.v] {
        wipe(secret);
    }
    let (reveal, proof) = proved?;
    debug_assert_eq!(&reveal.remainder, remainder.commitment.as_bytes());
    Ok(BuiltReveal {
        reveal,
        proof,
        remainder,
    })
}
