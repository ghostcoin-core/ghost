//! A prover that lies, so tests can show the verifier catches it.
//!
//! [`prove_coin_reveal_claiming`] runs the prover on a witness and a claimed
//! transaction with none of the honest prover's checks: the trace hashes what
//! the witness gives, the public values are the claimed transaction's, and
//! the conservation carries are a best guess. When the claim and the witness
//! disagree, a constraint fails and the proof does not verify. Nothing here
//! can make a proof the verifier accepts that the honest prover would refuse.

use crate::amount::guessed_carries;
use crate::binding::ChainParams;
use crate::reveal::{CoinOpening, CoinRemainder, CoinReveal, prove_unchecked};
use crate::{Proof, ProofError};

/// Prove a coin reveal claiming `claimed`, whatever the witness says.
pub fn prove_coin_reveal_claiming(
    params: &ChainParams,
    opening: &CoinOpening,
    remainder: &CoinRemainder,
    claimed: &CoinReveal,
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    let carries = guessed_carries(&opening.v, &claimed.out, &remainder.v, &claimed.fee);
    prove_unchecked(params, opening, remainder, claimed, carries, zk_randomness)
}
