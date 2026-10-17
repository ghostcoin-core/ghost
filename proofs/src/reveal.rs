//! Statement S1: the one-time reveal of a coin (spec 02, section 4).
//!
//! The proof opens one coin commitment `C` under the public coin-tree `root`,
//! publishes its one-time `marker = K("ghost/coin-marker/v1", r, b)`, builds
//! exactly one `remainder` commitment with the input's type tag, `cf` and
//! `rule`, shows `v = out + v' + fee` over the integers on 16-bit limbs, and
//! computes the coin reveal binding digest over every public field. `C`, `F`,
//! the position, the path, `v`, `v'` and every secret stay private.
//!
//! The hashes, in trace order (43 permutations):
//!
//! ```text
//! F       K(coin-fingerprint, s, r, b, COIN, 0^32, rule)   2 blocks
//! C       K(coin-commitment, COIN, F, v)                   1
//! N0..N31 K(coin-tree-node, level, left, right)            32, N31 = root
//! M       K(coin-marker, r, b)                             1, = marker
//! F'      K(coin-fingerprint, s', r', b', COIN, 0^32, rule) 2
//! C'      K(coin-commitment, COIN, F', v')                 1, = remainder
//! B       K(coin-reveal-binding, fields)                   4, = binding
//! ```
//!
//! `r` and `b` are carried columns read by both `F` and `M`, so the marker is
//! the one of the commitment opened. `s'`, `r'` and `b'` are unconstrained, so
//! the chain cannot tell a claim from a partial reveal; freshness of `b'` is
//! the wallet's rule, and [`prove_coin_reveal`] refuses `b' = b`.

use alloc::vec;
use alloc::vec::Vec;

use crate::amount::{AMOUNT_HIGH_BYTES, AMOUNT_LIMBS, CARRIES, amount_is_valid, conservation_carries, limb};
use crate::binding::{Binding, ChainParams, FieldWriter, PURPOSE_SPEND, STATEMENT_COIN_REVEAL, STATEMENT_VERSION_1, digest};
use crate::hash::{
    COIN, EMPTY_RULE, TAG_COIN_COMMITMENT, TAG_COIN_FINGERPRINT, TAG_COIN_MARKER, TAG_COIN_REVEAL_BINDING,
    TAG_COIN_TREE_NODE, TREE_DEPTH, Tree, coin_commitment, coin_fingerprint, coin_marker, merkle_root,
};
use crate::schedule::{Assignment, Conservation, HashBuilder, Schedule, ScheduleBuilder};
use crate::stark::{self, Statement};
use crate::{Proof, ProofError};

/// Length of an encrypted note on the chain (spec 01, section 9).
pub const NOTE_BYTES: usize = 156;

// Carried columns.
const R: usize = 0;
const B: usize = 32;
const V: usize = 64;
const V2: usize = V + AMOUNT_LIMBS;
const CARRY_BITS: usize = V2 + AMOUNT_LIMBS;
const CARRIED: usize = CARRY_BITS + 2 * CARRIES;

/// The commitment being revealed. It holds secrets, so it implements neither
/// `Debug` nor any serialization.
pub struct CoinOpening {
    pub s: [u8; 32],
    pub r: [u8; 32],
    pub b: [u8; 32],
    /// The amount, an amount word.
    pub v: [u8; 32],
    /// Position of `C` in the coin tree.
    pub position: u32,
    /// The 32 sibling hashes from `C` to the root.
    pub path: [[u8; 32]; TREE_DEPTH],
}

/// The remainder the reveal creates. Secrets: no `Debug`, no serialization.
pub struct CoinRemainder {
    pub s: [u8; 32],
    pub r: [u8; 32],
    /// Fresh blinding; never the input's `b`.
    pub b: [u8; 32],
    /// The amount left, an amount word.
    pub v: [u8; 32],
}

/// What the wallet chooses for a reveal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevealRequest {
    /// The shared epoch root the wallet proves against (spec 02, section 8).
    pub root: [u8; 32],
    pub recipient: [u8; 20],
    pub out: [u8; 32],
    pub fee: [u8; 32],
    pub rule: [u8; 32],
    pub remainder_note: [u8; NOTE_BYTES],
}

/// The public fields of a coin reveal: everything the node reads from the
/// transaction. The chain constants and codes are the verifier's own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinReveal {
    pub root: [u8; 32],
    pub marker: [u8; 32],
    pub remainder: [u8; 32],
    pub remainder_note: [u8; NOTE_BYTES],
    pub recipient: [u8; 20],
    pub out: [u8; 32],
    pub fee: [u8; 32],
    pub rule: [u8; 32],
}

fn fields(params: &ChainParams, tx: &CoinReveal) -> Vec<u8> {
    FieldWriter::new(Binding::CoinReveal, params, STATEMENT_COIN_REVEAL, COIN, PURPOSE_SPEND)
        .put("root", &tx.root)
        .put("marker", &tx.marker)
        .put("remainder", &tx.remainder)
        .put("recipient", &tx.recipient)
        .put("out", &tx.out)
        .put("fee", &tx.fee)
        .put("rule", &tx.rule)
        .put("remainder_note", &tx.remainder_note)
        .finish()
}

/// The coin reveal binding digest, computed from the verifier's own chain
/// constants and the transaction's fields.
pub fn coin_reveal_binding(params: &ChainParams, tx: &CoinReveal) -> [u8; 32] {
    digest(Binding::CoinReveal, &fields(params, tx))
}

/// The public values of the proof: the binding fields, then the digest, one
/// byte each.
fn public_values(params: &ChainParams, tx: &CoinReveal) -> Vec<u8> {
    let mut public = fields(params, tx);
    let binding = digest(Binding::CoinReveal, &public);
    public.extend_from_slice(&binding);
    public
}

/// The schedule of S1 and, with a witness, the free bytes and direction bits.
pub(crate) fn schedule(w: Option<(&CoinOpening, &CoinRemainder)>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::CoinReveal;
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let mut sb = ScheduleBuilder::new();

    sb.push(
        HashBuilder::new(TAG_COIN_FINGERPRINT)
            .free(32, w.map(|(o, _)| &o.s[..]))
            .carried(R, 32)
            .carried(B, 32)
            .constant(&COIN)
            .constant(&[0; 32])
            .public(off("rule"), 32),
    );
    sb.push(HashBuilder::new(TAG_COIN_COMMITMENT).constant(&COIN).prev().amount(V));
    for level in 0..TREE_DEPTH {
        let mut node = HashBuilder::new(TAG_COIN_TREE_NODE)
            .constant(&[level as u8])
            .node(w.map(|(o, _)| (&o.path[level], o.position >> level & 1 == 1)));
        if level + 1 == TREE_DEPTH {
            node = node.output(off("root"));
        }
        sb.push(node);
    }
    sb.push(
        HashBuilder::new(TAG_COIN_MARKER)
            .carried(R, 32)
            .carried(B, 32)
            .output(off("marker")),
    );
    sb.push(
        HashBuilder::new(TAG_COIN_FINGERPRINT)
            .free(32, w.map(|(_, rem)| &rem.s[..]))
            .free(32, w.map(|(_, rem)| &rem.r[..]))
            .free(32, w.map(|(_, rem)| &rem.b[..]))
            .constant(&COIN)
            .constant(&[0; 32])
            .public(off("rule"), 32),
    );
    sb.push(
        HashBuilder::new(TAG_COIN_COMMITMENT)
            .constant(&COIN)
            .prev()
            .amount(V2)
            .output(off("remainder")),
    );
    sb.push(
        HashBuilder::new(TAG_COIN_REVEAL_BINDING)
            .public(0, fields_len)
            .output(fields_len),
    );

    let mut consts = vec![
        (off("statement"), STATEMENT_COIN_REVEAL),
        (off("statement_version"), STATEMENT_VERSION_1),
        (off("type"), COIN[0]),
        (off("type") + 1, COIN[1]),
        (off("purpose"), PURPOSE_SPEND),
    ];
    // Public amounts are amount words; only the empty rule exists.
    for t in 0..AMOUNT_HIGH_BYTES {
        consts.push((off("out") + t, 0));
        consts.push((off("fee") + t, 0));
    }
    for t in 0..32 {
        consts.push((off("rule") + t, 0));
    }
    let conservation = Conservation {
        v: V,
        remainder: V2,
        carries: CARRY_BITS,
        out: off("out"),
        fee: off("fee"),
    };
    sb.finish(fields_len + 32, CARRIED, Some(conservation), consts)
}

fn carried_values(opening: &CoinOpening, remainder: &CoinRemainder, carries: [u8; CARRIES]) -> Vec<u32> {
    let mut carried = vec![0u32; CARRIED];
    for k in 0..32 {
        carried[R + k] = u32::from(opening.r[k]);
        carried[B + k] = u32::from(opening.b[k]);
    }
    for j in 0..AMOUNT_LIMBS {
        carried[V + j] = limb(&opening.v, j);
        carried[V2 + j] = limb(&remainder.v, j);
    }
    for (k, &carry) in carries.iter().enumerate() {
        carried[CARRY_BITS + 2 * k] = u32::from(carry & 1);
        carried[CARRY_BITS + 2 * k + 1] = u32::from(carry >> 1);
    }
    carried
}

/// Prove whatever the witness and the claimed transaction give, without any
/// check. Only an honest caller's checks make the result verify.
pub(crate) fn prove_unchecked(
    params: &ChainParams,
    opening: &CoinOpening,
    remainder: &CoinRemainder,
    claimed: &CoinReveal,
    carries: [u8; CARRIES],
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    let (_, free, dirs) = schedule(Some((opening, remainder)));
    let assignment = Assignment {
        public: public_values(params, claimed),
        carried: carried_values(opening, remainder, carries),
        free,
        dirs,
    };
    stark::prove(Statement::CoinReveal, &assignment, zk_randomness).map(Proof)
}

/// Prove a coin reveal. Returns the public fields the transaction carries and
/// the proof.
///
/// Refuses, before any proving: a non-empty rule; an amount word with a high
/// byte set; a remainder whose blinding equals the input's (it would publish
/// the same marker when revealed); `v != out + v' + fee`; and a commitment
/// that is not the leaf at `position` under `root`.
///
/// `zk_randomness` must be 32 fresh bytes from a secure random source.
pub fn prove_coin_reveal(
    params: &ChainParams,
    opening: &CoinOpening,
    remainder: &CoinRemainder,
    request: &RevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(CoinReveal, Proof), ProofError> {
    if request.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    if ![&opening.v, &remainder.v, &request.out, &request.fee].into_iter().all(amount_is_valid) {
        return Err(ProofError::AmountOutOfRange);
    }
    if remainder.b == opening.b {
        return Err(ProofError::ReusedBlinding);
    }
    let carries = conservation_carries(&opening.v, &request.out, &remainder.v, &request.fee)
        .ok_or(ProofError::ConservationFails)?;
    let leaf = coin_commitment(&coin_fingerprint(&opening.s, &opening.r, &opening.b, &request.rule), &opening.v);
    if merkle_root(Tree::Coin, &leaf, opening.position, &opening.path) != request.root {
        return Err(ProofError::NotInTree);
    }
    let tx = CoinReveal {
        root: request.root,
        marker: coin_marker(&opening.r, &opening.b),
        remainder: coin_commitment(
            &coin_fingerprint(&remainder.s, &remainder.r, &remainder.b, &request.rule),
            &remainder.v,
        ),
        remainder_note: request.remainder_note,
        recipient: request.recipient,
        out: request.out,
        fee: request.fee,
        rule: request.rule,
    };
    let proof = prove_unchecked(params, opening, remainder, &tx, carries, zk_randomness)?;
    Ok((tx, proof))
}

/// Verify a coin reveal against the verifier's own chain constants.
///
/// Rejects a non-empty rule and an out-of-range `out` or `fee` before the
/// proof is looked at, then verifies the proof against public values the
/// verifier builds itself, binding digest included.
pub fn verify_coin_reveal(params: &ChainParams, tx: &CoinReveal, proof: &Proof) -> Result<(), ProofError> {
    if tx.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    if !amount_is_valid(&tx.out) || !amount_is_valid(&tx.fee) {
        return Err(ProofError::AmountOutOfRange);
    }
    stark::verify(Statement::CoinReveal, &public_values(params, tx), proof.as_bytes())
}

#[cfg(test)]
mod tests {
    use p3_air::check_all_constraints;

    use super::*;
    use crate::amount::amount_word;
    use crate::air::F;
    use crate::hash::empty_leaf;
    use crate::schedule::execute;
    use p3_field::PrimeCharacteristicRing;

    fn params() -> ChainParams {
        ChainParams {
            chain_id: [0, 0, 0, 0, 0, 0, 0x04, 0xd2],
            version: crate::binding::PROTOCOL_VERSION_1,
            domain: [7; 32],
        }
    }

    fn witness() -> (CoinOpening, CoinRemainder, RevealRequest) {
        let mut path = [[0u8; 32]; TREE_DEPTH];
        let mut empty = empty_leaf();
        for (level, sibling) in path.iter_mut().enumerate() {
            *sibling = empty;
            empty = crate::hash::tree_node(Tree::Coin, level as u8, &empty, &empty);
        }
        path[0] = [9; 32];
        let opening = CoinOpening {
            s: [1; 32],
            r: [2; 32],
            b: [3; 32],
            v: amount_word(1_000_000),
            position: 0b101,
            path,
        };
        let leaf = coin_commitment(&coin_fingerprint(&opening.s, &opening.r, &opening.b, &EMPTY_RULE), &opening.v);
        let request = RevealRequest {
            root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
            recipient: [5; 20],
            out: amount_word(600_000),
            fee: amount_word(21),
            rule: EMPTY_RULE,
            remainder_note: [6; NOTE_BYTES],
        };
        let remainder = CoinRemainder {
            s: [1; 32],
            r: [2; 32],
            b: [4; 32],
            v: amount_word(1_000_000 - 600_000 - 21),
        };
        (opening, remainder, request)
    }

    fn trace_for(
        opening: &CoinOpening,
        remainder: &CoinRemainder,
        tx: &CoinReveal,
        carries: [u8; CARRIES],
    ) -> (crate::air::StatementAir, p3_matrix::dense::RowMajorMatrix<F>, Vec<F>) {
        let (schedule, free, dirs) = schedule(Some((opening, remainder)));
        let assignment = Assignment {
            public: public_values(&params(), tx),
            carried: carried_values(opening, remainder, carries),
            free,
            dirs,
        };
        let air = Statement::CoinReveal.air();
        let ex = execute(&schedule, &assignment);
        let trace = air.generate_trace(&ex, &assignment);
        let public = assignment.public.iter().map(|&b| F::from_u8(b)).collect();
        (air, trace, public)
    }

    fn honest_tx(opening: &CoinOpening, remainder: &CoinRemainder, request: &RevealRequest) -> CoinReveal {
        CoinReveal {
            root: request.root,
            marker: coin_marker(&opening.r, &opening.b),
            remainder: coin_commitment(
                &coin_fingerprint(&remainder.s, &remainder.r, &remainder.b, &request.rule),
                &remainder.v,
            ),
            remainder_note: request.remainder_note,
            recipient: request.recipient,
            out: request.out,
            fee: request.fee,
            rule: request.rule,
        }
    }

    #[test]
    fn honest_trace_satisfies_every_constraint() {
        let (opening, remainder, request) = witness();
        let tx = honest_tx(&opening, &remainder, &request);
        let carries = conservation_carries(&opening.v, &tx.out, &remainder.v, &tx.fee).unwrap();
        let (air, trace, public) = trace_for(&opening, &remainder, &tx, carries);
        let report = check_all_constraints(&air, &trace, &public, Some(4));
        assert!(report.is_ok(), "{report:?}");
    }

    /// Every public field is tied to the trace by some constraint: its first
    /// and last byte, and those of the digest, each change breaks one.
    #[test]
    fn every_public_field_is_constrained() {
        let (opening, remainder, request) = witness();
        let tx = honest_tx(&opening, &remainder, &request);
        let carries = conservation_carries(&opening.v, &tx.out, &remainder.v, &tx.fee).unwrap();
        let (air, trace, public) = trace_for(&opening, &remainder, &tx, carries);
        let mut probes: Vec<usize> = Binding::CoinReveal
            .layout()
            .iter()
            .flat_map(|f| [f.offset, f.offset + f.width - 1])
            .collect();
        probes.extend([public.len() - 32, public.len() - 1]);
        for i in probes {
            let mut changed = public.clone();
            changed[i] += F::ONE;
            assert!(
                !check_all_constraints(&air, &trace, &changed, Some(1)).is_ok(),
                "public value {i} is not constrained"
            );
        }
    }

    #[test]
    fn a_changed_carried_byte_is_rejected() {
        let (opening, remainder, request) = witness();
        let tx = honest_tx(&opening, &remainder, &request);
        let carries = conservation_carries(&opening.v, &tx.out, &remainder.v, &tx.fee).unwrap();
        let (air, mut trace, public) = trace_for(&opening, &remainder, &tx, carries);
        // Change the carried copy of `b` that the marker reads: the
        // fingerprint and the marker no longer read the same blinding.
        let width = trace.width;
        let column = p3_keccak_air::NUM_KECCAK_COLS + 136 * 8 + 1 + B;
        for row in 0..trace.values.len() / width {
            trace.values[row * width + column] += F::ONE;
        }
        assert!(!check_all_constraints(&air, &trace, &public, Some(1)).is_ok());
    }
}
