//! Statement S1: the one-time reveal of a coin (spec 02, section 4).
//!
//! The proof opens one salted (version 2) coin commitment `C` under the public
//! coin-tree `root`, publishes its one-time `marker`, builds exactly one
//! salted `remainder` commitment with the input's type tag, `cf` and `rule`,
//! shows `v = out + v' + fee` over the integers on 16-bit limbs, and computes
//! the coin reveal binding digest over every public field. `C`, `F`, the salt,
//! the position, the path, `v`, `v'` and every secret stay private. The
//! binding's `type` field is `COIN_V2`.
//!
//! The prover is [`prove_salted_coin_reveal`] and the verifier
//! [`verify_salted_coin_reveal`].
//!
//! The hashes, in trace order (43 permutations). `COIN` is the type tag
//! `0x02 0x01`, with the `v2` fingerprint and marker tags:
//!
//! ```text
//! F       K(coin-fingerprint, s, r, b, salt, COIN, 0^32, rule)       2 blocks
//! C       K(coin-commitment, COIN, F, v)                             1
//! N0..N31 K(coin-tree-node, level, left, right)                      32, N31 = root
//! M       K(coin-marker, r, b, salt)                                 1, = marker
//! F'      K(coin-fingerprint, s', r', b', salt', COIN, 0^32, rule)   2
//! C'      K(coin-commitment, COIN, F', v')                           1, = remainder
//! B       K(coin-reveal-binding, fields)                             4, = binding
//! ```
//!
//! `r`, `b` and the salt are carried columns read by both `F` and `M`, so the
//! marker is the one of the commitment opened. The salt is a private witness:
//! no public value holds it. `s'`, `r'`, `b'` and `salt'` are unconstrained,
//! so the chain cannot tell a claim from a partial reveal; freshness of `b'`
//! and `salt'` is the wallet's rule, and the prover refuses `b' = b`.

use alloc::vec;
use alloc::vec::Vec;

use crate::amount::{
    AMOUNT_HIGH_BYTES, AMOUNT_LIMBS, CARRIES, amount_is_valid, conservation_carries, guessed_carries, limb,
};
use crate::binding::{Binding, ChainParams, FieldWriter, PURPOSE_SPEND, STATEMENT_COIN_REVEAL, STATEMENT_VERSION_1, digest};
use crate::hash::{
    COIN_V2, EMPTY_RULE, SALT_BYTES, TAG_COIN_COMMITMENT, TAG_COIN_FINGERPRINT_V2, TAG_COIN_MARKER_V2,
    TAG_COIN_REVEAL_BINDING, TAG_COIN_TREE_NODE, TREE_DEPTH, Tree, coin_commitment_v2, coin_fingerprint_v2,
    coin_marker_v2, merkle_root,
};
use crate::schedule::{Assignment, Conservation, HashBuilder, Schedule, ScheduleBuilder};
use crate::stark::{self, Statement};
use crate::{Proof, ProofError};

/// Length of an encrypted note on the chain (spec 01, section 9).
pub const NOTE_BYTES: usize = 156;

// Carried columns: `r`, `b`, the salt, the limbs of `v` and `v'`, then the
// carry bits.
const R: usize = 0;
const B: usize = 32;
const SALT: usize = 64;
/// Carried column of limb `a0` of `v`.
const V: usize = SALT + SALT_BYTES;
/// Carried column of limb `a0` of `v'`.
const V2: usize = V + AMOUNT_LIMBS;
/// Carried column of the first carry bit.
const CARRY_BITS: usize = V2 + AMOUNT_LIMBS;
/// Number of carried columns.
const CARRIED: usize = CARRY_BITS + 2 * CARRIES;

/// A salted (version 2) commitment being revealed. Secrets: no `Debug`, no
/// serialization.
pub struct SaltedCoinOpening {
    pub s: [u8; 32],
    pub r: [u8; 32],
    pub b: [u8; 32],
    /// The commitment's salt, as its commit published it. A private witness
    /// of the proof, never a public value.
    pub salt: [u8; SALT_BYTES],
    /// The amount, an amount word.
    pub v: [u8; 32],
    /// Position of `C` in the coin tree.
    pub position: u32,
    /// The 32 sibling hashes from `C` to the root.
    pub path: [[u8; 32]; TREE_DEPTH],
}

/// The salted (version 2) remainder a salted reveal creates. Secrets: no
/// `Debug`, no serialization.
pub struct SaltedCoinRemainder {
    pub s: [u8; 32],
    pub r: [u8; 32],
    /// Fresh blinding; never the input's `b`.
    pub b: [u8; 32],
    /// A fresh salt from the wallet's secure random source, carried to the
    /// holder inside the remainder's note.
    pub salt: [u8; SALT_BYTES],
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

/// The secrets of one salted commitment.
struct Secrets<'a> {
    s: &'a [u8; 32],
    r: &'a [u8; 32],
    b: &'a [u8; 32],
    salt: &'a [u8; SALT_BYTES],
    v: &'a [u8; 32],
}

impl Secrets<'_> {
    /// `C` of spec 01, section 3.
    fn commitment(&self, rule: &[u8; 32]) -> [u8; 32] {
        coin_commitment_v2(&coin_fingerprint_v2(self.s, self.r, self.b, self.salt, rule), self.v)
    }

    fn marker(&self) -> [u8; 32] {
        coin_marker_v2(self.r, self.b, self.salt)
    }
}

/// The private side of a reveal.
struct Witness<'a> {
    input: Secrets<'a>,
    position: u32,
    path: &'a [[u8; 32]; TREE_DEPTH],
    remainder: Secrets<'a>,
}

impl<'a> Witness<'a> {
    fn new(opening: &'a SaltedCoinOpening, remainder: &'a SaltedCoinRemainder) -> Self {
        Self {
            input: Secrets {
                s: &opening.s,
                r: &opening.r,
                b: &opening.b,
                salt: &opening.salt,
                v: &opening.v,
            },
            position: opening.position,
            path: &opening.path,
            remainder: Secrets {
                s: &remainder.s,
                r: &remainder.r,
                b: &remainder.b,
                salt: &remainder.salt,
                v: &remainder.v,
            },
        }
    }
}

fn fields(params: &ChainParams, tx: &CoinReveal) -> Vec<u8> {
    FieldWriter::new(Binding::CoinReveal, params, STATEMENT_COIN_REVEAL, COIN_V2, PURPOSE_SPEND)
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

/// The coin reveal binding digest of a salted (version 2) reveal, computed
/// from the verifier's own chain constants and the transaction's fields.
pub fn salted_coin_reveal_binding(params: &ChainParams, tx: &CoinReveal) -> [u8; 32] {
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
fn schedule_with(w: Option<&Witness>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::CoinReveal;
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let type_tag = COIN_V2;
    let mut sb = ScheduleBuilder::new();

    sb.push(
        HashBuilder::new(TAG_COIN_FINGERPRINT_V2)
            .free(32, w.map(|w| &w.input.s[..]))
            .carried(R, 32)
            .carried(B, 32)
            .carried(SALT, SALT_BYTES)
            .constant(&type_tag)
            .constant(&[0; 32])
            .public(off("rule"), 32),
    );
    sb.push(HashBuilder::new(TAG_COIN_COMMITMENT).constant(&type_tag).prev().amount(V));
    for level in 0..TREE_DEPTH {
        let mut node = HashBuilder::new(TAG_COIN_TREE_NODE)
            .constant(&[level as u8])
            .node(w.map(|w| (&w.path[level], w.position >> level & 1 == 1)));
        if level + 1 == TREE_DEPTH {
            node = node.output(off("root"));
        }
        sb.push(node);
    }
    sb.push(
        HashBuilder::new(TAG_COIN_MARKER_V2)
            .carried(R, 32)
            .carried(B, 32)
            .carried(SALT, SALT_BYTES)
            .output(off("marker")),
    );
    sb.push(
        HashBuilder::new(TAG_COIN_FINGERPRINT_V2)
            .free(32, w.map(|w| &w.remainder.s[..]))
            .free(32, w.map(|w| &w.remainder.r[..]))
            .free(32, w.map(|w| &w.remainder.b[..]))
            .free(SALT_BYTES, w.map(|w| &w.remainder.salt[..]))
            .constant(&type_tag)
            .constant(&[0; 32])
            .public(off("rule"), 32),
    );
    sb.push(
        HashBuilder::new(TAG_COIN_COMMITMENT)
            .constant(&type_tag)
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
        (off("type"), type_tag[0]),
        (off("type") + 1, type_tag[1]),
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

/// The schedule of S1, without any witness.
pub(crate) fn schedule() -> Schedule {
    schedule_with(None).0
}

fn carried_values(w: &Witness, carries: [u8; CARRIES]) -> Vec<u32> {
    let mut carried = vec![0u32; CARRIED];
    for k in 0..32 {
        carried[R + k] = u32::from(w.input.r[k]);
        carried[B + k] = u32::from(w.input.b[k]);
    }
    for (k, &byte) in w.input.salt.iter().enumerate() {
        carried[SALT + k] = u32::from(byte);
    }
    for j in 0..AMOUNT_LIMBS {
        carried[V + j] = limb(w.input.v, j);
        carried[V2 + j] = limb(w.remainder.v, j);
    }
    for (k, &carry) in carries.iter().enumerate() {
        carried[CARRY_BITS + 2 * k] = u32::from(carry & 1);
        carried[CARRY_BITS + 2 * k + 1] = u32::from(carry >> 1);
    }
    carried
}

fn assignment(params: &ChainParams, w: &Witness, claimed: &CoinReveal, carries: [u8; CARRIES]) -> Assignment {
    let (_, free, dirs) = schedule_with(Some(w));
    Assignment {
        public: public_values(params, claimed),
        carried: carried_values(w, carries),
        free,
        dirs,
    }
}

fn prove_witness_unchecked(
    params: &ChainParams,
    w: &Witness,
    claimed: &CoinReveal,
    carries: [u8; CARRIES],
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    let assignment = assignment(params, w, claimed, carries);
    stark::prove(Statement::SaltedCoinReveal, &assignment, zk_randomness).map(Proof)
}

/// A salted reveal proof claiming `claimed`, whatever the witness says, with
/// none of the honest prover's checks, so tests can show the verifier catches
/// a lie (another salt, say). The trace hashes what the witness gives, the
/// public values are the claimed transaction's, and the conservation carries
/// are a best guess. Nothing here can make a proof the verifier accepts that
/// the honest prover would refuse.
#[doc(hidden)]
pub fn prove_salted_coin_reveal_claiming(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    remainder: &SaltedCoinRemainder,
    claimed: &CoinReveal,
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    let carries = guessed_carries(&opening.v, &claimed.out, &remainder.v, &claimed.fee);
    prove_witness_unchecked(params, &Witness::new(opening, remainder), claimed, carries, zk_randomness)
}

/// Prove a coin reveal of a salted (version 2) commitment, creating a salted
/// remainder. Returns the public fields the transaction carries and the
/// proof. The salts are private witnesses: neither the returned public fields
/// nor the proof hold a salt.
///
/// Refuses, before any proving: a non-empty rule; an amount word with a high
/// byte set; a remainder whose blinding equals the input's (it would publish
/// the same marker when revealed); `v != out + v' + fee`; and a commitment
/// that is not the leaf at `position` under `root`. A wrong salt makes
/// another commitment, which is not the leaf under `root`.
///
/// `zk_randomness` must be 32 fresh bytes from a secure random source.
pub fn prove_salted_coin_reveal(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    remainder: &SaltedCoinRemainder,
    request: &RevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(CoinReveal, Proof), ProofError> {
    let w = Witness::new(opening, remainder);
    if request.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    if ![w.input.v, w.remainder.v, &request.out, &request.fee].into_iter().all(amount_is_valid) {
        return Err(ProofError::AmountOutOfRange);
    }
    if w.remainder.b == w.input.b {
        return Err(ProofError::ReusedBlinding);
    }
    let carries = conservation_carries(w.input.v, &request.out, w.remainder.v, &request.fee)
        .ok_or(ProofError::ConservationFails)?;
    let leaf = w.input.commitment(&request.rule);
    if merkle_root(Tree::Coin, &leaf, w.position, w.path) != request.root {
        return Err(ProofError::NotInTree);
    }
    let tx = CoinReveal {
        root: request.root,
        marker: w.input.marker(),
        remainder: w.remainder.commitment(&request.rule),
        remainder_note: request.remainder_note,
        recipient: request.recipient,
        out: request.out,
        fee: request.fee,
        rule: request.rule,
    };
    let proof = prove_witness_unchecked(params, &w, &tx, carries, zk_randomness)?;
    Ok((tx, proof))
}

/// Verify a coin reveal of a salted (version 2) commitment against the
/// verifier's own chain constants.
///
/// Rejects a non-empty rule and an out-of-range `out` or `fee` before the
/// proof is looked at, then verifies the proof against public values the
/// verifier builds itself, binding digest included.
pub fn verify_salted_coin_reveal(params: &ChainParams, tx: &CoinReveal, proof: &Proof) -> Result<(), ProofError> {
    if tx.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    if !amount_is_valid(&tx.out) || !amount_is_valid(&tx.fee) {
        return Err(ProofError::AmountOutOfRange);
    }
    stark::verify(Statement::SaltedCoinReveal, &public_values(params, tx), proof.as_bytes())
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

    const INPUT_SALT: [u8; SALT_BYTES] = [0xa5; SALT_BYTES];
    const REMAINDER_SALT: [u8; SALT_BYTES] = [0x3c; SALT_BYTES];

    fn params() -> ChainParams {
        ChainParams {
            chain_id: [0, 0, 0, 0, 0, 0, 0x04, 0xd2],
            version: crate::binding::PROTOCOL_VERSION_1,
            domain: [7; 32],
        }
    }

    fn path() -> [[u8; 32]; TREE_DEPTH] {
        let mut path = [[0u8; 32]; TREE_DEPTH];
        let mut empty = empty_leaf();
        for (level, sibling) in path.iter_mut().enumerate() {
            *sibling = empty;
            empty = crate::hash::tree_node(Tree::Coin, level as u8, &empty, &empty);
        }
        path[0] = [9; 32];
        path
    }

    fn salted_witness() -> (SaltedCoinOpening, SaltedCoinRemainder, RevealRequest) {
        let opening = SaltedCoinOpening {
            s: [1; 32],
            r: [2; 32],
            b: [3; 32],
            salt: INPUT_SALT,
            v: amount_word(1_000_000),
            position: 0b101,
            path: path(),
        };
        let fingerprint = coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, &EMPTY_RULE);
        let leaf = coin_commitment_v2(&fingerprint, &opening.v);
        let request = RevealRequest {
            root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
            recipient: [5; 20],
            out: amount_word(600_000),
            fee: amount_word(21),
            rule: EMPTY_RULE,
            remainder_note: [6; NOTE_BYTES],
        };
        let remainder = SaltedCoinRemainder {
            s: [1; 32],
            r: [2; 32],
            b: [4; 32],
            salt: REMAINDER_SALT,
            v: amount_word(1_000_000 - 600_000 - 21),
        };
        (opening, remainder, request)
    }

    type Trace = (crate::air::StatementAir, p3_matrix::dense::RowMajorMatrix<F>, Vec<F>);

    fn trace_for(w: &Witness, tx: &CoinReveal, carries: [u8; CARRIES]) -> Trace {
        let assignment = assignment(&params(), w, tx, carries);
        let air = Statement::SaltedCoinReveal.air();
        let ex = execute(&schedule(), &assignment);
        let trace = air.generate_trace(&ex, &assignment);
        let public = assignment.public.iter().map(|&b| F::from_u8(b)).collect();
        (air, trace, public)
    }

    fn honest_tx(w: &Witness, request: &RevealRequest) -> CoinReveal {
        CoinReveal {
            root: request.root,
            marker: w.input.marker(),
            remainder: w.remainder.commitment(&request.rule),
            remainder_note: request.remainder_note,
            recipient: request.recipient,
            out: request.out,
            fee: request.fee,
            rule: request.rule,
        }
    }

    fn honest_trace(w: &Witness, request: &RevealRequest) -> Trace {
        let tx = honest_tx(w, request);
        let carries = conservation_carries(w.input.v, &tx.out, w.remainder.v, &tx.fee).unwrap();
        trace_for(w, &tx, carries)
    }

    /// The trace width: the 3,808 columns of a reveal without a salt and 16
    /// carried salt columns, the widest the budget allows.
    #[test]
    fn the_salt_adds_sixteen_carried_columns() {
        use p3_air::BaseAir;
        let width = BaseAir::<F>::width(&Statement::SaltedCoinReveal.air());
        assert_eq!(width, 3808 + SALT_BYTES);
        assert_eq!(width, stark::MAX_TRACE_WIDTH);
    }

    #[test]
    fn honest_trace_satisfies_every_constraint() {
        let (opening, remainder, request) = salted_witness();
        let (air, trace, public) = honest_trace(&Witness::new(&opening, &remainder), &request);
        let report = check_all_constraints(&air, &trace, &public, Some(4));
        assert!(report.is_ok(), "{report:?}");
    }

    /// Every public field is tied to the trace by some constraint: its first
    /// and last byte, and those of the digest, each change breaks one.
    #[test]
    fn every_public_field_is_constrained() {
        let (opening, remainder, request) = salted_witness();
        let (air, trace, public) = honest_trace(&Witness::new(&opening, &remainder), &request);
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
        let column = |c: usize| p3_keccak_air::NUM_KECCAK_COLS + 136 * 8 + 1 + c;
        let (opening, remainder, request) = salted_witness();
        let w = Witness::new(&opening, &remainder);
        // Change the carried copy of `b` or of the salt that the marker
        // reads: the fingerprint and the marker no longer read the same
        // opening.
        for col in [column(B), column(SALT), column(SALT + SALT_BYTES - 1)] {
            let (air, mut trace, public) = honest_trace(&w, &request);
            let width = trace.width;
            for row in 0..trace.values.len() / width {
                trace.values[row * width + col] += F::ONE;
            }
            assert!(!check_all_constraints(&air, &trace, &public, Some(1)).is_ok(), "column {col}");
        }
    }

    /// The right `s`, `r` and `b` with another salt open another commitment
    /// and publish another marker: no trace for the honest transaction.
    #[test]
    fn another_salt_does_not_open_the_commitment() {
        let (opening, remainder, request) = salted_witness();
        let honest = honest_tx(&Witness::new(&opening, &remainder), &request);
        let carries = conservation_carries(&opening.v, &honest.out, &remainder.v, &honest.fee).unwrap();
        for k in [0, SALT_BYTES - 1] {
            let mut salt = opening.salt;
            salt[k] ^= 1;
            let wrong = SaltedCoinOpening { salt, ..opening };
            let (air, trace, public) = trace_for(&Witness::new(&wrong, &remainder), &honest, carries);
            assert!(!check_all_constraints(&air, &trace, &public, Some(1)).is_ok(), "salt byte {k}");
        }
    }

    /// The public values carry the version 2 type tag and hold no salt.
    #[test]
    fn the_public_values_hold_no_salt() {
        let (opening, remainder, request) = salted_witness();
        let tx = honest_tx(&Witness::new(&opening, &remainder), &request);
        let public = public_values(&params(), &tx);
        let at = Binding::CoinReveal.offset("type");
        assert_eq!(&public[at..at + 2], &COIN_V2[..]);
        assert_eq!(public.len(), Binding::CoinReveal.fields_len() + 32);
        for salt in [INPUT_SALT, REMAINDER_SALT] {
            assert!(!public.windows(SALT_BYTES).any(|w| w == salt));
        }
    }
}
