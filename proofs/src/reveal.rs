//! Statement S1: the one-time reveal of a coin (spec 02, section 4).
//!
//! The proof opens one coin commitment `C` under the public coin-tree `root`,
//! publishes its one-time `marker`, builds exactly one `remainder` commitment
//! with the input's type tag, `cf` and `rule`, shows `v = out + v' + fee` over
//! the integers on 16-bit limbs, and computes the coin reveal binding digest
//! over every public field. `C`, `F`, the salt, the position, the path, `v`,
//! `v'` and every secret stay private.
//!
//! There is one statement per commitment format (spec 01, section 10), with
//! the same public fields and binding layout. The binding's `type` field is
//! the format's type tag, so a proof of one format never verifies as the
//! other.
//!
//! - Version 1, [`prove_coin_reveal`] and [`verify_coin_reveal`]: a commitment
//!   made without a salt, as before the salt was added.
//! - Version 2, [`prove_salted_coin_reveal`] and
//!   [`verify_salted_coin_reveal`]: a salted commitment and a salted
//!   remainder.
//!
//! The hashes, in trace order (43 permutations in both formats). `COIN` is
//! the format's type tag (`0x01 0x01` or `0x02 0x01`), and `salt` and `salt'`
//! are present only in version 2, with the `v2` fingerprint and marker tags:
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
//! `r`, `b` and, in version 2, the salt are carried columns read by both `F`
//! and `M`, so the marker is the one of the commitment opened. The salt is a
//! private witness: no public value holds it. `s'`, `r'`, `b'` and `salt'`
//! are unconstrained, so the chain cannot tell a claim from a partial reveal;
//! freshness of `b'` and `salt'` is the wallet's rule, and the provers refuse
//! `b' = b`.

use alloc::vec;
use alloc::vec::Vec;

use crate::amount::{
    AMOUNT_HIGH_BYTES, AMOUNT_LIMBS, CARRIES, amount_is_valid, conservation_carries, guessed_carries, limb,
};
use crate::binding::{Binding, ChainParams, FieldWriter, PURPOSE_SPEND, STATEMENT_COIN_REVEAL, STATEMENT_VERSION_1, digest};
use crate::hash::{
    COIN, COIN_V2, EMPTY_RULE, SALT_BYTES, TAG_COIN_COMMITMENT, TAG_COIN_FINGERPRINT, TAG_COIN_FINGERPRINT_V2,
    TAG_COIN_MARKER, TAG_COIN_MARKER_V2, TAG_COIN_REVEAL_BINDING, TAG_COIN_TREE_NODE, TREE_DEPTH, Tree,
    coin_commitment, coin_commitment_v2, coin_fingerprint, coin_fingerprint_v2, coin_marker, coin_marker_v2,
    merkle_root,
};
use crate::schedule::{Assignment, Conservation, HashBuilder, Schedule, ScheduleBuilder};
use crate::stark::{self, Statement};
use crate::{Proof, ProofError};

/// Length of an encrypted note on the chain (spec 01, section 9).
pub const NOTE_BYTES: usize = 156;

// Carried columns. The amounts and carries follow the salt, which has no
// columns in version 1, so the version 1 layout is the one before the salt.
const R: usize = 0;
const B: usize = 32;
const SALT: usize = 64;

/// The commitment format a reveal opens (spec 01, section 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    /// Version 1: no salt, the `v1` fingerprint and marker tags.
    V1,
    /// Version 2: a 16-byte salt right after `b`, the `v2` tags.
    V2,
}

impl Format {
    pub(crate) const fn statement(self) -> Statement {
        match self {
            Self::V1 => Statement::CoinReveal,
            Self::V2 => Statement::SaltedCoinReveal,
        }
    }

    const fn type_tag(self) -> [u8; 2] {
        match self {
            Self::V1 => COIN,
            Self::V2 => COIN_V2,
        }
    }

    const fn fingerprint_tag(self) -> &'static str {
        match self {
            Self::V1 => TAG_COIN_FINGERPRINT,
            Self::V2 => TAG_COIN_FINGERPRINT_V2,
        }
    }

    const fn marker_tag(self) -> &'static str {
        match self {
            Self::V1 => TAG_COIN_MARKER,
            Self::V2 => TAG_COIN_MARKER_V2,
        }
    }

    const fn salt_len(self) -> usize {
        match self {
            Self::V1 => 0,
            Self::V2 => SALT_BYTES,
        }
    }

    /// Carried column of limb `a0` of `v`.
    const fn v(self) -> usize {
        SALT + self.salt_len()
    }

    /// Carried column of limb `a0` of `v'`.
    const fn v2(self) -> usize {
        self.v() + AMOUNT_LIMBS
    }

    /// Carried column of the first carry bit.
    const fn carry_bits(self) -> usize {
        self.v2() + AMOUNT_LIMBS
    }

    /// Number of carried columns.
    const fn carried(self) -> usize {
        self.carry_bits() + 2 * CARRIES
    }
}

/// A version 1 commitment being revealed, made without a salt. It holds
/// secrets, so it implements neither `Debug` nor any serialization.
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

/// The remainder a version 1 reveal creates. Secrets: no `Debug`, no
/// serialization.
pub struct CoinRemainder {
    pub s: [u8; 32],
    pub r: [u8; 32],
    /// Fresh blinding; never the input's `b`.
    pub b: [u8; 32],
    /// The amount left, an amount word.
    pub v: [u8; 32],
}

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
/// transaction. The chain constants and codes are the verifier's own. The
/// same in both commitment formats.
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

/// The secrets of one commitment, with its salt in version 2.
struct Secrets<'a> {
    s: &'a [u8; 32],
    r: &'a [u8; 32],
    b: &'a [u8; 32],
    salt: Option<&'a [u8; SALT_BYTES]>,
    v: &'a [u8; 32],
}

impl Secrets<'_> {
    fn salt_bytes(&self) -> &[u8] {
        self.salt.map_or(&[], |salt| &salt[..])
    }

    /// `C` of spec 01, section 3, in the commitment's own format.
    fn commitment(&self, rule: &[u8; 32]) -> [u8; 32] {
        match self.salt {
            None => coin_commitment(&coin_fingerprint(self.s, self.r, self.b, rule), self.v),
            Some(salt) => coin_commitment_v2(&coin_fingerprint_v2(self.s, self.r, self.b, salt, rule), self.v),
        }
    }

    fn marker(&self) -> [u8; 32] {
        match self.salt {
            None => coin_marker(self.r, self.b),
            Some(salt) => coin_marker_v2(self.r, self.b, salt),
        }
    }
}

/// The private side of a reveal, in either format.
struct Witness<'a> {
    format: Format,
    input: Secrets<'a>,
    position: u32,
    path: &'a [[u8; 32]; TREE_DEPTH],
    remainder: Secrets<'a>,
}

impl<'a> Witness<'a> {
    fn v1(opening: &'a CoinOpening, remainder: &'a CoinRemainder) -> Self {
        Self {
            format: Format::V1,
            input: Secrets {
                s: &opening.s,
                r: &opening.r,
                b: &opening.b,
                salt: None,
                v: &opening.v,
            },
            position: opening.position,
            path: &opening.path,
            remainder: Secrets {
                s: &remainder.s,
                r: &remainder.r,
                b: &remainder.b,
                salt: None,
                v: &remainder.v,
            },
        }
    }

    fn v2(opening: &'a SaltedCoinOpening, remainder: &'a SaltedCoinRemainder) -> Self {
        Self {
            format: Format::V2,
            input: Secrets {
                s: &opening.s,
                r: &opening.r,
                b: &opening.b,
                salt: Some(&opening.salt),
                v: &opening.v,
            },
            position: opening.position,
            path: &opening.path,
            remainder: Secrets {
                s: &remainder.s,
                r: &remainder.r,
                b: &remainder.b,
                salt: Some(&remainder.salt),
                v: &remainder.v,
            },
        }
    }
}

fn fields(format: Format, params: &ChainParams, tx: &CoinReveal) -> Vec<u8> {
    FieldWriter::new(Binding::CoinReveal, params, STATEMENT_COIN_REVEAL, format.type_tag(), PURPOSE_SPEND)
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

/// The coin reveal binding digest of a version 1 reveal, computed from the
/// verifier's own chain constants and the transaction's fields.
pub fn coin_reveal_binding(params: &ChainParams, tx: &CoinReveal) -> [u8; 32] {
    digest(Binding::CoinReveal, &fields(Format::V1, params, tx))
}

/// The coin reveal binding digest of a salted (version 2) reveal: the same
/// fields, with the version 2 type tag.
pub fn salted_coin_reveal_binding(params: &ChainParams, tx: &CoinReveal) -> [u8; 32] {
    digest(Binding::CoinReveal, &fields(Format::V2, params, tx))
}

/// The public values of the proof: the binding fields, then the digest, one
/// byte each.
fn public_values(format: Format, params: &ChainParams, tx: &CoinReveal) -> Vec<u8> {
    let mut public = fields(format, params, tx);
    let binding = digest(Binding::CoinReveal, &public);
    public.extend_from_slice(&binding);
    public
}

/// The schedule of S1 in a format and, with a witness of that format, the
/// free bytes and direction bits.
fn schedule_with(format: Format, w: Option<&Witness>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    if let Some(w) = w {
        assert_eq!(w.format, format, "a witness of another format");
    }
    let binding = Binding::CoinReveal;
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let type_tag = format.type_tag();
    let salt = format.salt_len();
    let mut sb = ScheduleBuilder::new();

    let mut fingerprint = HashBuilder::new(format.fingerprint_tag())
        .free(32, w.map(|w| &w.input.s[..]))
        .carried(R, 32)
        .carried(B, 32);
    if salt > 0 {
        fingerprint = fingerprint.carried(SALT, salt);
    }
    sb.push(fingerprint.constant(&type_tag).constant(&[0; 32]).public(off("rule"), 32));
    sb.push(HashBuilder::new(TAG_COIN_COMMITMENT).constant(&type_tag).prev().amount(format.v()));
    for level in 0..TREE_DEPTH {
        let mut node = HashBuilder::new(TAG_COIN_TREE_NODE)
            .constant(&[level as u8])
            .node(w.map(|w| (&w.path[level], w.position >> level & 1 == 1)));
        if level + 1 == TREE_DEPTH {
            node = node.output(off("root"));
        }
        sb.push(node);
    }
    let mut marker = HashBuilder::new(format.marker_tag()).carried(R, 32).carried(B, 32);
    if salt > 0 {
        marker = marker.carried(SALT, salt);
    }
    sb.push(marker.output(off("marker")));
    let mut remainder = HashBuilder::new(format.fingerprint_tag())
        .free(32, w.map(|w| &w.remainder.s[..]))
        .free(32, w.map(|w| &w.remainder.r[..]))
        .free(32, w.map(|w| &w.remainder.b[..]));
    if salt > 0 {
        remainder = remainder.free(salt, w.map(|w| w.remainder.salt_bytes()));
    }
    sb.push(remainder.constant(&type_tag).constant(&[0; 32]).public(off("rule"), 32));
    sb.push(
        HashBuilder::new(TAG_COIN_COMMITMENT)
            .constant(&type_tag)
            .prev()
            .amount(format.v2())
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
        v: format.v(),
        remainder: format.v2(),
        carries: format.carry_bits(),
        out: off("out"),
        fee: off("fee"),
    };
    sb.finish(fields_len + 32, format.carried(), Some(conservation), consts)
}

/// The schedule of S1 in a format, without any witness.
pub(crate) fn schedule(format: Format) -> Schedule {
    schedule_with(format, None).0
}

fn carried_values(w: &Witness, carries: [u8; CARRIES]) -> Vec<u32> {
    let format = w.format;
    let mut carried = vec![0u32; format.carried()];
    for k in 0..32 {
        carried[R + k] = u32::from(w.input.r[k]);
        carried[B + k] = u32::from(w.input.b[k]);
    }
    for (k, &byte) in w.input.salt_bytes().iter().enumerate() {
        carried[SALT + k] = u32::from(byte);
    }
    for j in 0..AMOUNT_LIMBS {
        carried[format.v() + j] = limb(w.input.v, j);
        carried[format.v2() + j] = limb(w.remainder.v, j);
    }
    for (k, &carry) in carries.iter().enumerate() {
        carried[format.carry_bits() + 2 * k] = u32::from(carry & 1);
        carried[format.carry_bits() + 2 * k + 1] = u32::from(carry >> 1);
    }
    carried
}

fn assignment(params: &ChainParams, w: &Witness, claimed: &CoinReveal, carries: [u8; CARRIES]) -> Assignment {
    let (_, free, dirs) = schedule_with(w.format, Some(w));
    Assignment {
        public: public_values(w.format, params, claimed),
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
    stark::prove(w.format.statement(), &assignment, zk_randomness).map(Proof)
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
    prove_witness_unchecked(params, &Witness::v1(opening, remainder), claimed, carries, zk_randomness)
}

/// A salted reveal proof claiming `claimed`, whatever the witness says, with
/// none of the honest prover's checks, so tests can show the verifier catches
/// a lie (another salt, say). Nothing here can make a proof the verifier
/// accepts that the honest prover would refuse.
#[doc(hidden)]
pub fn prove_salted_coin_reveal_claiming(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    remainder: &SaltedCoinRemainder,
    claimed: &CoinReveal,
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    let carries = guessed_carries(&opening.v, &claimed.out, &remainder.v, &claimed.fee);
    prove_witness_unchecked(params, &Witness::v2(opening, remainder), claimed, carries, zk_randomness)
}

fn prove(
    params: &ChainParams,
    w: &Witness,
    request: &RevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(CoinReveal, Proof), ProofError> {
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
    let proof = prove_witness_unchecked(params, w, &tx, carries, zk_randomness)?;
    Ok((tx, proof))
}

/// Prove a coin reveal of a version 1 commitment (made without a salt).
/// Returns the public fields the transaction carries and the proof.
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
    prove(params, &Witness::v1(opening, remainder), request, zk_randomness)
}

/// Prove a coin reveal of a salted (version 2) commitment, creating a salted
/// remainder. The salts are private witnesses: the returned public fields are
/// those of every coin reveal, and neither they nor the proof hold a salt.
///
/// Refuses what [`prove_coin_reveal`] refuses; a wrong salt makes another
/// commitment, which is not the leaf under `root`.
///
/// `zk_randomness` must be 32 fresh bytes from a secure random source.
pub fn prove_salted_coin_reveal(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    remainder: &SaltedCoinRemainder,
    request: &RevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(CoinReveal, Proof), ProofError> {
    prove(params, &Witness::v2(opening, remainder), request, zk_randomness)
}

fn verify(format: Format, params: &ChainParams, tx: &CoinReveal, proof: &Proof) -> Result<(), ProofError> {
    if tx.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    if !amount_is_valid(&tx.out) || !amount_is_valid(&tx.fee) {
        return Err(ProofError::AmountOutOfRange);
    }
    stark::verify(format.statement(), &public_values(format, params, tx), proof.as_bytes())
}

/// Verify a coin reveal of a version 1 commitment against the verifier's own
/// chain constants.
///
/// Rejects a non-empty rule and an out-of-range `out` or `fee` before the
/// proof is looked at, then verifies the proof against public values the
/// verifier builds itself, binding digest included.
pub fn verify_coin_reveal(params: &ChainParams, tx: &CoinReveal, proof: &Proof) -> Result<(), ProofError> {
    verify(Format::V1, params, tx, proof)
}

/// Verify a coin reveal of a salted (version 2) commitment, as
/// [`verify_coin_reveal`] does for version 1. A version 1 proof never passes
/// here, nor a salted one there: the binding's type differs.
pub fn verify_salted_coin_reveal(params: &ChainParams, tx: &CoinReveal, proof: &Proof) -> Result<(), ProofError> {
    verify(Format::V2, params, tx, proof)
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

    fn request(leaf: &[u8; 32], position: u32, path: &[[u8; 32]; TREE_DEPTH]) -> RevealRequest {
        RevealRequest {
            root: merkle_root(Tree::Coin, leaf, position, path),
            recipient: [5; 20],
            out: amount_word(600_000),
            fee: amount_word(21),
            rule: EMPTY_RULE,
            remainder_note: [6; NOTE_BYTES],
        }
    }

    fn witness() -> (CoinOpening, CoinRemainder, RevealRequest) {
        let opening = CoinOpening {
            s: [1; 32],
            r: [2; 32],
            b: [3; 32],
            v: amount_word(1_000_000),
            position: 0b101,
            path: path(),
        };
        let leaf = coin_commitment(&coin_fingerprint(&opening.s, &opening.r, &opening.b, &EMPTY_RULE), &opening.v);
        let request = request(&leaf, opening.position, &opening.path);
        let remainder = CoinRemainder {
            s: [1; 32],
            r: [2; 32],
            b: [4; 32],
            v: amount_word(1_000_000 - 600_000 - 21),
        };
        (opening, remainder, request)
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
        let request = request(&leaf, opening.position, &opening.path);
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
        let air = w.format.statement().air();
        let ex = execute(&schedule(w.format), &assignment);
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

    /// Both formats, each with its request.
    fn check_both(check: impl Fn(&Witness, &RevealRequest)) {
        let (opening, remainder, request) = witness();
        check(&Witness::v1(&opening, &remainder), &request);
        let (opening, remainder, request) = salted_witness();
        check(&Witness::v2(&opening, &remainder), &request);
    }

    /// The trace width: version 1 as before, version 2 with 16 more carried
    /// columns, under the budget.
    #[test]
    fn the_salt_adds_sixteen_carried_columns() {
        use p3_air::BaseAir;
        let v1 = BaseAir::<F>::width(&Statement::CoinReveal.air());
        let v2 = BaseAir::<F>::width(&Statement::SaltedCoinReveal.air());
        assert_eq!(v1, 3808);
        assert_eq!(v2, v1 + SALT_BYTES);
        assert_eq!(v2, stark::MAX_TRACE_WIDTH);
        assert_eq!(Statement::CoinReveal.air().height(), Statement::SaltedCoinReveal.air().height());
    }

    #[test]
    fn honest_trace_satisfies_every_constraint() {
        check_both(|w, request| {
            let (air, trace, public) = honest_trace(w, request);
            let report = check_all_constraints(&air, &trace, &public, Some(4));
            assert!(report.is_ok(), "{:?}: {report:?}", w.format);
        });
    }

    /// Every public field is tied to the trace by some constraint: its first
    /// and last byte, and those of the digest, each change breaks one.
    #[test]
    fn every_public_field_is_constrained() {
        check_both(|w, request| {
            let (air, trace, public) = honest_trace(w, request);
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
                    "{:?}: public value {i} is not constrained",
                    w.format
                );
            }
        });
    }

    #[test]
    fn a_changed_carried_byte_is_rejected() {
        let column = |c: usize| p3_keccak_air::NUM_KECCAK_COLS + 136 * 8 + 1 + c;
        check_both(|w, request| {
            // Change the carried copy of `b`, and in version 2 of the salt,
            // that the marker reads: the fingerprint and the marker no longer
            // read the same opening.
            let mut columns = vec![column(B)];
            if w.format == Format::V2 {
                columns.extend([column(SALT), column(SALT + SALT_BYTES - 1)]);
            }
            for col in columns {
                let (air, mut trace, public) = honest_trace(w, request);
                let width = trace.width;
                for row in 0..trace.values.len() / width {
                    trace.values[row * width + col] += F::ONE;
                }
                assert!(!check_all_constraints(&air, &trace, &public, Some(1)).is_ok(), "column {col}");
            }
        });
    }

    /// The right `s`, `r` and `b` with another salt open another commitment
    /// and publish another marker: no trace for the honest transaction.
    #[test]
    fn another_salt_does_not_open_the_commitment() {
        let (opening, remainder, request) = salted_witness();
        let honest = honest_tx(&Witness::v2(&opening, &remainder), &request);
        let carries = conservation_carries(&opening.v, &honest.out, &remainder.v, &honest.fee).unwrap();
        for k in [0, SALT_BYTES - 1] {
            let mut salt = opening.salt;
            salt[k] ^= 1;
            let wrong = SaltedCoinOpening { salt, ..opening };
            let (air, trace, public) = trace_for(&Witness::v2(&wrong, &remainder), &honest, carries);
            assert!(!check_all_constraints(&air, &trace, &public, Some(1)).is_ok(), "salt byte {k}");
        }
        // The version 1 statement does not open a salted leaf either.
        let unsalted = CoinOpening {
            s: opening.s,
            r: opening.r,
            b: opening.b,
            v: opening.v,
            position: opening.position,
            path: opening.path,
        };
        let plain = CoinRemainder {
            s: remainder.s,
            r: remainder.r,
            b: remainder.b,
            v: remainder.v,
        };
        let (air, trace, public) = trace_for(&Witness::v1(&unsalted, &plain), &honest, carries);
        assert!(!check_all_constraints(&air, &trace, &public, Some(1)).is_ok());
    }

    /// The public values are those of version 1 but for the type tag, and
    /// hold no salt.
    #[test]
    fn the_public_values_hold_no_salt() {
        let (opening, remainder, request) = salted_witness();
        let tx = honest_tx(&Witness::v2(&opening, &remainder), &request);
        let v1 = public_values(Format::V1, &params(), &tx);
        let v2 = public_values(Format::V2, &params(), &tx);
        assert_eq!(v1.len(), v2.len());
        let at = Binding::CoinReveal.offset("type");
        let fields = Binding::CoinReveal.fields_len();
        assert_eq!((&v1[at..at + 2], &v2[at..at + 2]), (&COIN[..], &COIN_V2[..]));
        assert_eq!(v1[..at], v2[..at]);
        assert_eq!(v1[at + 2..fields], v2[at + 2..fields]);
        for salt in [INPUT_SALT, REMAINDER_SALT] {
            assert!(!v2.windows(SALT_BYTES).any(|w| w == salt));
        }
    }
}
