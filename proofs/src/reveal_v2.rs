//! Statement S1, version 2: the coin reveal of the ordinary class (spec 10,
//! sections 4.2 to 4.4).
//!
//! The proof is the salted coin reveal of [`crate::reveal`] with one private
//! switch, `use_override`, and a private remainder rule:
//!
//! - **O1.** `use_override` is boolean.
//! - **O2.** The six fields of the input rule hash to `RIN` under
//!   `ghost/reveal-policy/v2`, the 20-byte policy address left-padded to 32.
//! - **O3.** The input fingerprint `F` takes `use_override * RIN`, byte by
//!   byte: the empty rule for a plain coin, the opened rule for the override.
//! - **O4.** When the switch is on, `K("ghost/policy-override/v1",
//!   override_secret)` is the rule's `override_hash`.
//! - **O5.** When the switch is on, `override_hash` is not zero: its byte sum
//!   times a private inverse is one.
//! - **O6.** The remainder fingerprint `F'` takes a free private rule, the
//!   prover's choice: the input's rule, a rotated rule or the empty rule.
//! - **O7.** The binding is the one of section 4.2: `ghost/coin-reveal-binding/v2`
//!   over 607 bytes, the 380-byte note and no `rule` field.
//!
//! Neither rule, the switch, the override secret nor any rule field is a
//! public value. A plain-coin proof and an override proof are proofs of one
//! AIR with one public layout, so the transaction does not tell them apart.
//! A coin with a rule can never be spent here with the switch off (its
//! fingerprint holds a non-empty rule), and a coin with the empty rule never
//! with it on (a real rule is never zero).
//!
//! The prover is [`prove_coin_reveal_v2`] and the verifier
//! [`verify_coin_reveal_v2`].
//!
//! The hashes, in trace order (47 permutations):
//!
//! ```text
//! RIN     K(reveal-policy/v2, 0^12 || address, codehash, params_hash,
//!           override_hash, action_tag, action_salt)                      2, = carried RIN
//! OV      K(policy-override/v1, override_secret)                         1, = override_hash if on
//! F       K(coin-fingerprint, s, r, b, salt, COIN, 0^32, on * RIN)       2
//! C       K(coin-commitment, COIN, F, v)                                 1
//! N0..N31 K(coin-tree-node, level, left, right)                          32, N31 = root
//! M       K(coin-marker, r, b, salt)                                     1, = marker
//! F'      K(coin-fingerprint, s', r', b', salt', COIN, 0^32, R_out)      2
//! C'      K(coin-commitment, COIN, F', v')                               1, = remainder
//! B       K(coin-reveal-binding/v2, fields)                              5, = binding
//! ```
//!
//! The carried columns are those of version 1 (102) and `use_override` (1),
//! `RIN` (32), `override_hash` (32) and the inverse (1): 168, so the trace is
//! 3,890 columns wide.

use alloc::vec;
use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};

use crate::air::F;
use crate::amount::{
    AMOUNT_HIGH_BYTES, AMOUNT_LIMBS, CARRIES, amount_is_valid, conservation_carries, guessed_carries, limb,
};
use crate::binding::{
    Binding, ChainParams, FieldWriter, PURPOSE_SPEND, STATEMENT_COIN_REVEAL, STATEMENT_VERSION_2, digest,
};
use crate::hash::{
    COIN_V2, EMPTY_RULE, POLICY_ADDRESS_BYTES, SALT_BYTES, TAG_COIN_COMMITMENT, TAG_COIN_FINGERPRINT_V2,
    TAG_COIN_MARKER_V2, TAG_COIN_REVEAL_BINDING_V2, TAG_COIN_TREE_NODE, TAG_POLICY_OVERRIDE_V1, TAG_REVEAL_POLICY_V2,
    TREE_DEPTH, Tree, coin_commitment_v2, coin_fingerprint_v2, coin_marker_v2, merkle_root, policy_override_hash,
    reveal_policy_rule,
};
use crate::reveal::{SaltedCoinOpening, SaltedCoinRemainder};
use crate::schedule::{Assignment, Conservation, HashBuilder, Schedule, ScheduleBuilder, Switch};
use crate::scale::{self, ScaleShape};
use crate::stark::{self, Statement};
use crate::{Proof, ProofError};

/// Length of an encrypted note of note version 3 (spec 10, section 3.2):
/// 12 bytes of nonce, 352 of plaintext and a 16-byte tag.
pub const NOTE_V3_BYTES: usize = 380;

// Carried columns: those of version 1 (`r`, `b`, the salt, the limbs of `v`
// and `v'`, the carry bits), then the switch, `RIN`, `override_hash` and the
// inverse of the override hash's byte sum.
const R: usize = 0;
const B: usize = 32;
const SALT: usize = 64;
/// Carried column of limb `a0` of `v`.
const V: usize = SALT + SALT_BYTES;
/// Carried column of limb `a0` of `v'`.
const V2: usize = V + AMOUNT_LIMBS;
/// Carried column of the first carry bit.
const CARRY_BITS: usize = V2 + AMOUNT_LIMBS;
/// Carried column of `use_override`.
const USE_OVERRIDE: usize = CARRY_BITS + 2 * CARRIES;
/// Carried columns of `RIN`, the opened input rule.
const RIN: usize = USE_OVERRIDE + 1;
/// Carried columns of the input rule's `override_hash`.
const OVERRIDE_HASH: usize = RIN + 32;
/// Carried column of the inverse of the override hash's byte sum.
const SUM_INVERSE: usize = OVERRIDE_HASH + 32;
/// Number of carried columns.
const CARRIED: usize = SUM_INVERSE + 1;
const _: () = assert!(CARRY_BITS + 2 * CARRIES == 102 && CARRIED == 168);

/// The six fields of a rule (spec 10, section 3.1). Private witnesses of the
/// proof: no `Debug`, no serialization.
pub struct PolicyRule {
    pub policy_address: [u8; POLICY_ADDRESS_BYTES],
    pub policy_codehash: [u8; 32],
    pub params_hash: [u8; 32],
    /// `K("ghost/policy-override/v1", override_secret)`, or 32 zero bytes
    /// for a rule with no override.
    pub override_hash: [u8; 32],
    pub action_tag: [u8; 32],
    pub action_salt: [u8; 32],
}

impl PolicyRule {
    /// Every field zero: what a plain-coin proof opens, since it reads none.
    pub const fn zero() -> Self {
        Self {
            policy_address: [0; POLICY_ADDRESS_BYTES],
            policy_codehash: [0; 32],
            params_hash: [0; 32],
            override_hash: [0; 32],
            action_tag: [0; 32],
            action_salt: [0; 32],
        }
    }

    /// The rule these fields hash to.
    pub fn rule(&self) -> [u8; 32] {
        reveal_policy_rule(
            &self.policy_address,
            &self.policy_codehash,
            &self.params_hash,
            &self.override_hash,
            &self.action_tag,
            &self.action_salt,
        )
    }
}

/// How the proof opens the input's rule. Private witnesses: no `Debug`, no
/// serialization.
pub struct InputRule {
    /// `0`: the input's rule is the empty rule, a plain coin. `1`: the input's
    /// rule is [`Self::rule`], spent with [`Self::override_secret`]. A byte,
    /// not a `bool`, so tests can show that any other value fails; the honest
    /// prover refuses one.
    pub use_override: u8,
    /// The input rule's six fields; not read when `use_override` is `0`.
    pub rule: PolicyRule,
    /// The override secret; not read when `use_override` is `0`.
    pub override_secret: [u8; 32],
}

impl InputRule {
    /// A plain coin: the input's rule is the empty rule.
    pub const fn plain() -> Self {
        Self {
            use_override: 0,
            rule: PolicyRule::zero(),
            override_secret: [0; 32],
        }
    }

    /// A coin with `rule`, spent through its override with `override_secret`.
    pub const fn with_override(rule: PolicyRule, override_secret: [u8; 32]) -> Self {
        Self {
            use_override: 1,
            rule,
            override_secret,
        }
    }

    /// The rule inside the input fingerprint, after the honest prover's
    /// checks: the empty rule, or the opened rule when its override secret
    /// is right and its override hash is not zero.
    fn checked_rule(&self) -> Result<[u8; 32], ProofError> {
        match self.use_override {
            0 => Ok(EMPTY_RULE),
            1 if self.rule.override_hash == [0; 32] => Err(ProofError::OverrideNotSet),
            1 if policy_override_hash(&self.override_secret) != self.rule.override_hash => {
                Err(ProofError::WrongOverrideSecret)
            }
            1 => Ok(self.rule.rule()),
            _ => Err(ProofError::OverrideSwitchNotBit),
        }
    }
}

/// What the wallet chooses for a version 2 reveal. Neither rule is here:
/// both are private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinRevealV2Request {
    /// The shared epoch root the wallet proves against (spec 02, section 8).
    pub root: [u8; 32],
    pub recipient: [u8; 20],
    pub out: [u8; 32],
    pub fee: [u8; 32],
    pub remainder_note: [u8; NOTE_V3_BYTES],
}

/// The public fields of a version 2 coin reveal: everything the node reads
/// from the transaction. There is no `rule` field (spec 10, section 4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinRevealV2 {
    pub root: [u8; 32],
    pub marker: [u8; 32],
    pub remainder: [u8; 32],
    pub remainder_note: [u8; NOTE_V3_BYTES],
    pub recipient: [u8; 20],
    pub out: [u8; 32],
    pub fee: [u8; 32],
}

/// The private side of a version 2 reveal.
struct Witness<'a> {
    opening: &'a SaltedCoinOpening,
    input: &'a InputRule,
    remainder: &'a SaltedCoinRemainder,
    remainder_rule: &'a [u8; 32],
}

fn fields(params: &ChainParams, tx: &CoinRevealV2) -> Vec<u8> {
    FieldWriter::with_version(
        Binding::CoinRevealV2,
        params,
        STATEMENT_COIN_REVEAL,
        STATEMENT_VERSION_2,
        COIN_V2,
        PURPOSE_SPEND,
    )
    .put("root", &tx.root)
    .put("marker", &tx.marker)
    .put("remainder", &tx.remainder)
    .put("recipient", &tx.recipient)
    .put("out", &tx.out)
    .put("fee", &tx.fee)
    .put("remainder_note", &tx.remainder_note)
    .finish()
}

/// The binding digest of a version 2 coin reveal, computed from the
/// verifier's own chain constants and the transaction's fields.
pub fn coin_reveal_v2_binding(params: &ChainParams, tx: &CoinRevealV2) -> [u8; 32] {
    digest(Binding::CoinRevealV2, &fields(params, tx))
}

/// The public values of the proof, one byte each: the 607 binding field
/// bytes, then the 32-byte digest. What the verifier builds; exposed, hidden,
/// so tests can compare the public values of two reveals.
#[doc(hidden)]
pub fn coin_reveal_v2_public_values(params: &ChainParams, tx: &CoinRevealV2) -> Vec<u8> {
    let mut public = fields(params, tx);
    let binding = digest(Binding::CoinRevealV2, &public);
    public.extend_from_slice(&binding);
    public
}

/// The schedule of S1 version 2 and, with a witness, the free bytes and
/// direction bits.
fn schedule_with(w: Option<&Witness>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::CoinRevealV2;
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let type_tag = COIN_V2;
    let rule = w.map(|w| &w.input.rule);
    let mut sb = ScheduleBuilder::new();

    // O2: the rule opening, its digest carried to `F`. Its override hash is
    // the carried copy O4 and O5 read.
    sb.push(
        HashBuilder::new(TAG_REVEAL_POLICY_V2)
            .constant(&[0; 32 - POLICY_ADDRESS_BYTES])
            .free(POLICY_ADDRESS_BYTES, rule.map(|r| &r.policy_address[..]))
            .free(32, rule.map(|r| &r.policy_codehash[..]))
            .free(32, rule.map(|r| &r.params_hash[..]))
            .carried(OVERRIDE_HASH, 32)
            .free(32, rule.map(|r| &r.action_tag[..]))
            .free(32, rule.map(|r| &r.action_salt[..]))
            .carried_output(RIN, None),
    );
    // O4: the override secret, checked only when the switch is on.
    sb.push(
        HashBuilder::new(TAG_POLICY_OVERRIDE_V1)
            .free(32, w.map(|w| &w.input.override_secret[..]))
            .carried_output(OVERRIDE_HASH, Some(USE_OVERRIDE)),
    );
    // O3: the input fingerprint with `use_override * RIN` as its rule.
    sb.push(
        HashBuilder::new(TAG_COIN_FINGERPRINT_V2)
            .free(32, w.map(|w| &w.opening.s[..]))
            .carried(R, 32)
            .carried(B, 32)
            .carried(SALT, SALT_BYTES)
            .constant(&type_tag)
            .constant(&[0; 32])
            .gated(RIN, 32, USE_OVERRIDE),
    );
    sb.push(HashBuilder::new(TAG_COIN_COMMITMENT).constant(&type_tag).prev().amount(V));
    for level in 0..TREE_DEPTH {
        let mut node = HashBuilder::new(TAG_COIN_TREE_NODE)
            .constant(&[level as u8])
            .node(w.map(|w| (&w.opening.path[level], w.opening.position >> level & 1 == 1)));
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
    // O6: the remainder rule is free.
    sb.push(
        HashBuilder::new(TAG_COIN_FINGERPRINT_V2)
            .free(32, w.map(|w| &w.remainder.s[..]))
            .free(32, w.map(|w| &w.remainder.r[..]))
            .free(32, w.map(|w| &w.remainder.b[..]))
            .free(SALT_BYTES, w.map(|w| &w.remainder.salt[..]))
            .constant(&type_tag)
            .constant(&[0; 32])
            .free(32, w.map(|w| &w.remainder_rule[..])),
    );
    sb.push(
        HashBuilder::new(TAG_COIN_COMMITMENT)
            .constant(&type_tag)
            .prev()
            .amount(V2)
            .output(off("remainder")),
    );
    // O7: the binding of section 4.2.
    sb.push(
        HashBuilder::new(TAG_COIN_REVEAL_BINDING_V2)
            .public(0, fields_len)
            .output(fields_len),
    );

    let mut consts = vec![
        (off("statement"), STATEMENT_COIN_REVEAL),
        (off("statement_version"), STATEMENT_VERSION_2),
        (off("type"), type_tag[0]),
        (off("type") + 1, type_tag[1]),
        (off("purpose"), PURPOSE_SPEND),
    ];
    for t in 0..AMOUNT_HIGH_BYTES {
        consts.push((off("out") + t, 0));
        consts.push((off("fee") + t, 0));
    }
    let conservation = Conservation {
        v: V,
        remainder: V2,
        carries: CARRY_BITS,
        out: off("out"),
        fee: off("fee"),
    };
    let (mut schedule, free, dirs) = sb.finish(fields_len + 32, CARRIED, Some(conservation), consts);
    // O1 and O5.
    schedule.switch = Some(Switch {
        bit: USE_OVERRIDE,
        nonzero: OVERRIDE_HASH,
        nonzero_len: 32,
        inverse: SUM_INVERSE,
    });
    (schedule, free, dirs)
}

/// The schedule of S1 version 2, without any witness.
pub(crate) fn schedule() -> Schedule {
    schedule_with(None).0
}

fn carried_values(w: &Witness, carries: [u8; CARRIES]) -> Vec<u32> {
    let mut carried = vec![0u32; CARRIED];
    for k in 0..32 {
        carried[R + k] = u32::from(w.opening.r[k]);
        carried[B + k] = u32::from(w.opening.b[k]);
    }
    for (k, &byte) in w.opening.salt.iter().enumerate() {
        carried[SALT + k] = u32::from(byte);
    }
    for j in 0..AMOUNT_LIMBS {
        carried[V + j] = limb(&w.opening.v, j);
        carried[V2 + j] = limb(&w.remainder.v, j);
    }
    for (k, &carry) in carries.iter().enumerate() {
        carried[CARRY_BITS + 2 * k] = u32::from(carry & 1);
        carried[CARRY_BITS + 2 * k + 1] = u32::from(carry >> 1);
    }
    carried[USE_OVERRIDE] = u32::from(w.input.use_override);
    let rin = w.input.rule.rule();
    let override_hash = &w.input.rule.override_hash;
    for k in 0..32 {
        carried[RIN + k] = u32::from(rin[k]);
        carried[OVERRIDE_HASH + k] = u32::from(override_hash[k]);
    }
    let sum: u32 = override_hash.iter().map(|&b| u32::from(b)).sum();
    carried[SUM_INVERSE] = F::from_u32(sum).try_inverse().map_or(0, |inverse| inverse.as_canonical_u32());
    carried
}

fn assignment(params: &ChainParams, w: &Witness, claimed: &CoinRevealV2, carries: [u8; CARRIES]) -> Assignment {
    let (_, free, dirs) = schedule_with(Some(w));
    Assignment {
        public: coin_reveal_v2_public_values(params, claimed),
        carried: carried_values(w, carries),
        free,
        dirs,
    }
}

fn prove_witness_unchecked(
    params: &ChainParams,
    w: &Witness,
    claimed: &CoinRevealV2,
    carries: [u8; CARRIES],
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    let assignment = assignment(params, w, claimed, carries);
    stark::prove(Statement::CoinRevealV2, &assignment, zk_randomness).map(Proof)
}

/// A version 2 reveal proof claiming `claimed`, whatever the witness says,
/// with none of the honest prover's checks, so tests can show the verifier
/// catches a lie (a switch of 2, a wrong override secret, a policy coin
/// spent as a plain one). The trace hashes what the witness gives, the
/// public values are the claimed transaction's, and the conservation carries
/// are a best guess. Nothing here can make a proof the verifier accepts that
/// the honest prover would refuse.
#[doc(hidden)]
pub fn prove_coin_reveal_v2_claiming(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    input: &InputRule,
    remainder: &SaltedCoinRemainder,
    remainder_rule: &[u8; 32],
    claimed: &CoinRevealV2,
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    let w = Witness {
        opening,
        input,
        remainder,
        remainder_rule,
    };
    let carries = guessed_carries(&opening.v, &claimed.out, &remainder.v, &claimed.fee);
    prove_witness_unchecked(params, &w, claimed, carries, zk_randomness)
}

/// Prove a version 2 coin reveal of a salted commitment (spec 10, section
/// 4), creating a salted remainder whose rule is `remainder_rule`. Returns
/// the public fields the transaction carries and the proof. Neither rule,
/// the switch nor the override secret is a public value.
///
/// Refuses, before any proving: a switch other than 0 or 1; the override
/// with a zero override hash or a wrong override secret; an amount word with
/// a high byte set; a remainder whose blinding equals the input's;
/// `v != out + v' + fee`; and a commitment that is not the leaf at
/// `position` under `root` with the input rule `input` opens. So a coin with
/// a rule refuses the switch off, and a coin with the empty rule refuses it
/// on: neither is the leaf.
///
/// `zk_randomness` must be 32 fresh bytes from a secure random source.
pub fn prove_coin_reveal_v2(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    input: &InputRule,
    remainder: &SaltedCoinRemainder,
    remainder_rule: &[u8; 32],
    request: &CoinRevealV2Request,
    zk_randomness: [u8; 32],
) -> Result<(CoinRevealV2, Proof), ProofError> {
    let (tx, carries) = checked_reveal(opening, input, remainder, remainder_rule, request)?;
    let w = Witness {
        opening,
        input,
        remainder,
        remainder_rule,
    };
    let proof = prove_witness_unchecked(params, &w, &tx, carries, zk_randomness)?;
    Ok((tx, proof))
}

/// The honest prover's checks of [`prove_coin_reveal_v2`], and the
/// transaction and conservation carries they give.
fn checked_reveal(
    opening: &SaltedCoinOpening,
    input: &InputRule,
    remainder: &SaltedCoinRemainder,
    remainder_rule: &[u8; 32],
    request: &CoinRevealV2Request,
) -> Result<(CoinRevealV2, [u8; CARRIES]), ProofError> {
    let input_rule = input.checked_rule()?;
    if ![&opening.v, &remainder.v, &request.out, &request.fee].into_iter().all(amount_is_valid) {
        return Err(ProofError::AmountOutOfRange);
    }
    if remainder.b == opening.b {
        return Err(ProofError::ReusedBlinding);
    }
    let carries = conservation_carries(&opening.v, &request.out, &remainder.v, &request.fee)
        .ok_or(ProofError::ConservationFails)?;
    let fingerprint = coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, &input_rule);
    let leaf = coin_commitment_v2(&fingerprint, &opening.v);
    if merkle_root(Tree::Coin, &leaf, opening.position, &opening.path) != request.root {
        return Err(ProofError::NotInTree);
    }
    let remainder_fingerprint =
        coin_fingerprint_v2(&remainder.s, &remainder.r, &remainder.b, &remainder.salt, remainder_rule);
    let tx = CoinRevealV2 {
        root: request.root,
        marker: coin_marker_v2(&opening.r, &opening.b, &opening.salt),
        remainder: coin_commitment_v2(&remainder_fingerprint, &remainder.v),
        remainder_note: request.remainder_note,
        recipient: request.recipient,
        out: request.out,
        fee: request.fee,
    };
    Ok((tx, carries))
}

/// Verify a version 2 coin reveal against the verifier's own chain
/// constants.
///
/// Rejects an out-of-range `out` or `fee` before the proof is looked at,
/// then verifies the proof against public values the verifier builds itself,
/// binding digest included. There is no rule to check: the proof opens the
/// input rule itself (spec 10, section 4.2).
pub fn verify_coin_reveal_v2(params: &ChainParams, tx: &CoinRevealV2, proof: &Proof) -> Result<(), ProofError> {
    if !amount_is_valid(&tx.out) || !amount_is_valid(&tx.fee) {
        return Err(ProofError::AmountOutOfRange);
    }
    stark::verify(Statement::CoinRevealV2, &coin_reveal_v2_public_values(params, tx), proof.as_bytes())
}

/// [`prove_coin_reveal_v2`] at the scale configuration (`scale.rs`):
/// the same statement, the same checks before proving and the same public
/// fields, with Poseidon2 commitments and transcript, challenges from the
/// degree-8 extension and 96 queries. The proof verifies only with
/// [`verify_coin_reveal_v2_scale`].
///
/// `zk_randomness` must be 32 fresh bytes from a secure random source.
pub fn prove_coin_reveal_v2_scale(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    input: &InputRule,
    remainder: &SaltedCoinRemainder,
    remainder_rule: &[u8; 32],
    request: &CoinRevealV2Request,
    zk_randomness: [u8; 32],
) -> Result<(CoinRevealV2, Proof), ProofError> {
    prove_coin_reveal_v2_scale_shaped(
        params,
        opening,
        input,
        remainder,
        remainder_rule,
        request,
        zk_randomness,
        ScaleShape::SHIPPED,
    )
}

/// [`prove_coin_reveal_v2_scale`] at another query count or digest length,
/// so tests can show the verifier rejects a proof of the wrong shape.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn prove_coin_reveal_v2_scale_shaped(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    input: &InputRule,
    remainder: &SaltedCoinRemainder,
    remainder_rule: &[u8; 32],
    request: &CoinRevealV2Request,
    zk_randomness: [u8; 32],
    shape: ScaleShape,
) -> Result<(CoinRevealV2, Proof), ProofError> {
    let (tx, carries) = checked_reveal(opening, input, remainder, remainder_rule, request)?;
    let w = Witness {
        opening,
        input,
        remainder,
        remainder_rule,
    };
    let assignment = assignment(params, &w, &tx, carries);
    let proof = scale::prove(&assignment, zk_randomness, shape)?;
    Ok((tx, Proof(proof)))
}

/// [`verify_coin_reveal_v2`] at the scale configuration (`scale.rs`):
/// the same public values, binding digest included, built by the verifier.
/// A proof of the shipped Keccak configuration is rejected here, as a proof
/// of this one is by [`verify_coin_reveal_v2`].
pub fn verify_coin_reveal_v2_scale(params: &ChainParams, tx: &CoinRevealV2, proof: &Proof) -> Result<(), ProofError> {
    verify_coin_reveal_v2_scale_shaped(params, tx, proof, ScaleShape::SHIPPED)
}

/// [`verify_coin_reveal_v2_scale`] at another query count or digest length,
/// for tests.
#[doc(hidden)]
pub fn verify_coin_reveal_v2_scale_shaped(
    params: &ChainParams,
    tx: &CoinRevealV2,
    proof: &Proof,
    shape: ScaleShape,
) -> Result<(), ProofError> {
    if !amount_is_valid(&tx.out) || !amount_is_valid(&tx.fee) {
        return Err(ProofError::AmountOutOfRange);
    }
    scale::verify(&coin_reveal_v2_public_values(params, tx), proof.as_bytes(), shape)
}

#[cfg(test)]
mod tests {
    use p3_air::{BaseAir, check_all_constraints};

    use super::*;
    use crate::air::StatementAir;
    use crate::amount::amount_word;
    use crate::hash::{empty_leaf, tree_node};
    use crate::schedule::execute;

    fn params() -> ChainParams {
        ChainParams {
            chain_id: [0, 0, 0, 0, 0, 0, 0x04, 0xd2],
            version: crate::binding::PROTOCOL_VERSION_2,
            domain: [7; 32],
        }
    }

    fn path() -> [[u8; 32]; TREE_DEPTH] {
        let mut path = [[0u8; 32]; TREE_DEPTH];
        let mut empty = empty_leaf();
        for (level, sibling) in path.iter_mut().enumerate() {
            *sibling = empty;
            empty = tree_node(Tree::Coin, level as u8, &empty, &empty);
        }
        path[0] = [9; 32];
        path
    }

    const SECRET: [u8; 32] = [0x0e; 32];

    fn policy(override_hash: [u8; 32]) -> PolicyRule {
        PolicyRule {
            policy_address: [0x50; POLICY_ADDRESS_BYTES],
            policy_codehash: [0x51; 32],
            params_hash: [0x52; 32],
            override_hash,
            action_tag: [0x53; 32],
            action_salt: [0x54; 32],
        }
    }

    fn opening() -> SaltedCoinOpening {
        SaltedCoinOpening {
            s: [1; 32],
            r: [2; 32],
            b: [3; 32],
            salt: [0xa5; SALT_BYTES],
            v: amount_word(1_000_000),
            position: 0b101,
            path: path(),
        }
    }

    fn remainder() -> SaltedCoinRemainder {
        SaltedCoinRemainder {
            s: [1; 32],
            r: [2; 32],
            b: [4; 32],
            salt: [0x3c; SALT_BYTES],
            v: amount_word(1_000_000 - 600_000 - 21),
        }
    }

    /// The request for a coin whose fingerprint holds `rule`.
    fn request(rule: &[u8; 32]) -> CoinRevealV2Request {
        let o = opening();
        let leaf = coin_commitment_v2(&coin_fingerprint_v2(&o.s, &o.r, &o.b, &o.salt, rule), &o.v);
        CoinRevealV2Request {
            root: merkle_root(Tree::Coin, &leaf, o.position, &o.path),
            recipient: [5; 20],
            out: amount_word(600_000),
            fee: amount_word(21),
            remainder_note: [6; NOTE_V3_BYTES],
        }
    }

    /// The transaction an honest prover would publish for `request`.
    fn tx_for(request: &CoinRevealV2Request, remainder_rule: &[u8; 32]) -> CoinRevealV2 {
        let (o, rem) = (opening(), remainder());
        let f = coin_fingerprint_v2(&rem.s, &rem.r, &rem.b, &rem.salt, remainder_rule);
        CoinRevealV2 {
            root: request.root,
            marker: coin_marker_v2(&o.r, &o.b, &o.salt),
            remainder: coin_commitment_v2(&f, &rem.v),
            remainder_note: request.remainder_note,
            recipient: request.recipient,
            out: request.out,
            fee: request.fee,
        }
    }

    /// Whether the trace of `input` for `tx` satisfies every constraint of
    /// `schedule`.
    fn satisfies(schedule: Schedule, input: &InputRule, remainder_rule: &[u8; 32], tx: &CoinRevealV2) -> bool {
        let (o, rem) = (opening(), remainder());
        let w = Witness {
            opening: &o,
            input,
            remainder: &rem,
            remainder_rule,
        };
        let carries = guessed_carries(&o.v, &tx.out, &rem.v, &tx.fee);
        let a = assignment(&params(), &w, tx, carries);
        let air = StatementAir::new(schedule.clone(), Statement::CoinRevealV2.air().height());
        let trace = air.generate_trace(&execute(&schedule, &a), &a);
        let public: Vec<F> = a.public.iter().map(|&b| F::from_u8(b)).collect();
        check_all_constraints(&air, &trace, &public, Some(1)).is_ok()
    }

    /// Spec 10, section 4.4: 47 permutations, 168 carried columns, 3,890
    /// columns, 2,048 rows, 639 public values; the budget's widest trace.
    #[test]
    fn the_trace_has_the_spec_shape() {
        let s = schedule();
        assert_eq!(s.expand().len(), 47);
        assert_eq!(s.carried, 168);
        assert_eq!(s.num_public, 607 + 32);
        let air = Statement::CoinRevealV2.air();
        assert_eq!(air.height(), 2048);
        assert_eq!(BaseAir::<F>::width(&air), 3890);
        assert_eq!(BaseAir::<F>::width(&air), stark::MAX_TRACE_WIDTH);
        assert_eq!(BaseAir::<F>::width(&air), BaseAir::<F>::width(&Statement::SaltedCoinReveal.air()) + 66);
    }

    #[test]
    fn plain_and_override_traces_satisfy_every_constraint() {
        let rule = policy(policy_override_hash(&SECRET)).rule();
        let cases = [
            (InputRule::plain(), EMPTY_RULE),
            (InputRule::with_override(policy(policy_override_hash(&SECRET)), SECRET), rule),
        ];
        for (input, input_rule) in cases {
            for remainder_rule in [EMPTY_RULE, rule, [0x77; 32]] {
                let tx = tx_for(&request(&input_rule), &remainder_rule);
                assert!(satisfies(schedule(), &input, &remainder_rule, &tx), "switch {}", input.use_override);
            }
        }
    }

    /// RP-2 to RP-4 in the constraints themselves: each lie breaks one.
    #[test]
    fn every_broken_case_breaks_a_constraint() {
        let good = policy(policy_override_hash(&SECRET));
        let rule = good.rule();
        // RP-2: a switch of 2, on the policy coin and on a plain coin.
        let two = InputRule {
            use_override: 2,
            ..InputRule::with_override(policy(policy_override_hash(&SECRET)), SECRET)
        };
        assert!(!satisfies(schedule(), &two, &EMPTY_RULE, &tx_for(&request(&rule), &EMPTY_RULE)));
        assert!(!satisfies(schedule(), &two, &EMPTY_RULE, &tx_for(&request(&EMPTY_RULE), &EMPTY_RULE)));
        // RP-3: a plain coin with the switch on, a policy coin with it off.
        let on = InputRule::with_override(policy(policy_override_hash(&SECRET)), SECRET);
        assert!(!satisfies(schedule(), &on, &EMPTY_RULE, &tx_for(&request(&EMPTY_RULE), &EMPTY_RULE)));
        assert!(!satisfies(schedule(), &InputRule::plain(), &EMPTY_RULE, &tx_for(&request(&rule), &EMPTY_RULE)));
        let off = InputRule {
            use_override: 0,
            ..InputRule::with_override(policy(policy_override_hash(&SECRET)), SECRET)
        };
        assert!(!satisfies(schedule(), &off, &EMPTY_RULE, &tx_for(&request(&rule), &EMPTY_RULE)));
        // RP-4: a wrong override secret.
        let mut wrong = SECRET;
        wrong[31] ^= 1;
        let lie = InputRule::with_override(policy(policy_override_hash(&SECRET)), wrong);
        assert!(!satisfies(schedule(), &lie, &EMPTY_RULE, &tx_for(&request(&rule), &EMPTY_RULE)));
    }

    /// RP-4, `override_hash = 0`: no secret hashes to zero, so the override
    /// check alone already fails. With that check taken out of the schedule,
    /// O5 still refuses the trace, and only O5 does: without the switch's
    /// check the same trace passes.
    #[test]
    fn a_zero_override_hash_is_refused_by_its_own_constraint() {
        let zero = policy([0; 32]);
        let rule = zero.rule();
        let input = InputRule::with_override(policy([0; 32]), SECRET);
        let tx = tx_for(&request(&rule), &EMPTY_RULE);
        assert!(!satisfies(schedule(), &input, &EMPTY_RULE, &tx));

        let mut no_override_check = schedule();
        no_override_check.hashes[1].carried_output = None;
        assert!(!satisfies(no_override_check.clone(), &input, &EMPTY_RULE, &tx));
        let no_switch = Schedule {
            switch: None,
            ..no_override_check
        };
        assert!(satisfies(no_switch, &input, &EMPTY_RULE, &tx));
    }

    /// Every public field is tied to the trace by some constraint.
    #[test]
    fn every_public_field_is_constrained() {
        let (o, rem) = (opening(), remainder());
        let input = InputRule::plain();
        let w = Witness {
            opening: &o,
            input: &input,
            remainder: &rem,
            remainder_rule: &EMPTY_RULE,
        };
        let tx = tx_for(&request(&EMPTY_RULE), &EMPTY_RULE);
        let carries = conservation_carries(&o.v, &tx.out, &rem.v, &tx.fee).unwrap();
        let a = assignment(&params(), &w, &tx, carries);
        let air = Statement::CoinRevealV2.air();
        let trace = air.generate_trace(&execute(&schedule(), &a), &a);
        let public: Vec<F> = a.public.iter().map(|&b| F::from_u8(b)).collect();
        assert!(check_all_constraints(&air, &trace, &public, Some(1)).is_ok());
        let mut probes: Vec<usize> = Binding::CoinRevealV2
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

    /// The honest prover refuses each broken case before proving.
    #[test]
    fn the_honest_prover_refuses_before_proving() {
        let rule = policy(policy_override_hash(&SECRET)).rule();
        let (o, rem) = (opening(), remainder());
        let refuse = |input: &InputRule, coin_rule: &[u8; 32]| {
            prove_coin_reveal_v2(&params(), &o, input, &rem, &EMPTY_RULE, &request(coin_rule), [1; 32]).err()
        };
        let two = InputRule {
            use_override: 2,
            ..InputRule::with_override(policy(policy_override_hash(&SECRET)), SECRET)
        };
        assert_eq!(refuse(&two, &rule), Some(ProofError::OverrideSwitchNotBit));
        let on = InputRule::with_override(policy(policy_override_hash(&SECRET)), SECRET);
        assert_eq!(refuse(&on, &EMPTY_RULE), Some(ProofError::NotInTree));
        assert_eq!(refuse(&InputRule::plain(), &rule), Some(ProofError::NotInTree));
        let wrong = InputRule::with_override(policy(policy_override_hash(&SECRET)), [0x0f; 32]);
        assert_eq!(refuse(&wrong, &rule), Some(ProofError::WrongOverrideSecret));
        let zero = InputRule::with_override(policy([0; 32]), SECRET);
        assert_eq!(refuse(&zero, &policy([0; 32]).rule()), Some(ProofError::OverrideNotSet));
    }
}
