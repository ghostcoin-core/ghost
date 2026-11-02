//! Statement S4: the policy reveal of the policy class (spec 10, sections 5.1
//! and 5.4).
//!
//! The proof spends a coin whose rule is not empty, without its override:
//! the coin's whole value goes to the escrow slot of a frozen policy and to
//! the fee, and the remainder holds nothing.
//!
//! - **P1. Rule opening.** `RIN` is the rule hash of spec 10, section 3.1. Its
//!   five fields `policy_address`, `policy_codehash`, `params_hash`,
//!   `action_tag` and `action_salt` are read from the public values;
//!   `override_hash` is a private witness. The opened rule must be the one
//!   inside `F`, so the published fields, the action salt among them, are the
//!   committed ones.
//! - **P2. Input rule.** `F` is built with `R_in = RIN`, through an ungated
//!   carried copy: the digest of `RIN` is tied to 32 carried columns, which
//!   `F` reads. A coin with the empty rule can never be spent here: its
//!   fingerprint holds 32 zero bytes, and a real rule is never zero.
//! - **P3. Zero remainder.** The six limbs of `v'` are fixed at zero, so
//!   `v = out + fee`. `F'` is built with the empty rule (32 constant zero
//!   bytes) and free `s'`, `r'`, `b'` and salt.
//! - **P4. Membership, marker, ranges.** As S1.
//! - **P5. Bindings.** `ghost/policy-reveal-binding/v1` over the 767 bytes of
//!   section 5.1; `statement = 0x04`, `statement_version = 0x01`,
//!   `type = COIN`, `purpose = 0x05`, and the high 20 bytes of `out` and
//!   `fee` are zero.
//!
//! The prover is [`prove_policy_reveal`] and the verifier
//! [`verify_policy_reveal`].
//!
//! The hashes, in trace order (47 permutations):
//!
//! ```text
//! RIN     K(reveal-policy/v2, 0^12 || address, codehash, params_hash,
//!           override_hash, action_tag, action_salt)                      2, = carried RIN
//! F       K(coin-fingerprint, s, r, b, salt, COIN, 0^32, RIN)            2
//! C       K(coin-commitment, COIN, F, v)                                 1
//! N0..N31 K(coin-tree-node, level, left, right)                          32, N31 = root
//! M       K(coin-marker, r, b, salt)                                     1, = marker
//! F'      K(coin-fingerprint, s', r', b', salt', COIN, 0^32, 0^32)       2
//! C'      K(coin-commitment, COIN, F', v' = 0)                           1, = remainder
//! B       K(policy-reveal-binding/v1, fields)                            6, = binding
//! ```
//!
//! The carried columns are `r` (32), `b` (32), the salt (16), the limbs of
//! `v` (6) and `v'` (6), the carry bits (10) and `RIN` (32): 134, so the
//! trace is 3,856 columns wide.

use alloc::vec;
use alloc::vec::Vec;

use crate::amount::{
    AMOUNT_HIGH_BYTES, AMOUNT_LIMBS, CARRIES, amount_is_valid, conservation_carries, guessed_carries, limb,
};
use crate::binding::{
    Binding, ChainParams, FieldWriter, PURPOSE_POLICY_SPEND, STATEMENT_POLICY_REVEAL, STATEMENT_VERSION_1, digest,
};
use crate::hash::{
    COIN_V2, EMPTY_RULE, POLICY_ADDRESS_BYTES, SALT_BYTES, TAG_COIN_COMMITMENT, TAG_COIN_FINGERPRINT_V2,
    TAG_COIN_MARKER_V2, TAG_COIN_TREE_NODE, TAG_POLICY_REVEAL_BINDING_V1, TAG_REVEAL_POLICY_V2, TREE_DEPTH, Tree,
    coin_commitment_v2, coin_fingerprint_v2, coin_marker_v2, merkle_root,
};
use crate::reveal::{SaltedCoinOpening, SaltedCoinRemainder};
use crate::reveal_v2::{NOTE_V3_BYTES, PolicyRule};
use crate::schedule::{Assignment, Conservation, HashBuilder, Schedule, ScheduleBuilder};
use crate::stark::{self, Statement};
use crate::{Proof, ProofError};

// Carried columns: `r`, `b`, the salt, the limbs of `v` and `v'`, the carry
// bits, then `RIN`.
const R: usize = 0;
const B: usize = 32;
const SALT: usize = 64;
/// Carried column of limb `a0` of `v`.
const V: usize = SALT + SALT_BYTES;
/// Carried column of limb `a0` of `v'`, fixed at zero.
const V2: usize = V + AMOUNT_LIMBS;
/// Carried column of the first carry bit.
const CARRY_BITS: usize = V2 + AMOUNT_LIMBS;
/// Carried columns of `RIN`, the opened rule.
const RIN: usize = CARRY_BITS + 2 * CARRIES;
/// Number of carried columns.
const CARRIED: usize = RIN + 32;
const _: () = assert!(RIN == 102 && CARRIED == 134);

/// What the wallet chooses for a policy reveal. The rule fields are not
/// here: the proof publishes those of the rule it opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRevealRequest {
    /// The shared epoch root the wallet proves against (spec 02, section 8).
    pub root: [u8; 32],
    /// The amount that goes to the escrow slot.
    pub out: [u8; 32],
    pub fee: [u8; 32],
    /// The payout instruction, bound but not read by the chain.
    pub instr: [u8; 32],
    pub remainder_note: [u8; NOTE_V3_BYTES],
}

/// The public fields of a policy reveal: everything the node reads from the
/// transaction (spec 10, section 5.1). There is no `recipient` and no
/// `override_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyReveal {
    pub root: [u8; 32],
    pub marker: [u8; 32],
    /// The zero-value remainder commitment `C'`.
    pub remainder: [u8; 32],
    pub out: [u8; 32],
    pub fee: [u8; 32],
    pub policy_address: [u8; POLICY_ADDRESS_BYTES],
    pub policy_codehash: [u8; 32],
    pub params_hash: [u8; 32],
    pub action_tag: [u8; 32],
    pub action_salt: [u8; 32],
    pub instr: [u8; 32],
    pub remainder_note: [u8; NOTE_V3_BYTES],
}

/// The private side of a policy reveal.
struct Witness<'a> {
    opening: &'a SaltedCoinOpening,
    /// The opened rule's `override_hash`, the one rule field not public.
    override_hash: &'a [u8; 32],
    /// The rule carried into the input fingerprint. The honest prover
    /// carries the digest of the opened fields; a lying one may carry any.
    input_rule: &'a [u8; 32],
    remainder: &'a SaltedCoinRemainder,
}

fn fields(params: &ChainParams, tx: &PolicyReveal) -> Vec<u8> {
    FieldWriter::with_version(
        Binding::PolicyReveal,
        params,
        STATEMENT_POLICY_REVEAL,
        STATEMENT_VERSION_1,
        COIN_V2,
        PURPOSE_POLICY_SPEND,
    )
    .put("root", &tx.root)
    .put("marker", &tx.marker)
    .put("remainder", &tx.remainder)
    .put("out", &tx.out)
    .put("fee", &tx.fee)
    .put("policy_address", &tx.policy_address)
    .put("policy_codehash", &tx.policy_codehash)
    .put("params_hash", &tx.params_hash)
    .put("action_tag", &tx.action_tag)
    .put("action_salt", &tx.action_salt)
    .put("instr", &tx.instr)
    .put("remainder_note", &tx.remainder_note)
    .finish()
}

/// The binding digest of a policy reveal, computed from the verifier's own
/// chain constants and the transaction's fields.
pub fn policy_reveal_binding(params: &ChainParams, tx: &PolicyReveal) -> [u8; 32] {
    digest(Binding::PolicyReveal, &fields(params, tx))
}

/// The public values of the proof, one byte each: the 767 binding field
/// bytes, then the 32-byte digest. What the verifier builds; exposed, hidden,
/// so tests can check the layout.
#[doc(hidden)]
pub fn policy_reveal_public_values(params: &ChainParams, tx: &PolicyReveal) -> Vec<u8> {
    let mut public = fields(params, tx);
    let binding = digest(Binding::PolicyReveal, &public);
    public.extend_from_slice(&binding);
    public
}

/// The schedule of S4 and, with a witness, the free bytes and direction bits.
fn schedule_with(w: Option<&Witness>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::PolicyReveal;
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let type_tag = COIN_V2;
    let mut sb = ScheduleBuilder::new();

    // P1: the rule from its five public fields and the private override
    // hash, its digest tied to the carried `RIN` without a gate.
    sb.push(
        HashBuilder::new(TAG_REVEAL_POLICY_V2)
            .constant(&[0; 32 - POLICY_ADDRESS_BYTES])
            .public(off("policy_address"), POLICY_ADDRESS_BYTES)
            .public(off("policy_codehash"), 32)
            .public(off("params_hash"), 32)
            .free(32, w.map(|w| &w.override_hash[..]))
            .public(off("action_tag"), 32)
            .public(off("action_salt"), 32)
            .carried_output(RIN, None),
    );
    // P2: the input fingerprint with `RIN` as its rule.
    sb.push(
        HashBuilder::new(TAG_COIN_FINGERPRINT_V2)
            .free(32, w.map(|w| &w.opening.s[..]))
            .carried(R, 32)
            .carried(B, 32)
            .carried(SALT, SALT_BYTES)
            .constant(&type_tag)
            .constant(&[0; 32])
            .carried(RIN, 32),
    );
    sb.push(HashBuilder::new(TAG_COIN_COMMITMENT).constant(&type_tag).prev().amount(V));
    // P4: membership and the marker.
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
    // P3: the remainder, with the empty rule and the zero limbs of `v'`.
    sb.push(
        HashBuilder::new(TAG_COIN_FINGERPRINT_V2)
            .free(32, w.map(|w| &w.remainder.s[..]))
            .free(32, w.map(|w| &w.remainder.r[..]))
            .free(32, w.map(|w| &w.remainder.b[..]))
            .free(SALT_BYTES, w.map(|w| &w.remainder.salt[..]))
            .constant(&type_tag)
            .constant(&[0; 32])
            .constant(&EMPTY_RULE),
    );
    sb.push(
        HashBuilder::new(TAG_COIN_COMMITMENT)
            .constant(&type_tag)
            .prev()
            .amount(V2)
            .output(off("remainder")),
    );
    // P5: the binding of section 5.1.
    sb.push(
        HashBuilder::new(TAG_POLICY_REVEAL_BINDING_V1)
            .public(0, fields_len)
            .output(fields_len),
    );

    let mut consts = vec![
        (off("statement"), STATEMENT_POLICY_REVEAL),
        (off("statement_version"), STATEMENT_VERSION_1),
        (off("type"), type_tag[0]),
        (off("type") + 1, type_tag[1]),
        (off("purpose"), PURPOSE_POLICY_SPEND),
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
    // P3: `v' = 0`, so conservation is `v = out + fee`.
    schedule.zero_carried = (V2..V2 + AMOUNT_LIMBS).collect();
    (schedule, free, dirs)
}

/// The schedule of S4, without any witness.
pub(crate) fn schedule() -> Schedule {
    schedule_with(None).0
}

fn carried_values(w: &Witness, carries: [u8; CARRIES]) -> Vec<u32> {
    let mut carried = vec![0u32; CARRIED];
    for k in 0..32 {
        carried[R + k] = u32::from(w.opening.r[k]);
        carried[B + k] = u32::from(w.opening.b[k]);
        carried[RIN + k] = u32::from(w.input_rule[k]);
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
    carried
}

fn assignment(params: &ChainParams, w: &Witness, claimed: &PolicyReveal, carries: [u8; CARRIES]) -> Assignment {
    let (_, free, dirs) = schedule_with(Some(w));
    Assignment {
        public: policy_reveal_public_values(params, claimed),
        carried: carried_values(w, carries),
        free,
        dirs,
    }
}

fn prove_witness_unchecked(
    params: &ChainParams,
    w: &Witness,
    claimed: &PolicyReveal,
    carries: [u8; CARRIES],
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    let assignment = assignment(params, w, claimed, carries);
    stark::prove(Statement::PolicyReveal, &assignment, zk_randomness).map(Proof)
}

/// A policy reveal proof claiming `claimed`, whatever the witness says, with
/// none of the honest prover's checks, so tests can show the verifier
/// catches a lie (a published action salt that is not the coin's, a
/// remainder with value, a coin with the empty rule). The trace opens the
/// rule from the claimed public fields and `override_hash`, carries
/// `input_rule` into the input fingerprint, hashes what the witness gives,
/// and takes the conservation carries as a best guess. Nothing here can make
/// a proof the verifier accepts that the honest prover would refuse.
#[doc(hidden)]
pub fn prove_policy_reveal_claiming(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    override_hash: &[u8; 32],
    input_rule: &[u8; 32],
    remainder: &SaltedCoinRemainder,
    claimed: &PolicyReveal,
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    let w = Witness {
        opening,
        override_hash,
        input_rule,
        remainder,
    };
    let carries = guessed_carries(&opening.v, &claimed.out, &remainder.v, &claimed.fee);
    prove_witness_unchecked(params, &w, claimed, carries, zk_randomness)
}

/// Prove a policy reveal of a salted coin whose rule is `rule` (spec 10,
/// section 5), creating a zero-value remainder with the empty rule. Returns
/// the public fields the transaction carries, the rule's five public fields
/// among them, and the proof. `override_hash` is not a public value.
///
/// Refuses, before any proving: an amount word with a high byte set; a
/// remainder whose amount is not zero; a remainder whose blinding equals the
/// input's; `v != out + fee`; and a commitment that is not the leaf at
/// `position` under `root` with the rule `rule` hashes to. So a coin with the
/// empty rule, or with a rule other than `rule` (another action salt, say),
/// is refused: neither is the leaf.
///
/// `zk_randomness` must be 32 fresh bytes from a secure random source.
pub fn prove_policy_reveal(
    params: &ChainParams,
    opening: &SaltedCoinOpening,
    rule: &PolicyRule,
    remainder: &SaltedCoinRemainder,
    request: &PolicyRevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(PolicyReveal, Proof), ProofError> {
    if ![&opening.v, &remainder.v, &request.out, &request.fee].into_iter().all(amount_is_valid) {
        return Err(ProofError::AmountOutOfRange);
    }
    if remainder.v != [0; 32] {
        return Err(ProofError::RemainderNotZero);
    }
    if remainder.b == opening.b {
        return Err(ProofError::ReusedBlinding);
    }
    let carries = conservation_carries(&opening.v, &request.out, &remainder.v, &request.fee)
        .ok_or(ProofError::ConservationFails)?;
    let input_rule = rule.rule();
    let fingerprint = coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, &input_rule);
    let leaf = coin_commitment_v2(&fingerprint, &opening.v);
    if merkle_root(Tree::Coin, &leaf, opening.position, &opening.path) != request.root {
        return Err(ProofError::NotInTree);
    }
    let remainder_fingerprint =
        coin_fingerprint_v2(&remainder.s, &remainder.r, &remainder.b, &remainder.salt, &EMPTY_RULE);
    let tx = PolicyReveal {
        root: request.root,
        marker: coin_marker_v2(&opening.r, &opening.b, &opening.salt),
        remainder: coin_commitment_v2(&remainder_fingerprint, &remainder.v),
        out: request.out,
        fee: request.fee,
        policy_address: rule.policy_address,
        policy_codehash: rule.policy_codehash,
        params_hash: rule.params_hash,
        action_tag: rule.action_tag,
        action_salt: rule.action_salt,
        instr: request.instr,
        remainder_note: request.remainder_note,
    };
    let w = Witness {
        opening,
        override_hash: &rule.override_hash,
        input_rule: &input_rule,
        remainder,
    };
    let proof = prove_witness_unchecked(params, &w, &tx, carries, zk_randomness)?;
    Ok((tx, proof))
}

/// Verify a policy reveal against the verifier's own chain constants.
///
/// Rejects an out-of-range `out` or `fee` before the proof is looked at,
/// then verifies the proof against public values the verifier builds itself,
/// binding digest included. The node's own checks of spec 10, section 5.2
/// (the policy, the root's eligibility, the marker) are not here.
pub fn verify_policy_reveal(params: &ChainParams, tx: &PolicyReveal, proof: &Proof) -> Result<(), ProofError> {
    if !amount_is_valid(&tx.out) || !amount_is_valid(&tx.fee) {
        return Err(ProofError::AmountOutOfRange);
    }
    stark::verify(Statement::PolicyReveal, &policy_reveal_public_values(params, tx), proof.as_bytes())
}

#[cfg(test)]
mod tests {
    use p3_air::{BaseAir, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::air::{F, StatementAir};
    use crate::amount::amount_word;
    use crate::hash::{empty_leaf, policy_override_hash, tree_node};
    use crate::schedule::execute;

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
            empty = tree_node(Tree::Coin, level as u8, &empty, &empty);
        }
        path[0] = [9; 32];
        path
    }

    fn policy() -> PolicyRule {
        PolicyRule {
            policy_address: [0x50; POLICY_ADDRESS_BYTES],
            policy_codehash: [0x51; 32],
            params_hash: [0x52; 32],
            override_hash: policy_override_hash(&[0x0e; 32]),
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

    fn remainder(v: u128) -> SaltedCoinRemainder {
        SaltedCoinRemainder {
            s: [1; 32],
            r: [2; 32],
            b: [4; 32],
            salt: [0x3c; SALT_BYTES],
            v: amount_word(v),
        }
    }

    fn root(coin_rule: &[u8; 32]) -> [u8; 32] {
        let o = opening();
        let leaf = coin_commitment_v2(&coin_fingerprint_v2(&o.s, &o.r, &o.b, &o.salt, coin_rule), &o.v);
        merkle_root(Tree::Coin, &leaf, o.position, &o.path)
    }

    /// The transaction for the coin with `coin_rule`, publishing `rule`'s
    /// fields, with a remainder of `v'` and `out = v - v' - fee`.
    fn tx_for(coin_rule: &[u8; 32], rule: &PolicyRule, v_rem: u128) -> PolicyReveal {
        let (o, rem) = (opening(), remainder(v_rem));
        let f = coin_fingerprint_v2(&rem.s, &rem.r, &rem.b, &rem.salt, &EMPTY_RULE);
        PolicyReveal {
            root: root(coin_rule),
            marker: coin_marker_v2(&o.r, &o.b, &o.salt),
            remainder: coin_commitment_v2(&f, &rem.v),
            out: amount_word(1_000_000 - 21 - v_rem),
            fee: amount_word(21),
            policy_address: rule.policy_address,
            policy_codehash: rule.policy_codehash,
            params_hash: rule.params_hash,
            action_tag: rule.action_tag,
            action_salt: rule.action_salt,
            instr: [0x61; 32],
            remainder_note: [6; NOTE_V3_BYTES],
        }
    }

    /// Whether the trace for `tx`, with `input_rule` carried and a remainder
    /// of `v_rem`, satisfies every constraint of `schedule`.
    fn satisfies(schedule: Schedule, input_rule: &[u8; 32], v_rem: u128, tx: &PolicyReveal) -> bool {
        let (o, rem, rule) = (opening(), remainder(v_rem), policy());
        let w = Witness {
            opening: &o,
            override_hash: &rule.override_hash,
            input_rule,
            remainder: &rem,
        };
        let carries = guessed_carries(&o.v, &tx.out, &rem.v, &tx.fee);
        let a = assignment(&params(), &w, tx, carries);
        let air = StatementAir::new(schedule.clone(), Statement::PolicyReveal.air().height());
        let trace = air.generate_trace(&execute(&schedule, &a), &a);
        let public: Vec<F> = a.public.iter().map(|&b| F::from_u8(b)).collect();
        check_all_constraints(&air, &trace, &public, Some(1)).is_ok()
    }

    /// Spec 10, section 5.4: 47 permutations, 134 carried columns, 3,856
    /// columns, 2,048 rows, 799 public values.
    #[test]
    fn the_trace_has_the_spec_shape() {
        let s = schedule();
        assert_eq!(s.expand().len(), 47);
        assert_eq!(s.carried, 134);
        assert_eq!(s.num_public, 767 + 32);
        assert_eq!(s.zero_carried, (V2..V2 + AMOUNT_LIMBS).collect::<Vec<_>>());
        let air = Statement::PolicyReveal.air();
        assert_eq!(air.height(), 2048);
        assert_eq!(BaseAir::<F>::width(&air), 3856);
        assert!(BaseAir::<F>::width(&air) <= stark::MAX_TRACE_WIDTH);
        assert_eq!(BaseAir::<F>::width(&air), BaseAir::<F>::width(&Statement::CoinRevealV2.air()) - 34);
    }

    #[test]
    fn the_honest_trace_satisfies_every_constraint() {
        let rule = policy().rule();
        assert!(satisfies(schedule(), &rule, 0, &tx_for(&rule, &policy(), 0)));
        // A fee-only spend: `out = 0`.
        let mut fee_only = tx_for(&rule, &policy(), 0);
        fee_only.out = amount_word(0);
        fee_only.fee = amount_word(1_000_000);
        assert!(satisfies(schedule(), &rule, 0, &fee_only));
    }

    /// RP-6, RP-7 and the empty-rule coin in the constraints themselves.
    #[test]
    fn every_broken_case_breaks_a_constraint() {
        let rule = policy().rule();
        // RP-6: the published action salt is not the coin's, with the coin's
        // rule carried (the opening fails) or the published one (the leaf
        // fails).
        let other = PolicyRule {
            action_salt: [0x55; 32],
            ..policy()
        };
        let lying = tx_for(&rule, &other, 0);
        assert!(!satisfies(schedule(), &rule, 0, &lying));
        assert!(!satisfies(schedule(), &other.rule(), 0, &lying));
        // The empty-rule coin, with the empty rule carried or the opened one.
        let empty = tx_for(&EMPTY_RULE, &policy(), 0);
        assert!(!satisfies(schedule(), &EMPTY_RULE, 0, &empty));
        assert!(!satisfies(schedule(), &rule, 0, &empty));
        // RP-7: a remainder of 1,000.
        assert!(!satisfies(schedule(), &rule, 1_000, &tx_for(&rule, &policy(), 1_000)));
    }

    /// RP-7: the remainder's value is refused by its own constraint. Without
    /// the zero limbs the same trace passes: conservation alone allows it.
    #[test]
    fn a_remainder_with_value_is_refused_only_by_the_zero_limbs() {
        let rule = policy().rule();
        let tx = tx_for(&rule, &policy(), 1_000);
        assert!(!satisfies(schedule(), &rule, 1_000, &tx));
        let without = Schedule {
            zero_carried: Vec::new(),
            ..schedule()
        };
        assert!(satisfies(without, &rule, 1_000, &tx));
    }

    /// The ungated link is what ties the opened rule to the fingerprint:
    /// without it, a published action salt other than the coin's passes.
    #[test]
    fn the_rule_link_is_what_binds_the_published_fields() {
        let rule = policy().rule();
        let other = PolicyRule {
            action_salt: [0x55; 32],
            ..policy()
        };
        let lying = tx_for(&rule, &other, 0);
        let mut unlinked = schedule();
        assert!(unlinked.hashes[0].carried_output.is_some());
        unlinked.hashes[0].carried_output = None;
        assert!(satisfies(unlinked, &rule, 0, &lying));
    }

    /// Every public field is tied to the trace by some constraint.
    #[test]
    fn every_public_field_is_constrained() {
        let (o, rem, p) = (opening(), remainder(0), policy());
        let rule = p.rule();
        let w = Witness {
            opening: &o,
            override_hash: &p.override_hash,
            input_rule: &rule,
            remainder: &rem,
        };
        let tx = tx_for(&rule, &p, 0);
        let carries = conservation_carries(&o.v, &tx.out, &rem.v, &tx.fee).unwrap();
        let a = assignment(&params(), &w, &tx, carries);
        let air = Statement::PolicyReveal.air();
        let trace = air.generate_trace(&execute(&schedule(), &a), &a);
        let public: Vec<F> = a.public.iter().map(|&b| F::from_u8(b)).collect();
        assert!(check_all_constraints(&air, &trace, &public, Some(1)).is_ok());
        let mut probes: Vec<usize> = Binding::PolicyReveal
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
        let rule = policy().rule();
        let o = opening();
        let request = |coin_rule: &[u8; 32], out: u128| PolicyRevealRequest {
            root: root(coin_rule),
            out: amount_word(out),
            fee: amount_word(21),
            instr: [0x61; 32],
            remainder_note: [6; NOTE_V3_BYTES],
        };
        let refuse = |p: &PolicyRule, rem: &SaltedCoinRemainder, req: &PolicyRevealRequest| {
            prove_policy_reveal(&params(), &o, p, rem, req, [1; 32]).err()
        };
        let other = PolicyRule {
            action_salt: [0x55; 32],
            ..policy()
        };
        assert_eq!(refuse(&other, &remainder(0), &request(&rule, 999_979)), Some(ProofError::NotInTree));
        let empty = request(&EMPTY_RULE, 999_979);
        assert_eq!(refuse(&policy(), &remainder(0), &empty), Some(ProofError::NotInTree));
        assert_eq!(refuse(&PolicyRule::zero(), &remainder(0), &empty), Some(ProofError::NotInTree));
        assert_eq!(refuse(&policy(), &remainder(1_000), &request(&rule, 998_979)), Some(ProofError::RemainderNotZero));
        assert_eq!(refuse(&policy(), &remainder(0), &request(&rule, 999_978)), Some(ProofError::ConservationFails));
        let reused = SaltedCoinRemainder { b: o.b, ..remainder(0) };
        assert_eq!(refuse(&policy(), &reused, &request(&rule, 999_979)), Some(ProofError::ReusedBlinding));
        let mut high = request(&rule, 999_979);
        high.out[0] = 1;
        assert_eq!(refuse(&policy(), &remainder(0), &high), Some(ProofError::AmountOutOfRange));
    }
}
