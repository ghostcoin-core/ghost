//! The native statements of spec 10, sections 8.2 and 9: `KNOW_ACTION_v1`
//! and `KNOW_PREIMAGE_v1`.
//!
//! Both are small: a single private 32-byte value, one hash over it and the
//! binding. Neither carries any column, so each trace is the Keccak circuit,
//! the bit columns and the direction column, 3,722 columns, over 128 rows,
//! and each proof fits [`ACTION_PROOF_BYTES`].
//!
//! **`KNOW_ACTION_v1`** (statement `0x05`, version `0x01`, purpose `0x06`).
//! The node sets every public input from the slot and the transaction; the
//! prover supplies none. `action_tag` and `action_salt` are the slot's, never
//! the transaction's: the verifier takes both as inputs, and a proof made
//! for another tag or salt does not verify against them.
//!
//! - **A1.** `A = K("ghost/policy-action/v1", action_root, action_salt)`, with
//!   `action_root` free and private (one permutation, 87 bytes of input).
//! - **A2.** `A` equals the public `action_tag` byte by byte.
//! - **A3.** The binding `ghost/action-binding/v1` over the 273 bytes of
//!   section 8.2 (three permutations).
//! - **A4.** `statement = 0x05`, `statement_version = 0x01`, `purpose = 0x06`.
//!
//! The node has already refused a slot with `action_tag = 0`, so the circuit
//! does not test it.
//!
//! **`KNOW_PREIMAGE_v1`** (statement `0x06`, version `0x01`, purpose `0x07`).
//! `y = K("ghost/policy-preimage/v1", x)` with `x` free and private (one
//! permutation), and the binding `ghost/preimage-binding/v1` over the 161
//! bytes of section 9.2 (two permutations), with the statement, its version
//! and the purpose fixed.
//!
//! Each statement has its own binding tag, statement code and purpose code,
//! so a proof of one never verifies as the other (spec 10, section 9.1).
//!
//! The hashes, in trace order:
//!
//! ```text
//! KNOW_ACTION_v1
//! A   K(policy-action/v1, action_root, action_salt)      1, = action_tag
//! B   K(action-binding/v1, fields)                       3, = binding
//!
//! KNOW_PREIMAGE_v1
//! Y   K(policy-preimage/v1, x)                           1, = y
//! B   K(preimage-binding/v1, fields)                     2, = binding
//! ```

use alloc::vec;
use alloc::vec::Vec;

use crate::binding::{
    Binding, ChainParams, FieldWriter, PURPOSE_ACTION, PURPOSE_PREIMAGE, STATEMENT_KNOW_ACTION,
    STATEMENT_KNOW_PREIMAGE, STATEMENT_VERSION_1, digest,
};
use crate::hash::{
    POLICY_ADDRESS_BYTES, TAG_ACTION_BINDING_V1, TAG_ACTION_CALLDATA_V1, TAG_POLICY_ACTION_V1,
    TAG_POLICY_PREIMAGE_V1, TAG_PREIMAGE_BINDING_V1, policy_action_tag, policy_preimage_hash, tagged,
};
use crate::schedule::{Assignment, HashBuilder, Schedule, ScheduleBuilder};
use crate::stark::{self, Statement};
use crate::{Proof, ProofError};

/// The proof field of a policy action and of the statement checker (spec 10,
/// section 8.1): the proof-length bound of the small statements, 947,283
/// bytes for 128 rows by 3,722 columns, rounded up to a multiple of 1,024.
pub const ACTION_PROOF_BYTES: usize = 948_224;
const _: () = assert!(ACTION_PROOF_BYTES % 1024 == 0);

/// The calldata field of an action: at most 1,024 bytes (spec 10, section
/// 8.1).
pub const ACTION_CALLDATA_MAX: usize = 1_024;

/// Width of the `context` of `KNOW_PREIMAGE_v1`.
pub const PREIMAGE_CONTEXT_BYTES: usize = 64;

/// `calldata_hash = K("ghost/action-calldata/v1", calldata_len (2),
/// calldata)` (spec 10, section 8.2), the length big-endian. Refuses
/// calldata over [`ACTION_CALLDATA_MAX`] bytes.
pub fn action_calldata_hash(calldata: &[u8]) -> Result<[u8; 32], ProofError> {
    if calldata.len() > ACTION_CALLDATA_MAX {
        return Err(ProofError::CalldataTooLong);
    }
    let len = u16::try_from(calldata.len()).map_err(|_| ProofError::CalldataTooLong)?;
    Ok(tagged(TAG_ACTION_CALLDATA_V1, &[&len.to_be_bytes(), calldata]))
}

/// The public inputs of `KNOW_ACTION_v1`, all set by the node from the slot
/// and the transaction (spec 10, section 8.2). `action_tag` and
/// `action_salt` are read from the slot, never from the transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnowAction {
    /// The slot's `policy_address`.
    pub policy_address: [u8; POLICY_ADDRESS_BYTES],
    /// The slot.
    pub marker: [u8; 32],
    /// The slot's nonce, bound big-endian.
    pub action_nonce: u64,
    /// The slot's `action_tag`.
    pub action_tag: [u8; 32],
    /// The slot's `action_salt`.
    pub action_salt: [u8; 32],
    /// Amount word: the slot's `remaining`.
    pub expected_remaining: [u8; 32],
    /// Amount word charged from the slot.
    pub debit: [u8; 32],
    /// Last block height at which the action is valid, bound big-endian.
    pub expiry: u64,
    /// [`action_calldata_hash`] of the action's calldata.
    pub calldata_hash: [u8; 32],
}

/// The public inputs of `KNOW_PREIMAGE_v1` (spec 10, section 9.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnowPreimage {
    /// The calling policy.
    pub policy_address: [u8; POLICY_ADDRESS_BYTES],
    /// `y = K("ghost/policy-preimage/v1", x)`.
    pub y: [u8; 32],
    /// A value the policy supplies.
    pub context: [u8; PREIMAGE_CONTEXT_BYTES],
}

fn action_fields(params: &ChainParams, s: &KnowAction) -> Vec<u8> {
    FieldWriter::untyped(Binding::Action, params, STATEMENT_KNOW_ACTION, STATEMENT_VERSION_1, PURPOSE_ACTION)
        .put("policy_address", &s.policy_address)
        .put("marker", &s.marker)
        .put("action_nonce", &s.action_nonce.to_be_bytes())
        .put("action_tag", &s.action_tag)
        .put("action_salt", &s.action_salt)
        .put("expected_remaining", &s.expected_remaining)
        .put("debit", &s.debit)
        .put("expiry", &s.expiry.to_be_bytes())
        .put("calldata_hash", &s.calldata_hash)
        .finish()
}

fn preimage_fields(params: &ChainParams, s: &KnowPreimage) -> Vec<u8> {
    FieldWriter::untyped(Binding::Preimage, params, STATEMENT_KNOW_PREIMAGE, STATEMENT_VERSION_1, PURPOSE_PREIMAGE)
        .put("policy_address", &s.policy_address)
        .put("y", &s.y)
        .put("context", &s.context)
        .finish()
}

/// The binding digest of `KNOW_ACTION_v1`, computed from the verifier's own
/// chain constants and the public inputs.
pub fn know_action_binding(params: &ChainParams, s: &KnowAction) -> [u8; 32] {
    digest(Binding::Action, &action_fields(params, s))
}

/// The binding digest of `KNOW_PREIMAGE_v1`, computed from the verifier's
/// own chain constants and the public inputs.
pub fn know_preimage_binding(params: &ChainParams, s: &KnowPreimage) -> [u8; 32] {
    digest(Binding::Preimage, &preimage_fields(params, s))
}

fn with_digest(binding: Binding, mut fields: Vec<u8>) -> Vec<u8> {
    let d = digest(binding, &fields);
    fields.extend_from_slice(&d);
    fields
}

/// The public values of a `KNOW_ACTION_v1` proof, one byte each: the 273
/// binding field bytes, then the digest. Exposed, hidden, so tests can check
/// the layout.
#[doc(hidden)]
pub fn know_action_public_values(params: &ChainParams, s: &KnowAction) -> Vec<u8> {
    with_digest(Binding::Action, action_fields(params, s))
}

/// The public values of a `KNOW_PREIMAGE_v1` proof: the 161 binding field
/// bytes, then the digest.
#[doc(hidden)]
pub fn know_preimage_public_values(params: &ChainParams, s: &KnowPreimage) -> Vec<u8> {
    with_digest(Binding::Preimage, preimage_fields(params, s))
}

/// The schedule of one native statement: the hash of the private value,
/// whose digest is a public field, then the binding; no carried column.
fn native_schedule(
    binding: Binding,
    secret_hash: HashBuilder,
    statement: u8,
    purpose: u8,
) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let mut sb = ScheduleBuilder::new();
    sb.push(secret_hash);
    sb.push(HashBuilder::new(binding.tag()).public(0, fields_len).output(fields_len));
    let consts = vec![
        (off("statement"), statement),
        (off("statement_version"), STATEMENT_VERSION_1),
        (off("purpose"), purpose),
    ];
    sb.finish(fields_len + 32, 0, None, consts)
}

/// A1 to A4, with `action_root` when proving.
fn action_schedule_with(action_root: Option<&[u8; 32]>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::Action;
    debug_assert_eq!(binding.tag(), TAG_ACTION_BINDING_V1);
    let a = HashBuilder::new(TAG_POLICY_ACTION_V1)
        .free(32, action_root.map(|r| &r[..]))
        .public(binding.offset("action_salt"), 32)
        .output(binding.offset("action_tag"));
    native_schedule(binding, a, STATEMENT_KNOW_ACTION, PURPOSE_ACTION)
}

fn preimage_schedule_with(x: Option<&[u8; 32]>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::Preimage;
    debug_assert_eq!(binding.tag(), TAG_PREIMAGE_BINDING_V1);
    let y = HashBuilder::new(TAG_POLICY_PREIMAGE_V1)
        .free(32, x.map(|x| &x[..]))
        .output(binding.offset("y"));
    native_schedule(binding, y, STATEMENT_KNOW_PREIMAGE, PURPOSE_PREIMAGE)
}

/// The schedule of `KNOW_ACTION_v1`, without any witness.
pub(crate) fn action_schedule() -> Schedule {
    action_schedule_with(None).0
}

/// The schedule of `KNOW_PREIMAGE_v1`, without any witness.
pub(crate) fn preimage_schedule() -> Schedule {
    preimage_schedule_with(None).0
}

fn action_assignment(params: &ChainParams, s: &KnowAction, action_root: &[u8; 32]) -> Assignment {
    let (_, free, dirs) = action_schedule_with(Some(action_root));
    Assignment {
        public: know_action_public_values(params, s),
        carried: Vec::new(),
        free,
        dirs,
    }
}

fn preimage_assignment(params: &ChainParams, s: &KnowPreimage, x: &[u8; 32]) -> Assignment {
    let (_, free, dirs) = preimage_schedule_with(Some(x));
    Assignment {
        public: know_preimage_public_values(params, s),
        carried: Vec::new(),
        free,
        dirs,
    }
}

/// Prove an assignment, refusing a proof that would not fit the field.
fn prove_native(statement: Statement, a: &Assignment, zk_randomness: [u8; 32]) -> Result<Proof, ProofError> {
    let bytes = stark::prove(statement, a, zk_randomness)?;
    if bytes.len() > ACTION_PROOF_BYTES {
        return Err(ProofError::Proving);
    }
    Ok(Proof(bytes))
}

/// Verify against public values the verifier built, refusing a proof longer
/// than the field before decoding it.
fn verify_native(statement: Statement, public: &[u8], proof: &Proof) -> Result<(), ProofError> {
    if proof.as_bytes().len() > ACTION_PROOF_BYTES {
        return Err(ProofError::MalformedProof);
    }
    stark::verify(statement, public, proof.as_bytes())
}

/// Prove `KNOW_ACTION_v1`: knowledge of `action_root` with
/// `K("ghost/policy-action/v1", action_root, action_salt) = action_tag`, bound
/// to every public input of `statement`. Refuses, before any proving, an
/// `action_root` that does not give the statement's `action_tag` under its
/// `action_salt`. `action_root` is not a public value.
///
/// `zk_randomness` must be 32 fresh bytes from a secure random source.
pub fn prove_know_action(
    params: &ChainParams,
    statement: &KnowAction,
    action_root: &[u8; 32],
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    if policy_action_tag(action_root, &statement.action_salt) != statement.action_tag {
        return Err(ProofError::NotThePreimage);
    }
    prove_know_action_claiming(params, statement, action_root, zk_randomness)
}

/// A `KNOW_ACTION_v1` proof claiming `statement` whatever `action_root`
/// hashes to, with none of the honest prover's checks, so tests can show the
/// verifier catches a lie. Nothing here can make a proof the verifier
/// accepts that the honest prover would refuse.
#[doc(hidden)]
pub fn prove_know_action_claiming(
    params: &ChainParams,
    statement: &KnowAction,
    action_root: &[u8; 32],
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    prove_native(
        Statement::KnowAction,
        &action_assignment(params, statement, action_root),
        zk_randomness,
    )
}

/// Verify a `KNOW_ACTION_v1` proof against the verifier's own chain
/// constants and the public inputs the node set from the slot and the
/// transaction, binding digest included. The node's checks of spec 10,
/// section 8.3 are not here.
pub fn verify_know_action(params: &ChainParams, statement: &KnowAction, proof: &Proof) -> Result<(), ProofError> {
    verify_native(Statement::KnowAction, &know_action_public_values(params, statement), proof)
}

/// Prove `KNOW_PREIMAGE_v1`: knowledge of `x` with
/// `K("ghost/policy-preimage/v1", x) = y`, bound to every public input of
/// `statement`. Refuses, before any proving, an `x` that does not hash to
/// `y`. `x` is not a public value.
///
/// `zk_randomness` must be 32 fresh bytes from a secure random source.
pub fn prove_know_preimage(
    params: &ChainParams,
    statement: &KnowPreimage,
    x: &[u8; 32],
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    if policy_preimage_hash(x) != statement.y {
        return Err(ProofError::NotThePreimage);
    }
    prove_know_preimage_claiming(params, statement, x, zk_randomness)
}

/// A `KNOW_PREIMAGE_v1` proof claiming `statement` whatever `x` hashes to,
/// with none of the honest prover's checks, for tests of a lying prover.
#[doc(hidden)]
pub fn prove_know_preimage_claiming(
    params: &ChainParams,
    statement: &KnowPreimage,
    x: &[u8; 32],
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    prove_native(
        Statement::KnowPreimage,
        &preimage_assignment(params, statement, x),
        zk_randomness,
    )
}

/// Verify a `KNOW_PREIMAGE_v1` proof against the verifier's own chain
/// constants and the public inputs, binding digest included.
pub fn verify_know_preimage(params: &ChainParams, statement: &KnowPreimage, proof: &Proof) -> Result<(), ProofError> {
    verify_native(Statement::KnowPreimage, &know_preimage_public_values(params, statement), proof)
}

#[cfg(test)]
mod tests {
    use p3_air::{BaseAir, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::air::{F, StatementAir};
    use crate::schedule::execute;

    fn params() -> ChainParams {
        ChainParams {
            chain_id: [0, 0, 0, 0, 0, 0, 0x04, 0xd2],
            version: crate::binding::PROTOCOL_VERSION_1,
            domain: [7; 32],
        }
    }

    const ROOT: [u8; 32] = [0x31; 32];
    const X: [u8; 32] = [0x41; 32];

    fn action() -> KnowAction {
        let salt = [0x32; 32];
        KnowAction {
            policy_address: [0x50; POLICY_ADDRESS_BYTES],
            marker: [0x33; 32],
            action_nonce: 7,
            action_tag: policy_action_tag(&ROOT, &salt),
            action_salt: salt,
            expected_remaining: crate::amount::amount_word(1_000),
            debit: crate::amount::amount_word(10),
            expiry: 900,
            calldata_hash: action_calldata_hash(b"call").unwrap(),
        }
    }

    fn preimage() -> KnowPreimage {
        KnowPreimage {
            policy_address: [0x50; POLICY_ADDRESS_BYTES],
            y: policy_preimage_hash(&X),
            context: [0x42; PREIMAGE_CONTEXT_BYTES],
        }
    }

    /// The trace and public values of an assignment, and whether they meet
    /// every constraint of `statement`.
    fn check(statement: Statement, a: &Assignment, public: &[u8]) -> bool {
        let air = statement.air();
        let trace = air.generate_trace(&execute(&statement.schedule(), a), a);
        let public: Vec<F> = public.iter().map(|&b| F::from_u8(b)).collect();
        check_all_constraints(&air, &trace, &public, Some(1)).is_ok()
    }

    /// Spec 10, sections 8.2 and 9.2: four and three permutations, no
    /// carried column, 128 rows by 3,722 columns.
    #[test]
    fn the_traces_have_the_spec_shape() {
        let cases = [(Statement::KnowAction, 4, 273 + 32), (Statement::KnowPreimage, 3, 161 + 32)];
        for (statement, perms, public) in cases {
            let s = statement.schedule();
            assert_eq!(s.expand().len(), perms, "{statement:?}");
            assert_eq!(s.carried, 0);
            assert_eq!(s.num_public, public);
            let air = statement.air();
            assert_eq!(air.height(), 128);
            assert_eq!(StatementAir::height_for(&s, 1), 128);
            assert_eq!(BaseAir::<F>::width(&air), 3722);
        }
    }

    #[test]
    fn the_honest_traces_satisfy_every_constraint() {
        let (p, s) = (params(), action());
        let a = action_assignment(&p, &s, &ROOT);
        assert!(check(Statement::KnowAction, &a, &a.public));
        let (p, s) = (params(), preimage());
        let a = preimage_assignment(&p, &s, &X);
        assert!(check(Statement::KnowPreimage, &a, &a.public));
    }

    /// A2: another root, or a salt other than the one the tag was made with,
    /// breaks a constraint.
    #[test]
    fn a_wrong_witness_breaks_a_constraint() {
        let p = params();
        let a = action_assignment(&p, &action(), &[0x30; 32]);
        assert!(!check(Statement::KnowAction, &a, &a.public));
        let other_salt = KnowAction {
            action_salt: [0x34; 32],
            ..action()
        };
        let a = action_assignment(&p, &other_salt, &ROOT);
        assert!(!check(Statement::KnowAction, &a, &a.public));
        let a = preimage_assignment(&p, &preimage(), &[0x40; 32]);
        assert!(!check(Statement::KnowPreimage, &a, &a.public));
    }

    /// Every public byte, the binding digest included, is tied to the trace.
    #[test]
    fn every_public_value_is_constrained() {
        let p = params();
        let cases = [
            (Statement::KnowAction, action_assignment(&p, &action(), &ROOT)),
            (Statement::KnowPreimage, preimage_assignment(&p, &preimage(), &X)),
        ];
        for (statement, a) in cases {
            for i in 0..a.public.len() {
                let mut changed = a.public.clone();
                changed[i] ^= 1;
                assert!(!check(statement, &a, &changed), "{statement:?}: public value {i} is not constrained");
            }
        }
    }

    #[test]
    fn the_honest_provers_refuse_a_wrong_witness() {
        let p = params();
        assert_eq!(prove_know_action(&p, &action(), &[0x30; 32], [1; 32]).err(), Some(ProofError::NotThePreimage));
        assert_eq!(prove_know_preimage(&p, &preimage(), &[0x40; 32], [1; 32]).err(), Some(ProofError::NotThePreimage));
    }
}
