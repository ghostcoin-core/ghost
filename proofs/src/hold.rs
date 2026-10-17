//! Statement S3: the proof of holding (spec 02, section 6), and the
//! verifier's challenge book.
//!
//! The proof opens one data commitment under the public data-tree `root`,
//! computes its marker privately, and computes the hold binding digest over
//! the chain, the tree state, the spent-marker-set root, the verifier and the
//! verifier's challenge. It publishes no marker and no value tied to the
//! commitment. What it shows is only that the prover holds *some* commitment
//! of the type under that tree state (spec 02, section 6, "What S3 shows"): it
//! names no particular commitment or content, so it is no capability for a
//! particular resource.
//!
//! **Not implemented: constraint 4, the absence of the marker from the
//! spent-marker set.** The set's structure and its header root are not
//! settled (spec 02, section 13, item 2), so there is nothing defined to check
//! the marker against. The marker is computed in the proof from the `r` and
//! `b` that open the commitment, and `marker_set_root` is bound through the
//! digest, but no constraint relates the two. Because of that gap, the shipped
//! [`verify_hold`] rejects every proof of holding with
//! [`ProofError::HoldUnsettled`].
//!
//! **Not settled: holding of coins** (item 3). A context with `COIN` is
//! rejected by [`HoldContext::check`], by [`hold_binding`] and by the test-only
//! prover and verifier.
//!
//! The statement is built and checked only by functions compiled under the
//! `unsettled-points-test` feature, for tests. They settle nothing, and the
//! public verifier rejects regardless of the feature.
//!
//! The hashes, in trace order (38 permutations):
//!
//! ```text
//! F_d     K(data-fingerprint, s, r, b, DATA, cf, rule)  2 blocks, rule private
//! C       K(data-commitment, DATA, F_d)                 1
//! N0..N31 K(data-tree-node, level, left, right)         32, N31 = root
//! M       K(data-marker, r, b)                          1, private
//! B       K(hold-binding, fields)                       2, = binding
//! ```

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::binding::{Binding, ChainParams, FieldWriter, PURPOSE_HOLD, STATEMENT_HOLD, STATEMENT_VERSION_1, digest};
use crate::data::{CARRIED, DataSecrets, RuleSource, data_marker_hash, push_data_opening};
use crate::hash::{COIN, DATA, TAG_HOLD_BINDING, TREE_DEPTH};
use crate::schedule::{HashBuilder, Schedule, ScheduleBuilder};
use crate::{Proof, ProofError};

/// What a verifier chose for one proof of holding, and the type proven.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldContext {
    /// The commitment type: `DATA` (`COIN` is not settled).
    pub type_tag: [u8; 2],
    /// The shared epoch root of the tree of the type, from a trusted header.
    pub root: [u8; 32],
    /// The spent-marker-set root of the type, from a header accepted as
    /// current.
    pub marker_set_root: [u8; 32],
    /// The verifier's own identity.
    pub verifier: [u8; 32],
    /// The verifier's fresh challenge, issued once.
    pub challenge: [u8; 32],
}

impl HoldContext {
    /// Fail closed on the type: an unknown type is rejected, and so is `COIN`
    /// until holding of coins is settled.
    pub fn check(&self) -> Result<(), ProofError> {
        match self.type_tag {
            DATA => Ok(()),
            COIN => Err(ProofError::HoldCoinUnsettled),
            _ => Err(ProofError::UnknownType),
        }
    }
}

fn fields(params: &ChainParams, ctx: &HoldContext) -> Vec<u8> {
    FieldWriter::new(Binding::Hold, params, STATEMENT_HOLD, ctx.type_tag, PURPOSE_HOLD)
        .put("root", &ctx.root)
        .put("marker_set_root", &ctx.marker_set_root)
        .put("verifier", &ctx.verifier)
        .put("challenge", &ctx.challenge)
        .finish()
}

/// The hold binding digest, from the verifier's own chain constants and its
/// choices. Rejects what [`HoldContext::check`] rejects.
pub fn hold_binding(params: &ChainParams, ctx: &HoldContext) -> Result<[u8; 32], ProofError> {
    ctx.check()?;
    Ok(digest(Binding::Hold, &fields(params, ctx)))
}

#[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
fn public_values(params: &ChainParams, ctx: &HoldContext) -> Result<Vec<u8>, ProofError> {
    let binding = hold_binding(params, ctx)?;
    let mut public = fields(params, ctx);
    public.extend_from_slice(&binding);
    Ok(public)
}

/// The data commitment whose holding is proven. Secrets: no `Debug`, no
/// serialization.
pub struct HoldOpening {
    pub s: [u8; 32],
    pub r: [u8; 32],
    pub b: [u8; 32],
    pub cf: [u8; 32],
    /// The commitment's rule, a private input of S3.
    pub rule: [u8; 32],
    pub position: u32,
    pub path: [[u8; 32]; TREE_DEPTH],
}

/// The schedule of S3 for `DATA` and, with a witness, the free bytes and
/// direction bits.
pub(crate) fn schedule(w: Option<&HoldOpening>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::Hold;
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let secrets = w.map(|o| DataSecrets {
        s: &o.s,
        cf: &o.cf,
        rule: Some(&o.rule),
        position: o.position,
        path: &o.path,
    });
    let mut sb = ScheduleBuilder::new();
    push_data_opening(&mut sb, secrets.as_ref(), RuleSource::Private, off("root"));
    // Constraint 3: the marker of the opened commitment, kept private. With
    // constraint 4 not implemented, nothing reads it yet.
    sb.push(data_marker_hash());
    sb.push(HashBuilder::new(TAG_HOLD_BINDING).public(0, fields_len).output(fields_len));
    let consts = vec![
        (off("statement"), STATEMENT_HOLD),
        (off("statement_version"), STATEMENT_VERSION_1),
        (off("type"), DATA[0]),
        (off("type") + 1, DATA[1]),
        (off("purpose"), PURPOSE_HOLD),
    ];
    sb.finish(fields_len + 32, CARRIED, None, consts)
}

/// The shipped verifier of a proof of holding. The spent-marker-set
/// structure and its header root are not settled (spec 02, section 13, item
/// 2), so it rejects every input with [`ProofError::HoldUnsettled`].
pub fn verify_hold(params: &ChainParams, ctx: &HoldContext, proof: &Proof) -> Result<(), ProofError> {
    let _ = (params, ctx, proof);
    Err(ProofError::HoldUnsettled)
}

/// Prove holding, for tests only. Rejects what [`HoldContext::check`]
/// rejects, and a commitment that is not the leaf at `position` under `root`.
#[cfg(feature = "unsettled-points-test")]
pub fn prove_hold(
    params: &ChainParams,
    opening: &HoldOpening,
    ctx: &HoldContext,
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    use crate::hash::{Tree, data_commitment, data_fingerprint, merkle_root};
    use crate::schedule::Assignment;
    use crate::stark::{self, Statement};

    let public = public_values(params, ctx)?;
    let leaf = data_commitment(&data_fingerprint(&opening.s, &opening.r, &opening.b, &opening.cf, &opening.rule));
    if merkle_root(Tree::Data, &leaf, opening.position, &opening.path) != ctx.root {
        return Err(ProofError::NotInTree);
    }
    let (_, free, dirs) = schedule(Some(opening));
    let assignment = Assignment {
        public,
        carried: crate::data::carried_values(&opening.r, &opening.b),
        free,
        dirs,
    };
    stark::prove(Statement::Hold, &assignment, zk_randomness).map(Proof)
}

/// Verify the statement S3 as written, without the absence check, for tests
/// only. Rejects what [`HoldContext::check`] rejects.
#[cfg(feature = "unsettled-points-test")]
pub fn verify_hold_unsettled(params: &ChainParams, ctx: &HoldContext, proof: &Proof) -> Result<(), ProofError> {
    use crate::stark::{self, Statement};

    let public = public_values(params, ctx)?;
    stark::verify(Statement::Hold, &public, proof.as_bytes())
}

/// [`verify_hold_unsettled`] with the challenge redeemed from the verifier's
/// book: the challenge must be one the book issued, unused and unexpired, and
/// it is used up only by a proof that verifies. For tests only.
#[cfg(feature = "unsettled-points-test")]
pub fn verify_hold_unsettled_with_book(
    params: &ChainParams,
    book: &mut ChallengeBook,
    ctx: &HoldContext,
    proof: &Proof,
    now: u64,
) -> Result<(), ProofError> {
    book.check(&ctx.challenge, now)?;
    verify_hold_unsettled(params, ctx, proof)?;
    book.accept(&ctx.challenge, now)
}

/// A verifier's record of the challenges it issued (PS-16). Each challenge
/// is accepted once, before it expires; a challenge it never issued, one
/// already accepted and an expired one are rejected.
///
/// The challenge is the 32 random bytes the caller supplies, which must come
/// from a secure random source; time is whatever monotonic clock the caller
/// counts in. The book reads neither the operating system's random source nor
/// its clock.
#[derive(Clone, Debug)]
pub struct ChallengeBook {
    lifetime: u64,
    entries: BTreeMap<[u8; 32], Entry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    expires: u64,
    used: bool,
}

impl ChallengeBook {
    /// A book whose challenges live for `lifetime` units of the caller's
    /// clock.
    pub fn new(lifetime: u64) -> Self {
        Self {
            lifetime,
            entries: BTreeMap::new(),
        }
    }

    /// Issue `random` as a challenge at time `now`. A value still in the book
    /// is refused, so no challenge is ever live twice.
    pub fn issue(&mut self, random: [u8; 32], now: u64) -> Result<[u8; 32], ProofError> {
        self.prune(now);
        if self.entries.contains_key(&random) {
            return Err(ProofError::ChallengeAlreadyIssued);
        }
        self.entries.insert(
            random,
            Entry {
                expires: now.saturating_add(self.lifetime),
                used: false,
            },
        );
        Ok(random)
    }

    /// Whether `challenge` would be accepted at `now`, without using it.
    pub fn check(&self, challenge: &[u8; 32], now: u64) -> Result<(), ProofError> {
        match self.entries.get(challenge) {
            None => Err(ProofError::ChallengeUnknown),
            Some(entry) if entry.used => Err(ProofError::ChallengeUsed),
            Some(entry) if now >= entry.expires => Err(ProofError::ChallengeExpired),
            Some(_) => Ok(()),
        }
    }

    /// Accept `challenge` at `now`: once, and only before it expires.
    pub fn accept(&mut self, challenge: &[u8; 32], now: u64) -> Result<(), ProofError> {
        self.check(challenge, now)?;
        if let Some(entry) = self.entries.get_mut(challenge) {
            entry.used = true;
        }
        Ok(())
    }

    /// Forget the challenges that expired before `now`; an expired value is
    /// rejected either way.
    pub fn prune(&mut self, now: u64) {
        self.entries.retain(|_, entry| now < entry.expires);
    }
}
