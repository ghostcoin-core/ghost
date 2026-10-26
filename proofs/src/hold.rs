//! Statement S3: the proof of holding (spec 02, section 6), and the
//! verifier's challenge book.
//!
//! The proof opens one data commitment under the public data-tree `root`,
//! computes its marker privately, and computes the hold binding digest over
//! the chain, the tree state, the spent-marker-set root, the verifier, the
//! verifier's challenge and the content fingerprint `cf`. It publishes no
//! marker and no value tied to the commitment beyond `cf`, which names the
//! content and not the commitment. The fingerprint hash reads `cf` from the
//! public values, so the proof holds only for the content fingerprint it was
//! made with. What it shows is that the prover holds *some* commitment of the
//! type to that content under that tree state (spec 02, section 6, "What S3
//! shows"): it names no particular commitment, so it is no capability for a
//! particular resource.
//!
//! **Constraint 4, the absence of the marker from the data spent-marker set,
//! is only half in the circuit.** The set is the indexed tree of depth 40 of
//! spec 05, section 6, and the private [`AbsenceWitness`] names its low leaf.
//! The trace opens that leaf under the public `marker_set_root`: the leaf hash
//! `L` and the 40 node hashes `S0..S39` up to the root. The ordering of
//! constraint 4 is not yet in the circuit: no constraint relates the marker
//! `M` to the low leaf, so a proof shows only that *some* leaf is under
//! `marker_set_root`, not that the marker is absent. Because of that gap, the
//! shipped [`verify_hold`] rejects every proof of holding with
//! [`ProofError::HoldUnsettled`].
//!
//! **Not settled: holding of coins** (item 3). A context with `COIN_V2` is
//! rejected by [`HoldContext::check`], by [`hold_binding`] and by the test-only
//! prover and verifier.
//!
//! The statement opens a salted (version 2) data commitment
//! ([`SaltedHoldOpening`]), whose salt is a private witness; the context's
//! type must be `DATA_V2`. It is built and checked only by functions compiled
//! under the `unsettled-points-test` feature, which now covers the proof of
//! holding only, for tests. It settles nothing, and the public verifier
//! rejects regardless of the feature.
//!
//! The hashes, in trace order (79 permutations, 1,896 rows padded to 2,048).
//! `DATA` is the type tag `0x02 0x02`, with the `v2` fingerprint and marker
//! tags:
//!
//! ```text
//! F_d     K(data-fingerprint, s, r, b, salt, DATA, cf, rule)          2 blocks, cf public, rule private
//! C       K(data-commitment, DATA, DATA_RESERVE, F_d)                 1, reserve constant
//! N0..N31 K(data-tree-node, level, left, right)                       32, N31 = root
//! M       K(data-marker, r, b, salt)                                  1, private
//! L       K(data-marker-set-leaf, value, nextValue, nextIndex)        1, private
//! S0..S39 K(data-marker-set-node, level, left, right)                 40, S39 = marker_set_root
//! B       K(hold-binding, fields)                                     2, = binding
//! ```
//!
//! `C` takes the fee reserve `DATA_RESERVE` as a constant amount word, as in
//! S2 (the opening is the same, [`push_data_opening`]): a leaf made with
//! another reserve does not open.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::binding::{Binding, ChainParams, FieldWriter, PURPOSE_HOLD, STATEMENT_HOLD, STATEMENT_VERSION_1, digest};
use crate::data::{CARRIED, DataSecrets, RuleSource, data_marker_hash, push_data_opening};
use crate::hash::{
    COIN_V2, DATA_V2, MARKER_SET_DEPTH, MARKER_SET_INDEX_BYTES, SALT_BYTES, TAG_DATA_MARKER_SET_LEAF,
    TAG_DATA_MARKER_SET_NODE, TAG_HOLD_BINDING, TREE_DEPTH,
};
use crate::schedule::{HashBuilder, Schedule, ScheduleBuilder};
use crate::{Proof, ProofError};

/// What a verifier chose for one proof of holding, and the type proven.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldContext {
    /// The commitment type: `DATA_V2`, a salted data commitment (`COIN_V2`
    /// is not settled).
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
    /// The content fingerprint the verifier asks about (spec 01, section 3).
    pub cf: [u8; 32],
}

impl HoldContext {
    /// Fail closed on the type: `DATA_V2` is accepted, `COIN_V2` is rejected
    /// until holding of coins is settled, and every other type, the version
    /// 1 tags `0x01 0x01` and `0x01 0x02` included, is unknown.
    pub fn check(&self) -> Result<(), ProofError> {
        match self.type_tag {
            DATA_V2 => Ok(()),
            COIN_V2 => Err(ProofError::HoldCoinUnsettled),
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
        .put("cf", &ctx.cf)
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

/// The salted (version 2) data commitment whose holding is proven. Secrets:
/// no `Debug`, no serialization.
pub struct SaltedHoldOpening {
    pub s: [u8; 32],
    pub r: [u8; 32],
    pub b: [u8; 32],
    /// The commitment's salt, as its commit published it. A private witness
    /// of the proof, never a public value.
    pub salt: [u8; SALT_BYTES],
    pub cf: [u8; 32],
    /// The commitment's rule, a private input of S3.
    pub rule: [u8; 32],
    pub position: u32,
    pub path: [[u8; 32]; TREE_DEPTH],
    /// The low leaf of the marker in the data marker-set tree and its path,
    /// a private input of S3.
    pub absence: AbsenceWitness,
}

/// The `absence` witness of spec 02, section 6 and spec 05, section 6: the
/// low leaf `(value, nextValue, nextIndex)` of the marker, its position and
/// its 40 siblings from level 0 up, 1,354 bytes in the spec layout. A private
/// input of S3: no `Debug`, no serialization.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AbsenceWitness {
    pub low_value: [u8; 32],
    pub low_next_value: [u8; 32],
    /// A big-endian position.
    pub low_next_index: [u8; MARKER_SET_INDEX_BYTES],
    /// Position of the low leaf, below 2^40.
    pub position: u64,
    pub siblings: [[u8; 32]; MARKER_SET_DEPTH],
}

impl AbsenceWitness {
    /// The hash of the low leaf.
    pub fn leaf(&self) -> [u8; 32] {
        crate::hash::marker_set_leaf(&self.low_value, &self.low_next_value, &self.low_next_index)
    }

    /// The marker-set root the low leaf's path gives, or `None` for a
    /// position at or above 2^40.
    pub fn root(&self) -> Option<[u8; 32]> {
        (self.position >> MARKER_SET_DEPTH == 0)
            .then(|| crate::hash::marker_set_root(&self.leaf(), self.position, &self.siblings))
    }
}

impl SaltedHoldOpening {
    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    fn secrets(&self) -> DataSecrets<'_> {
        DataSecrets {
            s: &self.s,
            r: &self.r,
            b: &self.b,
            salt: &self.salt,
            cf: &self.cf,
            rule: Some(&self.rule),
            position: self.position,
            path: &self.path,
        }
    }
}

/// The schedule of S3 and, with a witness, the free bytes and direction bits.
fn schedule_with(
    w: Option<&DataSecrets<'_>>,
    absence: Option<&AbsenceWitness>,
) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::Hold;
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let mut sb = ScheduleBuilder::new();
    push_data_opening(&mut sb, w, RuleSource::Private, off("cf"), off("root"));
    // Constraint 3: the marker of the opened commitment, kept private. With
    // the ordering of constraint 4 not in the circuit, nothing reads it yet.
    sb.push(data_marker_hash());
    // Constraint 4, the membership half: the low leaf, as free bytes, and its
    // 40 nodes up to the public `marker_set_root`, the direction bits from
    // the low leaf's position.
    sb.push(
        HashBuilder::new(TAG_DATA_MARKER_SET_LEAF)
            .free(32, absence.map(|a| &a.low_value[..]))
            .free(32, absence.map(|a| &a.low_next_value[..]))
            .free(MARKER_SET_INDEX_BYTES, absence.map(|a| &a.low_next_index[..])),
    );
    for level in 0..MARKER_SET_DEPTH {
        let mut node = HashBuilder::new(TAG_DATA_MARKER_SET_NODE)
            .constant(&[level as u8])
            .node(absence.map(|a| (&a.siblings[level], a.position >> level & 1 == 1)));
        if level + 1 == MARKER_SET_DEPTH {
            node = node.output(off("marker_set_root"));
        }
        sb.push(node);
    }
    sb.push(HashBuilder::new(TAG_HOLD_BINDING).public(0, fields_len).output(fields_len));
    let consts = vec![
        (off("statement"), STATEMENT_HOLD),
        (off("statement_version"), STATEMENT_VERSION_1),
        (off("type"), DATA_V2[0]),
        (off("type") + 1, DATA_V2[1]),
        (off("purpose"), PURPOSE_HOLD),
    ];
    sb.finish(fields_len + 32, CARRIED, None, consts)
}

/// The schedule of S3, without any witness.
pub(crate) fn schedule() -> Schedule {
    schedule_with(None, None).0
}

/// The shipped verifier of a proof of holding. The trace opens the low leaf
/// of the absence witness under `marker_set_root`, but the ordering of
/// constraint 4 is not yet in the circuit, so nothing shows the marker is
/// absent: it rejects every input with [`ProofError::HoldUnsettled`].
pub fn verify_hold(params: &ChainParams, ctx: &HoldContext, proof: &Proof) -> Result<(), ProofError> {
    let _ = (params, ctx, proof);
    Err(ProofError::HoldUnsettled)
}

/// The proof for whatever the witness and the context give, without the
/// tree check. Refuses only a context [`HoldContext::check`] rejects.
#[cfg(feature = "unsettled-points-test")]
fn prove_unchecked(
    params: &ChainParams,
    w: &DataSecrets<'_>,
    absence: &AbsenceWitness,
    ctx: &HoldContext,
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    use crate::schedule::Assignment;

    let public = public_values(params, ctx)?;
    let (_, free, dirs) = schedule_with(Some(w), Some(absence));
    let assignment = Assignment {
        public,
        carried: w.carried_values(),
        free,
        dirs,
    };
    crate::stark::prove(crate::stark::Statement::SaltedHold, &assignment, zk_randomness).map(Proof)
}

/// Prove holding of a salted (version 2) commitment, for tests only. The
/// context's type must be `DATA_V2`. The salt is a private witness: neither
/// the public values nor the proof hold it. Rejects what
/// [`HoldContext::check`] rejects, a context whose `cf` is not the opening's,
/// a commitment that is not the leaf at `position` under `root` (a wrong salt
/// makes another commitment, which is not the leaf under `root`), and an
/// absence witness whose low leaf is not under `marker_set_root`
/// ([`ProofError::NotInMarkerSet`]).
#[cfg(feature = "unsettled-points-test")]
pub fn prove_salted_hold(
    params: &ChainParams,
    opening: &SaltedHoldOpening,
    ctx: &HoldContext,
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    use crate::hash::{Tree, merkle_root};

    let w = opening.secrets();
    ctx.check()?;
    if *w.cf != ctx.cf {
        return Err(ProofError::WrongContentFingerprint);
    }
    let rule = w.rule.expect("a private rule");
    if merkle_root(Tree::Data, &w.commitment(rule), w.position, w.path) != ctx.root {
        return Err(ProofError::NotInTree);
    }
    if opening.absence.root() != Some(ctx.marker_set_root) {
        return Err(ProofError::NotInMarkerSet);
    }
    prove_unchecked(params, &w, &opening.absence, ctx, zk_randomness)
}

/// A salted proof of holding for `ctx`, whatever the opening says, without
/// the honest prover's tree and marker-set checks, so tests can show the
/// verifier catches a lie (another salt, another sibling, say). For tests
/// only.
#[cfg(feature = "unsettled-points-test")]
#[doc(hidden)]
pub fn prove_salted_hold_claiming(
    params: &ChainParams,
    opening: &SaltedHoldOpening,
    ctx: &HoldContext,
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    prove_unchecked(params, &opening.secrets(), &opening.absence, ctx, zk_randomness)
}

/// The absence witness of `absent` in the data marker-set tree built from
/// the genesis set by inserting `markers` in order (spec 05, section 6,
/// "Insert"), and that set's root, so tests prove against real sets. Panics
/// on a zero marker, a marker inserted twice, or an `absent` that is in the
/// set. For tests only.
#[cfg(feature = "unsettled-points-test")]
pub fn test_absence_witness(markers: &[[u8; 32]], absent: &[u8; 32]) -> (AbsenceWitness, [u8; 32]) {
    use crate::hash::{empty_leaf, marker_set_leaf, marker_set_node};

    // The used leaves as (value, nextValue, nextIndex), the sentinel at 0.
    let mut leaves: Vec<([u8; 32], [u8; 32], u64)> = vec![([0; 32], [0; 32], 0)];
    let fresh = |leaves: &[([u8; 32], [u8; 32], u64)], m: &[u8; 32]| {
        *m != [0; 32] && leaves.iter().all(|(value, _, _)| value != m)
    };
    // Byte arrays compare as big-endian integers.
    let low_of = |leaves: &[([u8; 32], [u8; 32], u64)], m: &[u8; 32]| {
        leaves
            .iter()
            .position(|(value, next, _)| value < m && (m < next || *next == [0; 32]))
            .expect("exactly one low leaf")
    };
    for m in markers {
        assert!(fresh(&leaves, m), "a marker is non-zero and inserted once");
        let low = low_of(&leaves, m);
        let n = leaves.len() as u64;
        let (_, next, next_index) = leaves[low];
        leaves.push((*m, next, next_index));
        leaves[low].1 = *m;
        leaves[low].2 = n;
    }
    assert!(fresh(&leaves, absent), "the marker is non-zero and not in the set");
    let low = low_of(&leaves, absent);
    let index = |i: u64| -> [u8; MARKER_SET_INDEX_BYTES] {
        i.to_be_bytes()[8 - MARKER_SET_INDEX_BYTES..].try_into().expect("5 bytes")
    };

    let mut nodes: Vec<[u8; 32]> = leaves
        .iter()
        .map(|(value, next, next_index)| marker_set_leaf(value, next, &index(*next_index)))
        .collect();
    let mut empty = empty_leaf();
    let mut siblings = [[0u8; 32]; MARKER_SET_DEPTH];
    let mut at = low;
    for (level, sibling) in siblings.iter_mut().enumerate() {
        *sibling = nodes.get(at ^ 1).copied().unwrap_or(empty);
        nodes = nodes
            .chunks(2)
            .map(|pair| marker_set_node(level as u8, &pair[0], pair.get(1).unwrap_or(&empty)))
            .collect();
        empty = marker_set_node(level as u8, &empty, &empty);
        at >>= 1;
    }
    let root = nodes[0];
    let (value, next, next_index) = leaves[low];
    let witness = AbsenceWitness {
        low_value: value,
        low_next_value: next,
        low_next_index: index(next_index),
        position: low as u64,
        siblings,
    };
    assert_eq!(witness.root(), Some(root));
    (witness, root)
}

/// Verify the statement S3 as the circuit has it, the low leaf under
/// `marker_set_root` included but without the ordering of constraint 4, for
/// tests only. Rejects what [`HoldContext::check`] rejects.
#[cfg(feature = "unsettled-points-test")]
pub fn verify_hold_unsettled(params: &ChainParams, ctx: &HoldContext, proof: &Proof) -> Result<(), ProofError> {
    let public = public_values(params, ctx)?;
    crate::stark::verify(crate::stark::Statement::SaltedHold, &public, proof.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::Seg;

    /// The 38 permutations of the opening, the marker and the binding, plus
    /// the low leaf and its 40 nodes: 79 permutations, 1,896 rows padded to
    /// 2,048, the last node's digest the public `marker_set_root`.
    #[test]
    fn schedule_has_79_permutations() {
        let schedule = schedule();
        assert_eq!(schedule.expand().len(), 79);
        assert_eq!(schedule.expand().len() * p3_keccak_air::NUM_ROUNDS, 1896);
        assert_eq!(crate::air::StatementAir::height_for(&schedule, 0), 2048);

        // F_d, C, N0..N31, M, then L at 35, S0..S39 at 36..76, B at 76.
        assert_eq!(schedule.hashes.len(), 77);
        let leaf = &schedule.hashes[35];
        assert_eq!(leaf.segs[0], Seg::Const(crate::hash::tag_bytes(TAG_DATA_MARKER_SET_LEAF)));
        assert_eq!(leaf.segs[1..], [Seg::Free(32), Seg::Free(32), Seg::Free(MARKER_SET_INDEX_BYTES)]);
        assert_eq!(leaf.output, None);
        for level in 0..MARKER_SET_DEPTH {
            let node = &schedule.hashes[36 + level];
            assert_eq!(
                node.segs,
                [
                    Seg::Const(crate::hash::tag_bytes(TAG_DATA_MARKER_SET_NODE)),
                    Seg::Const(vec![level as u8]),
                    Seg::Node
                ]
            );
            let root = (level + 1 == MARKER_SET_DEPTH).then(|| Binding::Hold.offset("marker_set_root"));
            assert_eq!(node.output, root, "level {level}");
        }
        assert_eq!(Binding::Hold.offset("marker_set_root"), 79);

        // The data-tree nodes have their pair at offset 25, the marker-set
        // nodes at 31: the AIR checks both, each under its own selector.
        let node_offsets: Vec<Option<usize>> = schedule.expand().iter().map(|perm| perm.node_at).collect();
        assert_eq!(node_offsets.iter().filter(|&&at| at == Some(25)).count(), TREE_DEPTH);
        assert_eq!(node_offsets.iter().filter(|&&at| at == Some(31)).count(), MARKER_SET_DEPTH);
        assert_eq!(node_offsets.iter().flatten().count(), TREE_DEPTH + MARKER_SET_DEPTH);
        assert_eq!(schedule.hashes[76].segs[0], Seg::Const(crate::hash::tag_bytes(TAG_HOLD_BINDING)));
    }
}
