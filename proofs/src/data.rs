//! Statement S2: the one-time reveal of data, with the reveal or the revoke
//! purpose (spec 02, section 5).
//!
//! The proof opens one data commitment under the public data-tree `root`,
//! publishes its marker `K("ghost/data-marker/v1", r, b)` and computes the
//! data reveal binding digest, purpose included, so a reveal cannot pass as a
//! revocation or the other way round. It mints nothing and has no amounts.
//!
//! **Not settled: the fee of a data reveal** (spec 02, section 13, item 1).
//! No constraint ties `fee` to anything inside a data commitment, because a
//! data commitment holds no value. So the public [`verify_data_reveal`]
//! rejects every data reveal with [`ProofError::DataFeeUnsettled`]. The
//! statement itself is built and checked only by the functions compiled under
//! the `unsettled-points-test` feature, for tests; they do not settle the
//! point and the public verifier rejects regardless of the feature.
//!
//! The hashes, in trace order (38 permutations):
//!
//! ```text
//! F_d     K(data-fingerprint, s, r, b, DATA, cf, rule)  2 blocks
//! C       K(data-commitment, DATA, F_d)                 1
//! N0..N31 K(data-tree-node, level, left, right)         32, N31 = root
//! M       K(data-marker, r, b)                          1, = marker
//! B       K(data-reveal-binding, fields)                2, = binding
//! ```

use alloc::vec;
use alloc::vec::Vec;

use crate::binding::{
    Binding, ChainParams, FieldWriter, PURPOSE_REVEAL, PURPOSE_REVOKE, STATEMENT_DATA_REVEAL, STATEMENT_VERSION_1,
    digest,
};
use crate::hash::{
    DATA, TAG_DATA_COMMITMENT, TAG_DATA_FINGERPRINT, TAG_DATA_MARKER, TAG_DATA_REVEAL_BINDING, TAG_DATA_TREE_NODE,
    TREE_DEPTH,
};
use crate::schedule::{HashBuilder, Schedule, ScheduleBuilder};
use crate::{Proof, ProofError};

// Carried columns, shared with S3.
pub(crate) const R: usize = 0;
pub(crate) const B: usize = 32;
pub(crate) const CARRIED: usize = 64;

/// The purpose of a data reveal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataPurpose {
    /// `0x02`: reveal the data to a party.
    Reveal,
    /// `0x03`: revoke the commitment.
    Revoke,
}

impl DataPurpose {
    pub const fn code(self) -> u8 {
        match self {
            Self::Reveal => PURPOSE_REVEAL,
            Self::Revoke => PURPOSE_REVOKE,
        }
    }

    /// The purpose of a code; every code other than `0x02` and `0x03` is
    /// rejected.
    pub const fn from_code(code: u8) -> Result<Self, ProofError> {
        match code {
            PURPOSE_REVEAL => Ok(Self::Reveal),
            PURPOSE_REVOKE => Ok(Self::Revoke),
            _ => Err(ProofError::UnknownPurpose),
        }
    }
}

/// The data commitment being revealed. Secrets: no `Debug`, no serialization.
pub struct DataOpening {
    pub s: [u8; 32],
    pub r: [u8; 32],
    pub b: [u8; 32],
    /// The content fingerprint.
    pub cf: [u8; 32],
    /// Position of `C` in the data tree.
    pub position: u32,
    /// The 32 sibling hashes from `C` to the root.
    pub path: [[u8; 32]; TREE_DEPTH],
}

/// The public fields of a data reveal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataReveal {
    pub purpose: DataPurpose,
    pub root: [u8; 32],
    pub marker: [u8; 32],
    /// The verifier or recipient the ticket is for, or zero for none.
    pub party: [u8; 32],
    pub fee: [u8; 32],
    pub rule: [u8; 32],
}

fn fields(params: &ChainParams, tx: &DataReveal) -> Vec<u8> {
    FieldWriter::new(Binding::DataReveal, params, STATEMENT_DATA_REVEAL, DATA, tx.purpose.code())
        .put("root", &tx.root)
        .put("marker", &tx.marker)
        .put("party", &tx.party)
        .put("fee", &tx.fee)
        .put("rule", &tx.rule)
        .finish()
}

/// The data reveal binding digest, from the verifier's own chain constants
/// and the transaction's fields.
pub fn data_reveal_binding(params: &ChainParams, tx: &DataReveal) -> [u8; 32] {
    digest(Binding::DataReveal, &fields(params, tx))
}

#[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
fn public_values(params: &ChainParams, tx: &DataReveal) -> Vec<u8> {
    let mut public = fields(params, tx);
    let binding = digest(Binding::DataReveal, &public);
    public.extend_from_slice(&binding);
    public
}

/// The secret side of a data opening, as the schedule reads it.
pub(crate) struct DataSecrets<'a> {
    pub s: &'a [u8; 32],
    pub cf: &'a [u8; 32],
    /// `Some` when the rule is private (S3); S2 reads the public rule.
    pub rule: Option<&'a [u8; 32]>,
    pub position: u32,
    pub path: &'a [[u8; 32]; TREE_DEPTH],
}

/// Where the rule of a data fingerprint comes from.
#[derive(Clone, Copy)]
pub(crate) enum RuleSource {
    /// A public field at this offset (S2).
    Public(usize),
    /// A private input (S3).
    Private,
}

/// Open a data commitment and climb to the root: `F_d`, `C`, 32 nodes. The
/// last node's digest must equal the public bytes at `root`.
pub(crate) fn push_data_opening(
    sb: &mut ScheduleBuilder,
    w: Option<&DataSecrets<'_>>,
    rule: RuleSource,
    root: usize,
) {
    let fingerprint = HashBuilder::new(TAG_DATA_FINGERPRINT)
        .free(32, w.map(|w| &w.s[..]))
        .carried(R, 32)
        .carried(B, 32)
        .constant(&DATA)
        .free(32, w.map(|w| &w.cf[..]));
    let fingerprint = match rule {
        RuleSource::Public(offset) => fingerprint.public(offset, 32),
        RuleSource::Private => fingerprint.free(32, w.map(|w| &w.rule.expect("a private rule")[..])),
    };
    sb.push(fingerprint);
    sb.push(HashBuilder::new(TAG_DATA_COMMITMENT).constant(&DATA).prev());
    for level in 0..TREE_DEPTH {
        let mut node = HashBuilder::new(TAG_DATA_TREE_NODE)
            .constant(&[level as u8])
            .node(w.map(|w| (&w.path[level], w.position >> level & 1 == 1)));
        if level + 1 == TREE_DEPTH {
            node = node.output(root);
        }
        sb.push(node);
    }
}

/// The marker hash of a data commitment from the carried `r` and `b`.
pub(crate) fn data_marker_hash() -> HashBuilder {
    HashBuilder::new(TAG_DATA_MARKER).carried(R, 32).carried(B, 32)
}

/// The carried columns of a data statement: the bytes of `r` and `b`.
#[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
pub(crate) fn carried_values(r: &[u8; 32], b: &[u8; 32]) -> Vec<u32> {
    let mut carried = vec![0u32; CARRIED];
    for k in 0..32 {
        carried[R + k] = u32::from(r[k]);
        carried[B + k] = u32::from(b[k]);
    }
    carried
}

/// The schedule of S2 and, with a witness, the free bytes and direction bits.
pub(crate) fn schedule(w: Option<&DataOpening>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::DataReveal;
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let secrets = w.map(|o| DataSecrets {
        s: &o.s,
        cf: &o.cf,
        rule: None,
        position: o.position,
        path: &o.path,
    });
    let mut sb = ScheduleBuilder::new();
    push_data_opening(&mut sb, secrets.as_ref(), RuleSource::Public(off("rule")), off("root"));
    sb.push(data_marker_hash().output(off("marker")));
    sb.push(
        HashBuilder::new(TAG_DATA_REVEAL_BINDING)
            .public(0, fields_len)
            .output(fields_len),
    );
    let mut consts = vec![
        (off("statement"), STATEMENT_DATA_REVEAL),
        (off("statement_version"), STATEMENT_VERSION_1),
        (off("type"), DATA[0]),
        (off("type") + 1, DATA[1]),
    ];
    for t in 0..32 {
        consts.push((off("rule") + t, 0));
    }
    sb.finish(fields_len + 32, CARRIED, None, consts)
}

/// The shipped verifier of a data reveal. The fee of a data reveal is not
/// settled (spec 02, section 13, item 1), so it rejects every data reveal
/// with [`ProofError::DataFeeUnsettled`], whatever the proof.
pub fn verify_data_reveal(params: &ChainParams, tx: &DataReveal, proof: &Proof) -> Result<(), ProofError> {
    let _ = (params, tx, proof);
    Err(ProofError::DataFeeUnsettled)
}

/// What the wallet chooses for a data reveal.
#[cfg(feature = "unsettled-points-test")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataRevealRequest {
    pub purpose: DataPurpose,
    pub root: [u8; 32],
    pub party: [u8; 32],
    pub fee: [u8; 32],
    pub rule: [u8; 32],
}

/// Prove S2, for tests only. Refuses a non-empty rule and a commitment that is
/// not the leaf at `position` under `root`.
#[cfg(feature = "unsettled-points-test")]
pub fn prove_data_reveal(
    params: &ChainParams,
    opening: &DataOpening,
    request: &DataRevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(DataReveal, Proof), ProofError> {
    use crate::hash::{EMPTY_RULE, Tree, data_commitment, data_fingerprint, data_marker, merkle_root};
    use crate::schedule::Assignment;
    use crate::stark::{self, Statement};

    if request.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    let leaf = data_commitment(&data_fingerprint(&opening.s, &opening.r, &opening.b, &opening.cf, &request.rule));
    if merkle_root(Tree::Data, &leaf, opening.position, &opening.path) != request.root {
        return Err(ProofError::NotInTree);
    }
    let tx = DataReveal {
        purpose: request.purpose,
        root: request.root,
        marker: data_marker(&opening.r, &opening.b),
        party: request.party,
        fee: request.fee,
        rule: request.rule,
    };
    let (_, free, dirs) = schedule(Some(opening));
    let assignment = Assignment {
        public: public_values(params, &tx),
        carried: carried_values(&opening.r, &opening.b),
        free,
        dirs,
    };
    let proof = stark::prove(Statement::DataReveal, &assignment, zk_randomness).map(Proof)?;
    Ok((tx, proof))
}

/// Verify S2 without the fee step, for tests only. Rejects a non-empty rule
/// before the proof.
#[cfg(feature = "unsettled-points-test")]
pub fn verify_data_reveal_unsettled(params: &ChainParams, tx: &DataReveal, proof: &Proof) -> Result<(), ProofError> {
    use crate::hash::EMPTY_RULE;
    use crate::stark::{self, Statement};

    if tx.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    stark::verify(Statement::DataReveal, &public_values(params, tx), proof.as_bytes())
}
