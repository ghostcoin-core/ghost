//! Statement S2: the one-time reveal of data, with the reveal or the revoke
//! purpose (spec 02, section 5).
//!
//! The proof opens one salted (version 2) data commitment under the public
//! data-tree `root`, publishes its marker and computes the data reveal binding
//! digest, purpose included, so a reveal cannot pass as a revocation or the
//! other way round. It mints nothing and has no amounts. The binding's `type`
//! field is `DATA_V2`, and the salt is a private witness: no public value
//! holds it.
//!
//! The content fingerprint `cf` of the commitment (spec 01, section 3) is a
//! public field: the fingerprint hash reads it from the public values, so the
//! commitment's own `cf` must equal it and a reveal claiming another `cf`
//! fails. Anyone holding the revealed bytes computes
//! `K(content-fingerprint, length, content)` and compares it with `cf`.
//!
//! **Not settled: the fee of a data reveal** (spec 02, section 13, item 1).
//! No constraint ties `fee` to anything inside a data commitment, because a
//! data commitment holds no value. So the public [`verify_salted_data_reveal`]
//! rejects every data reveal with [`ProofError::DataFeeUnsettled`]. The
//! statement itself is built and checked only by the functions compiled under
//! the `unsettled-points-test` feature, for tests; they do not settle the
//! point and the public verifier rejects regardless of the feature.
//!
//! The hashes, in trace order (38 permutations). `DATA` is the type tag
//! `0x02 0x02`, with the `v2` fingerprint and marker tags:
//!
//! ```text
//! F_d     K(data-fingerprint, s, r, b, salt, DATA, cf, rule)  2 blocks, cf public
//! C       K(data-commitment, DATA, F_d)                       1
//! N0..N31 K(data-tree-node, level, left, right)               32, N31 = root
//! M       K(data-marker, r, b, salt)                          1, = marker
//! B       K(data-reveal-binding, fields)                      2, = binding
//! ```
//!
//! `r`, `b` and the salt are carried columns read by both `F_d` and `M`, so
//! the marker is the one of the commitment opened.

use alloc::vec;
use alloc::vec::Vec;

use crate::binding::{
    Binding, ChainParams, FieldWriter, PURPOSE_REVEAL, PURPOSE_REVOKE, STATEMENT_DATA_REVEAL, STATEMENT_VERSION_1,
    digest,
};
use crate::hash::{
    DATA_V2, SALT_BYTES, TAG_DATA_COMMITMENT, TAG_DATA_FINGERPRINT_V2, TAG_DATA_MARKER_V2, TAG_DATA_REVEAL_BINDING,
    TAG_DATA_TREE_NODE, TREE_DEPTH,
};
use crate::schedule::{HashBuilder, Schedule, ScheduleBuilder};
#[cfg(feature = "unsettled-points-test")]
use crate::stark::Statement;
use crate::{Proof, ProofError};

// Carried columns, shared with S3: `r`, `b` and the salt.
pub(crate) const R: usize = 0;
pub(crate) const B: usize = 32;
pub(crate) const SALT: usize = 64;
/// Number of carried columns.
pub(crate) const CARRIED: usize = SALT + SALT_BYTES;

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

/// The salted (version 2) data commitment being revealed. Secrets: no
/// `Debug`, no serialization.
pub struct SaltedDataOpening {
    pub s: [u8; 32],
    pub r: [u8; 32],
    pub b: [u8; 32],
    /// The commitment's salt, as its commit published it. A private witness
    /// of the proof, never a public value.
    pub salt: [u8; SALT_BYTES],
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
    /// The content fingerprint of the commitment revealed (spec 01, section
    /// 3), which the revealed bytes are checked against.
    pub cf: [u8; 32],
}

fn fields(params: &ChainParams, tx: &DataReveal) -> Vec<u8> {
    FieldWriter::new(Binding::DataReveal, params, STATEMENT_DATA_REVEAL, DATA_V2, tx.purpose.code())
        .put("root", &tx.root)
        .put("marker", &tx.marker)
        .put("party", &tx.party)
        .put("fee", &tx.fee)
        .put("rule", &tx.rule)
        .put("cf", &tx.cf)
        .finish()
}

/// The data reveal binding digest of a salted (version 2) reveal, from the
/// verifier's own chain constants and the transaction's fields.
pub fn salted_data_reveal_binding(params: &ChainParams, tx: &DataReveal) -> [u8; 32] {
    digest(Binding::DataReveal, &fields(params, tx))
}

#[cfg(feature = "unsettled-points-test")]
fn public_values(params: &ChainParams, tx: &DataReveal) -> Vec<u8> {
    let mut public = fields(params, tx);
    let binding = digest(Binding::DataReveal, &public);
    public.extend_from_slice(&binding);
    public
}

/// The secret side of a salted data opening, as the schedule reads it.
pub(crate) struct DataSecrets<'a> {
    pub s: &'a [u8; 32],
    pub r: &'a [u8; 32],
    pub b: &'a [u8; 32],
    pub salt: &'a [u8; SALT_BYTES],
    pub cf: &'a [u8; 32],
    /// `Some` when the rule is private (S3); S2 reads the public rule.
    pub rule: Option<&'a [u8; 32]>,
    pub position: u32,
    pub path: &'a [[u8; 32]; TREE_DEPTH],
}

impl DataSecrets<'_> {
    /// `C` of spec 01, section 3.
    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    pub(crate) fn commitment(&self, rule: &[u8; 32]) -> [u8; 32] {
        use crate::hash::{data_commitment_v2, data_fingerprint_v2};
        data_commitment_v2(&data_fingerprint_v2(self.s, self.r, self.b, self.salt, self.cf, rule))
    }

    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    pub(crate) fn marker(&self) -> [u8; 32] {
        crate::hash::data_marker_v2(self.r, self.b, self.salt)
    }

    /// The carried columns: the bytes of `r`, `b` and the salt.
    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    pub(crate) fn carried_values(&self) -> Vec<u32> {
        let mut carried = vec![0u32; CARRIED];
        for k in 0..32 {
            carried[R + k] = u32::from(self.r[k]);
            carried[B + k] = u32::from(self.b[k]);
        }
        for (k, &byte) in self.salt.iter().enumerate() {
            carried[SALT + k] = u32::from(byte);
        }
        carried
    }
}

impl<'a> DataSecrets<'a> {
    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    fn reveal(o: &'a SaltedDataOpening) -> Self {
        Self {
            s: &o.s,
            r: &o.r,
            b: &o.b,
            salt: &o.salt,
            cf: &o.cf,
            rule: None,
            position: o.position,
            path: &o.path,
        }
    }
}

/// Where the rule of a data fingerprint comes from.
#[derive(Clone, Copy)]
pub(crate) enum RuleSource {
    /// A public field at this offset (S2).
    Public(usize),
    /// A private input (S3).
    Private,
}

/// Open a salted data commitment and climb to the root: `F_d`, `C`, 32
/// nodes. `F_d` reads the content fingerprint from the public bytes at `cf`,
/// and the last node's digest must equal the public bytes at `root`.
pub(crate) fn push_data_opening(
    sb: &mut ScheduleBuilder,
    w: Option<&DataSecrets<'_>>,
    rule: RuleSource,
    cf: usize,
    root: usize,
) {
    let fingerprint = HashBuilder::new(TAG_DATA_FINGERPRINT_V2)
        .free(32, w.map(|w| &w.s[..]))
        .carried(R, 32)
        .carried(B, 32)
        .carried(SALT, SALT_BYTES)
        .constant(&DATA_V2)
        .public(cf, 32);
    let fingerprint = match rule {
        RuleSource::Public(offset) => fingerprint.public(offset, 32),
        RuleSource::Private => fingerprint.free(32, w.map(|w| &w.rule.expect("a private rule")[..])),
    };
    sb.push(fingerprint);
    sb.push(HashBuilder::new(TAG_DATA_COMMITMENT).constant(&DATA_V2).prev());
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

/// The marker hash of a salted data commitment, from the carried `r`, `b`
/// and salt.
pub(crate) fn data_marker_hash() -> HashBuilder {
    HashBuilder::new(TAG_DATA_MARKER_V2)
        .carried(R, 32)
        .carried(B, 32)
        .carried(SALT, SALT_BYTES)
}

/// The schedule of S2 and, with a witness, the free bytes and direction bits.
fn schedule_with(w: Option<&DataSecrets<'_>>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::DataReveal;
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let mut sb = ScheduleBuilder::new();
    push_data_opening(&mut sb, w, RuleSource::Public(off("rule")), off("cf"), off("root"));
    sb.push(data_marker_hash().output(off("marker")));
    sb.push(
        HashBuilder::new(TAG_DATA_REVEAL_BINDING)
            .public(0, fields_len)
            .output(fields_len),
    );
    let mut consts = vec![
        (off("statement"), STATEMENT_DATA_REVEAL),
        (off("statement_version"), STATEMENT_VERSION_1),
        (off("type"), DATA_V2[0]),
        (off("type") + 1, DATA_V2[1]),
    ];
    for t in 0..32 {
        consts.push((off("rule") + t, 0));
    }
    sb.finish(fields_len + 32, CARRIED, None, consts)
}

/// The schedule of S2, without any witness.
pub(crate) fn schedule() -> Schedule {
    schedule_with(None).0
}

/// The shipped verifier of a salted (version 2) data reveal. The fee of a
/// data reveal is not settled (spec 02, section 13, item 1), so it rejects
/// every data reveal with [`ProofError::DataFeeUnsettled`], whatever the
/// proof.
pub fn verify_salted_data_reveal(params: &ChainParams, tx: &DataReveal, proof: &Proof) -> Result<(), ProofError> {
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

/// Prove S2 for a salted (version 2) commitment, for tests only. The salt is
/// a private witness: neither the returned public fields nor the proof hold
/// it. Refuses a non-empty rule and a commitment that is not the leaf at
/// `position` under `root`; a wrong salt makes another commitment, which is
/// not the leaf under `root`.
#[cfg(feature = "unsettled-points-test")]
pub fn prove_salted_data_reveal(
    params: &ChainParams,
    opening: &SaltedDataOpening,
    request: &DataRevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(DataReveal, Proof), ProofError> {
    use crate::hash::{EMPTY_RULE, Tree, merkle_root};

    let w = DataSecrets::reveal(opening);
    if request.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    if merkle_root(Tree::Data, &w.commitment(&request.rule), w.position, w.path) != request.root {
        return Err(ProofError::NotInTree);
    }
    let tx = DataReveal {
        purpose: request.purpose,
        root: request.root,
        marker: w.marker(),
        party: request.party,
        fee: request.fee,
        rule: request.rule,
        cf: *w.cf,
    };
    let proof = prove_salted_data_reveal_claiming(params, opening, &tx, zk_randomness)?;
    Ok((tx, proof))
}

/// A salted data reveal proof claiming `claimed`, whatever the opening says,
/// with none of the honest prover's checks, so tests can show the verifier
/// catches a lie (another salt, say). For tests only.
#[cfg(feature = "unsettled-points-test")]
#[doc(hidden)]
pub fn prove_salted_data_reveal_claiming(
    params: &ChainParams,
    opening: &SaltedDataOpening,
    claimed: &DataReveal,
    zk_randomness: [u8; 32],
) -> Result<Proof, ProofError> {
    use crate::schedule::Assignment;

    let w = DataSecrets::reveal(opening);
    let (_, free, dirs) = schedule_with(Some(&w));
    let assignment = Assignment {
        public: public_values(params, claimed),
        carried: w.carried_values(),
        free,
        dirs,
    };
    crate::stark::prove(Statement::SaltedDataReveal, &assignment, zk_randomness).map(Proof)
}

/// Verify S2 of a salted (version 2) commitment without the fee step, for
/// tests only. Rejects a non-empty rule before the proof.
#[cfg(feature = "unsettled-points-test")]
pub fn verify_salted_data_reveal_unsettled(
    params: &ChainParams,
    tx: &DataReveal,
    proof: &Proof,
) -> Result<(), ProofError> {
    use crate::hash::EMPTY_RULE;

    if tx.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    crate::stark::verify(Statement::SaltedDataReveal, &public_values(params, tx), proof.as_bytes())
}
