//! Statement S2: the one-time reveal of data, with the reveal or the revoke
//! purpose (spec 02, section 5).
//!
//! The proof opens one data commitment under the public data-tree `root`,
//! publishes its marker and computes the data reveal binding digest, purpose
//! included, so a reveal cannot pass as a revocation or the other way round.
//! It mints nothing and has no amounts.
//!
//! There is one statement per commitment format (spec 01, section 10), with
//! the same public fields and binding layout. The binding's `type` field is
//! the format's type tag, so a proof of one format never verifies as the
//! other.
//!
//! - Version 1, [`DataOpening`]: a commitment made without a salt.
//! - Version 2, [`SaltedDataOpening`]: a salted commitment. The salt is a
//!   private witness: no public value holds it.
//!
//! **Not settled: the fee of a data reveal** (spec 02, section 13, item 1).
//! No constraint ties `fee` to anything inside a data commitment, because a
//! data commitment holds no value. So the public [`verify_data_reveal`] and
//! [`verify_salted_data_reveal`] reject every data reveal with
//! [`ProofError::DataFeeUnsettled`]. The statements themselves are built and
//! checked only by the functions compiled under the `unsettled-points-test`
//! feature, for tests; they do not settle the point and the public verifiers
//! reject regardless of the feature.
//!
//! The hashes, in trace order (38 permutations in both formats). `DATA` is
//! the format's type tag (`0x01 0x02` or `0x02 0x02`), and `salt` is present
//! only in version 2, with the `v2` fingerprint and marker tags:
//!
//! ```text
//! F_d     K(data-fingerprint, s, r, b, salt, DATA, cf, rule)  2 blocks
//! C       K(data-commitment, DATA, F_d)                       1
//! N0..N31 K(data-tree-node, level, left, right)               32, N31 = root
//! M       K(data-marker, r, b, salt)                          1, = marker
//! B       K(data-reveal-binding, fields)                      2, = binding
//! ```
//!
//! `r`, `b` and, in version 2, the salt are carried columns read by both
//! `F_d` and `M`, so the marker is the one of the commitment opened.

use alloc::vec;
use alloc::vec::Vec;

use crate::binding::{
    Binding, ChainParams, FieldWriter, PURPOSE_REVEAL, PURPOSE_REVOKE, STATEMENT_DATA_REVEAL, STATEMENT_VERSION_1,
    digest,
};
use crate::hash::{
    DATA, DATA_V2, SALT_BYTES, TAG_DATA_COMMITMENT, TAG_DATA_FINGERPRINT, TAG_DATA_FINGERPRINT_V2, TAG_DATA_MARKER,
    TAG_DATA_MARKER_V2, TAG_DATA_REVEAL_BINDING, TAG_DATA_TREE_NODE, TREE_DEPTH,
};
use crate::schedule::{HashBuilder, Schedule, ScheduleBuilder};
use crate::stark::Statement;
use crate::{Proof, ProofError};

// Carried columns, shared with S3. The salt has no columns in version 1.
pub(crate) const R: usize = 0;
pub(crate) const B: usize = 32;
pub(crate) const SALT: usize = 64;

/// The format of a data commitment (spec 01, section 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataFormat {
    /// Version 1: no salt, the `v1` fingerprint and marker tags.
    V1,
    /// Version 2: a 16-byte salt right after `b`, the `v2` tags.
    V2,
}

impl DataFormat {
    /// The format of a type tag, `None` for any tag but `DATA` and `DATA_V2`.
    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    pub(crate) const fn of(type_tag: [u8; 2]) -> Option<Self> {
        match type_tag {
            DATA => Some(Self::V1),
            DATA_V2 => Some(Self::V2),
            _ => None,
        }
    }

    pub(crate) const fn type_tag(self) -> [u8; 2] {
        match self {
            Self::V1 => DATA,
            Self::V2 => DATA_V2,
        }
    }

    const fn fingerprint_tag(self) -> &'static str {
        match self {
            Self::V1 => TAG_DATA_FINGERPRINT,
            Self::V2 => TAG_DATA_FINGERPRINT_V2,
        }
    }

    const fn marker_tag(self) -> &'static str {
        match self {
            Self::V1 => TAG_DATA_MARKER,
            Self::V2 => TAG_DATA_MARKER_V2,
        }
    }

    const fn salt_len(self) -> usize {
        match self {
            Self::V1 => 0,
            Self::V2 => SALT_BYTES,
        }
    }

    /// Number of carried columns: `r`, `b` and the salt.
    pub(crate) const fn carried(self) -> usize {
        SALT + self.salt_len()
    }

    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    const fn reveal_statement(self) -> Statement {
        match self {
            Self::V1 => Statement::DataReveal,
            Self::V2 => Statement::SaltedDataReveal,
        }
    }
}

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

/// The version 1 data commitment being revealed, made without a salt.
/// Secrets: no `Debug`, no serialization.
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

/// The public fields of a data reveal, the same in both commitment formats.
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

fn fields(format: DataFormat, params: &ChainParams, tx: &DataReveal) -> Vec<u8> {
    FieldWriter::new(Binding::DataReveal, params, STATEMENT_DATA_REVEAL, format.type_tag(), tx.purpose.code())
        .put("root", &tx.root)
        .put("marker", &tx.marker)
        .put("party", &tx.party)
        .put("fee", &tx.fee)
        .put("rule", &tx.rule)
        .finish()
}

/// The data reveal binding digest of a version 1 reveal, from the verifier's
/// own chain constants and the transaction's fields.
pub fn data_reveal_binding(params: &ChainParams, tx: &DataReveal) -> [u8; 32] {
    digest(Binding::DataReveal, &fields(DataFormat::V1, params, tx))
}

/// The data reveal binding digest of a salted (version 2) reveal: the same
/// fields, with the version 2 type tag.
pub fn salted_data_reveal_binding(params: &ChainParams, tx: &DataReveal) -> [u8; 32] {
    digest(Binding::DataReveal, &fields(DataFormat::V2, params, tx))
}

#[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
fn public_values(format: DataFormat, params: &ChainParams, tx: &DataReveal) -> Vec<u8> {
    let mut public = fields(format, params, tx);
    let binding = digest(Binding::DataReveal, &public);
    public.extend_from_slice(&binding);
    public
}

/// The secret side of a data opening, as the schedule reads it.
pub(crate) struct DataSecrets<'a> {
    pub s: &'a [u8; 32],
    pub r: &'a [u8; 32],
    pub b: &'a [u8; 32],
    /// `Some` exactly in version 2.
    pub salt: Option<&'a [u8; SALT_BYTES]>,
    pub cf: &'a [u8; 32],
    /// `Some` when the rule is private (S3); S2 reads the public rule.
    pub rule: Option<&'a [u8; 32]>,
    pub position: u32,
    pub path: &'a [[u8; 32]; TREE_DEPTH],
}

impl DataSecrets<'_> {
    pub(crate) const fn format(&self) -> DataFormat {
        match self.salt {
            None => DataFormat::V1,
            Some(_) => DataFormat::V2,
        }
    }

    /// `C` of spec 01, section 3, in the commitment's own format.
    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    pub(crate) fn commitment(&self, rule: &[u8; 32]) -> [u8; 32] {
        use crate::hash::{data_commitment, data_commitment_v2, data_fingerprint, data_fingerprint_v2};
        match self.salt {
            None => data_commitment(&data_fingerprint(self.s, self.r, self.b, self.cf, rule)),
            Some(salt) => data_commitment_v2(&data_fingerprint_v2(self.s, self.r, self.b, salt, self.cf, rule)),
        }
    }

    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    pub(crate) fn marker(&self) -> [u8; 32] {
        use crate::hash::{data_marker, data_marker_v2};
        match self.salt {
            None => data_marker(self.r, self.b),
            Some(salt) => data_marker_v2(self.r, self.b, salt),
        }
    }

    /// The carried columns: the bytes of `r`, `b` and, in version 2, the
    /// salt.
    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    pub(crate) fn carried_values(&self) -> Vec<u32> {
        let mut carried = vec![0u32; self.format().carried()];
        for k in 0..32 {
            carried[R + k] = u32::from(self.r[k]);
            carried[B + k] = u32::from(self.b[k]);
        }
        for (k, &byte) in self.salt.into_iter().flatten().enumerate() {
            carried[SALT + k] = u32::from(byte);
        }
        carried
    }
}

impl<'a> DataSecrets<'a> {
    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    fn reveal_v1(o: &'a DataOpening) -> Self {
        Self {
            s: &o.s,
            r: &o.r,
            b: &o.b,
            salt: None,
            cf: &o.cf,
            rule: None,
            position: o.position,
            path: &o.path,
        }
    }

    #[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
    fn reveal_v2(o: &'a SaltedDataOpening) -> Self {
        Self {
            s: &o.s,
            r: &o.r,
            b: &o.b,
            salt: Some(&o.salt),
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

/// Open a data commitment of a format and climb to the root: `F_d`, `C`, 32
/// nodes. The last node's digest must equal the public bytes at `root`.
pub(crate) fn push_data_opening(
    sb: &mut ScheduleBuilder,
    format: DataFormat,
    w: Option<&DataSecrets<'_>>,
    rule: RuleSource,
    root: usize,
) {
    if let Some(w) = w {
        assert_eq!(w.format(), format, "a witness of another format");
    }
    let type_tag = format.type_tag();
    let mut fingerprint = HashBuilder::new(format.fingerprint_tag())
        .free(32, w.map(|w| &w.s[..]))
        .carried(R, 32)
        .carried(B, 32);
    if format.salt_len() > 0 {
        fingerprint = fingerprint.carried(SALT, format.salt_len());
    }
    let fingerprint = fingerprint.constant(&type_tag).free(32, w.map(|w| &w.cf[..]));
    let fingerprint = match rule {
        RuleSource::Public(offset) => fingerprint.public(offset, 32),
        RuleSource::Private => fingerprint.free(32, w.map(|w| &w.rule.expect("a private rule")[..])),
    };
    sb.push(fingerprint);
    sb.push(HashBuilder::new(TAG_DATA_COMMITMENT).constant(&type_tag).prev());
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

/// The marker hash of a data commitment of a format, from the carried `r`,
/// `b` and, in version 2, salt.
pub(crate) fn data_marker_hash(format: DataFormat) -> HashBuilder {
    let marker = HashBuilder::new(format.marker_tag()).carried(R, 32).carried(B, 32);
    if format.salt_len() > 0 {
        marker.carried(SALT, format.salt_len())
    } else {
        marker
    }
}

/// The schedule of S2 in a format and, with a witness of that format, the
/// free bytes and direction bits.
fn schedule_with(format: DataFormat, w: Option<&DataSecrets<'_>>) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
    let binding = Binding::DataReveal;
    let off = |name: &str| binding.offset(name);
    let fields_len = binding.fields_len();
    let type_tag = format.type_tag();
    let mut sb = ScheduleBuilder::new();
    push_data_opening(&mut sb, format, w, RuleSource::Public(off("rule")), off("root"));
    sb.push(data_marker_hash(format).output(off("marker")));
    sb.push(
        HashBuilder::new(TAG_DATA_REVEAL_BINDING)
            .public(0, fields_len)
            .output(fields_len),
    );
    let mut consts = vec![
        (off("statement"), STATEMENT_DATA_REVEAL),
        (off("statement_version"), STATEMENT_VERSION_1),
        (off("type"), type_tag[0]),
        (off("type") + 1, type_tag[1]),
    ];
    for t in 0..32 {
        consts.push((off("rule") + t, 0));
    }
    sb.finish(fields_len + 32, format.carried(), None, consts)
}

/// The schedule of S2 in a format, without any witness.
pub(crate) fn schedule(format: DataFormat) -> Schedule {
    schedule_with(format, None).0
}

/// The shipped verifier of a version 1 data reveal. The fee of a data reveal
/// is not settled (spec 02, section 13, item 1), so it rejects every data
/// reveal with [`ProofError::DataFeeUnsettled`], whatever the proof.
pub fn verify_data_reveal(params: &ChainParams, tx: &DataReveal, proof: &Proof) -> Result<(), ProofError> {
    let _ = (params, tx, proof);
    Err(ProofError::DataFeeUnsettled)
}

/// The shipped verifier of a salted (version 2) data reveal. Like
/// [`verify_data_reveal`], it rejects every data reveal with
/// [`ProofError::DataFeeUnsettled`] until the fee is settled.
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

#[cfg(feature = "unsettled-points-test")]
fn prove(
    params: &ChainParams,
    w: &DataSecrets<'_>,
    request: &DataRevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(DataReveal, Proof), ProofError> {
    use crate::hash::{EMPTY_RULE, Tree, merkle_root};
    use crate::schedule::Assignment;

    if request.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    if merkle_root(Tree::Data, &w.commitment(&request.rule), w.position, w.path) != request.root {
        return Err(ProofError::NotInTree);
    }
    let format = w.format();
    let tx = DataReveal {
        purpose: request.purpose,
        root: request.root,
        marker: w.marker(),
        party: request.party,
        fee: request.fee,
        rule: request.rule,
    };
    let (_, free, dirs) = schedule_with(format, Some(w));
    let assignment = Assignment {
        public: public_values(format, params, &tx),
        carried: w.carried_values(),
        free,
        dirs,
    };
    let proof = crate::stark::prove(format.reveal_statement(), &assignment, zk_randomness).map(Proof)?;
    Ok((tx, proof))
}

/// Prove S2 for a version 1 commitment, for tests only. Refuses a non-empty
/// rule and a commitment that is not the leaf at `position` under `root`.
#[cfg(feature = "unsettled-points-test")]
pub fn prove_data_reveal(
    params: &ChainParams,
    opening: &DataOpening,
    request: &DataRevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(DataReveal, Proof), ProofError> {
    prove(params, &DataSecrets::reveal_v1(opening), request, zk_randomness)
}

/// Prove S2 for a salted (version 2) commitment, for tests only. The salt is
/// a private witness: neither the returned public fields nor the proof hold
/// it. Refuses what [`prove_data_reveal`] refuses; a wrong salt makes another
/// commitment, which is not the leaf under `root`.
#[cfg(feature = "unsettled-points-test")]
pub fn prove_salted_data_reveal(
    params: &ChainParams,
    opening: &SaltedDataOpening,
    request: &DataRevealRequest,
    zk_randomness: [u8; 32],
) -> Result<(DataReveal, Proof), ProofError> {
    prove(params, &DataSecrets::reveal_v2(opening), request, zk_randomness)
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

    let w = DataSecrets::reveal_v2(opening);
    let (_, free, dirs) = schedule_with(DataFormat::V2, Some(&w));
    let assignment = Assignment {
        public: public_values(DataFormat::V2, params, claimed),
        carried: w.carried_values(),
        free,
        dirs,
    };
    crate::stark::prove(Statement::SaltedDataReveal, &assignment, zk_randomness).map(Proof)
}

#[cfg(feature = "unsettled-points-test")]
fn verify_unsettled(
    format: DataFormat,
    params: &ChainParams,
    tx: &DataReveal,
    proof: &Proof,
) -> Result<(), ProofError> {
    use crate::hash::EMPTY_RULE;

    if tx.rule != EMPTY_RULE {
        return Err(ProofError::RuleNotEmpty);
    }
    crate::stark::verify(format.reveal_statement(), &public_values(format, params, tx), proof.as_bytes())
}

/// Verify S2 of a version 1 commitment without the fee step, for tests only.
/// Rejects a non-empty rule before the proof.
#[cfg(feature = "unsettled-points-test")]
pub fn verify_data_reveal_unsettled(params: &ChainParams, tx: &DataReveal, proof: &Proof) -> Result<(), ProofError> {
    verify_unsettled(DataFormat::V1, params, tx, proof)
}

/// Verify S2 of a salted (version 2) commitment without the fee step, for
/// tests only. A version 1 proof never passes here, nor a salted one there:
/// the binding's type differs.
#[cfg(feature = "unsettled-points-test")]
pub fn verify_salted_data_reveal_unsettled(
    params: &ChainParams,
    tx: &DataReveal,
    proof: &Proof,
) -> Result<(), ProofError> {
    verify_unsettled(DataFormat::V2, params, tx, proof)
}
