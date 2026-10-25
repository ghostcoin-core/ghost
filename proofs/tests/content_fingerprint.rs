#![cfg(feature = "unsettled-points-test")]
//! The content fingerprint is a public input of the data reveal (S2) and the
//! proof of holding (S3), in both data commitment formats (spec 02, sections
//! 5 and 6; spec 04, question 8).
//!
//! A proof made for one content verifies only with that content's
//! fingerprint: the same proof with another `cf` fails, and a prover that
//! claims another `cf` for its commitment makes no proof that verifies.
//! Anyone holding the revealed bytes computes the fingerprint and compares it
//! with the reveal's `cf`.
//!
//! The S2 and S3 provers exist only under the `unsettled-points-test`
//! feature. Every negative test starts from the honest proof, asserted to
//! verify, and changes one thing. Proving runs one test at a time to bound
//! memory.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard};

use ghost_proofs::*;

static PROVING: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only zero-knowledge randomness; a real prover draws it from a secure
/// random source.
fn zk(n: u8) -> [u8; 32] {
    let mut seed = [0x3cu8; 32];
    seed[0] = n;
    seed
}

/// Example chain constants, not Ghost's.
fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    }
}

const CONTENT: &[u8] = b"Ghost example data";
const OTHER_CONTENT: &[u8] = b"Ghost example datb";
const SALT: [u8; SALT_BYTES] = [0x5e; SALT_BYTES];
const FEE: [u8; 32] = {
    let mut fee = [0u8; 32];
    fee[31] = 21;
    fee
};

/// `cf = K("ghost/content-fingerprint/v1", len(content) as 8 bytes, content)`
/// of spec 01, section 3: what a third party computes from revealed bytes.
fn content_fingerprint(content: &[u8]) -> [u8; 32] {
    tagged("ghost/content-fingerprint/v1", &[&(content.len() as u64).to_be_bytes(), content])
}

fn path() -> [[u8; 32]; TREE_DEPTH] {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Data, level as u8, &empty, &empty);
    }
    path
}

/// The format of a data commitment, for tests that run over both.
#[derive(Clone, Copy, Debug)]
enum Format {
    V1,
    V2,
}

const FORMATS: [Format; 2] = [Format::V1, Format::V2];

/// The secrets of one data commitment of `content`, alone at position 0 of a
/// data tree.
struct Commitment {
    format: Format,
    s: [u8; 32],
    r: [u8; 32],
    b: [u8; 32],
    cf: [u8; 32],
}

impl Commitment {
    fn of(format: Format, content: &[u8]) -> Self {
        Self {
            format,
            s: [1; 32],
            r: [2; 32],
            b: [3; 32],
            cf: content_fingerprint(content),
        }
    }

    fn with_cf(&self, cf: [u8; 32]) -> Self {
        Self { cf, ..*self }
    }

    fn root(&self) -> [u8; 32] {
        let leaf = match self.format {
            Format::V1 => data_commitment(&data_fingerprint(&self.s, &self.r, &self.b, &self.cf, &EMPTY_RULE)),
            Format::V2 => {
                data_commitment_v2(&data_fingerprint_v2(&self.s, &self.r, &self.b, &SALT, &self.cf, &EMPTY_RULE))
            }
        };
        merkle_root(Tree::Data, &leaf, 0, &path())
    }

    fn reveal(&self, root: [u8; 32], seed: u8) -> Result<(DataReveal, Proof), ProofError> {
        let request = DataRevealRequest {
            purpose: DataPurpose::Reveal,
            root,
            party: [0x70; 32],
            fee: FEE,
            rule: EMPTY_RULE,
        };
        match self.format {
            Format::V1 => prove_data_reveal(&params(), &self.data_opening(), &request, zk(seed)),
            Format::V2 => prove_salted_data_reveal(&params(), &self.salted_data_opening(), &request, zk(seed)),
        }
    }

    fn verify_reveal(&self, tx: &DataReveal, proof: &Proof) -> Result<(), ProofError> {
        match self.format {
            Format::V1 => verify_data_reveal_unsettled(&params(), tx, proof),
            Format::V2 => verify_salted_data_reveal_unsettled(&params(), tx, proof),
        }
    }

    fn reveal_binding(&self, tx: &DataReveal) -> [u8; 32] {
        match self.format {
            Format::V1 => data_reveal_binding(&params(), tx),
            Format::V2 => salted_data_reveal_binding(&params(), tx),
        }
    }

    fn hold_context(&self, root: [u8; 32], cf: [u8; 32]) -> HoldContext {
        HoldContext {
            type_tag: match self.format {
                Format::V1 => DATA,
                Format::V2 => DATA_V2,
            },
            root,
            marker_set_root: [0x6d; 32],
            verifier: [0x0a; 32],
            challenge: [0xc1; 32],
            cf,
        }
    }

    fn hold(&self, ctx: &HoldContext, seed: u8) -> Result<Proof, ProofError> {
        match self.format {
            Format::V1 => prove_hold(&params(), &self.hold_opening(), ctx, zk(seed)),
            Format::V2 => prove_salted_hold(&params(), &self.salted_hold_opening(), ctx, zk(seed)),
        }
    }

    fn data_opening(&self) -> DataOpening {
        DataOpening {
            s: self.s,
            r: self.r,
            b: self.b,
            cf: self.cf,
            position: 0,
            path: path(),
        }
    }

    fn salted_data_opening(&self) -> SaltedDataOpening {
        SaltedDataOpening {
            s: self.s,
            r: self.r,
            b: self.b,
            salt: SALT,
            cf: self.cf,
            position: 0,
            path: path(),
        }
    }

    fn hold_opening(&self) -> HoldOpening {
        HoldOpening {
            s: self.s,
            r: self.r,
            b: self.b,
            cf: self.cf,
            rule: EMPTY_RULE,
            position: 0,
            path: path(),
        }
    }

    fn salted_hold_opening(&self) -> SaltedHoldOpening {
        SaltedHoldOpening {
            s: self.s,
            r: self.r,
            b: self.b,
            salt: SALT,
            cf: self.cf,
            rule: EMPTY_RULE,
            position: 0,
            path: path(),
        }
    }
}

/// A lying prover's proof does not verify. In a release build the prover
/// makes bytes and the verifier rejects them; with debug assertions on,
/// Plonky3 checks every constraint before it proves and panics on the broken
/// one, so no proof exists at all.
fn lying_proof_fails(
    prove: impl FnOnce() -> Result<Proof, ProofError>,
    verify: impl FnOnce(&Proof) -> Result<(), ProofError>,
) {
    match catch_unwind(AssertUnwindSafe(prove)) {
        Ok(proof) => {
            let proof = proof.expect("the lying prover still produces bytes");
            assert_eq!(verify(&proof), Err(ProofError::Rejected));
        }
        Err(_) => assert!(cfg!(debug_assertions), "only the debug constraint check may stop the prover"),
    }
}

/// The fingerprint a third party computes from the bytes is the one of the
/// spec 01 example, and another content gives another fingerprint.
#[test]
fn the_fingerprint_is_computed_from_the_bytes() {
    let example = "7da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c";
    let hex: String = content_fingerprint(CONTENT).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, example);
    assert_ne!(content_fingerprint(CONTENT), content_fingerprint(OTHER_CONTENT));
    // The length is part of it: a prefix is not the same content.
    assert_ne!(content_fingerprint(CONTENT), content_fingerprint(&CONTENT[..CONTENT.len() - 1]));
}

/// A data reveal carries its commitment's content fingerprint, checkable
/// against the revealed bytes, and verifies only for that fingerprint, in
/// both commitment formats.
#[test]
fn data_reveal_rejects_other_fingerprint() {
    let _one = one_at_a_time();
    let other_cf = content_fingerprint(OTHER_CONTENT);
    for (n, format) in FORMATS.into_iter().enumerate() {
        let n = n as u8;
        let c = Commitment::of(format, CONTENT);
        let root = c.root();
        let (tx, proof) = c.reveal(root, 10 + n).expect("honest proof");
        assert_eq!(c.verify_reveal(&tx, &proof), Ok(()), "{format:?}");
        // The revealed bytes check against the reveal; other bytes do not.
        assert_eq!(tx.cf, content_fingerprint(CONTENT), "{format:?}");
        assert_ne!(tx.cf, other_cf, "{format:?}");

        // The same proof with another fingerprint fails, and the binding
        // digest differs.
        let other = DataReveal {
            cf: other_cf,
            ..tx.clone()
        };
        assert_ne!(c.reveal_binding(&other), c.reveal_binding(&tx), "{format:?}");
        assert_eq!(c.verify_reveal(&other, &proof), Err(ProofError::Rejected), "{format:?}");
        let mut flipped = tx.clone();
        flipped.cf[31] ^= 1;
        assert_eq!(c.verify_reveal(&flipped, &proof), Err(ProofError::Rejected), "{format:?}");

        // The honest prover does not open the commitment as another content:
        // that is another commitment, not the leaf under the root.
        let refused = c.with_cf(other_cf).reveal(root, 20 + n);
        assert_eq!(refused.err(), Some(ProofError::NotInTree), "{format:?}");

        // A reveal of another content's commitment verifies for its own
        // fingerprint only.
        let o = Commitment::of(format, OTHER_CONTENT);
        let (other_tx, other_proof) = o.reveal(o.root(), 30 + n).expect("honest proof");
        assert_eq!(o.verify_reveal(&other_tx, &other_proof), Ok(()), "{format:?}");
        assert_eq!(other_tx.cf, other_cf, "{format:?}");
        let as_first = DataReveal {
            cf: tx.cf,
            ..other_tx
        };
        assert_eq!(o.verify_reveal(&as_first, &other_proof), Err(ProofError::Rejected), "{format:?}");
    }

    // A salted prover that opens the commitment but claims another
    // fingerprint makes no proof that verifies.
    let c = Commitment::of(Format::V2, CONTENT);
    let (tx, _) = c.reveal(c.root(), 40).expect("honest proof");
    let claimed = DataReveal {
        cf: other_cf,
        ..tx
    };
    lying_proof_fails(
        || prove_salted_data_reveal_claiming(&params(), &c.salted_data_opening(), &claimed, zk(41)),
        |proof| verify_salted_data_reveal_unsettled(&params(), &claimed, proof),
    );
}

/// A proof of holding is bound to the content fingerprint it was made for,
/// next to the challenge, in both commitment formats.
#[test]
fn hold_rejects_other_fingerprint() {
    let _one = one_at_a_time();
    let other_cf = content_fingerprint(OTHER_CONTENT);
    for (n, format) in FORMATS.into_iter().enumerate() {
        let n = n as u8;
        let c = Commitment::of(format, CONTENT);
        let root = c.root();
        let ctx = c.hold_context(root, content_fingerprint(CONTENT));
        let proof = c.hold(&ctx, 50 + n).expect("honest proof");
        assert_eq!(verify_hold_unsettled(&params(), &ctx, &proof), Ok(()), "{format:?}");
        // The shipped verifier still rejects every proof of holding.
        assert_eq!(verify_hold(&params(), &ctx, &proof), Err(ProofError::HoldUnsettled));

        // The same proof for another fingerprint fails, and the binding
        // digest differs.
        let other = HoldContext {
            cf: other_cf,
            ..ctx.clone()
        };
        assert_ne!(hold_binding(&params(), &other), hold_binding(&params(), &ctx), "{format:?}");
        assert_eq!(verify_hold_unsettled(&params(), &other, &proof), Err(ProofError::Rejected), "{format:?}");
        let mut flipped = ctx.clone();
        flipped.cf[0] ^= 1;
        assert_eq!(verify_hold_unsettled(&params(), &flipped, &proof), Err(ProofError::Rejected), "{format:?}");

        // The honest prover refuses a context asking about another content.
        assert_eq!(c.hold(&other, 60 + n).err(), Some(ProofError::WrongContentFingerprint), "{format:?}");
        // An opening claiming the asked fingerprint is another commitment,
        // not the leaf under the root.
        assert_eq!(c.with_cf(other_cf).hold(&other, 62 + n).err(), Some(ProofError::NotInTree), "{format:?}");
    }

    // A salted prover that opens the commitment but answers for another
    // fingerprint makes no proof that verifies.
    let c = Commitment::of(Format::V2, CONTENT);
    let other = c.hold_context(c.root(), other_cf);
    lying_proof_fails(
        || prove_salted_hold_claiming(&params(), &c.salted_hold_opening(), &other, zk(70)),
        |proof| verify_hold_unsettled(&params(), &other, proof),
    );
}
