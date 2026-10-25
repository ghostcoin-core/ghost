//! Building a commit (spec 01, sections 3 and 8).
//!
//! Every commitment takes version 2, the salted format: a fresh 16-byte salt
//! right after `b` in the fingerprint and the marker.
//!
//! ```text
//! coin:  F   = K("ghost/coin-fingerprint/v2", s, r, b, salt, COIN_V2, cf, rule)
//!        C   = K("ghost/coin-commitment/v1", COIN_V2, F, v)
//! data:  F_d = K("ghost/data-fingerprint/v2", s, r, b, salt, DATA_V2, cf, rule)
//!        C   = K("ghost/data-commitment/v1", DATA_V2, F_d)
//! cf = K("ghost/content-fingerprint/v1", len(content) as 8 bytes, content)
//! coin marker:  m = K("ghost/coin-marker/v2", r, b, salt)
//! data marker:  m = K("ghost/data-marker/v2", r, b, salt)
//! ```
//!
//! The salt comes from the caller's secure random source, never from the key,
//! and is public: the commit carries it in the clear beside `F`
//! ([`salted_commit_data`]) and the commitment's note carries it too.
//!
//! The wallet sends the fingerprint; the node computes the commitment from it.
//! The commitment and the marker are computed here too, so the wallet can find
//! its leaf and its marker on the chain.

use core::fmt;

use rand_core::CryptoRng;

use crate::derive::{Blinding, RevealSecret, Secret};
use crate::hash::{
    self, TAG_COIN_COMMITMENT, TAG_COIN_FINGERPRINT_V2, TAG_COIN_MARKER_V2,
    TAG_CONTENT_FINGERPRINT, TAG_DATA_COMMITMENT, TAG_DATA_FINGERPRINT_V2, TAG_DATA_MARKER_V2,
};
use crate::key::PhantomKey;
use crate::note::NOTE_BYTES;
use crate::wipe::wipe;

/// A type tag: the commitment format version, then the type.
pub type TypeTag = [u8; 2];

/// The type tag of a coin commitment, version 2: the salted format.
pub const COIN_V2: TypeTag = [0x02, 0x01];

/// The type tag of a data commitment, version 2: the salted format.
pub const DATA_V2: TypeTag = [0x02, 0x02];

/// Length of the salt of a version 2 commitment.
pub const SALT_BYTES: usize = 16;

/// The salt of a version 2 commitment: 16 bytes the wallet draws at random
/// for every new commitment (spec 01, section 3). It is public.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Salt([u8; SALT_BYTES]);

impl Salt {
    /// The salt from its 16 bytes.
    pub const fn from_bytes(bytes: [u8; SALT_BYTES]) -> Self {
        Self(bytes)
    }

    /// The 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; SALT_BYTES] {
        &self.0
    }

    /// A fresh salt: 16 bytes from the caller's secure random source.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; SALT_BYTES];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Salt(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// The largest amount in wei, `2^96 - 1`.
pub const V_MAX: u128 = (1 << 96) - 1;

/// Why a commit cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitError {
    /// The amount is above [`V_MAX`].
    AmountTooLarge,
    /// The rule is not the empty rule, the only rule version 1 accepts.
    RuleNotSupported,
}

impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmountTooLarge => write!(f, "the amount is above 2^96 - 1 wei"),
            Self::RuleNotSupported => write!(f, "version 1 accepts only the empty rule"),
        }
    }
}

impl std::error::Error for CommitError {}

/// An amount in wei, in `[0, V_MAX]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u128);

impl Amount {
    /// The amount, if it is at most [`V_MAX`].
    pub const fn new(wei: u128) -> Result<Self, CommitError> {
        if wei > V_MAX {
            Err(CommitError::AmountTooLarge)
        } else {
            Ok(Self(wei))
        }
    }

    /// The amount in wei.
    pub const fn wei(self) -> u128 {
        self.0
    }

    /// The amount as 32 big-endian bytes, the field `v`.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&self.0.to_be_bytes());
        out
    }
}

/// The optional rule of a commitment, a 32-byte value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rule([u8; 32]);

impl Rule {
    /// The empty rule, 32 zero bytes: the only rule version 1 accepts.
    pub const EMPTY: Self = Self([0; 32]);

    /// A rule from its 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether this is the empty rule.
    pub fn is_empty(&self) -> bool {
        self.0 == [0; 32]
    }
}

macro_rules! public_32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// The value from its 32 bytes.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// The 32 bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(", stringify!($name))?;
                for byte in &self.0 {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, ")")
            }
        }
    };
}

public_32! {
    /// A fingerprint: `F` of a coin or `F_d` of a data commitment. The commit
    /// carries it.
    Fingerprint
}

public_32! {
    /// A commitment `C`, the leaf the node writes into the tree.
    Commitment
}

public_32! {
    /// The one-time marker of a commitment, published when it is revealed.
    Marker
}

/// The content fingerprint `cf` of a data commitment. It is a hash of the
/// content and goes into the encrypted note, so it has no `Debug`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentFingerprint([u8; 32]);

impl ContentFingerprint {
    /// The content fingerprint of a coin: 32 zero bytes, a coin has no content.
    pub const COIN: Self = Self([0; 32]);

    /// The value from its 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The plaintext content of a data commitment, the input of its content
/// fingerprint. It has no `Debug`, `Display` or `Clone`, and its bytes are
/// overwritten with zeros when it is dropped.
pub struct Content(Vec<u8>);

impl Content {
    /// Takes ownership of the content bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The content bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The content length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the content is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `cf = K("ghost/content-fingerprint/v1", len(content) as 8 bytes,
    /// content)`.
    pub fn fingerprint(&self) -> ContentFingerprint {
        let len = self.0.len() as u64;
        ContentFingerprint(hash::k(
            TAG_CONTENT_FINGERPRINT,
            &[&len.to_be_bytes(), self.0.as_slice()],
        ))
    }
}

impl Drop for Content {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// `F = K("ghost/coin-fingerprint/v2", s, r, b, salt, COIN_V2, cf, rule)`
/// with `cf` the 32 zero bytes of a coin.
pub fn salted_coin_fingerprint(
    s: &Secret,
    r: &RevealSecret,
    b: &Blinding,
    salt: &Salt,
    rule: &Rule,
) -> Fingerprint {
    Fingerprint(hash::k(
        TAG_COIN_FINGERPRINT_V2,
        &[
            s.as_bytes(),
            r.as_bytes(),
            b.as_bytes(),
            salt.as_bytes(),
            &COIN_V2,
            ContentFingerprint::COIN.as_bytes(),
            rule.as_bytes(),
        ],
    ))
}

/// `C = K("ghost/coin-commitment/v1", COIN_V2, F, v)`.
pub fn salted_coin_commitment(fingerprint: &Fingerprint, amount: Amount) -> Commitment {
    Commitment(hash::k(
        TAG_COIN_COMMITMENT,
        &[&COIN_V2, fingerprint.as_bytes(), &amount.to_bytes()],
    ))
}

/// `m = K("ghost/coin-marker/v2", r, b, salt)`.
pub fn salted_coin_marker(r: &RevealSecret, b: &Blinding, salt: &Salt) -> Marker {
    Marker(hash::k(
        TAG_COIN_MARKER_V2,
        &[r.as_bytes(), b.as_bytes(), salt.as_bytes()],
    ))
}

/// `F_d = K("ghost/data-fingerprint/v2", s, r, b, salt, DATA_V2, cf, rule)`.
pub fn salted_data_fingerprint(
    s: &Secret,
    r: &RevealSecret,
    b: &Blinding,
    salt: &Salt,
    cf: &ContentFingerprint,
    rule: &Rule,
) -> Fingerprint {
    Fingerprint(hash::k(
        TAG_DATA_FINGERPRINT_V2,
        &[
            s.as_bytes(),
            r.as_bytes(),
            b.as_bytes(),
            salt.as_bytes(),
            &DATA_V2,
            cf.as_bytes(),
            rule.as_bytes(),
        ],
    ))
}

/// `C = K("ghost/data-commitment/v1", DATA_V2, F_d)`.
pub fn salted_data_commitment(fingerprint: &Fingerprint) -> Commitment {
    Commitment(hash::k(TAG_DATA_COMMITMENT, &[&DATA_V2, fingerprint.as_bytes()]))
}

/// `m = K("ghost/data-marker/v2", r, b, salt)`.
pub fn salted_data_marker(r: &RevealSecret, b: &Blinding, salt: &Salt) -> Marker {
    Marker(hash::k(
        TAG_DATA_MARKER_V2,
        &[r.as_bytes(), b.as_bytes(), salt.as_bytes()],
    ))
}

/// The format version of a salted commit's data, its first two bytes.
pub const SALTED_COMMIT_FORMAT_VERSION: [u8; 2] = [0x00, 0x02];

/// Length of a salted commit's data: format version (2), fingerprint (32),
/// salt (16), note (156).
pub const SALTED_COMMIT_DATA_BYTES: usize =
    SALTED_COMMIT_FORMAT_VERSION.len() + 32 + SALT_BYTES + NOTE_BYTES;

const _: () = assert!(SALTED_COMMIT_DATA_BYTES == 206);

/// The data of a version 2 commit, coin or data alike:
/// `SALTED_COMMIT_FORMAT_VERSION || F || salt || note`. The salt travels in
/// the clear beside `F`, so the node can store it beside the leaf.
pub fn salted_commit_data(
    fingerprint: &Fingerprint,
    salt: &Salt,
    note: &[u8; NOTE_BYTES],
) -> [u8; SALTED_COMMIT_DATA_BYTES] {
    let mut out = [0u8; SALTED_COMMIT_DATA_BYTES];
    let (version, rest) = out.split_at_mut(SALTED_COMMIT_FORMAT_VERSION.len());
    version.copy_from_slice(&SALTED_COMMIT_FORMAT_VERSION);
    let (f, rest) = rest.split_at_mut(32);
    f.copy_from_slice(fingerprint.as_bytes());
    let (s, rest) = rest.split_at_mut(SALT_BYTES);
    s.copy_from_slice(salt.as_bytes());
    rest.copy_from_slice(note);
    out
}

/// A coin commitment of a key: what the commit carries and what the wallet
/// looks for on the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinCommit {
    /// `F`, carried by the commit.
    pub fingerprint: Fingerprint,
    /// `C`, the leaf the node computes from `F` and the amount.
    pub commitment: Commitment,
    /// The marker published when this commitment is revealed.
    pub marker: Marker,
    /// The salt, which the commit carries in the clear beside `F`.
    pub salt: Salt,
}

impl CoinCommit {
    /// The type tag of this commitment: `COIN_V2`.
    pub fn type_tag(&self) -> TypeTag {
        COIN_V2
    }
}

/// A data commitment of a key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DataCommit {
    /// `cf`, the content fingerprint; it goes into the note.
    pub content_fingerprint: ContentFingerprint,
    /// `F_d`, carried by the commit.
    pub fingerprint: Fingerprint,
    /// `C`, the leaf the node computes from `F_d`.
    pub commitment: Commitment,
    /// The marker published when this commitment is revealed or revoked.
    pub marker: Marker,
    /// The salt, which the commit carries in the clear beside `F_d`.
    pub salt: Salt,
}

impl DataCommit {
    /// The type tag of this commitment: `DATA_V2`.
    pub fn type_tag(&self) -> TypeTag {
        DATA_V2
    }
}

impl PhantomKey {
    /// A new version 2 coin commitment number `index` of this key, holding
    /// `amount`, under a fresh 16-byte salt drawn from the caller's secure
    /// random source. The salt is returned in the commit: the caller puts it
    /// in the clear beside `F` ([`salted_commit_data`]) and in the note
    /// ([`NoteContents::salted_coin`](crate::note::NoteContents::salted_coin)).
    ///
    /// Number 0 is the key's first commitment (the commit); a remainder takes
    /// one more than the number of the commitment it spends (spec 01,
    /// section 8). Only the empty rule is accepted.
    pub fn salted_coin_commit<R: CryptoRng + ?Sized>(
        &self,
        index: u64,
        amount: Amount,
        rule: Rule,
        rng: &mut R,
    ) -> Result<CoinCommit, CommitError> {
        if !rule.is_empty() {
            return Err(CommitError::RuleNotSupported);
        }
        self.coin_commit_with_salt(index, amount, rule, Salt::random(rng))
    }

    /// The version 2 coin commitment number `index` of this key, holding
    /// `amount`, under `salt`: what restore and a reveal recompute from the
    /// salt read back from the chain.
    pub fn coin_commit_with_salt(
        &self,
        index: u64,
        amount: Amount,
        rule: Rule,
        salt: Salt,
    ) -> Result<CoinCommit, CommitError> {
        if !rule.is_empty() {
            return Err(CommitError::RuleNotSupported);
        }
        let key_bytes = self.key_bytes();
        let s = key_bytes.secret();
        let r = key_bytes.reveal_secret();
        let b = key_bytes.blinding(index);
        let fingerprint = salted_coin_fingerprint(&s, &r, &b, &salt, &rule);
        Ok(CoinCommit {
            fingerprint,
            commitment: salted_coin_commitment(&fingerprint, amount),
            marker: salted_coin_marker(&r, &b, &salt),
            salt,
        })
    }

    /// A new version 2 data commitment of this key for `content`, under a
    /// fresh 16-byte salt drawn from the caller's secure random source and
    /// returned in the commit.
    pub fn salted_data_commit<R: CryptoRng + ?Sized>(
        &self,
        content: &Content,
        rule: Rule,
        rng: &mut R,
    ) -> Result<DataCommit, CommitError> {
        if !rule.is_empty() {
            return Err(CommitError::RuleNotSupported);
        }
        self.data_commit_with_salt(content, rule, Salt::random(rng))
    }

    /// The version 2 data commitment of this key for `content` under `salt`.
    /// A data commitment has no remainder, so it always uses the blinding
    /// `b_0`.
    pub fn data_commit_with_salt(
        &self,
        content: &Content,
        rule: Rule,
        salt: Salt,
    ) -> Result<DataCommit, CommitError> {
        if !rule.is_empty() {
            return Err(CommitError::RuleNotSupported);
        }
        let key_bytes = self.key_bytes();
        let s = key_bytes.secret();
        let r = key_bytes.reveal_secret();
        let b = key_bytes.blinding(0);
        let content_fingerprint = content.fingerprint();
        let fingerprint = salted_data_fingerprint(&s, &r, &b, &salt, &content_fingerprint, &rule);
        Ok(DataCommit {
            content_fingerprint,
            fingerprint,
            commitment: salted_data_commitment(&fingerprint),
            marker: salted_data_marker(&r, &b, &salt),
            salt,
        })
    }
}
