//! Building a commit (spec 01, sections 3 and 8).
//!
//! ```text
//! coin:  F   = K("ghost/coin-fingerprint/v1", s, r, b, COIN, cf, rule)
//!        C   = K("ghost/coin-commitment/v1", COIN, F, v)
//! data:  F_d = K("ghost/data-fingerprint/v1", s, r, b, DATA, cf, rule)
//!        C   = K("ghost/data-commitment/v1", DATA, F_d)
//! cf = K("ghost/content-fingerprint/v1", len(content) as 8 bytes, content)
//! coin marker:  m = K("ghost/coin-marker/v1", r, b)
//! data marker:  m = K("ghost/data-marker/v1", r, b)
//! ```
//!
//! The wallet sends the fingerprint; the node computes the commitment from it.
//! The commitment and the marker are computed here too, so the wallet can find
//! its leaf and its marker on the chain.

use core::fmt;

use crate::derive::{Blinding, RevealSecret, Secret};
use crate::hash::{
    self, TAG_COIN_COMMITMENT, TAG_COIN_FINGERPRINT, TAG_COIN_MARKER, TAG_CONTENT_FINGERPRINT,
    TAG_DATA_COMMITMENT, TAG_DATA_FINGERPRINT, TAG_DATA_MARKER,
};
use crate::key::PhantomKey;
use crate::wipe::wipe;

/// A type tag: the commitment format version, then the type.
pub type TypeTag = [u8; 2];

/// The type tag of a coin commitment, version 1.
pub const COIN: TypeTag = [0x01, 0x01];

/// The type tag of a data commitment, version 1.
pub const DATA: TypeTag = [0x01, 0x02];

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

/// `F = K("ghost/coin-fingerprint/v1", s, r, b, COIN, cf, rule)` with `cf` the
/// 32 zero bytes of a coin.
pub fn coin_fingerprint(s: &Secret, r: &RevealSecret, b: &Blinding, rule: &Rule) -> Fingerprint {
    Fingerprint(hash::k(
        TAG_COIN_FINGERPRINT,
        &[
            s.as_bytes(),
            r.as_bytes(),
            b.as_bytes(),
            &COIN,
            ContentFingerprint::COIN.as_bytes(),
            rule.as_bytes(),
        ],
    ))
}

/// `C = K("ghost/coin-commitment/v1", COIN, F, v)`.
pub fn coin_commitment(fingerprint: &Fingerprint, amount: Amount) -> Commitment {
    Commitment(hash::k(
        TAG_COIN_COMMITMENT,
        &[&COIN, fingerprint.as_bytes(), &amount.to_bytes()],
    ))
}

/// `m = K("ghost/coin-marker/v1", r, b)`.
pub fn coin_marker(r: &RevealSecret, b: &Blinding) -> Marker {
    Marker(hash::k(TAG_COIN_MARKER, &[r.as_bytes(), b.as_bytes()]))
}

/// `F_d = K("ghost/data-fingerprint/v1", s, r, b, DATA, cf, rule)`.
pub fn data_fingerprint(
    s: &Secret,
    r: &RevealSecret,
    b: &Blinding,
    cf: &ContentFingerprint,
    rule: &Rule,
) -> Fingerprint {
    Fingerprint(hash::k(
        TAG_DATA_FINGERPRINT,
        &[
            s.as_bytes(),
            r.as_bytes(),
            b.as_bytes(),
            &DATA,
            cf.as_bytes(),
            rule.as_bytes(),
        ],
    ))
}

/// `C = K("ghost/data-commitment/v1", DATA, F_d)`.
pub fn data_commitment(fingerprint: &Fingerprint) -> Commitment {
    Commitment(hash::k(TAG_DATA_COMMITMENT, &[&DATA, fingerprint.as_bytes()]))
}

/// `m = K("ghost/data-marker/v1", r, b)`.
pub fn data_marker(r: &RevealSecret, b: &Blinding) -> Marker {
    Marker(hash::k(TAG_DATA_MARKER, &[r.as_bytes(), b.as_bytes()]))
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
}

impl PhantomKey {
    /// The coin commitment number `index` of this key, holding `amount`.
    ///
    /// Number 0 is the key's first commitment (the commit); a remainder takes
    /// one more than the number of the commitment it spends (spec 01,
    /// section 8). Version 1 accepts only the empty rule.
    pub fn coin_commit(
        &self,
        index: u64,
        amount: Amount,
        rule: Rule,
    ) -> Result<CoinCommit, CommitError> {
        if !rule.is_empty() {
            return Err(CommitError::RuleNotSupported);
        }
        let key_bytes = self.key_bytes();
        let s = key_bytes.secret();
        let r = key_bytes.reveal_secret();
        let b = key_bytes.blinding(index);
        let fingerprint = coin_fingerprint(&s, &r, &b, &rule);
        Ok(CoinCommit {
            fingerprint,
            commitment: coin_commitment(&fingerprint, amount),
            marker: coin_marker(&r, &b),
        })
    }

    /// The data commitment of this key for `content`.
    ///
    /// A data commitment has no remainder in version 1, so it always uses the
    /// blinding `b_0`. Version 1 accepts only the empty rule.
    pub fn data_commit(&self, content: &Content, rule: Rule) -> Result<DataCommit, CommitError> {
        if !rule.is_empty() {
            return Err(CommitError::RuleNotSupported);
        }
        let key_bytes = self.key_bytes();
        let s = key_bytes.secret();
        let r = key_bytes.reveal_secret();
        let b = key_bytes.blinding(0);
        let content_fingerprint = content.fingerprint();
        let fingerprint = data_fingerprint(&s, &r, &b, &content_fingerprint, &rule);
        Ok(DataCommit {
            content_fingerprint,
            fingerprint,
            commitment: data_commitment(&fingerprint),
            marker: data_marker(&r, &b),
        })
    }
}
