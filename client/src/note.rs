//! The encrypted note stored with every commitment (spec 01, section 9; spec
//! 10, section 3.2).
//!
//! ```text
//! version 3 plaintext (352 bytes)
//!     = 0x03 || 0x01 || type || i (8) || v (12) || cf (32)
//!       || content length (8) || rule (32) || salt (16) || 16 zero bytes
//!       || capsule (224)
//! capsule (224 bytes)
//!     = version (1) || policy_address (20) || policy_codehash (32)
//!       || override_hash (32) || action_tag (32) || action_salt (32)
//!       || params_len (1) || params (64) || zero pad (10)
//! associated data   = chain_id as 8 bytes || C
//! note (380 bytes)  = nonce (12) || ciphertext (352) || tag (16)
//! nonce (12 bytes)  = tag_i (3) || 9 random bytes
//! ```
//!
//! Every note a wallet writes into the tree is note version 3, 380 bytes, coin
//! or data alike, so the length is not a fingerprint. Its first 128 plaintext
//! bytes are the fields of note version 2 with the version byte `0x03`; they
//! carry the salt of the commitment, so a wallet restoring from the digits
//! can reopen a remainder. The type tag must be `COIN_V2` or `DATA_V2`. The
//! amount is 12 bytes, enough for `2^96 - 1`.
//!
//! The capsule opens the note's rule. A coin with the empty rule carries a
//! version 0 capsule: all 224 bytes zero ([`Capsule::empty`]). Any other rule
//! carries a version 1 capsule, from which the rule is recomputed as
//! `K("ghost/reveal-policy/v2", policy_address (left-padded to 32),
//! policy_codehash, params_hash, override_hash, action_tag, action_salt)` with
//! `params_hash = K("ghost/policy-params/v1", params)` (spec 10, section 3.1).
//! A reader rejects a capsule of another version, a `params_len` above 64,
//! non-zero bytes after the params or in the pad, and a capsule whose rule is
//! not the 32 bytes at plaintext offset 64, all as [`NoteError::BadCapsule`].
//! The chain cannot read a note, so this is the wallet's check.
//!
//! The version 1 coin reveal and the data reveal keep a 156-byte note slot
//! ([`REVEAL_NOTE_BYTES`], equal to `ghost_proofs::NOTE_BYTES`): the remainder
//! note a reveal carries is note version 2, the 128-byte plaintext alone
//! ([`encrypt_note_v2`], [`decrypt_note_v2`]). The node stores it in the tree
//! zero-padded to 380 bytes ([`pad_reveal_note`]), and restore reads it so.
//!
//! The cipher is ChaCha20-Poly1305 of RFC 8439, from the `chacha20poly1305`
//! crate, under the key's note key. The nonce is 12 bytes: the note's 3-byte
//! lookup tag `tag_i` ([`crate::note_tag`]), derived from the note key and the
//! commitment number, then 9 bytes from the caller's secure random source, new
//! for every note. The tag lets a wallet read only the buckets of notes its own
//! tags fall in; being part of the nonce, it is authenticated, so a changed
//! tag fails to decrypt. Reading ignores what the nonce holds, so a note with
//! a fully random nonce still decrypts. The associated data ties the note to
//! its chain and its leaf, so a note copied to another leaf or another chain
//! does not decrypt.
//!
//! The note's contents hold the commitment's number and amount, and its
//! capsule the rule's private fields: they have no `Debug` or `Display`, and
//! every plaintext buffer is overwritten with zeros after use. The cipher's
//! own state is not wiped: the crate's `zeroize` feature needs a crate the
//! shared cargo home does not hold.

use core::fmt;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use rand_core::CryptoRng;

use crate::commit::{Amount, Commitment, ContentFingerprint, Rule, Salt, TypeTag, COIN_V2, DATA_V2};
use crate::derive::NoteKey;
use crate::hash;
use crate::note_tag::{lookup_tag, LOOKUP_TAG_BYTES};
use crate::wipe::wipe;

/// Length of the note version 2 fields: the whole plaintext of a reveal's
/// remainder note, and the first part of a version 3 plaintext.
pub const NOTE_V2_PLAINTEXT_BYTES: usize = 128;
/// Length of the capsule at the end of a version 3 plaintext.
pub const CAPSULE_BYTES: usize = 224;
/// Length of the note plaintext: the version 2 fields, then the capsule.
pub const NOTE_PLAINTEXT_BYTES: usize = NOTE_V2_PLAINTEXT_BYTES + CAPSULE_BYTES;
/// Length of the nonce at the start of a note.
pub const NOTE_NONCE_BYTES: usize = 12;
/// Length of the tag at the end of a note.
pub const NOTE_TAG_BYTES: usize = 16;
/// Length of every note in the tree: nonce, ciphertext and tag.
pub const NOTE_BYTES: usize = NOTE_NONCE_BYTES + NOTE_PLAINTEXT_BYTES + NOTE_TAG_BYTES;
/// Length of the note slot of the version 1 coin reveal and of the data
/// reveal: a note version 2, nonce, 128-byte ciphertext and tag.
pub const REVEAL_NOTE_BYTES: usize = NOTE_NONCE_BYTES + NOTE_V2_PLAINTEXT_BYTES + NOTE_TAG_BYTES;
/// Length of the associated data: `chain_id` as 8 bytes, then `C`.
pub const NOTE_ASSOCIATED_DATA_BYTES: usize = 8 + 32;
/// Note version 2, byte 0 of a reveal's remainder note plaintext.
pub const NOTE_VERSION_2: u8 = 0x02;
/// Note version 3, byte 0 of the plaintext of every note in the tree but a
/// reveal's padded remainder note.
pub const NOTE_VERSION_3: u8 = 0x03;
/// Scheme 1, byte 1 of the plaintext (spec 01, section 10).
pub const SCHEME_ID: u8 = 0x01;
/// Capsule version 0: the empty rule, all 224 bytes zero.
pub const CAPSULE_VERSION_EMPTY: u8 = 0x00;
/// Capsule version 1: a rule other than the empty rule.
pub const CAPSULE_VERSION_1: u8 = 0x01;
/// The most bytes of policy parameters a capsule holds.
pub const CAPSULE_PARAMS_BYTES: usize = 64;
/// Tag of `params_hash = K("ghost/policy-params/v1", params)` (spec 10,
/// section 3.1).
pub const TAG_POLICY_PARAMS: &str = "ghost/policy-params/v1";

const _: () = assert!(NOTE_BYTES == 380 && NOTE_BYTES == ghost_proofs::NOTE_V3_BYTES);
const _: () = assert!(REVEAL_NOTE_BYTES == 156 && REVEAL_NOTE_BYTES == ghost_proofs::NOTE_BYTES);
const _: () = assert!(NOTE_PLAINTEXT_BYTES == 352);
const _: () = assert!(POLICY_ADDRESS_BYTES == ghost_proofs::POLICY_ADDRESS_BYTES);

// Plaintext offsets of the note version 2 fields (spec 01, section 9): a
// 12-byte amount, then the 16-byte salt after the rule.
const AT_TYPE: usize = 2;
const AT_NUMBER: usize = 4;
const AT_AMOUNT: usize = 12;
const AT_CONTENT_FINGERPRINT: usize = 24;
const AT_CONTENT_LENGTH: usize = 56;
const AT_RULE: usize = 64;
const AT_SALT: usize = 96;
const AT_PADDING: usize = 112;

const _: () = assert!(AT_PADDING - AT_SALT == crate::commit::SALT_BYTES);

/// Length of the policy address in a capsule.
pub const POLICY_ADDRESS_BYTES: usize = 20;

// Capsule offsets (spec 10, section 3.2).
const CAP_ADDRESS: usize = 1;
const CAP_CODEHASH: usize = CAP_ADDRESS + POLICY_ADDRESS_BYTES;
const CAP_OVERRIDE: usize = CAP_CODEHASH + 32;
const CAP_ACTION_TAG: usize = CAP_OVERRIDE + 32;
const CAP_ACTION_SALT: usize = CAP_ACTION_TAG + 32;
const CAP_PARAMS_LEN: usize = CAP_ACTION_SALT + 32;
const CAP_PARAMS: usize = CAP_PARAMS_LEN + 1;
const CAP_PAD: usize = CAP_PARAMS + CAPSULE_PARAMS_BYTES;

const _: () = assert!(CAP_PAD + 10 == CAPSULE_BYTES);

/// Why a note was not read. It never carries a byte of the note.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NoteError {
    /// The tag does not authenticate: the note was written under another key,
    /// for another leaf or another chain, or it was changed.
    Unauthentic,
    /// A note version other than the one read: [`NOTE_VERSION_3`] for a note
    /// in the tree, [`NOTE_VERSION_2`] for a reveal's remainder note. The
    /// unsalted version 1 is unknown to both.
    UnknownVersion,
    /// A scheme ID other than [`SCHEME_ID`].
    UnknownScheme,
    /// A type tag other than `COIN_V2` and `DATA_V2`, the unsalted version 1
    /// tags among them.
    UnknownType,
    /// An amount above `2^96 - 1`.
    AmountTooLarge,
    /// Padding bytes of the note version 2 fields that are not zero.
    NonZeroPadding,
    /// The capsule is not one a wallet writes for the note's rule: a capsule
    /// version other than 0 and 1, a non-zero version 0 capsule, a
    /// `params_len` above 64, non-zero bytes after the params or in the pad,
    /// or a rule recomputed from the capsule that is not the note's rule.
    BadCapsule,
}

impl fmt::Debug for NoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unauthentic => "Unauthentic",
            Self::UnknownVersion => "UnknownVersion",
            Self::UnknownScheme => "UnknownScheme",
            Self::UnknownType => "UnknownType",
            Self::AmountTooLarge => "AmountTooLarge",
            Self::NonZeroPadding => "NonZeroPadding",
            Self::BadCapsule => "BadCapsule",
        })
    }
}

impl fmt::Display for NoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unauthentic => "the note does not decrypt under this key for this leaf",
            Self::UnknownVersion => "unknown note version",
            Self::UnknownScheme => "unknown scheme ID",
            Self::UnknownType => "unknown type tag",
            Self::AmountTooLarge => "the amount is above 2^96 - 1 wei",
            Self::NonZeroPadding => "the note padding is not zero",
            Self::BadCapsule => "the note's capsule does not open its rule",
        })
    }
}

impl std::error::Error for NoteError {}

/// The capsule of a note version 3 (spec 10, section 3.2): what opens the
/// note's rule, so a wallet restoring from the digits can rebuild it.
///
/// Version 0 is the empty rule, every field zero. Version 1 holds the fields
/// of any other rule. Only [`Capsule::empty`], [`Capsule::policy`] and
/// [`Capsule::from_bytes`] make one, so a capsule always has a known version,
/// at most 64 bytes of params and zeros after them.
///
/// It holds the rule's private fields (the action salt among them), so it has
/// no `Debug` or `Display`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Capsule {
    version: u8,
    policy_address: [u8; POLICY_ADDRESS_BYTES],
    policy_codehash: [u8; 32],
    override_hash: [u8; 32],
    action_tag: [u8; 32],
    action_salt: [u8; 32],
    params_len: u8,
    params: [u8; CAPSULE_PARAMS_BYTES],
}

impl Capsule {
    /// The version 0 capsule of a coin or data commitment with the empty
    /// rule: all 224 bytes zero.
    pub const fn empty() -> Self {
        Self {
            version: CAPSULE_VERSION_EMPTY,
            policy_address: [0; POLICY_ADDRESS_BYTES],
            policy_codehash: [0; 32],
            override_hash: [0; 32],
            action_tag: [0; 32],
            action_salt: [0; 32],
            params_len: 0,
            params: [0; CAPSULE_PARAMS_BYTES],
        }
    }

    /// The version 1 capsule of a policy rule (spec 10, section 3.1).
    /// `override_hash` is 32 zero bytes for a rule with no override;
    /// `action_tag` and `action_salt` are 32 zero bytes for a coin with no
    /// actions. More than 64 bytes of `params` is [`NoteError::BadCapsule`].
    pub fn policy(
        policy_address: [u8; POLICY_ADDRESS_BYTES],
        policy_codehash: [u8; 32],
        params: &[u8],
        override_hash: [u8; 32],
        action_tag: [u8; 32],
        action_salt: [u8; 32],
    ) -> Result<Self, NoteError> {
        if params.len() > CAPSULE_PARAMS_BYTES {
            return Err(NoteError::BadCapsule);
        }
        let mut padded = [0u8; CAPSULE_PARAMS_BYTES];
        padded[..params.len()].copy_from_slice(params);
        Ok(Self {
            version: CAPSULE_VERSION_1,
            policy_address,
            policy_codehash,
            override_hash,
            action_tag,
            action_salt,
            params_len: params.len() as u8,
            params: padded,
        })
    }

    /// The capsule version: [`CAPSULE_VERSION_EMPTY`] or
    /// [`CAPSULE_VERSION_1`].
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Whether this is the version 0 capsule of the empty rule.
    pub const fn is_empty(&self) -> bool {
        self.version == CAPSULE_VERSION_EMPTY
    }

    /// The policy address.
    pub const fn policy_address(&self) -> &[u8; POLICY_ADDRESS_BYTES] {
        &self.policy_address
    }

    /// The policy's code hash.
    pub const fn policy_codehash(&self) -> &[u8; 32] {
        &self.policy_codehash
    }

    /// The override hash; 32 zero bytes for no override.
    pub const fn override_hash(&self) -> &[u8; 32] {
        &self.override_hash
    }

    /// The action tag; 32 zero bytes for no actions.
    pub const fn action_tag(&self) -> &[u8; 32] {
        &self.action_tag
    }

    /// The action salt; 32 zero bytes for no actions.
    pub const fn action_salt(&self) -> &[u8; 32] {
        &self.action_salt
    }

    /// The policy parameters, 0 to 64 bytes.
    pub fn params(&self) -> &[u8] {
        &self.params[..usize::from(self.params_len)]
    }

    /// `params_hash = K("ghost/policy-params/v1", params)`.
    pub fn params_hash(&self) -> [u8; 32] {
        hash::k(TAG_POLICY_PARAMS, &[self.params()])
    }

    /// The rule this capsule opens: the empty rule for version 0, otherwise
    /// `K("ghost/reveal-policy/v2", ...)` of spec 10, section 3.1.
    pub fn rule(&self) -> Rule {
        if self.is_empty() {
            return Rule::EMPTY;
        }
        Rule::from_bytes(ghost_proofs::reveal_policy_rule(
            &self.policy_address,
            &self.policy_codehash,
            &self.params_hash(),
            &self.override_hash,
            &self.action_tag,
            &self.action_salt,
        ))
    }

    /// The 224 bytes of the capsule. The caller wipes them after use.
    pub fn to_bytes(&self) -> [u8; CAPSULE_BYTES] {
        let mut out = [0u8; CAPSULE_BYTES];
        if self.is_empty() {
            return out;
        }
        out[0] = self.version;
        out[CAP_ADDRESS..CAP_CODEHASH].copy_from_slice(&self.policy_address);
        out[CAP_CODEHASH..CAP_OVERRIDE].copy_from_slice(&self.policy_codehash);
        out[CAP_OVERRIDE..CAP_ACTION_TAG].copy_from_slice(&self.override_hash);
        out[CAP_ACTION_TAG..CAP_ACTION_SALT].copy_from_slice(&self.action_tag);
        out[CAP_ACTION_SALT..CAP_PARAMS_LEN].copy_from_slice(&self.action_salt);
        out[CAP_PARAMS_LEN] = self.params_len;
        out[CAP_PARAMS..CAP_PAD].copy_from_slice(&self.params);
        out
    }

    /// Reads 224 capsule bytes, rejecting as [`NoteError::BadCapsule`] a
    /// version other than 0 and 1, a version 0 capsule with a non-zero byte,
    /// a `params_len` above 64 and a non-zero byte after the params or in the
    /// pad. It does not compare the rule with a note's: [`decrypt_note`] does.
    pub fn from_bytes(bytes: &[u8; CAPSULE_BYTES]) -> Result<Self, NoteError> {
        match bytes[0] {
            CAPSULE_VERSION_EMPTY => {
                if bytes.iter().any(|&byte| byte != 0) {
                    return Err(NoteError::BadCapsule);
                }
                Ok(Self::empty())
            }
            CAPSULE_VERSION_1 => {
                let params_len = usize::from(bytes[CAP_PARAMS_LEN]);
                if params_len > CAPSULE_PARAMS_BYTES {
                    return Err(NoteError::BadCapsule);
                }
                if bytes[CAP_PARAMS + params_len..].iter().any(|&byte| byte != 0) {
                    return Err(NoteError::BadCapsule);
                }
                Self::policy(
                    read(&bytes[CAP_ADDRESS..CAP_CODEHASH]),
                    read(&bytes[CAP_CODEHASH..CAP_OVERRIDE]),
                    &bytes[CAP_PARAMS..CAP_PARAMS + params_len],
                    read(&bytes[CAP_OVERRIDE..CAP_ACTION_TAG]),
                    read(&bytes[CAP_ACTION_TAG..CAP_ACTION_SALT]),
                    read(&bytes[CAP_ACTION_SALT..CAP_PARAMS_LEN]),
                )
            }
            _ => Err(NoteError::BadCapsule),
        }
    }
}

/// What a note holds besides its capsule: only what the key cannot derive.
/// It never holds `s`, `r`, `b_i`, a key, the digits or a tree position.
///
/// It holds the commitment's number and amount, so it has no `Debug` or
/// `Display`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NoteContents {
    /// `COIN_V2` or `DATA_V2`.
    pub type_tag: TypeTag,
    /// The commitment number `i` (spec 01, section 8).
    pub number: u64,
    /// The amount; zero for data.
    pub amount: Amount,
    /// The content fingerprint; 32 zero bytes for a coin.
    pub content_fingerprint: ContentFingerprint,
    /// The content length in bytes; zero for a coin.
    pub content_length: u64,
    /// The rule; the empty rule is 32 zero bytes.
    pub rule: Rule,
    /// The commitment's salt.
    pub salt: Salt,
}

/// Whether a type tag is one a note can hold: `COIN_V2` or `DATA_V2`.
fn is_known_type(type_tag: TypeTag) -> bool {
    matches!(type_tag, COIN_V2 | DATA_V2)
}

impl NoteContents {
    /// The contents of the note of salted coin commitment number `number`,
    /// carrying its salt.
    pub fn salted_coin(number: u64, amount: Amount, rule: Rule, salt: Salt) -> Self {
        Self {
            type_tag: COIN_V2,
            number,
            amount,
            content_fingerprint: ContentFingerprint::COIN,
            content_length: 0,
            rule,
            salt,
        }
    }

    /// The note version [`encrypt_note`] writes these contents as: always
    /// [`NOTE_VERSION_3`].
    pub fn version(&self) -> u8 {
        NOTE_VERSION_3
    }

    /// The 128 bytes of the note version 2 fields under `version`.
    ///
    /// # Panics
    ///
    /// If the type tag is not `COIN_V2` or `DATA_V2`.
    fn fields(&self, version: u8) -> [u8; NOTE_V2_PLAINTEXT_BYTES] {
        assert!(
            is_known_type(self.type_tag),
            "the note's type tag is not COIN_V2 or DATA_V2"
        );
        let mut out = [0u8; NOTE_V2_PLAINTEXT_BYTES];
        out[0] = version;
        out[1] = SCHEME_ID;
        out[AT_TYPE..AT_NUMBER].copy_from_slice(&self.type_tag);
        out[AT_NUMBER..AT_AMOUNT].copy_from_slice(&self.number.to_be_bytes());
        // The amount is right-aligned in its 12-byte field; `V_MAX` fits.
        let amount = self.amount.to_bytes();
        out[AT_AMOUNT..AT_CONTENT_FINGERPRINT]
            .copy_from_slice(&amount[32 - (AT_CONTENT_FINGERPRINT - AT_AMOUNT)..]);
        out[AT_CONTENT_FINGERPRINT..AT_CONTENT_LENGTH]
            .copy_from_slice(self.content_fingerprint.as_bytes());
        out[AT_CONTENT_LENGTH..AT_RULE].copy_from_slice(&self.content_length.to_be_bytes());
        out[AT_RULE..AT_SALT].copy_from_slice(self.rule.as_bytes());
        out[AT_SALT..AT_PADDING].copy_from_slice(self.salt.as_bytes());
        out
    }

    /// Reads the note version 2 fields, whose version byte must be
    /// `version`, rejecting an unknown version, scheme or type tag, non-zero
    /// padding and an amount above the maximum.
    fn read_fields(fields: &[u8; NOTE_V2_PLAINTEXT_BYTES], version: u8) -> Result<Self, NoteError> {
        if fields[0] != version {
            return Err(NoteError::UnknownVersion);
        }
        if fields[1] != SCHEME_ID {
            return Err(NoteError::UnknownScheme);
        }
        let type_tag: TypeTag = [fields[AT_TYPE], fields[AT_TYPE + 1]];
        if !is_known_type(type_tag) {
            return Err(NoteError::UnknownType);
        }
        if fields[AT_PADDING..].iter().any(|&byte| byte != 0) {
            return Err(NoteError::NonZeroPadding);
        }
        let mut amount_word = [0u8; 16];
        amount_word[16 - (AT_CONTENT_FINGERPRINT - AT_AMOUNT)..]
            .copy_from_slice(&fields[AT_AMOUNT..AT_CONTENT_FINGERPRINT]);
        let amount = Amount::new(u128::from_be_bytes(amount_word))
            .map_err(|_| NoteError::AmountTooLarge)?;
        Ok(Self {
            type_tag,
            number: u64::from_be_bytes(read(&fields[AT_NUMBER..AT_AMOUNT])),
            amount,
            content_fingerprint: ContentFingerprint::from_bytes(read(
                &fields[AT_CONTENT_FINGERPRINT..AT_CONTENT_LENGTH],
            )),
            content_length: u64::from_be_bytes(read(&fields[AT_CONTENT_LENGTH..AT_RULE])),
            rule: Rule::from_bytes(read(&fields[AT_RULE..AT_SALT])),
            salt: Salt::from_bytes(read(&fields[AT_SALT..AT_PADDING])),
        })
    }

    /// The 352-byte plaintext of note version 3: the version 2 fields with
    /// version byte `0x03`, then `capsule`. The caller wipes it after use.
    ///
    /// # Panics
    ///
    /// If the type tag is not `COIN_V2` or `DATA_V2`, or if the capsule does
    /// not open the contents' rule: a wallet never writes such a note.
    pub fn to_plaintext(&self, capsule: &Capsule) -> [u8; NOTE_PLAINTEXT_BYTES] {
        assert!(
            capsule.rule() == self.rule,
            "the capsule does not open the note's rule"
        );
        let mut out = [0u8; NOTE_PLAINTEXT_BYTES];
        let mut fields = self.fields(NOTE_VERSION_3);
        out[..NOTE_V2_PLAINTEXT_BYTES].copy_from_slice(&fields);
        wipe(&mut fields);
        let mut capsule = capsule.to_bytes();
        out[NOTE_V2_PLAINTEXT_BYTES..].copy_from_slice(&capsule);
        wipe(&mut capsule);
        out
    }

    /// Reads a version 3 plaintext: the version 2 fields under version byte
    /// `0x03` (rejecting an unknown version, scheme or type tag, an amount
    /// above the maximum and non-zero padding), then the capsule, which must
    /// be well formed and open the rule at offset 64
    /// ([`NoteError::BadCapsule`] otherwise).
    pub fn from_plaintext(plaintext: &[u8; NOTE_PLAINTEXT_BYTES]) -> Result<(Self, Capsule), NoteError> {
        let mut fields: [u8; NOTE_V2_PLAINTEXT_BYTES] = read(&plaintext[..NOTE_V2_PLAINTEXT_BYTES]);
        let contents = Self::read_fields(&fields, NOTE_VERSION_3);
        wipe(&mut fields);
        let contents = contents?;
        let mut bytes: [u8; CAPSULE_BYTES] = read(&plaintext[NOTE_V2_PLAINTEXT_BYTES..]);
        let capsule = Capsule::from_bytes(&bytes);
        wipe(&mut bytes);
        let capsule = capsule?;
        if capsule.rule() != contents.rule {
            return Err(NoteError::BadCapsule);
        }
        Ok((contents, capsule))
    }

    /// The 128-byte plaintext of note version 2, a reveal's remainder note.
    /// The caller wipes it after use.
    ///
    /// # Panics
    ///
    /// If the type tag is not `COIN_V2` or `DATA_V2`. The constructors never
    /// make such contents.
    pub fn to_plaintext_v2(&self) -> [u8; NOTE_V2_PLAINTEXT_BYTES] {
        self.fields(NOTE_VERSION_2)
    }

    /// Reads a note version 2 plaintext, rejecting an unknown version
    /// (version 1 and version 3 among them), scheme or type tag, an amount
    /// above the maximum and non-zero padding.
    pub fn from_plaintext_v2(plaintext: &[u8; NOTE_V2_PLAINTEXT_BYTES]) -> Result<Self, NoteError> {
        Self::read_fields(plaintext, NOTE_VERSION_2)
    }
}

/// The last `N` bytes of `bytes`, as an array.
fn read<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[bytes.len() - N..]);
    out
}

/// The associated data of a note: `chain_id` as 8 bytes, then the leaf `C`
/// it is stored with.
pub fn note_associated_data(chain_id: u64, leaf: &Commitment) -> [u8; NOTE_ASSOCIATED_DATA_BYTES] {
    let mut out = [0u8; NOTE_ASSOCIATED_DATA_BYTES];
    out[..8].copy_from_slice(&chain_id.to_be_bytes());
    out[8..].copy_from_slice(leaf.as_bytes());
    out
}

/// ChaCha20-Poly1305 (RFC 8439, section 2.8): encrypts `buffer` in place and
/// returns the tag.
pub fn chacha20poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; NOTE_NONCE_BYTES],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> [u8; NOTE_TAG_BYTES] {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(*nonce), associated_data, buffer.into())
        .expect("a note is far below the cipher's length limit");
    let mut out = [0u8; NOTE_TAG_BYTES];
    out.copy_from_slice(&tag);
    out
}

/// ChaCha20-Poly1305 (RFC 8439, section 2.8): checks the tag and decrypts
/// `buffer` in place. On a bad tag the buffer is overwritten with zeros.
pub fn chacha20poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; NOTE_NONCE_BYTES],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &[u8; NOTE_TAG_BYTES],
) -> Result<(), NoteError> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    match cipher.decrypt_inout_detached(
        &Nonce::from(*nonce),
        associated_data,
        (&mut *buffer).into(),
        &Tag::from(*tag),
    ) {
        Ok(()) => Ok(()),
        Err(_) => {
            wipe(buffer);
            Err(NoteError::Unauthentic)
        }
    }
}

/// Seals `plaintext` into `note` (nonce, ciphertext, tag), whose length is
/// the plaintext's plus the nonce and the tag. The nonce is the lookup tag
/// of `number` under the note key, then 9 fresh random bytes.
fn seal_into<R: CryptoRng + ?Sized>(
    key: &NoteKey,
    chain_id: u64,
    leaf: &Commitment,
    number: u64,
    plaintext: &[u8],
    note: &mut [u8],
    rng: &mut R,
) {
    debug_assert_eq!(note.len(), NOTE_NONCE_BYTES + plaintext.len() + NOTE_TAG_BYTES);
    let (nonce, rest) = note.split_at_mut(NOTE_NONCE_BYTES);
    let (tag_bytes, random) = nonce.split_at_mut(LOOKUP_TAG_BYTES);
    tag_bytes.copy_from_slice(&lookup_tag(key, number));
    rng.fill_bytes(random);
    let nonce: [u8; NOTE_NONCE_BYTES] = read(nonce);
    let (body, tag_slot) = rest.split_at_mut(plaintext.len());
    body.copy_from_slice(plaintext);
    let tag = chacha20poly1305_seal(
        key.as_bytes(),
        &nonce,
        &note_associated_data(chain_id, leaf),
        body,
    );
    tag_slot.copy_from_slice(&tag);
}

/// Opens `note` into `plaintext`, whose length is the note's less the nonce
/// and the tag. On a bad tag the plaintext is all zeros.
fn open_into(
    key: &NoteKey,
    chain_id: u64,
    leaf: &Commitment,
    note: &[u8],
    plaintext: &mut [u8],
) -> Result<(), NoteError> {
    debug_assert_eq!(note.len(), NOTE_NONCE_BYTES + plaintext.len() + NOTE_TAG_BYTES);
    let nonce: [u8; NOTE_NONCE_BYTES] = read(&note[..NOTE_NONCE_BYTES]);
    let tag: [u8; NOTE_TAG_BYTES] = read(&note[note.len() - NOTE_TAG_BYTES..]);
    plaintext.copy_from_slice(&note[NOTE_NONCE_BYTES..note.len() - NOTE_TAG_BYTES]);
    chacha20poly1305_open(
        key.as_bytes(),
        &nonce,
        &note_associated_data(chain_id, leaf),
        plaintext,
        &tag,
    )
}

/// Encrypts a note version 3 under the note key for the leaf `C` on chain
/// `chain_id`: the contents, then `capsule` ([`Capsule::empty`] for the empty
/// rule). The nonce is 12 bytes: the lookup tag of the contents' number under
/// this note key (nonce bytes 0 to 2), then 9 fresh bytes from the caller's
/// secure random source. The note is 380 bytes whatever the rule.
///
/// # Panics
///
/// As [`NoteContents::to_plaintext`], if the type tag is not `COIN_V2` or
/// `DATA_V2` or the capsule does not open the contents' rule.
pub fn encrypt_note<R: CryptoRng + ?Sized>(
    key: &NoteKey,
    chain_id: u64,
    leaf: &Commitment,
    contents: &NoteContents,
    capsule: &Capsule,
    rng: &mut R,
) -> [u8; NOTE_BYTES] {
    let mut note = [0u8; NOTE_BYTES];
    let mut plaintext = contents.to_plaintext(capsule);
    seal_into(key, chain_id, leaf, contents.number, &plaintext, &mut note, rng);
    wipe(&mut plaintext);
    note
}

/// Decrypts a note version 3 stored with the leaf `C` on chain `chain_id`,
/// and returns its contents and its capsule.
///
/// Rejects a note whose tag does not authenticate under this key, leaf and
/// chain, then one whose version (anything but 3), scheme ID or type tag is
/// unknown, whose padding is not zero or whose amount is above the maximum,
/// and last one whose capsule is malformed or does not open its rule
/// ([`NoteError::BadCapsule`]). It does not check that the contents open
/// `C`: restore does that.
pub fn decrypt_note_with_capsule(
    key: &NoteKey,
    chain_id: u64,
    leaf: &Commitment,
    note: &[u8; NOTE_BYTES],
) -> Result<(NoteContents, Capsule), NoteError> {
    let mut plaintext = [0u8; NOTE_PLAINTEXT_BYTES];
    let result = open_into(key, chain_id, leaf, note, &mut plaintext)
        .and_then(|()| NoteContents::from_plaintext(&plaintext));
    wipe(&mut plaintext);
    result
}

/// [`decrypt_note_with_capsule`], keeping only the contents: the capsule is
/// checked against the rule all the same.
pub fn decrypt_note(
    key: &NoteKey,
    chain_id: u64,
    leaf: &Commitment,
    note: &[u8; NOTE_BYTES],
) -> Result<NoteContents, NoteError> {
    decrypt_note_with_capsule(key, chain_id, leaf, note).map(|(contents, _)| contents)
}

/// Encrypts a note version 2, the 156-byte remainder note of a version 1
/// coin reveal, as [`encrypt_note`] does but with no capsule.
///
/// # Panics
///
/// As [`NoteContents::to_plaintext_v2`], if the type tag is not `COIN_V2` or
/// `DATA_V2`.
pub fn encrypt_note_v2<R: CryptoRng + ?Sized>(
    key: &NoteKey,
    chain_id: u64,
    leaf: &Commitment,
    contents: &NoteContents,
    rng: &mut R,
) -> [u8; REVEAL_NOTE_BYTES] {
    let mut note = [0u8; REVEAL_NOTE_BYTES];
    let mut plaintext = contents.to_plaintext_v2();
    seal_into(key, chain_id, leaf, contents.number, &plaintext, &mut note, rng);
    wipe(&mut plaintext);
    note
}

/// Decrypts a 156-byte note version 2, a reveal's remainder note, stored with
/// the leaf `C` on chain `chain_id`. Rejects what [`decrypt_note`] rejects
/// but the capsule, and any version but 2.
pub fn decrypt_note_v2(
    key: &NoteKey,
    chain_id: u64,
    leaf: &Commitment,
    note: &[u8; REVEAL_NOTE_BYTES],
) -> Result<NoteContents, NoteError> {
    let mut plaintext = [0u8; NOTE_V2_PLAINTEXT_BYTES];
    let result = open_into(key, chain_id, leaf, note, &mut plaintext)
        .and_then(|()| NoteContents::from_plaintext_v2(&plaintext));
    wipe(&mut plaintext);
    result
}

/// A reveal's 156-byte remainder note as the tree stores it: the note, then
/// 224 zero bytes, 380 bytes like every other note.
pub fn pad_reveal_note(note: &[u8; REVEAL_NOTE_BYTES]) -> [u8; NOTE_BYTES] {
    let mut out = [0u8; NOTE_BYTES];
    out[..REVEAL_NOTE_BYTES].copy_from_slice(note);
    out
}

/// The 156-byte reveal note inside a 380-byte tree note, if the tree note is
/// a padded one: every byte after the first 156 zero.
pub fn unpad_reveal_note(note: &[u8; NOTE_BYTES]) -> Option<[u8; REVEAL_NOTE_BYTES]> {
    if note[REVEAL_NOTE_BYTES..].iter().any(|&byte| byte != 0) {
        return None;
    }
    Some(read(&note[..REVEAL_NOTE_BYTES]))
}
