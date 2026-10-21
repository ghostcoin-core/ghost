//! The encrypted note stored with every commitment (spec 01, section 9).
//!
//! ```text
//! version 1 (128 bytes)  = 0x01 || 0x01 || type || i (8) || v (32) || cf (32)
//!                          || content length (8) || rule (32) || 12 zero bytes
//! version 2 (128 bytes)  = 0x02 || 0x01 || type || i (8) || v (12) || cf (32)
//!                          || content length (8) || rule (32) || salt (16)
//!                          || 16 zero bytes
//! associated data        = chain_id as 8 bytes || C
//! note (156 bytes)       = nonce (12) || ciphertext (128) || tag (16)
//! ```
//!
//! Note version 2 carries the salt of a version 2 commitment, so a wallet
//! restoring from the digits can reopen a remainder. Its type tag must be a
//! version 2 tag (`COIN_V2` or `DATA_V2`), and a version 1 note's a version 1
//! tag (`COIN` or `DATA`); a note whose version and type tag disagree is
//! rejected. The amount of version 2 is 12 bytes, enough for `2^96 - 1`.
//!
//! The cipher is ChaCha20-Poly1305 of RFC 8439, from the `chacha20poly1305`
//! crate, under the key's note key. The nonce is 12 bytes from the caller's
//! secure random source, new for every note. The associated data ties the note
//! to its chain and its leaf, so a note copied to another leaf or another chain
//! does not decrypt.
//!
//! The note's contents hold the commitment's number and amount: they have no
//! `Debug` or `Display`, and every plaintext buffer is overwritten with zeros
//! after use. The cipher's own state is not wiped: the crate's `zeroize`
//! feature needs a crate the shared cargo home does not hold.

use core::fmt;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use rand_core::CryptoRng;

use crate::commit::{
    Amount, Commitment, ContentFingerprint, Rule, Salt, TypeTag, COIN, COIN_V2, DATA, DATA_V2,
};
use crate::derive::NoteKey;
use crate::wipe::wipe;

/// Length of the note plaintext.
pub const NOTE_PLAINTEXT_BYTES: usize = 128;
/// Length of the nonce at the start of a note.
pub const NOTE_NONCE_BYTES: usize = 12;
/// Length of the tag at the end of a note.
pub const NOTE_TAG_BYTES: usize = 16;
/// Length of a note on the chain: nonce, ciphertext and tag.
pub const NOTE_BYTES: usize = NOTE_NONCE_BYTES + NOTE_PLAINTEXT_BYTES + NOTE_TAG_BYTES;
/// Length of the associated data: `chain_id` as 8 bytes, then `C`.
pub const NOTE_ASSOCIATED_DATA_BYTES: usize = 8 + 32;
/// Note version 1, byte 0 of the plaintext: no salt.
pub const NOTE_VERSION: u8 = 0x01;
/// Note version 2, byte 0 of the plaintext: carries the commitment's salt.
pub const NOTE_VERSION_2: u8 = 0x02;
/// Scheme 1, byte 1 of the plaintext (spec 01, section 10).
pub const SCHEME_ID: u8 = 0x01;

const _: () = assert!(NOTE_BYTES == ghost_proofs::NOTE_BYTES);

// Plaintext offsets shared by both note versions (spec 01, section 9).
const AT_TYPE: usize = 2;
const AT_NUMBER: usize = 4;
const AT_AMOUNT: usize = 12;

/// Where the fields after the amount sit in one note version.
struct Layout {
    content_fingerprint: usize,
    content_length: usize,
    rule: usize,
    /// Where the salt starts; the salt ends where the padding starts.
    salt: usize,
    padding: usize,
}

/// Note version 1: a 32-byte amount, no salt.
const LAYOUT_1: Layout = Layout {
    content_fingerprint: 44,
    content_length: 76,
    rule: 84,
    salt: 116,
    padding: 116,
};

/// Note version 2: a 12-byte amount, then the 16-byte salt after the rule.
const LAYOUT_2: Layout = Layout {
    content_fingerprint: 24,
    content_length: 56,
    rule: 64,
    salt: 96,
    padding: 112,
};

const _: () = assert!(LAYOUT_2.padding - LAYOUT_2.salt == crate::commit::SALT_BYTES);

/// Why a note was not read. It never carries a byte of the note.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NoteError {
    /// The tag does not authenticate: the note was written under another key,
    /// for another leaf or another chain, or it was changed.
    Unauthentic,
    /// A note version other than [`NOTE_VERSION`] and [`NOTE_VERSION_2`].
    UnknownVersion,
    /// A scheme ID other than [`SCHEME_ID`].
    UnknownScheme,
    /// A type tag other than `COIN`, `DATA`, `COIN_V2` and `DATA_V2`.
    UnknownType,
    /// A type tag of another version than the note's: note version 1 takes
    /// only `COIN` and `DATA`, note version 2 only `COIN_V2` and `DATA_V2`.
    VersionMismatch,
    /// An amount above `2^96 - 1`.
    AmountTooLarge,
    /// Padding bytes that are not zero.
    NonZeroPadding,
}

impl fmt::Debug for NoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unauthentic => "Unauthentic",
            Self::UnknownVersion => "UnknownVersion",
            Self::UnknownScheme => "UnknownScheme",
            Self::UnknownType => "UnknownType",
            Self::VersionMismatch => "VersionMismatch",
            Self::AmountTooLarge => "AmountTooLarge",
            Self::NonZeroPadding => "NonZeroPadding",
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
            Self::VersionMismatch => "the type tag is not of the note's version",
            Self::AmountTooLarge => "the amount is above 2^96 - 1 wei",
            Self::NonZeroPadding => "the note padding is not zero",
        })
    }
}

impl std::error::Error for NoteError {}

/// What a note holds: only what the key cannot derive. It never holds `s`,
/// `r`, `b_i`, a key, the digits or a tree position.
///
/// It holds the commitment's number and amount, so it has no `Debug` or
/// `Display`.
///
/// A note with a salt is note version 2 and has a version 2 type tag; a note
/// without one is note version 1 and has a version 1 type tag.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NoteContents {
    /// `COIN` or `DATA` in note version 1, `COIN_V2` or `DATA_V2` in note
    /// version 2.
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
    /// The commitment's salt in note version 2; `None` in note version 1.
    pub salt: Option<Salt>,
}

/// The note version a type tag belongs to, if it is a known type tag.
fn note_version_of(type_tag: TypeTag) -> Option<u8> {
    match type_tag {
        COIN | DATA => Some(NOTE_VERSION),
        COIN_V2 | DATA_V2 => Some(NOTE_VERSION_2),
        _ => None,
    }
}

impl NoteContents {
    /// The contents of the version 1 note of coin commitment number
    /// `number`, without a salt.
    pub fn coin(number: u64, amount: Amount, rule: Rule) -> Self {
        Self {
            type_tag: COIN,
            number,
            amount,
            content_fingerprint: ContentFingerprint::COIN,
            content_length: 0,
            rule,
            salt: None,
        }
    }

    /// The contents of the version 2 note of salted coin commitment number
    /// `number`, carrying its salt.
    pub fn salted_coin(number: u64, amount: Amount, rule: Rule, salt: Salt) -> Self {
        Self {
            type_tag: COIN_V2,
            number,
            amount,
            content_fingerprint: ContentFingerprint::COIN,
            content_length: 0,
            rule,
            salt: Some(salt),
        }
    }

    /// The note version these contents are written as: 2 with a salt, 1
    /// without.
    pub fn version(&self) -> u8 {
        if self.salt.is_some() {
            NOTE_VERSION_2
        } else {
            NOTE_VERSION
        }
    }

    /// The 128-byte plaintext. The caller wipes it after use.
    ///
    /// # Panics
    ///
    /// If the type tag is not one of the note's version: a salt with a
    /// version 1 type tag, or no salt with a version 2 type tag. Such
    /// contents have no layout, and the constructors never make them.
    pub fn to_plaintext(&self) -> [u8; NOTE_PLAINTEXT_BYTES] {
        let version = self.version();
        assert!(
            note_version_of(self.type_tag) == Some(version),
            "the note's type tag is not of note version {version}"
        );
        let mut out = [0u8; NOTE_PLAINTEXT_BYTES];
        out[0] = version;
        out[1] = SCHEME_ID;
        out[AT_TYPE..AT_NUMBER].copy_from_slice(&self.type_tag);
        out[AT_NUMBER..AT_AMOUNT].copy_from_slice(&self.number.to_be_bytes());
        let layout = match self.salt {
            None => &LAYOUT_1,
            Some(_) => &LAYOUT_2,
        };
        // The amount is right-aligned in its field: 32 bytes in version 1,
        // 12 in version 2, and `V_MAX` fits in 12.
        let amount = self.amount.to_bytes();
        let width = layout.content_fingerprint - AT_AMOUNT;
        out[AT_AMOUNT..layout.content_fingerprint].copy_from_slice(&amount[32 - width..]);
        out[layout.content_fingerprint..layout.content_length]
            .copy_from_slice(self.content_fingerprint.as_bytes());
        out[layout.content_length..layout.rule].copy_from_slice(&self.content_length.to_be_bytes());
        out[layout.rule..layout.salt].copy_from_slice(self.rule.as_bytes());
        if let Some(salt) = &self.salt {
            out[layout.salt..layout.padding].copy_from_slice(salt.as_bytes());
        }
        out
    }

    /// Reads a plaintext, rejecting an unknown version, scheme or type tag,
    /// a type tag of the other note version, an amount above the maximum and
    /// non-zero padding. A version 2 note returns its salt.
    pub fn from_plaintext(plaintext: &[u8; NOTE_PLAINTEXT_BYTES]) -> Result<Self, NoteError> {
        let version = plaintext[0];
        let layout = match version {
            NOTE_VERSION => &LAYOUT_1,
            NOTE_VERSION_2 => &LAYOUT_2,
            _ => return Err(NoteError::UnknownVersion),
        };
        if plaintext[1] != SCHEME_ID {
            return Err(NoteError::UnknownScheme);
        }
        let type_tag: TypeTag = [plaintext[AT_TYPE], plaintext[AT_TYPE + 1]];
        match note_version_of(type_tag) {
            None => return Err(NoteError::UnknownType),
            Some(tag_version) if tag_version != version => {
                return Err(NoteError::VersionMismatch)
            }
            Some(_) => {}
        }
        if plaintext[layout.padding..].iter().any(|&byte| byte != 0) {
            return Err(NoteError::NonZeroPadding);
        }
        let amount_field = &plaintext[AT_AMOUNT..layout.content_fingerprint];
        let (high, low) = amount_field.split_at(amount_field.len().saturating_sub(16));
        if high.iter().any(|&byte| byte != 0) {
            return Err(NoteError::AmountTooLarge);
        }
        let mut amount_word = [0u8; 16];
        amount_word[16 - low.len()..].copy_from_slice(low);
        let amount = Amount::new(u128::from_be_bytes(amount_word))
            .map_err(|_| NoteError::AmountTooLarge)?;
        let salt = (version == NOTE_VERSION_2)
            .then(|| Salt::from_bytes(read(&plaintext[layout.salt..layout.padding])));
        Ok(Self {
            type_tag,
            number: u64::from_be_bytes(read(&plaintext[AT_NUMBER..AT_AMOUNT])),
            amount,
            content_fingerprint: ContentFingerprint::from_bytes(read(
                &plaintext[layout.content_fingerprint..layout.content_length],
            )),
            content_length: u64::from_be_bytes(read(&plaintext[layout.content_length..layout.rule])),
            rule: Rule::from_bytes(read(&plaintext[layout.rule..layout.salt])),
            salt,
        })
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

/// Encrypts a note under the note key for the leaf `C` on chain `chain_id`,
/// with a fresh 12-byte nonce from the caller's secure random source. The
/// note is version 2 when the contents carry a salt, version 1 otherwise.
///
/// # Panics
///
/// As [`NoteContents::to_plaintext`], if the type tag is not of that version.
pub fn encrypt_note<R: CryptoRng + ?Sized>(
    key: &NoteKey,
    chain_id: u64,
    leaf: &Commitment,
    contents: &NoteContents,
    rng: &mut R,
) -> [u8; NOTE_BYTES] {
    let mut note = [0u8; NOTE_BYTES];
    let (nonce, rest) = note.split_at_mut(NOTE_NONCE_BYTES);
    rng.fill_bytes(nonce);
    let nonce: [u8; NOTE_NONCE_BYTES] = read(nonce);
    let (body, tag_slot) = rest.split_at_mut(NOTE_PLAINTEXT_BYTES);
    let mut plaintext = contents.to_plaintext();
    body.copy_from_slice(&plaintext);
    wipe(&mut plaintext);
    let tag = chacha20poly1305_seal(
        key.as_bytes(),
        &nonce,
        &note_associated_data(chain_id, leaf),
        body,
    );
    tag_slot.copy_from_slice(&tag);
    note
}

/// Decrypts a note stored with the leaf `C` on chain `chain_id`.
///
/// Rejects a note whose tag does not authenticate under this key, leaf and
/// chain, then one whose version, scheme ID or type tag is unknown, whose
/// type tag is not of its version, whose amount is above the maximum or whose
/// padding is not zero. A version 2 note returns the commitment's salt. It
/// does not check that the contents open `C`: restore does that.
pub fn decrypt_note(
    key: &NoteKey,
    chain_id: u64,
    leaf: &Commitment,
    note: &[u8; NOTE_BYTES],
) -> Result<NoteContents, NoteError> {
    let nonce: [u8; NOTE_NONCE_BYTES] = read(&note[..NOTE_NONCE_BYTES]);
    let tag: [u8; NOTE_TAG_BYTES] = read(&note[NOTE_NONCE_BYTES + NOTE_PLAINTEXT_BYTES..]);
    let mut plaintext: [u8; NOTE_PLAINTEXT_BYTES] =
        read(&note[NOTE_NONCE_BYTES..NOTE_NONCE_BYTES + NOTE_PLAINTEXT_BYTES]);
    let result = chacha20poly1305_open(
        key.as_bytes(),
        &nonce,
        &note_associated_data(chain_id, leaf),
        &mut plaintext,
        &tag,
    )
    .and_then(|()| NoteContents::from_plaintext(&plaintext));
    wipe(&mut plaintext);
    result
}
