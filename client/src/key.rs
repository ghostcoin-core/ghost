//! The Phantom Key: generation, formatting, entry and the checksum (spec 01,
//! sections 5 and 6).
//!
//! A Phantom Key is 24 words: a 256-bit secret and an 8-bit check
//! ([`KeyFormat::Words`]). The same key can be shown as 21 groups of four
//! digits: 80 secret digits and one checksum group. There is no other format:
//! digits of any other count are refused. A [`PhantomKey`] only exists with its
//! check correct, so nothing is ever derived from words or digits that failed
//! it.

use core::fmt;

use rand_core::CryptoRng;

use crate::hash::{self, TAG_KEY_CHECK};
use crate::key_words::{self, SECRET_BYTES, SECRET_DIGITS};
use crate::wipe::wipe;

/// Digits in one group.
const GROUP: usize = 4;
/// Digits in the digit view of a key, the checksum group included.
const DIGITS: usize = SECRET_DIGITS + GROUP;

/// The key format. Typed words select it, and so do typed digits of its digit
/// view; no other format exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFormat {
    /// Twenty-four words: a 256-bit secret and an 8-bit check. Shown as digits
    /// it is twenty-one groups: 80 secret digits and one checksum group.
    Words,
}

impl KeyFormat {
    /// The format of new keys: 24 words, about 128 bits of strength even
    /// against a quantum search.
    pub const DEFAULT: Self = Self::Words;

    /// The format code, `0x20`. It is the first byte of the key bytes and of
    /// every checksum input.
    pub const fn code(self) -> u8 {
        match self {
            Self::Words => key_words::CODE,
        }
    }

    /// The number of groups of four digits in the digit view: 21.
    pub const fn groups(self) -> usize {
        match self {
            Self::Words => DIGITS / GROUP,
        }
    }

    /// The number of digits of the digit view, checksum group included: 84.
    pub const fn digit_count(self) -> usize {
        self.groups() * GROUP
    }

    /// The number of secret digits of the digit view: 80.
    pub const fn secret_digit_count(self) -> usize {
        match self {
            Self::Words => SECRET_DIGITS,
        }
    }

    /// The number of words: 24.
    pub const fn word_count(self) -> Option<usize> {
        match self {
            Self::Words => Some(key_words::WORDS),
        }
    }

    /// The format with this many digits: only 84, the digit view of a words
    /// key. The 48 and 96 digits of the old digit keys select nothing.
    pub const fn from_digit_count(digits: usize) -> Option<Self> {
        match digits {
            DIGITS => Some(Self::Words),
            _ => None,
        }
    }
}

/// Why typed words or digits are not a valid Phantom Key. It never carries a
/// digit or a word of the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// A character that cannot be part of a key, at this character position
    /// (counted from zero) of the input. Digits allow ASCII digits, spaces and
    /// hyphens; words allow letters, spaces and hyphens.
    InvalidCharacter {
        /// Character position in the input.
        position: usize,
    },
    /// After removing separators the input has this many digits, not 84.
    WrongLength {
        /// Number of digits found.
        digits: usize,
    },
    /// The checksum group with this number, 21, does not match the digits
    /// before it.
    ChecksumMismatch {
        /// The group number of the failing checksum, 21.
        group: usize,
    },
    /// Word number `word` (counted from one) is not a word of the list. It is
    /// the text `input[start..end]`, so it can be shown to the person who
    /// typed it; it is never corrected to a near word.
    UnknownWord {
        /// The word's number in the input, counted from one.
        word: usize,
        /// Byte offset of the word's first character in the input.
        start: usize,
        /// Byte offset just after the word's last character.
        end: usize,
    },
    /// The input has this many words of the list, not 24.
    WrongWordCount {
        /// Number of words found.
        words: usize,
    },
    /// The 24 words are all in the list, but their check does not match.
    WordCheckMismatch,
    /// The 80 secret digits of a key shown as digits are `2^256` or more,
    /// which no key can be.
    SecretOutOfRange,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter { position } => write!(
                f,
                "character {} cannot be part of a key: a key is words or digits, separated by spaces or hyphens",
                position + 1
            ),
            Self::WrongLength { digits } => {
                write!(f, "a key shown as digits has 84 digits, not {digits}")
            }
            Self::ChecksumMismatch { group } => {
                write!(f, "group {group} does not match the digits before it")
            }
            Self::UnknownWord { word, .. } => {
                write!(f, "word {word} is not in the word list")
            }
            Self::WrongWordCount { words } => {
                write!(f, "a key has 24 words, not {words}")
            }
            Self::WordCheckMismatch => {
                write!(f, "the words do not pass the check: one of them is wrong or out of place")
            }
            Self::SecretOutOfRange => {
                write!(f, "the first 80 digits are too large for a key")
            }
        }
    }
}

impl std::error::Error for KeyError {}

/// The check group: `int(S("ghost/key-check/v1", 0x20, 0x01, digits)) mod
/// 10000`, with the digest read as a big-endian integer (spec 01, section 6).
///
/// `digits` are the 80 ASCII secret digits before group 21.
fn check_group(format: KeyFormat, digits: &[u8]) -> u16 {
    let mut digest = hash::s(TAG_KEY_CHECK, &[&[format.code()], &[0x01], digits]);
    let mut value: u32 = 0;
    for &byte in digest.iter() {
        value = (value * 256 + u32::from(byte)) % 10_000;
    }
    wipe(&mut digest);
    value as u16
}

/// The correct checksum groups for these secret digits: one value, group 21.
///
/// `secret_digits` are the 80 ASCII secret digits without separators and
/// without the checksum group.
pub fn check_groups(format: KeyFormat, secret_digits: &[u8]) -> Result<Vec<u16>, KeyError> {
    if secret_digits.len() != format.secret_digit_count() {
        return Err(KeyError::WrongLength {
            digits: secret_digits.len(),
        });
    }
    if let Some(position) = secret_digits.iter().position(|d| !d.is_ascii_digit()) {
        return Err(KeyError::InvalidCharacter { position });
    }
    Ok(vec![check_group(format, secret_digits)])
}

/// Writes a group value as four ASCII digits with leading zeros.
fn write_group(out: &mut [u8], value: u16) {
    let mut value = value;
    for slot in out[..GROUP].iter_mut().rev() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
    }
}

/// Reads four ASCII digits as a group value.
fn read_group(digits: &[u8]) -> u16 {
    digits[..GROUP]
        .iter()
        .fold(0, |acc, d| acc * 10 + u16::from(d - b'0'))
}

/// A Phantom Key whose check is correct.
///
/// It holds the 32 secret bytes and nothing else. It has no `Debug`,
/// `Display`, `Clone` or serialisation, and its bytes are overwritten with
/// zeros when it is dropped. The library never stores it.
pub struct PhantomKey {
    secret: [u8; SECRET_BYTES],
}

impl Drop for PhantomKey {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

impl PhantomKey {
    fn empty() -> Self {
        Self {
            secret: [0; SECRET_BYTES],
        }
    }

    /// Generates a new key in the default format, 24 words
    /// ([`KeyFormat::DEFAULT`]), from the caller's secure random source.
    pub fn generate_default<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::generate(KeyFormat::DEFAULT, rng)
    }

    /// Generates a new key from the caller's secure random source: 32 bytes
    /// from the source are its secret. [`KeyFormat`] has no other format, so
    /// no other kind of key can be asked for.
    pub fn generate<R: CryptoRng + ?Sized>(format: KeyFormat, rng: &mut R) -> Self {
        let mut key = Self::empty();
        match format {
            KeyFormat::Words => rng.fill_bytes(&mut key.secret),
        }
        key
    }

    /// Parses a typed key, as words or as its digit view.
    ///
    /// Text with a letter and no ASCII digit is read as words: 24 whole words
    /// of the list, in any case, separated by any mix of spaces and hyphens. A
    /// word not in the list is rejected and named, the wrong number of words
    /// is its own error, and the check is verified before the key is
    /// returned.
    ///
    /// Any other text is read as digits. Spaces and hyphens between the
    /// digits are allowed in any mix; any other character, including a letter
    /// or a non-ASCII digit, is rejected. After separators are removed there
    /// must be exactly 84 digits: digits of any other count, such as the 48 or
    /// 96 of the old digit keys, are refused. Group 21 is checked, then the 80
    /// secret digits must be below `2^256`.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        let mut key = Self::empty();
        let has_digit = text.bytes().any(|b| b.is_ascii_digit());
        if !has_digit && text.chars().any(char::is_alphabetic) {
            key_words::parse_words(text, &mut key.secret)?;
            return Ok(key);
        }
        let mut digits = [0u8; DIGITS];
        let mut count = 0usize;
        let mut result = Ok(());
        for (position, ch) in text.chars().enumerate() {
            match ch {
                ' ' | '-' => {}
                '0'..='9' => {
                    if count < DIGITS {
                        digits[count] = ch as u8;
                    }
                    count += 1;
                }
                _ => {
                    result = Err(KeyError::InvalidCharacter { position });
                    break;
                }
            }
        }
        let result = result
            .and_then(|()| {
                KeyFormat::from_digit_count(count).ok_or(KeyError::WrongLength { digits: count })
            })
            .and_then(|format| {
                if read_group(&digits[SECRET_DIGITS..]) != check_group(format, &digits[..SECRET_DIGITS]) {
                    return Err(KeyError::ChecksumMismatch {
                        group: format.groups(),
                    });
                }
                key_words::from_digits(&digits, &mut key.secret)
            });
        wipe(&mut digits);
        result.map(|()| key)
    }

    /// The key's format, always [`KeyFormat::Words`].
    pub fn key_format(&self) -> KeyFormat {
        KeyFormat::Words
    }

    /// The key's digit view: 21 groups of four digits separated by single
    /// spaces, the last the checksum.
    pub fn format_groups(&self) -> FormattedKey {
        let mut digits = [0u8; DIGITS];
        key_words::to_digits(&self.secret, &mut digits);
        let check = check_group(KeyFormat::Words, &digits[..SECRET_DIGITS]);
        write_group(&mut digits[SECRET_DIGITS..], check);
        let mut text = String::with_capacity(KeyFormat::Words.groups() * (GROUP + 1));
        for (index, group) in digits.chunks(GROUP).enumerate() {
            if index > 0 {
                text.push(' ');
            }
            for &digit in group {
                text.push(char::from(digit));
            }
        }
        wipe(&mut digits);
        FormattedKey(text)
    }

    /// The key as 24 words separated by single spaces, the way it is shown to
    /// the user. Every key has words, so this is always `Some`.
    pub fn format_words(&self) -> Option<FormattedKey> {
        let mut text = String::with_capacity(key_words::WORDS * 9);
        key_words::write_words(&self.secret, &mut text);
        Some(FormattedKey(text))
    }

    /// Copies what follows the format code in the key bytes, the 32 secret
    /// bytes, to the start of `out` and returns how many there are (spec 01,
    /// section 7).
    pub(crate) fn copy_key_secret(&self, out: &mut [u8]) -> usize {
        out[..SECRET_BYTES].copy_from_slice(&self.secret);
        SECRET_BYTES
    }
}

/// A Phantom Key as shown to the user: words, or groups of four digits,
/// separated by single spaces. It holds the whole key, so it has no `Debug`,
/// `Display` or `Clone`, and its text is overwritten with zeros when it is
/// dropped.
pub struct FormattedKey(String);

impl FormattedKey {
    /// The text, for showing it to the user once.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for FormattedKey {
    fn drop(&mut self) {
        // SAFETY: zero bytes are valid UTF-8, so the string stays valid.
        wipe(unsafe { self.0.as_bytes_mut() });
    }
}
