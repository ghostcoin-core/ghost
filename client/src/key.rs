//! The Phantom Key: generation, formatting, entry and the checksum (spec 01,
//! sections 5 and 6).
//!
//! The default key is 24 words: a 256-bit secret and an 8-bit check
//! ([`KeyFormat::Words`]). The same key can be shown as 21 groups of four
//! digits: 80 secret digits and one checksum group. The digit keys issued
//! before it still parse and derive the same values: a standard key is twelve
//! groups of four digits, groups 1 to 11 the secret and group 12 the
//! checksum; a long key is twenty-four groups, groups 12 and 24 checksums, the
//! rest the secret. A [`PhantomKey`] only exists with its check correct, so
//! nothing is ever derived from words or digits that failed it.

use core::fmt;

use rand_core::CryptoRng;

use crate::hash::{self, TAG_KEY_CHECK};
use crate::key_words::{self, SECRET_BYTES, SECRET_DIGITS};
use crate::wipe::wipe;

/// Digits in a long key, the longest format.
const MAX_DIGITS: usize = 96;
/// Secret digits in a long key.
const MAX_SECRET_DIGITS: usize = 88;
/// Digits in one group.
const GROUP: usize = 4;
/// Digits in one half of a key: eleven secret groups and one checksum group.
const HALF: usize = 48;
/// Secret digits in one half of a key.
const HALF_SECRET: usize = 44;

/// The key formats. Typed words select the words format; typed digits select
/// a format by their number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFormat {
    /// Twelve groups: 44 secret digits and one checksum group.
    Standard,
    /// Twenty-four groups: 88 secret digits and two checksum groups.
    Long,
    /// Twenty-four words: a 256-bit secret and an 8-bit check. Shown as digits
    /// it is twenty-one groups: 80 secret digits and one checksum group.
    Words,
}

impl KeyFormat {
    /// The format of new keys: 24 words, about 128 bits of strength even
    /// against a quantum search.
    pub const DEFAULT: Self = Self::Words;

    /// The format code: `0x0C` for twelve groups, `0x18` for twenty-four,
    /// `0x20` for words. It is the first byte of the key bytes and of every
    /// checksum input.
    pub const fn code(self) -> u8 {
        match self {
            Self::Standard => 0x0C,
            Self::Long => 0x18,
            Self::Words => key_words::CODE,
        }
    }

    /// The number of groups of four digits: 12, 24, or 21 for the digit view
    /// of a words key.
    pub const fn groups(self) -> usize {
        match self {
            Self::Standard => 12,
            Self::Long => 24,
            Self::Words => SECRET_DIGITS / GROUP + 1,
        }
    }

    /// The number of digits, checksum groups included: 48, 96 or 84.
    pub const fn digit_count(self) -> usize {
        self.groups() * GROUP
    }

    /// The number of secret digits: 44, 88 or 80.
    pub const fn secret_digit_count(self) -> usize {
        match self {
            Self::Standard => HALF_SECRET,
            Self::Long => MAX_SECRET_DIGITS,
            Self::Words => SECRET_DIGITS,
        }
    }

    /// The number of words, for the format written as words: 24.
    pub const fn word_count(self) -> Option<usize> {
        match self {
            Self::Words => Some(key_words::WORDS),
            Self::Standard | Self::Long => None,
        }
    }

    /// The format with this many digits, if any.
    pub const fn from_digit_count(digits: usize) -> Option<Self> {
        match digits {
            48 => Some(Self::Standard),
            84 => Some(Self::Words),
            96 => Some(Self::Long),
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
    /// After removing separators the input has this many digits, not 48, 84
    /// or 96.
    WrongLength {
        /// Number of digits found.
        digits: usize,
    },
    /// The checksum group with this number (12, 21 or 24) does not match the
    /// digits before it.
    ChecksumMismatch {
        /// The group number of the failing checksum, 12, 21 or 24.
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
    /// The 80 secret digits of a words key shown as digits are `2^256` or
    /// more, which no words key can be.
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
                write!(f, "a key has 48 or 96 digits, or 84 for a words key, not {digits}")
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

/// One checksum group: `int(S("ghost/key-check/v1", code, part, digits)) mod
/// 10000`, with the digest read as a big-endian integer (spec 01, section 6).
///
/// `part` is 1 for group 12 (or group 21 of a words key) and 2 for group 24;
/// `digits` are the ASCII secret digits before the check group.
fn check_group(format: KeyFormat, part: u8, digits: &[u8]) -> u16 {
    let mut digest = hash::s(TAG_KEY_CHECK, &[&[format.code()], &[part], digits]);
    let mut value: u32 = 0;
    for &byte in digest.iter() {
        value = (value * 256 + u32::from(byte)) % 10_000;
    }
    wipe(&mut digest);
    value as u16
}

/// The correct checksum groups for these secret digits, in order: one value
/// for a standard key (group 12) and a words key shown as digits (group 21),
/// two for a long key (groups 12 and 24).
///
/// `secret_digits` are the 44, 80 or 88 ASCII secret digits without
/// separators and without the checksum groups.
pub fn check_groups(format: KeyFormat, secret_digits: &[u8]) -> Result<Vec<u16>, KeyError> {
    if secret_digits.len() != format.secret_digit_count() {
        return Err(KeyError::WrongLength {
            digits: secret_digits.len(),
        });
    }
    if let Some(position) = secret_digits.iter().position(|d| !d.is_ascii_digit()) {
        return Err(KeyError::InvalidCharacter { position });
    }
    Ok(match format {
        KeyFormat::Standard => vec![check_group(format, 1, secret_digits)],
        KeyFormat::Long => vec![
            check_group(format, 1, &secret_digits[..HALF_SECRET]),
            check_group(format, 2, secret_digits),
        ],
        KeyFormat::Words => vec![check_group(format, 1, secret_digits)],
    })
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
/// It holds the digits of a digit key, or the 32 secret bytes of a words key,
/// and nothing else. It has no `Debug`, `Display`, `Clone` or serialisation,
/// and its bytes are overwritten with zeros when it is dropped. The library
/// never stores it.
pub struct PhantomKey {
    format: KeyFormat,
    /// ASCII digits of a standard or long key, checksum groups included; only
    /// the first `format.digit_count()` are used, the rest are zero. All zero
    /// for a words key.
    digits: [u8; MAX_DIGITS],
    /// The secret of a words key; all zero for a digit key.
    secret: [u8; SECRET_BYTES],
}

impl Drop for PhantomKey {
    fn drop(&mut self) {
        wipe(&mut self.digits);
        wipe(&mut self.secret);
    }
}

impl PhantomKey {
    fn empty(format: KeyFormat) -> Self {
        Self {
            format,
            digits: [0; MAX_DIGITS],
            secret: [0; SECRET_BYTES],
        }
    }

    /// Generates a new key in the default format, 24 words
    /// ([`KeyFormat::DEFAULT`]), from the caller's secure random source.
    pub fn generate_default<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::generate(KeyFormat::DEFAULT, rng)
    }

    /// Generates a new key from the caller's secure random source.
    ///
    /// A words key takes 32 bytes from the source as its secret. For a digit
    /// key each secret digit is drawn as spec 01, section 5 says: take one
    /// byte from the source, discard it if it is 250 or more, otherwise use
    /// its value modulo 10. The checksum groups are then appended.
    pub fn generate<R: CryptoRng + ?Sized>(format: KeyFormat, rng: &mut R) -> Self {
        let mut key = Self::empty(format);
        if format == KeyFormat::Words {
            rng.fill_bytes(&mut key.secret);
            return key;
        }
        let mut byte = [0u8; 1];
        for position in 0..format.secret_digit_count() {
            let digit = loop {
                rng.fill_bytes(&mut byte);
                if byte[0] < 250 {
                    break b'0' + byte[0] % 10;
                }
            };
            key.digits[Self::secret_position(position)] = digit;
        }
        wipe(&mut byte);
        key.fill_check_groups();
        key
    }

    /// Parses a typed key, as words or as digits.
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
    /// must be exactly 48, 84 or 96 digits. The checksum groups are checked
    /// before the key is returned: group 12 first, so a mistyped first half
    /// of a long key is named before the second. 84 digits are a words key:
    /// after group 21 is checked, the 80 secret digits must be below `2^256`.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        let has_digit = text.bytes().any(|b| b.is_ascii_digit());
        if !has_digit && text.chars().any(char::is_alphabetic) {
            let mut key = Self::empty(KeyFormat::Words);
            key_words::parse_words(text, &mut key.secret)?;
            return Ok(key);
        }
        let mut key = Self::empty(KeyFormat::Standard);
        let mut count = 0usize;
        for (position, ch) in text.chars().enumerate() {
            match ch {
                ' ' | '-' => {}
                '0'..='9' => {
                    if count < MAX_DIGITS {
                        key.digits[count] = ch as u8;
                    }
                    count += 1;
                }
                _ => return Err(KeyError::InvalidCharacter { position }),
            }
        }
        key.format =
            KeyFormat::from_digit_count(count).ok_or(KeyError::WrongLength { digits: count })?;
        if key.format == KeyFormat::Words {
            let expected = check_group(KeyFormat::Words, 1, &key.digits[..SECRET_DIGITS]);
            if read_group(&key.digits[SECRET_DIGITS..]) != expected {
                return Err(KeyError::ChecksumMismatch {
                    group: KeyFormat::Words.groups(),
                });
            }
            key_words::from_digits(&key.digits, &mut key.secret)?;
            wipe(&mut key.digits);
            return Ok(key);
        }
        key.verify_check_groups()?;
        Ok(key)
    }

    /// The key's format.
    pub fn key_format(&self) -> KeyFormat {
        self.format
    }

    /// The key as groups of four digits separated by single spaces. For a
    /// words key this is its digit view: 21 groups, the last the checksum.
    pub fn format_groups(&self) -> FormattedKey {
        let mut digits = [0u8; MAX_DIGITS];
        let n = self.write_digits(&mut digits);
        let mut text = String::with_capacity(self.format.groups() * (GROUP + 1));
        for (index, group) in digits[..n].chunks(GROUP).enumerate() {
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
    /// the user; `None` for a digit key, which has no words.
    pub fn format_words(&self) -> Option<FormattedKey> {
        if self.format != KeyFormat::Words {
            return None;
        }
        let mut text = String::with_capacity(key_words::WORDS * 9);
        key_words::write_words(&self.secret, &mut text);
        Some(FormattedKey(text))
    }

    /// Writes all the ASCII digits, checksum groups included, to the start of
    /// `out` and returns how many there are.
    fn write_digits(&self, out: &mut [u8; MAX_DIGITS]) -> usize {
        let n = self.format.digit_count();
        if self.format == KeyFormat::Words {
            key_words::to_digits(&self.secret, out);
            let check = check_group(KeyFormat::Words, 1, &out[..SECRET_DIGITS]);
            write_group(&mut out[SECRET_DIGITS..], check);
        } else {
            out[..n].copy_from_slice(&self.digits[..n]);
        }
        n
    }

    /// Copies what follows the format code in the key bytes to the start of
    /// `out` and returns how many bytes there are: the ASCII secret digits of
    /// a digit key, in order and without the checksum groups, or the 32
    /// secret bytes of a words key (spec 01, section 7).
    pub(crate) fn copy_key_secret(&self, out: &mut [u8]) -> usize {
        if self.format == KeyFormat::Words {
            out[..SECRET_BYTES].copy_from_slice(&self.secret);
            return SECRET_BYTES;
        }
        self.copy_secret_digits(out)
    }

    /// Copies the ASCII secret digits of a digit key, in order and without the
    /// checksum groups, to the start of `out` and returns how many there are.
    fn copy_secret_digits(&self, out: &mut [u8]) -> usize {
        let n = self.format.secret_digit_count();
        for (position, slot) in out[..n].iter_mut().enumerate() {
            *slot = self.digits[Self::secret_position(position)];
        }
        n
    }

    /// Where secret digit number `position` sits among all the digits: the
    /// second half's secret digits come after group 12.
    fn secret_position(position: usize) -> usize {
        if position < HALF_SECRET {
            position
        } else {
            position + GROUP
        }
    }

    /// The correct checksum groups of a digit key and the digit offset of
    /// each.
    fn expected_check_groups(&self) -> [(usize, u16); 2] {
        let mut secret = [0u8; MAX_SECRET_DIGITS];
        let n = self.copy_secret_digits(&mut secret);
        let first = (HALF_SECRET, check_group(self.format, 1, &secret[..HALF_SECRET]));
        let second = match self.format {
            KeyFormat::Long => (HALF + HALF_SECRET, check_group(self.format, 2, &secret[..n])),
            KeyFormat::Standard | KeyFormat::Words => first,
        };
        wipe(&mut secret);
        [first, second]
    }

    fn fill_check_groups(&mut self) {
        for (offset, value) in self.expected_check_groups() {
            write_group(&mut self.digits[offset..], value);
        }
    }

    fn verify_check_groups(&self) -> Result<(), KeyError> {
        for (offset, value) in self.expected_check_groups() {
            if read_group(&self.digits[offset..]) != value {
                return Err(KeyError::ChecksumMismatch {
                    group: offset / GROUP + 1,
                });
            }
        }
        Ok(())
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
