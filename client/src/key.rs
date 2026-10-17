//! The Phantom Key: generation, formatting, entry and the checksum (spec 01,
//! sections 5 and 6).
//!
//! A standard key is twelve groups of four digits: groups 1 to 11 are the
//! secret and group 12 the checksum. A long key is twenty-four groups: groups
//! 12 and 24 are checksums, the rest the secret. A [`PhantomKey`] only exists
//! with its checksum groups correct, so nothing is ever derived from digits
//! that failed the check.

use core::fmt;

use rand_core::CryptoRng;

use crate::hash::{self, TAG_KEY_CHECK};
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

/// The two key formats. The number of groups selects the format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFormat {
    /// Twelve groups: 44 secret digits and one checksum group.
    Standard,
    /// Twenty-four groups: 88 secret digits and two checksum groups.
    Long,
}

impl KeyFormat {
    /// The format code: `0x0C` for twelve groups, `0x18` for twenty-four. It is
    /// the first byte of the key bytes and of every checksum input.
    pub const fn code(self) -> u8 {
        match self {
            Self::Standard => 0x0C,
            Self::Long => 0x18,
        }
    }

    /// The number of groups of four digits.
    pub const fn groups(self) -> usize {
        match self {
            Self::Standard => 12,
            Self::Long => 24,
        }
    }

    /// The number of digits, checksum groups included: 48 or 96.
    pub const fn digit_count(self) -> usize {
        self.groups() * GROUP
    }

    /// The number of secret digits: 44 or 88.
    pub const fn secret_digit_count(self) -> usize {
        match self {
            Self::Standard => HALF_SECRET,
            Self::Long => MAX_SECRET_DIGITS,
        }
    }

    /// The format with this many digits, if any.
    pub const fn from_digit_count(digits: usize) -> Option<Self> {
        match digits {
            48 => Some(Self::Standard),
            96 => Some(Self::Long),
            _ => None,
        }
    }
}

/// Why typed digits are not a valid Phantom Key. It never carries a digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// A character that is neither an ASCII digit, a space nor a hyphen, at
    /// this character position (counted from zero) of the input.
    InvalidCharacter {
        /// Character position in the input.
        position: usize,
    },
    /// After removing separators the input has this many digits, not 48 or 96.
    WrongLength {
        /// Number of digits found.
        digits: usize,
    },
    /// The checksum group with this number (12 or 24) does not match the
    /// digits before it.
    ChecksumMismatch {
        /// The group number of the failing checksum, 12 or 24.
        group: usize,
    },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter { position } => write!(
                f,
                "character {} is not a digit, a space or a hyphen",
                position + 1
            ),
            Self::WrongLength { digits } => {
                write!(f, "a key has 48 or 96 digits, not {digits}")
            }
            Self::ChecksumMismatch { group } => {
                write!(f, "group {group} does not match the digits before it")
            }
        }
    }
}

impl std::error::Error for KeyError {}

/// One checksum group: `int(S("ghost/key-check/v1", code, part, digits)) mod
/// 10000`, with the digest read as a big-endian integer (spec 01, section 6).
///
/// `part` is 1 for group 12 and 2 for group 24; `digits` are the ASCII secret
/// digits before the check group.
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
/// for a standard key (group 12), two for a long key (groups 12 and 24).
///
/// `secret_digits` are the 44 or 88 ASCII secret digits without separators
/// and without the checksum groups.
pub fn check_groups(format: KeyFormat, secret_digits: &[u8]) -> Result<Vec<u16>, KeyError> {
    if secret_digits.len() != format.secret_digit_count() {
        return Err(KeyError::WrongLength {
            digits: secret_digits.len(),
        });
    }
    if let Some(position) = secret_digits.iter().position(|d| !d.is_ascii_digit()) {
        return Err(KeyError::InvalidCharacter { position });
    }
    let mut groups = vec![check_group(format, 1, &secret_digits[..HALF_SECRET])];
    if format == KeyFormat::Long {
        groups.push(check_group(format, 2, secret_digits));
    }
    Ok(groups)
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

/// A Phantom Key whose checksum groups are correct.
///
/// It holds the digits and nothing else. It has no `Debug`, `Display`,
/// `Clone` or serialisation, and its digits are overwritten with zeros when it
/// is dropped. The library never stores it.
pub struct PhantomKey {
    format: KeyFormat,
    /// ASCII digits, checksum groups included; only the first
    /// `format.digit_count()` are used, the rest are zero.
    digits: [u8; MAX_DIGITS],
}

impl Drop for PhantomKey {
    fn drop(&mut self) {
        wipe(&mut self.digits);
    }
}

impl PhantomKey {
    fn empty(format: KeyFormat) -> Self {
        Self {
            format,
            digits: [0; MAX_DIGITS],
        }
    }

    /// Generates a new key from the caller's secure random source.
    ///
    /// Each secret digit is drawn as spec 01, section 5 says: take one byte
    /// from the source, discard it if it is 250 or more, otherwise use its
    /// value modulo 10. The checksum groups are then appended.
    pub fn generate<R: CryptoRng + ?Sized>(format: KeyFormat, rng: &mut R) -> Self {
        let mut key = Self::empty(format);
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

    /// Parses typed digits.
    ///
    /// Spaces and hyphens between the digits are allowed in any mix; any other
    /// character, including a non-ASCII digit, is rejected. After separators
    /// are removed there must be exactly 48 or 96 digits. The checksum groups
    /// are checked before the key is returned: group 12 first, so a mistyped
    /// first half of a long key is named before the second.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
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
        key.verify_check_groups()?;
        Ok(key)
    }

    /// The key's format.
    pub fn key_format(&self) -> KeyFormat {
        self.format
    }

    /// The key as groups of four digits separated by single spaces, the way
    /// it is shown to the user.
    pub fn format_groups(&self) -> FormattedKey {
        let groups = self.format.groups();
        let mut text = String::with_capacity(groups * (GROUP + 1));
        for (index, group) in self.digits().chunks(GROUP).enumerate() {
            if index > 0 {
                text.push(' ');
            }
            for &digit in group {
                text.push(char::from(digit));
            }
        }
        FormattedKey(text)
    }

    /// All the ASCII digits, checksum groups included.
    pub(crate) fn digits(&self) -> &[u8] {
        &self.digits[..self.format.digit_count()]
    }

    /// Copies the ASCII secret digits, in order and without the checksum
    /// groups, to the start of `out` and returns how many there are.
    pub(crate) fn copy_secret_digits(&self, out: &mut [u8]) -> usize {
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

    /// The correct checksum groups and the digit offset of each.
    fn expected_check_groups(&self) -> [(usize, u16); 2] {
        let mut secret = [0u8; MAX_SECRET_DIGITS];
        let n = self.copy_secret_digits(&mut secret);
        let first = (HALF_SECRET, check_group(self.format, 1, &secret[..HALF_SECRET]));
        let second = match self.format {
            KeyFormat::Standard => first,
            KeyFormat::Long => (HALF + HALF_SECRET, check_group(self.format, 2, &secret[..n])),
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

/// A Phantom Key as shown to the user: groups of four digits separated by
/// single spaces. It holds the whole key, so it has no `Debug`, `Display` or
/// `Clone`, and its text is overwritten with zeros when it is dropped.
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
