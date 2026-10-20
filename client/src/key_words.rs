//! The words format of a Phantom Key (spec 01, sections 5 and 6): a 256-bit
//! secret written as 24 words of the 2,048-word list, or as 21 groups of four
//! digits.
//!
//! ```text
//! check  = first byte of S("ghost/key-check/v1", 0x20, 0x01, secret)
//! words  = secret || check, 264 bits, read as 24 indexes of 11 bits each,
//!          most significant bit first
//! digits = secret as a decimal number, zero-padded to 80 digits, then
//!          check(0x20, 0x01, the 80 digits) of section 6 as group 21
//! ```
//!
//! Every buffer here that holds part of a secret is overwritten with zeros
//! before it is dropped.

use crate::hash::{self, TAG_KEY_CHECK};
use crate::key::KeyError;
use crate::wipe::wipe;
use crate::wordlist::WORDLIST;

/// The format code of the words format.
pub(crate) const CODE: u8 = 0x20;
/// Words in a key.
pub(crate) const WORDS: usize = 24;
/// Bytes of secret.
pub(crate) const SECRET_BYTES: usize = 32;
/// Secret digits in the digit view: `10^80 > 2^256`, the smallest group count
/// that holds every secret.
pub(crate) const SECRET_DIGITS: usize = 80;
/// Bits per word.
const WORD_BITS: u32 = 11;
/// The longest word of the list has eight letters.
const LONGEST_WORD: usize = 8;

/// The 8-bit check: the first byte of
/// `S("ghost/key-check/v1", 0x20, 0x01, secret)`.
pub(crate) fn check_byte(secret: &[u8; SECRET_BYTES]) -> u8 {
    let mut digest = hash::s(TAG_KEY_CHECK, &[&[CODE], &[0x01], secret]);
    let check = digest[0];
    wipe(&mut digest);
    check
}

/// The 24 word indexes of a secret: the secret followed by its check byte,
/// 11 bits per word, most significant bit first.
pub(crate) fn encode(secret: &[u8; SECRET_BYTES], out: &mut [u16; WORDS]) {
    let check = [check_byte(secret)];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut word = 0;
    for &byte in secret.iter().chain(check.iter()) {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        if bits >= WORD_BITS {
            bits -= WORD_BITS;
            out[word] = ((acc >> bits) & 0x7ff) as u16;
            acc &= (1 << bits) - 1;
            word += 1;
        }
    }
    debug_assert!(word == WORDS && bits == 0);
}

/// The secret of 24 word indexes, if the check byte they carry is correct.
pub(crate) fn decode(indexes: &[u16; WORDS], secret: &mut [u8; SECRET_BYTES]) -> Result<(), KeyError> {
    let mut bytes = [0u8; SECRET_BYTES + 1];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut next = 0;
    for &index in indexes {
        acc = (acc << WORD_BITS) | u32::from(index & 0x7ff);
        bits += WORD_BITS;
        while bits >= 8 {
            bits -= 8;
            bytes[next] = (acc >> bits) as u8;
            acc &= (1 << bits) - 1;
            next += 1;
        }
    }
    debug_assert!(next == SECRET_BYTES + 1 && bits == 0);
    secret.copy_from_slice(&bytes[..SECRET_BYTES]);
    let written = bytes[SECRET_BYTES];
    wipe(&mut bytes);
    if check_byte(secret) != written {
        wipe(secret);
        return Err(KeyError::WordCheckMismatch);
    }
    Ok(())
}

/// The index of a whole word of the list, compared without regard to ASCII
/// case. Anything else, including a prefix of a word, gives `None`.
pub(crate) fn lookup(word: &str) -> Option<u16> {
    if word.len() > LONGEST_WORD || !word.is_ascii() {
        return None;
    }
    let mut lower = [0u8; LONGEST_WORD];
    for (slot, byte) in lower.iter_mut().zip(word.bytes()) {
        *slot = byte.to_ascii_lowercase();
    }
    let found = WORDLIST
        .binary_search_by(|listed| listed.as_bytes().cmp(&lower[..word.len()]))
        .ok()
        .map(|index| index as u16);
    wipe(&mut lower);
    found
}

/// Reads typed words.
///
/// Words are separated by any mix of spaces and hyphens. A character that is
/// neither a letter nor a separator is rejected with its position; a run of
/// letters that is not a whole word of the list is rejected and named by its
/// number and its place in the text, never corrected. Then there must be
/// exactly 24 words, and their check byte must be correct.
pub(crate) fn parse_words(text: &str, secret: &mut [u8; SECRET_BYTES]) -> Result<(), KeyError> {
    let mut indexes = [0u16; WORDS];
    let mut count = 0usize;
    let mut start: Option<usize> = None;
    let mut chars = text.char_indices().enumerate().peekable();
    let result = loop {
        let next = chars.next();
        let at_separator = match next {
            None => true,
            Some((_, (_, ' ' | '-'))) => true,
            Some((_, (offset, ch))) if ch.is_alphabetic() => {
                start.get_or_insert(offset);
                false
            }
            Some((position, _)) => break Err(KeyError::InvalidCharacter { position }),
        };
        if at_separator {
            if let Some(begin) = start.take() {
                let end = next.map_or(text.len(), |(_, (offset, _))| offset);
                let Some(index) = lookup(&text[begin..end]) else {
                    break Err(KeyError::UnknownWord {
                        word: count + 1,
                        start: begin,
                        end,
                    });
                };
                if count < WORDS {
                    indexes[count] = index;
                }
                count += 1;
            }
            if next.is_none() {
                break if count == WORDS {
                    decode(&indexes, secret)
                } else {
                    Err(KeyError::WrongWordCount { words: count })
                };
            }
        }
    };
    wipe_indexes(&mut indexes);
    result
}

/// The words of a secret, separated by single spaces.
pub(crate) fn write_words(secret: &[u8; SECRET_BYTES], out: &mut String) {
    let mut indexes = [0u16; WORDS];
    encode(secret, &mut indexes);
    for (number, &index) in indexes.iter().enumerate() {
        if number > 0 {
            out.push(' ');
        }
        out.push_str(WORDLIST[usize::from(index)]);
    }
    wipe_indexes(&mut indexes);
}

/// Overwrites word indexes with zeros, the way [`wipe`] does bytes.
fn wipe_indexes(indexes: &mut [u16]) {
    for index in indexes.iter_mut() {
        // SAFETY: `index` is a valid, aligned, exclusive reference to a `u16`.
        unsafe { core::ptr::write_volatile(index, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// The secret as 80 ASCII decimal digits, most significant first, with
/// leading zeros.
pub(crate) fn to_digits(secret: &[u8; SECRET_BYTES], out: &mut [u8]) {
    let mut number = *secret;
    for slot in out[..SECRET_DIGITS].iter_mut().rev() {
        let mut remainder: u32 = 0;
        for byte in number.iter_mut() {
            let current = remainder * 256 + u32::from(*byte);
            *byte = (current / 10) as u8;
            remainder = current % 10;
        }
        *slot = b'0' + remainder as u8;
    }
    wipe(&mut number);
}

/// The secret of 80 ASCII decimal digits, or `SecretOutOfRange` if they are
/// `2^256` or more.
pub(crate) fn from_digits(digits: &[u8], secret: &mut [u8; SECRET_BYTES]) -> Result<(), KeyError> {
    let mut number = [0u8; SECRET_BYTES];
    for &digit in &digits[..SECRET_DIGITS] {
        let mut carry = u32::from(digit - b'0');
        for byte in number.iter_mut().rev() {
            let current = u32::from(*byte) * 10 + carry;
            *byte = current as u8;
            carry = current >> 8;
        }
        if carry != 0 {
            wipe(&mut number);
            return Err(KeyError::SecretOutOfRange);
        }
    }
    secret.copy_from_slice(&number);
    wipe(&mut number);
    Ok(())
}
