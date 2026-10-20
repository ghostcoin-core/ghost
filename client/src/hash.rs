//! Tagged hashing (spec 01, sections 2 and 4).
//!
//! Every hash input starts with `tagbytes(tag)`: one byte holding the tag's
//! length, then its ASCII bytes. [`k`] is Keccak-256 with the original Keccak
//! padding, used for commitments, fingerprints and markers. [`s`] is SHA3-256
//! (FIPS 202), used for the checksum and every derivation from the digits.

use tiny_keccak::{Hasher, Keccak, Sha3};

/// Phantom Key checksum group (SHA3-256).
pub const TAG_KEY_CHECK: &str = "ghost/key-check/v1";
/// Secret `s` (SHA3-256).
pub const TAG_SECRET: &str = "ghost/secret/v1";
/// Reveal secret `r` (SHA3-256).
pub const TAG_REVEAL_SECRET: &str = "ghost/reveal-secret/v1";
/// Blinding `b_i` (SHA3-256).
pub const TAG_BLINDING: &str = "ghost/blinding/v1";
/// Note key (SHA3-256).
pub const TAG_NOTE_KEY: &str = "ghost/note-key/v1";
/// Data key (SHA3-256).
pub const TAG_DATA_KEY: &str = "ghost/data-key/v1";
/// Coin fingerprint `F` (Keccak-256).
pub const TAG_COIN_FINGERPRINT: &str = "ghost/coin-fingerprint/v1";
/// Coin commitment `C` (Keccak-256).
pub const TAG_COIN_COMMITMENT: &str = "ghost/coin-commitment/v1";
/// Data fingerprint `F_d` (Keccak-256).
pub const TAG_DATA_FINGERPRINT: &str = "ghost/data-fingerprint/v1";
/// Data commitment `C` (Keccak-256).
pub const TAG_DATA_COMMITMENT: &str = "ghost/data-commitment/v1";
/// Content fingerprint `cf` (Keccak-256).
pub const TAG_CONTENT_FINGERPRINT: &str = "ghost/content-fingerprint/v1";
/// Marker of a coin commitment (Keccak-256).
pub const TAG_COIN_MARKER: &str = "ghost/coin-marker/v1";
/// Marker of a data commitment (Keccak-256).
pub const TAG_DATA_MARKER: &str = "ghost/data-marker/v1";

fn tagged<H: Hasher>(mut hasher: H, tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let len = u8::try_from(tag.len()).expect("a tag is shorter than 256 bytes");
    hasher.update(&[len]);
    hasher.update(tag.as_bytes());
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// `K(tag, parts...)`: Keccak-256, original padding, over `tagbytes(tag)`
/// followed by the parts.
pub fn k(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    tagged(Keccak::v256(), tag, parts)
}

/// `S(tag, parts...)`: SHA3-256 (FIPS 202) over `tagbytes(tag)` followed by
/// the parts.
pub fn s(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    tagged(Sha3::v256(), tag, parts)
}

/// `X(tag, n, parts...)`: SHAKE256 (FIPS 202) over `tagbytes(tag)` followed by
/// the parts, with `N` bytes of output (spec 09, section 2).
pub fn x<const N: usize>(tag: &str, parts: &[&[u8]]) -> [u8; N] {
    let mut hasher = tiny_keccak::Shake::v256();
    let len = u8::try_from(tag.len()).expect("a tag is shorter than 256 bytes");
    hasher.update(&[len]);
    hasher.update(tag.as_bytes());
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; N];
    hasher.finalize(&mut out);
    out
}

/// Keccak-256 with the original padding and no tag: transaction hashes and
/// the hash of an RLP encoding.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}
