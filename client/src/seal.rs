//! The RandomX block seal (spec 08), checked in light verification mode.
//!
//! A header's seal is valid when RandomX v1, keyed with the hash of the
//! header's key block and salted with Ghost's salt, maps the seal hash
//! followed by the 8-byte nonce to a value that, read big-endian, is at most
//! `(2^256 - 1) // difficulty`, and the header's `mixDigest` is all zero.
//! The seal hash is Keccak-256 of the header's RLP with `mixDigest` and
//! `nonce` set to zero, so it covers every other field, both tree roots and
//! `dataMarkerRoot` included (spec 05, section 4, "Seal coverage").
//!
//! The caller supplies the header's RLP bytes (spec 05, section 10), the
//! difficulty it requires of the header, and the key: the hash of the
//! ancestor at [`seed_height`] on the header's own branch, found by
//! following parent hashes. Building a [`SealKey`] costs a 256 MiB Argon2d
//! pass; one key serves every header of its epoch.

use core::fmt;

use tiny_keccak::{Hasher, Keccak};

use crate::randomx;

/// Epoch length `E`: key blocks are at multiples of this height.
pub const EPOCH_BLOCKS: u64 = 8192;
/// Lag `L`: a key block is first used `L + 1` blocks after it.
pub const EPOCH_LAG: u64 = 256;

/// Number of fields in a header (spec 05, section 10).
const HEADER_FIELDS: usize = 19;
const PARENT_HASH: usize = 0;
const DIFFICULTY: usize = 7;
const NUMBER: usize = 8;
const TIMESTAMP: usize = 11;
const MIX_DIGEST: usize = 13;
const NONCE: usize = 14;

/// The size rule of each field: `Fixed(n)` is exactly `n` bytes,
/// `Bytes(n)` at most `n`, `Int(n)` a canonical integer of at most `n` bytes.
#[derive(Clone, Copy)]
enum Field {
    Fixed(usize),
    Bytes(usize),
    Int(usize),
}

const FIELDS: [Field; HEADER_FIELDS] = [
    Field::Fixed(32),  // parentHash
    Field::Fixed(32),  // uncleHash
    Field::Fixed(20),  // coinbase
    Field::Fixed(32),  // stateRoot
    Field::Fixed(32),  // transactionsRoot
    Field::Fixed(32),  // receiptsRoot
    Field::Fixed(256), // logsBloom
    Field::Int(32),    // difficulty
    Field::Int(8),     // number
    Field::Int(8),     // gasLimit
    Field::Int(8),     // gasUsed
    Field::Int(8),     // timestamp
    Field::Bytes(32),  // extraData
    Field::Fixed(32),  // mixDigest
    Field::Fixed(8),   // nonce
    Field::Int(32),    // baseFee
    Field::Fixed(32),  // coinTreeRoot
    Field::Fixed(32),  // dataTreeRoot
    Field::Fixed(32),  // dataMarkerRoot
];

/// Why a header's bytes do not decode (spec 05, section 10, "Decoding").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    NonCanonicalRlp,
    TrailingBytes,
    ItemCount,
    FieldSize,
    NonCanonicalInteger,
    IntegerRange,
}

/// Why a seal is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The header's bytes do not decode.
    Header(HeaderError),
    /// The difficulty is zero.
    ZeroDifficulty,
    /// The header's difficulty field is not the difficulty required of it.
    DifficultyMismatch,
    /// The header's `mixDigest` is not all zero.
    MixDigestNotZero,
    /// The RandomX hash is above the target.
    AboveTarget,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Header(HeaderError::NonCanonicalRlp) => "the header is not canonical RLP",
            Self::Header(HeaderError::TrailingBytes) => "bytes follow the header",
            Self::Header(HeaderError::ItemCount) => "the header does not have 19 fields",
            Self::Header(HeaderError::FieldSize) => "a header field has the wrong size",
            Self::Header(HeaderError::NonCanonicalInteger) => "a header integer is not canonical",
            Self::Header(HeaderError::IntegerRange) => "a header integer is out of range",
            Self::ZeroDifficulty => "the difficulty is zero",
            Self::DifficultyMismatch => "the header does not carry the required difficulty",
            Self::MixDigestNotZero => "the header's mix digest is not zero",
            Self::AboveTarget => "the seal's hash is above the target",
        };
        f.write_str(text)
    }
}

/// Where each field's value sits in the header's bytes.
struct Decoded {
    fields: [(usize, usize); HEADER_FIELDS],
}

impl Decoded {
    fn value<'a>(&self, bytes: &'a [u8], index: usize) -> &'a [u8] {
        let (start, len) = self.fields[index];
        &bytes[start..start + len]
    }
}

/// Reads an RLP length prefix at `at`: returns (is a list, header length,
/// payload length).
fn prefix(bytes: &[u8], at: usize) -> Result<(bool, usize, usize), HeaderError> {
    let first = *bytes.get(at).ok_or(HeaderError::NonCanonicalRlp)?;
    let (list, short_base, long_base) = match first {
        0x00..=0x7f => return Ok((false, 0, 1)),
        0x80..=0xbf => (false, 0x80, 0xb7),
        _ => (true, 0xc0, 0xf7),
    };
    if first <= long_base {
        let len = usize::from(first - short_base);
        if !list && len == 1 && *bytes.get(at + 1).ok_or(HeaderError::NonCanonicalRlp)? < 0x80 {
            return Err(HeaderError::NonCanonicalRlp);
        }
        return Ok((list, 1, len));
    }
    let size = usize::from(first - long_base);
    let digits = bytes.get(at + 1..at + 1 + size).ok_or(HeaderError::NonCanonicalRlp)?;
    if digits[0] == 0 || size > 4 {
        return Err(HeaderError::NonCanonicalRlp);
    }
    let len = digits.iter().fold(0usize, |acc, &d| (acc << 8) | usize::from(d));
    if len < 56 {
        return Err(HeaderError::NonCanonicalRlp);
    }
    Ok((list, 1 + size, len))
}

fn decode(bytes: &[u8]) -> Result<Decoded, HeaderError> {
    let (list, header, len) = prefix(bytes, 0)?;
    if !list {
        return Err(HeaderError::NonCanonicalRlp);
    }
    let end = header.checked_add(len).filter(|&end| end <= bytes.len()).ok_or(HeaderError::NonCanonicalRlp)?;
    let mut items = Vec::new();
    let mut at = header;
    let mut nested = false;
    while at < end {
        let (is_list, item_header, item_len) = prefix(bytes, at)?;
        let start = at + item_header;
        if start + item_len > end {
            return Err(HeaderError::NonCanonicalRlp);
        }
        nested |= is_list;
        items.push((start, item_len));
        at = start + item_len;
    }
    if end != bytes.len() {
        return Err(HeaderError::TrailingBytes);
    }
    if nested || items.len() != HEADER_FIELDS {
        return Err(HeaderError::ItemCount);
    }
    let mut fields = [(0, 0); HEADER_FIELDS];
    fields.copy_from_slice(&items);
    for (&(_, len), rule) in fields.iter().zip(FIELDS) {
        match rule {
            Field::Fixed(size) if len != size => return Err(HeaderError::FieldSize),
            Field::Bytes(size) if len > size => return Err(HeaderError::FieldSize),
            _ => {}
        }
    }
    for (&(start, len), rule) in fields.iter().zip(FIELDS) {
        if let Field::Int(width) = rule {
            if len > 0 && bytes[start] == 0 {
                return Err(HeaderError::NonCanonicalInteger);
            }
            if len > width {
                return Err(HeaderError::IntegerRange);
            }
        }
    }
    Ok(Decoded { fields })
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn seal_hash_of(bytes: &[u8], decoded: &Decoded) -> [u8; 32] {
    let mut copy = bytes.to_vec();
    for index in [MIX_DIGEST, NONCE] {
        let (start, len) = decoded.fields[index];
        copy[start..start + len].fill(0);
    }
    keccak256(&copy)
}

/// The fields of a decoded header that link it into a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderFields {
    /// The header's hash: Keccak-256 of its RLP (spec 05, section 10).
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    /// The difficulty field, big-endian with no leading zero byte.
    pub difficulty: Vec<u8>,
    pub number: u64,
    pub timestamp: u64,
}

fn integer(be: &[u8]) -> u64 {
    be.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

/// Decodes a header (spec 05, section 10) and returns its hash, parent hash,
/// difficulty, number and timestamp.
pub fn header_fields(header: &[u8]) -> Result<HeaderFields, HeaderError> {
    let decoded = decode(header)?;
    Ok(HeaderFields {
        hash: keccak256(header),
        parent_hash: decoded.value(header, PARENT_HASH).try_into().expect("a fixed 32-byte field"),
        difficulty: decoded.value(header, DIFFICULTY).to_vec(),
        number: integer(decoded.value(header, NUMBER)),
        timestamp: integer(decoded.value(header, TIMESTAMP)),
    })
}

/// The header's seal hash: Keccak-256 of its RLP with `mixDigest` and
/// `nonce` set to zero. Zeroing does not change any length, so this is the
/// header's own bytes with those 40 bytes cleared.
pub fn seal_hash(header: &[u8]) -> Result<[u8; 32], SealError> {
    let decoded = decode(header).map_err(SealError::Header)?;
    Ok(seal_hash_of(header, &decoded))
}

/// The 40 bytes RandomX hashes for a header: the seal hash, then the 8-byte
/// nonce as it is in the header (big-endian).
pub fn seal_input(header: &[u8]) -> Result<[u8; 40], SealError> {
    let decoded = decode(header).map_err(SealError::Header)?;
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(&seal_hash_of(header, &decoded));
    input[32..].copy_from_slice(decoded.value(header, NONCE));
    Ok(input)
}

/// The height of the key block for a header at `height`: 0 while
/// `height <= E + L`, otherwise `height - L - 1` rounded down to a multiple
/// of `E`. The key is the hash of the ancestor at this height on the
/// header's own branch, never the canonical block at this number.
pub fn seed_height(height: u64) -> u64 {
    if height <= EPOCH_BLOCKS + EPOCH_LAG {
        0
    } else {
        (height - EPOCH_LAG - 1) / EPOCH_BLOCKS * EPOCH_BLOCKS
    }
}

/// The RandomX cache for one key block, under Ghost's salt.
pub struct SealKey {
    cache: randomx::Cache,
}

impl SealKey {
    /// The key for headers whose key block has hash `key_block_hash`.
    pub fn new(key_block_hash: &[u8; 32]) -> Self {
        Self { cache: randomx::Cache::new(key_block_hash) }
    }

    /// The key under another Argon2 salt. Ghost seals never validate under
    /// it; it exists to test that the salt is part of the check.
    pub fn with_salt(key_block_hash: &[u8; 32], salt: &[u8]) -> Self {
        Self { cache: randomx::Cache::with_salt(key_block_hash, salt) }
    }

    /// The RandomX hash of `input` under this key.
    pub fn hash(&self, input: &[u8]) -> [u8; 32] {
        randomx::hash(&self.cache, input)
    }
}

/// `difficulty` as four big-endian-ordered 64-bit limbs (most significant
/// first), or `None` if it does not fit in 256 bits.
fn limbs(be: &[u8]) -> Option<[u64; 4]> {
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    let digits = &be[first..];
    if digits.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[32 - digits.len()..].copy_from_slice(digits);
    let mut out = [0u64; 4];
    for (limb, chunk) in out.iter_mut().zip(padded.chunks_exact(8)) {
        *limb = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    Some(out)
}

/// Whether `hash`, read big-endian, is at most `(2^256 - 1) // difficulty`.
/// That holds exactly when `hash * difficulty < 2^256`. A difficulty of zero
/// never passes.
pub fn meets_target(hash: &[u8; 32], difficulty: &[u8]) -> bool {
    let Some(d) = limbs(difficulty) else { return false };
    if d == [0; 4] {
        return false;
    }
    let h = limbs(hash).expect("32 bytes fit");
    // Schoolbook product, least significant limb first.
    let (h, d) = ([h[3], h[2], h[1], h[0]], [d[3], d[2], d[1], d[0]]);
    let mut product = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = u128::from(h[i]) * u128::from(d[j]) + u128::from(product[i + j]) + carry;
            product[i + j] = t as u64;
            carry = t >> 64;
        }
        product[i + 4] = carry as u64;
    }
    product[4..] == [0; 4]
}

/// Checks a header's seal: the header decodes, carries `difficulty`
/// (big-endian, leading zero bytes allowed), has an all-zero `mixDigest`,
/// and its RandomX hash under `key` meets the target of `difficulty`.
pub fn verify_seal(header: &[u8], difficulty: &[u8], key: &SealKey) -> Result<(), SealError> {
    let decoded = decode(header).map_err(SealError::Header)?;
    let required = limbs(difficulty).ok_or(SealError::DifficultyMismatch)?;
    if required == [0; 4] {
        return Err(SealError::ZeroDifficulty);
    }
    if limbs(decoded.value(header, DIFFICULTY)) != Some(required) {
        return Err(SealError::DifficultyMismatch);
    }
    if decoded.value(header, MIX_DIGEST).iter().any(|&b| b != 0) {
        return Err(SealError::MixDigestNotZero);
    }
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(&seal_hash_of(header, &decoded));
    input[32..].copy_from_slice(decoded.value(header, NONCE));
    if meets_target(&key.hash(&input), difficulty) { Ok(()) } else { Err(SealError::AboveTarget) }
}

/// Whether a header's seal is valid; see [`verify_seal`].
pub fn check_seal(header: &[u8], difficulty: &[u8], key: &SealKey) -> bool {
    verify_seal(header, difficulty, key).is_ok()
}
