//! A header chain the wallet checks itself, so that the server it talks to
//! cannot show it a chain, confirmations or tree roots no miner sealed.
//!
//! The chain starts from a trusted header: the genesis header, or a pinned
//! header that the caller supplies together with its height, its total work
//! and the hashes of the key blocks below it ([`PinnedStart`]). From there,
//! [`HeaderChain::add_header`] adopts a header only after checking all of
//! this:
//!
//! - it decodes (spec 05, section 10);
//! - its parent is a header already held, and its number is the parent's
//!   plus one;
//! - its timestamp is after the parent's, below `2^63`, and at most the
//!   future drift after the caller's clock (spec 06, section 5.1);
//! - its difficulty field equals [`required_difficulty`] exactly (spec 06,
//!   section 4.3);
//! - its RandomX seal is valid under the key block found by following parent
//!   hashes on its own branch (spec 08, sections 8 and 9).
//!
//! No seal is skipped after the trusted start. A header that cannot be fully
//! checked (its parent or its key block is not held) is refused and reported
//! as such; it is never accepted on trust.
//!
//! The work of a header is its difficulty; the best chain is the one with the
//! most total work, and the first seen wins a tie (spec 06, section 4.5).
//!
//! The library has no clock and no network code: the caller passes its own
//! clock as `now` and the header bytes it fetched. Each RandomX cache takes
//! 256 MiB, so the chain holds at most two at a time: the key it used last
//! and the one before it.

use core::cmp::Ordering;
use core::fmt;
use std::collections::HashMap;

use crate::seal::{header_fields, seed_height, verify_seal, HeaderError, SealError, SealKey, EPOCH_BLOCKS};

/// An unsigned 256-bit integer: a difficulty, a target or a total work.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct U256([u64; 4]); // least significant limb first

impl U256 {
    pub const ZERO: Self = Self([0; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    /// `M = 2^256 - 1`.
    pub const MAX: Self = Self([u64::MAX; 4]);

    /// Reads a big-endian integer; leading zero bytes are allowed. `None` if
    /// the value does not fit in 256 bits.
    pub fn from_be_bytes(be: &[u8]) -> Option<Self> {
        let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        let digits = &be[first..];
        if digits.len() > 32 {
            return None;
        }
        let mut padded = [0u8; 32];
        padded[32 - digits.len()..].copy_from_slice(digits);
        let mut limbs = [0u64; 4];
        for (i, chunk) in padded.chunks_exact(8).enumerate() {
            limbs[3 - i] = u64::from_be_bytes(chunk.try_into().expect("8 bytes"));
        }
        Some(Self(limbs))
    }

    /// The value as 32 big-endian bytes.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        out
    }

    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = false;
        for (i, limb) in out.iter_mut().enumerate() {
            let (sum, c1) = self.0[i].overflowing_add(other.0[i]);
            let (sum, c2) = sum.overflowing_add(u64::from(carry));
            *limb = sum;
            carry = c1 || c2;
        }
        if carry { None } else { Some(Self(out)) }
    }

    fn wrapping_sub(self, other: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for (i, limb) in out.iter_mut().enumerate() {
            let (diff, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (diff, b2) = diff.overflowing_sub(u64::from(borrow));
            *limb = diff;
            borrow = b1 || b2;
        }
        Self(out)
    }

    fn bit(&self, index: usize) -> bool {
        self.0[index / 64] >> (index % 64) & 1 == 1
    }

    /// Shifts left by one and sets the lowest bit to `low`; returns the bit
    /// shifted out at the top.
    fn shift_in(&mut self, low: bool) -> bool {
        let out = self.0[3] >> 63 == 1;
        for i in (1..4).rev() {
            self.0[i] = (self.0[i] << 1) | (self.0[i - 1] >> 63);
        }
        self.0[0] = (self.0[0] << 1) | u64::from(low);
        out
    }

    /// Floor division; `divisor` must not be zero.
    fn div(self, divisor: Self) -> Self {
        assert!(!divisor.is_zero(), "division by zero");
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        for index in (0..256).rev() {
            // The remainder stays below the divisor, so with the bit shifted
            // out it is below twice the divisor and one subtraction reduces it.
            let carry = remainder.shift_in(self.bit(index));
            if carry || remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                quotient.0[index / 64] |= 1 << (index % 64);
            }
        }
        quotient
    }

    /// Floor division by a small number, with the remainder.
    fn div_rem_small(self, divisor: u64) -> (Self, u64) {
        let mut out = [0u64; 4];
        let mut rem = 0u128;
        for i in (0..4).rev() {
            let current = (rem << 64) | u128::from(self.0[i]);
            out[i] = (current / u128::from(divisor)) as u64;
            rem = current % u128::from(divisor);
        }
        (Self(out), rem as u64)
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self([value, 0, 0, 0])
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut digits = Vec::new();
        let mut value = *self;
        loop {
            let (quotient, digit) = value.div_rem_small(10);
            digits.push(b'0' + digit as u8);
            value = quotient;
            if value.is_zero() {
                break;
            }
        }
        digits.reverse();
        f.write_str(core::str::from_utf8(&digits).expect("ASCII digits"))
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A 512-bit intermediate, least significant limb first: the ASERT product
/// reaches 488 bits (spec 06, section 4.3).
type Wide = [u64; 8];

fn widen_mul(value: U256, factor: u64) -> Wide {
    let mut out = [0u64; 8];
    let mut carry = 0u128;
    for i in 0..4 {
        let t = u128::from(value.0[i]) * u128::from(factor) + carry;
        out[i] = t as u64;
        carry = t >> 64;
    }
    out[4] = carry as u64;
    out
}

fn wide_shl(value: Wide, shift: u32) -> Wide {
    let (limbs, bits) = ((shift / 64) as usize, shift % 64);
    let mut out = [0u64; 8];
    for i in limbs..8 {
        out[i] = value[i - limbs] << bits;
        if bits > 0 && i > limbs {
            out[i] |= value[i - limbs - 1] >> (64 - bits);
        }
    }
    out
}

fn wide_shr(value: Wide, shift: u32) -> Wide {
    let (limbs, bits) = ((shift / 64) as usize, shift % 64);
    let mut out = [0u64; 8];
    for i in 0..8usize.saturating_sub(limbs) {
        out[i] = value[i + limbs] >> bits;
        if bits > 0 && i + limbs + 1 < 8 {
            out[i] |= value[i + limbs + 1] << (64 - bits);
        }
    }
    out
}

/// The value if it fits in 256 bits.
fn narrow(value: Wide) -> Option<U256> {
    if value[4..] == [0; 4] { Some(U256([value[0], value[1], value[2], value[3]])) } else { None }
}

/// The chain constants of spec 06, section 4.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainParams {
    /// `B`: the block time, seconds.
    pub block_time: u64,
    /// `TAU`: the ASERT half-life, seconds.
    pub half_life: u64,
    /// `D_START`: the genesis difficulty, the ASERT anchor.
    pub start_difficulty: u64,
    /// `D_MIN`: difficulty never goes below this.
    pub min_difficulty: u64,
    /// `FUTURE_DRIFT`: how many seconds a header may be ahead of the clock.
    pub future_drift: u64,
}

impl ChainParams {
    /// The 30-second chain.
    pub const THIRTY_SECONDS: Self = Self {
        block_time: 30,
        half_life: 3600,
        start_difficulty: 1 << 24,
        min_difficulty: 1 << 17,
        future_drift: 30,
    };

    /// The 60-second chain, the fallback of spec 06, section 3.
    pub const SIXTY_SECONDS: Self = Self {
        block_time: 60,
        half_life: 3600,
        start_difficulty: 1 << 25,
        min_difficulty: 1 << 17,
        future_drift: 30,
    };

    /// Whether every constant the rule divides by is positive.
    pub fn is_valid(&self) -> bool {
        self.block_time > 0 && self.half_life > 0 && self.start_difficulty > 0 && self.min_difficulty > 0
    }
}

/// `RADIX`: 2^16 fixed point, as BCH.
const RADIX: i128 = 1 << 16;

/// The difficulty required of the header at `height` with `timestamp`, on
/// the chain whose genesis timestamp is `genesis_timestamp` (spec 06,
/// section 4.3, ASERT anchored at genesis with the header's own timestamp).
///
/// Panics if `params` is not [valid](ChainParams::is_valid).
pub fn required_difficulty(params: &ChainParams, genesis_timestamp: u64, height: u64, timestamp: u64) -> U256 {
    assert!(params.is_valid(), "chain constants must be positive");
    let max_target = U256::MAX.div(U256::from(params.min_difficulty));
    let start_target = U256::MAX.div(U256::from(params.start_difficulty));

    // Inputs below 2^63 never saturate; beyond that the result is clamped
    // either way.
    let schedule = i128::from(params.block_time).saturating_mul(i128::from(height));
    let lag = i128::from(timestamp).saturating_sub(i128::from(genesis_timestamp)).saturating_sub(schedule);
    let exponent = lag.saturating_mul(RADIX).div_euclid(i128::from(params.half_life));
    let shifts = exponent >> 16;
    let frac = (exponent & 0xffff) as u128;
    let factor = 65536
        + ((195_766_423_245_049 * frac + 971_821_376 * frac * frac + 5127 * frac * frac * frac + (1 << 47)) >> 48)
            as u64;

    let target = if shifts >= 256 {
        max_target
    } else {
        let product = widen_mul(start_target, factor);
        let shift = shifts - 16;
        let shifted = if shift >= 0 {
            wide_shl(product, shift as u32)
        } else {
            wide_shr(product, shift.unsigned_abs().min(512) as u32)
        };
        match narrow(shifted) {
            Some(target) if target <= max_target => target.max(U256::ONE),
            _ => max_target,
        }
    };
    U256::MAX.div(target).max(U256::from(params.min_difficulty))
}

/// A pinned header the caller trusts, with what the chain cannot check below
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedStart {
    /// The pinned header's RLP.
    pub header: Vec<u8>,
    /// Its height; must equal the header's number.
    pub height: u64,
    /// The total work of the chain up to and including it.
    pub total_work: U256,
    /// The genesis timestamp, the zero of the difficulty schedule.
    pub genesis_timestamp: u64,
    /// `(height, hash)` of the key blocks below the pinned height that headers
    /// after it use, until the chain holds its own key blocks. Heights are
    /// 0 or multiples of the epoch length.
    pub key_blocks: Vec<(u64, [u8; 32])>,
}

/// Why a trusted start is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// The header does not decode.
    Header(HeaderError),
    /// A chain constant is zero.
    Params,
    /// The genesis header's number is not 0.
    NotGenesis,
    /// The genesis header's difficulty is not the start difficulty.
    GenesisDifficulty,
    /// The pinned height is not the header's number.
    Height,
    /// A timestamp is `2^63` or more.
    Timestamp,
    /// The total work is zero.
    Work,
    /// A key block is not at 0 or a multiple of the epoch length, is above
    /// the pinned height, or contradicts the pinned header or another entry.
    KeyBlock,
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(e) => write!(f, "the trusted header does not decode: {}", SealError::Header(*e)),
            Self::Params => f.write_str("a chain constant is zero"),
            Self::NotGenesis => f.write_str("the genesis header's number is not zero"),
            Self::GenesisDifficulty => f.write_str("the genesis header does not carry the start difficulty"),
            Self::Height => f.write_str("the pinned height is not the header's number"),
            Self::Timestamp => f.write_str("a timestamp is out of range"),
            Self::Work => f.write_str("the pinned total work is zero"),
            Self::KeyBlock => f.write_str("a pinned key block is not a key block below the pinned header"),
        }
    }
}

/// Why a header is refused. Nothing refused is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// The header does not decode.
    Header(HeaderError),
    /// Its parent is not held: it cannot be checked, so it is not adopted.
    UnknownParent,
    /// Its number is not its parent's plus one.
    Number,
    /// Its timestamp is not after its parent's.
    TimestampNotAfterParent,
    /// Its timestamp is `2^63` or more.
    TimestampOutOfRange,
    /// Its difficulty field is not the required difficulty.
    Difficulty,
    /// Its key block on its own branch is not held: its seal cannot be
    /// checked, so it is not adopted.
    MissingKeyBlock,
    /// Its seal is not valid under its key block.
    Seal(SealError),
    /// The total work does not fit in 256 bits.
    WorkOverflow,
    /// The header passes every other check but is more than the future drift
    /// ahead of `now`. It is not invalid for ever: the caller can offer it
    /// again once its clock has caught up.
    TooFarAhead,
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(e) => fmt::Display::fmt(&SealError::Header(*e), f),
            Self::UnknownParent => f.write_str("the header's parent is not held"),
            Self::Number => f.write_str("the header's number is not its parent's plus one"),
            Self::TimestampNotAfterParent => f.write_str("the header's timestamp is not after its parent's"),
            Self::TimestampOutOfRange => f.write_str("the header's timestamp is out of range"),
            Self::Difficulty => f.write_str("the header does not carry the required difficulty"),
            Self::MissingKeyBlock => f.write_str("the header's key block on its own branch is not held"),
            Self::Seal(e) => fmt::Display::fmt(e, f),
            Self::WorkOverflow => f.write_str("the total work does not fit in 256 bits"),
            Self::TooFarAhead => f.write_str("the header is too far ahead of the clock; try again later"),
        }
    }
}

/// What adding a header did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    /// The header extends the best chain and is its new tip.
    Extended,
    /// The header is held on a side branch; the best chain is unchanged.
    SideBranch,
    /// The header made its branch the heaviest: the best chain switched to
    /// it, `removed` headers of the old best chain are no longer on it and
    /// `added` headers (this one included) now are.
    Reorganised { removed: u64, added: u64 },
    /// The header was already held.
    AlreadyHeld,
}

struct Held {
    rlp: Vec<u8>,
    parent: [u8; 32],
    number: u64,
    timestamp: u64,
    total_work: U256,
}

/// At most this many RandomX caches, 256 MiB each, are held at a time.
pub const MAX_CACHES: usize = 2;

const TIMESTAMP_LIMIT: u64 = 1 << 63;

/// A header chain checked from a trusted start; see the module documentation.
pub struct HeaderChain {
    params: ChainParams,
    genesis_timestamp: u64,
    /// Every held header by hash, the trusted start included.
    headers: HashMap<[u8; 32], Held>,
    start_hash: [u8; 32],
    start_height: u64,
    /// Key blocks below the trusted start, by height.
    pinned_keys: HashMap<u64, [u8; 32]>,
    best: [u8; 32],
    /// The most recently used first.
    caches: Vec<([u8; 32], SealKey)>,
}

impl HeaderChain {
    /// A chain starting at the genesis header, which counts the start
    /// difficulty as its work. The genesis header is accepted by its
    /// derivation (spec 06, section 8), not by a seal.
    pub fn from_genesis(genesis: &[u8], params: ChainParams) -> Result<Self, StartError> {
        let fields = header_fields(genesis).map_err(StartError::Header)?;
        if fields.number != 0 {
            return Err(StartError::NotGenesis);
        }
        if U256::from_be_bytes(&fields.difficulty) != Some(U256::from(params.start_difficulty)) {
            return Err(StartError::GenesisDifficulty);
        }
        let pin = PinnedStart {
            header: genesis.to_vec(),
            height: 0,
            total_work: U256::from(params.start_difficulty),
            genesis_timestamp: fields.timestamp,
            key_blocks: Vec::new(),
        };
        Self::from_pinned(pin, params)
    }

    /// A chain starting at a pinned header. Every header after it is checked
    /// in full.
    pub fn from_pinned(pin: PinnedStart, params: ChainParams) -> Result<Self, StartError> {
        if !params.is_valid() {
            return Err(StartError::Params);
        }
        let fields = header_fields(&pin.header).map_err(StartError::Header)?;
        if fields.number != pin.height {
            return Err(StartError::Height);
        }
        if fields.timestamp >= TIMESTAMP_LIMIT || pin.genesis_timestamp >= TIMESTAMP_LIMIT {
            return Err(StartError::Timestamp);
        }
        if pin.total_work.is_zero() {
            return Err(StartError::Work);
        }
        let mut pinned_keys = HashMap::new();
        for &(height, hash) in &pin.key_blocks {
            let on_schedule = height % EPOCH_BLOCKS == 0;
            let below = height < pin.height || (height == pin.height && hash == fields.hash);
            let agrees = pinned_keys.get(&height).is_none_or(|&known| known == hash);
            if !on_schedule || !below || !agrees {
                return Err(StartError::KeyBlock);
            }
            if height < pin.height {
                pinned_keys.insert(height, hash);
            }
        }
        let start = Held {
            rlp: pin.header,
            parent: fields.parent_hash,
            number: fields.number,
            timestamp: fields.timestamp,
            total_work: pin.total_work,
        };
        let mut headers = HashMap::new();
        headers.insert(fields.hash, start);
        Ok(Self {
            params,
            genesis_timestamp: pin.genesis_timestamp,
            headers,
            start_hash: fields.hash,
            start_height: fields.number,
            pinned_keys,
            best: fields.hash,
            caches: Vec::new(),
        })
    }

    /// Checks a header and, if it passes, holds it and updates the best
    /// chain. `now` is the caller's clock in Unix seconds.
    pub fn add_header(&mut self, header: &[u8], now: u64) -> Result<Added, ChainError> {
        let fields = header_fields(header).map_err(ChainError::Header)?;
        if self.headers.contains_key(&fields.hash) {
            return Ok(Added::AlreadyHeld);
        }
        let parent = self.headers.get(&fields.parent_hash).ok_or(ChainError::UnknownParent)?;
        if parent.number.checked_add(1) != Some(fields.number) {
            return Err(ChainError::Number);
        }
        if fields.timestamp <= parent.timestamp {
            return Err(ChainError::TimestampNotAfterParent);
        }
        if fields.timestamp >= TIMESTAMP_LIMIT {
            return Err(ChainError::TimestampOutOfRange);
        }
        let required = required_difficulty(&self.params, self.genesis_timestamp, fields.number, fields.timestamp);
        if U256::from_be_bytes(&fields.difficulty) != Some(required) {
            return Err(ChainError::Difficulty);
        }
        let total_work = parent.total_work.checked_add(required).ok_or(ChainError::WorkOverflow)?;
        let key = self.key_block(&fields.parent_hash, fields.number).ok_or(ChainError::MissingKeyBlock)?;
        verify_seal(header, &required.to_be_bytes(), self.seal_key(key)).map_err(ChainError::Seal)?;
        if fields.timestamp > now.saturating_add(self.params.future_drift) {
            return Err(ChainError::TooFarAhead);
        }

        let best_work = self.headers[&self.best].total_work;
        self.headers.insert(
            fields.hash,
            Held {
                rlp: header.to_vec(),
                parent: fields.parent_hash,
                number: fields.number,
                timestamp: fields.timestamp,
                total_work,
            },
        );
        if total_work <= best_work {
            return Ok(Added::SideBranch);
        }
        let old = core::mem::replace(&mut self.best, fields.hash);
        if old == fields.parent_hash {
            return Ok(Added::Extended);
        }
        let (removed, added) = self.divergence(old, fields.hash);
        Ok(Added::Reorganised { removed, added })
    }

    /// The hash of the key block for a header at `height` whose parent is
    /// `parent`: its ancestor at [`seed_height`] on its own branch, or a
    /// pinned key block below the trusted start.
    fn key_block(&self, parent: &[u8; 32], height: u64) -> Option<[u8; 32]> {
        let seed = seed_height(height);
        if seed < self.start_height {
            return self.pinned_keys.get(&seed).copied();
        }
        let mut hash = *parent;
        let mut number = height - 1;
        while number > seed {
            hash = self.headers.get(&hash)?.parent;
            number -= 1;
        }
        Some(hash)
    }

    /// The cache for `key`, built if it is not held; the least recently used
    /// cache is dropped first when [`MAX_CACHES`] are held.
    fn seal_key(&mut self, key: [u8; 32]) -> &SealKey {
        if let Some(index) = self.caches.iter().position(|(held, _)| *held == key) {
            let entry = self.caches.remove(index);
            self.caches.insert(0, entry);
        } else {
            if self.caches.len() >= MAX_CACHES {
                self.caches.truncate(MAX_CACHES - 1);
            }
            self.caches.insert(0, (key, SealKey::new(&key)));
        }
        &self.caches[0].1
    }

    /// How many headers of `old`'s branch and of `new`'s branch lie above
    /// their common ancestor.
    fn divergence(&self, mut old: [u8; 32], mut new: [u8; 32]) -> (u64, u64) {
        let (mut removed, mut added) = (0, 0);
        while old != new {
            let (old_number, new_number) = (self.headers[&old].number, self.headers[&new].number);
            if old_number >= new_number {
                old = self.headers[&old].parent;
                removed += 1;
            }
            if new_number >= old_number {
                new = self.headers[&new].parent;
                added += 1;
            }
        }
        (removed, added)
    }

    /// The hash of the best chain's tip.
    pub fn best_hash(&self) -> [u8; 32] {
        self.best
    }

    /// The height of the best chain's tip.
    pub fn best_height(&self) -> u64 {
        self.headers[&self.best].number
    }

    /// The total work of the best chain.
    pub fn best_total_work(&self) -> U256 {
        self.headers[&self.best].total_work
    }

    /// The trusted start's hash.
    pub fn start_hash(&self) -> [u8; 32] {
        self.start_hash
    }

    /// The total work up to and including a held header.
    pub fn total_work(&self, hash: &[u8; 32]) -> Option<U256> {
        self.headers.get(hash).map(|held| held.total_work)
    }

    /// A held header's RLP, so the caller can read its fields (its tree roots,
    /// for instance) from bytes that were checked.
    pub fn header(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.headers.get(hash).map(|held| held.rlp.as_slice())
    }

    /// Whether a header is held, on any branch.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.headers.contains_key(hash)
    }

    /// The hash of the best chain's header at `height`, if the best chain
    /// holds one there (from the trusted start to the tip).
    pub fn best_hash_at(&self, height: u64) -> Option<[u8; 32]> {
        let mut hash = self.best;
        let mut held = &self.headers[&hash];
        if height < self.start_height || height > held.number {
            return None;
        }
        while held.number > height {
            hash = held.parent;
            held = &self.headers[&hash];
        }
        Some(hash)
    }

    /// The confirmations of a header on the best chain (1 for the tip), or
    /// `None` if it is not on the best chain.
    pub fn confirmations(&self, hash: &[u8; 32]) -> Option<u64> {
        let number = self.headers.get(hash)?.number;
        (self.best_hash_at(number)? == *hash).then(|| self.best_height() - number + 1)
    }

    /// How many RandomX caches are held now (at most [`MAX_CACHES`]).
    pub fn cache_count(&self) -> usize {
        self.caches.len()
    }

    /// The keys whose RandomX caches are held, the most recently used first.
    pub fn cached_keys(&self) -> Vec<[u8; 32]> {
        self.caches.iter().map(|(key, _)| *key).collect()
    }
}
