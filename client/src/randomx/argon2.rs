//! Argon2d as RandomX uses it to build the cache from the key: version 0x13,
//! one lane, three passes over 262,144 blocks of 1 KiB, no secret, no
//! associated data and an output length of zero. The filled memory is the
//! cache; Argon2's final hash is never taken.

use super::blake2b::{hash512, hash_long};

/// Memory in 1 KiB blocks (`RANDOMX_ARGON_MEMORY`).
pub const MEMORY_BLOCKS: usize = 262_144;
/// Passes over the memory (`RANDOMX_ARGON_ITERATIONS`).
const PASSES: u32 = 3;
const SYNC_POINTS: usize = 4;
const SEGMENT_LENGTH: usize = MEMORY_BLOCKS / SYNC_POINTS;
/// 64-bit words in one block.
pub const BLOCK_WORDS: usize = 128;
const VERSION: u32 = 0x13;
const TYPE_ARGON2D: u32 = 0;

/// Fills the Argon2d memory for `key` and `salt` and returns it as
/// little-endian 64-bit words, block after block.
pub fn fill_memory(key: &[u8], salt: &[u8]) -> Vec<u64> {
    let le = |value: u32| value.to_le_bytes();
    let h0 = hash512(&[
        &le(1),
        &le(0),
        &le(MEMORY_BLOCKS as u32),
        &le(PASSES),
        &le(VERSION),
        &le(TYPE_ARGON2D),
        &le(key.len() as u32),
        key,
        &le(salt.len() as u32),
        salt,
        &le(0),
        &le(0),
    ]);

    let mut memory = vec![0u64; MEMORY_BLOCKS * BLOCK_WORDS];
    for index in 0..2u32 {
        let mut bytes = [0u8; 1024];
        hash_long(&mut bytes, &[&h0, &le(index), &le(0)]);
        let block = &mut memory[index as usize * BLOCK_WORDS..(index as usize + 1) * BLOCK_WORDS];
        for (word, chunk) in block.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(chunk.try_into().unwrap());
        }
    }

    for pass in 0..PASSES {
        for slice in 0..SYNC_POINTS {
            let start = if pass == 0 && slice == 0 { 2 } else { 0 };
            for index in start..SEGMENT_LENGTH {
                let current = slice * SEGMENT_LENGTH + index;
                let previous = if current == 0 { MEMORY_BLOCKS - 1 } else { current - 1 };
                let pseudo_rand = memory[previous * BLOCK_WORDS];
                let reference = reference_index(pass, slice, index, pseudo_rand as u32);
                fill_block(&mut memory, previous, reference, current, pass != 0);
            }
        }
    }
    memory
}

/// The block a new block references, for one lane (RFC 9106, section 3.4.1.2).
fn reference_index(pass: u32, slice: usize, index: usize, j1: u32) -> usize {
    let area = if pass == 0 {
        if slice == 0 { index - 1 } else { slice * SEGMENT_LENGTH + index - 1 }
    } else {
        MEMORY_BLOCKS - SEGMENT_LENGTH + index - 1
    } as u64;
    let x = (u64::from(j1) * u64::from(j1)) >> 32;
    let relative = area - 1 - ((area * x) >> 32);
    let start = if pass != 0 && slice != SYNC_POINTS - 1 { (slice + 1) * SEGMENT_LENGTH } else { 0 };
    (start + relative as usize) % MEMORY_BLOCKS
}

fn fill_block(memory: &mut [u64], previous: usize, reference: usize, current: usize, with_xor: bool) {
    let mut r = [0u64; BLOCK_WORDS];
    for (i, word) in r.iter_mut().enumerate() {
        *word = memory[previous * BLOCK_WORDS + i] ^ memory[reference * BLOCK_WORDS + i];
    }
    let mut tmp = r;
    if with_xor {
        for (i, word) in tmp.iter_mut().enumerate() {
            *word ^= memory[current * BLOCK_WORDS + i];
        }
    }
    for row in 0..8 {
        let mut idx = [0usize; 16];
        for (k, slot) in idx.iter_mut().enumerate() {
            *slot = 16 * row + k;
        }
        round(&mut r, &idx);
    }
    for column in 0..8 {
        let mut idx = [0usize; 16];
        for (k, slot) in idx.iter_mut().enumerate() {
            *slot = 2 * column + (k % 2) + 16 * (k / 2);
        }
        round(&mut r, &idx);
    }
    for (i, word) in memory[current * BLOCK_WORDS..(current + 1) * BLOCK_WORDS].iter_mut().enumerate() {
        *word = tmp[i] ^ r[i];
    }
}

fn round(v: &mut [u64; BLOCK_WORDS], i: &[usize; 16]) {
    g(v, i[0], i[4], i[8], i[12]);
    g(v, i[1], i[5], i[9], i[13]);
    g(v, i[2], i[6], i[10], i[14]);
    g(v, i[3], i[7], i[11], i[15]);
    g(v, i[0], i[5], i[10], i[15]);
    g(v, i[1], i[6], i[11], i[12]);
    g(v, i[2], i[7], i[8], i[13]);
    g(v, i[3], i[4], i[9], i[14]);
}

fn bla_mka(x: u64, y: u64) -> u64 {
    let product = u64::from(x as u32).wrapping_mul(u64::from(y as u32));
    x.wrapping_add(y).wrapping_add(product.wrapping_mul(2))
}

fn g(v: &mut [u64; BLOCK_WORDS], a: usize, b: usize, c: usize, d: usize) {
    v[a] = bla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = bla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = bla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = bla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}
