//! RandomX v1 in light mode, in Rust: the hash a Ghost seal is checked with
//! (spec 08). It follows the reference `tevador/RandomX` at the commit spec
//! 08 pins, with the default configuration except the Argon2 salt, and runs
//! the program VM as an interpreter with software AES and software
//! floating-point rounding, so it builds for `wasm32-unknown-unknown`.
//!
//! Light mode keeps only the 256 MiB cache and computes each dataset item
//! when a program reads it. It is slow (every hash computes 16,384 items) but
//! needs no 2 GiB dataset.

mod aes;
mod argon2;
mod blake2b;
mod float;
mod superscalar;
mod vm;

use superscalar::{Blake2Generator, Program};

/// Ghost's Argon2 salt, 14 bytes: the ASCII text `Ghost-RandomX` followed
/// by the byte `0x01`.
pub const GHOST_SALT: &[u8; 14] = b"Ghost-RandomX\x01";
/// The reference's own salt, `RandomX` followed by `0x03` (Monero's). Ghost
/// never uses it; it is here for the reference test vectors.
pub const REFERENCE_SALT: &[u8; 8] = b"RandomX\x03";

/// Bytes in one cache line and one dataset item.
const CACHE_LINE_SIZE: usize = 64;
/// Cache lines in the cache (`RANDOMX_ARGON_MEMORY` KiB).
const CACHE_LINES: usize = argon2::MEMORY_BLOCKS * 1024 / CACHE_LINE_SIZE;
/// SuperscalarHash programs, one per cache access (`RANDOMX_CACHE_ACCESSES`).
const CACHE_ACCESSES: usize = 8;

const SUPERSCALAR_MUL0: u64 = 6364136223846793005;
const SUPERSCALAR_ADD: [u64; 8] = [
    0,
    9298411001130361340,
    12065312585734608966,
    9306329213124626780,
    5281919268842080866,
    10536153434571861004,
    3398623926847679864,
    9549104520008361294,
];

/// The RandomX cache for one key: the Argon2d memory (256 MiB) and the eight
/// SuperscalarHash programs. Building it is the expensive step; one cache
/// serves every hash under the same key.
pub struct Cache {
    memory: Vec<u64>,
    programs: Vec<Program>,
}

impl Cache {
    /// The cache for `key` under Ghost's salt.
    pub fn new(key: &[u8]) -> Self {
        Self::with_salt(key, GHOST_SALT)
    }

    /// The cache for `key` under another Argon2 salt (at least 8 bytes).
    /// Only Ghost's salt gives Ghost seals; other salts are for tests.
    pub fn with_salt(key: &[u8], salt: &[u8]) -> Self {
        assert!(salt.len() >= 8, "an Argon2 salt has at least 8 bytes");
        let memory = argon2::fill_memory(key, salt);
        let mut rng = Blake2Generator::new(key);
        let programs = (0..CACHE_ACCESSES).map(|_| superscalar::generate(&mut rng)).collect();
        Self { memory, programs }
    }

    /// Dataset item `item` (64 bytes as eight words), computed from the cache.
    fn dataset_item(&self, item: u64) -> [u64; 8] {
        let mut r = [0u64; 8];
        r[0] = item.wrapping_add(1).wrapping_mul(SUPERSCALAR_MUL0);
        for i in 1..8 {
            r[i] = r[0] ^ SUPERSCALAR_ADD[i];
        }
        let mut register_value = item;
        for program in &self.programs {
            let line = (register_value as usize) & (CACHE_LINES - 1);
            superscalar::execute(program, &mut r);
            for (q, word) in r.iter_mut().enumerate() {
                *word ^= self.memory[line * 8 + q];
            }
            register_value = r[program.address_register];
        }
        r
    }
}

/// The RandomX hash of `input` under `cache`'s key and salt.
pub fn hash(cache: &Cache, input: &[u8]) -> [u8; 32] {
    let mut seed = blake2b::hash512(&[input]);
    let mut scratchpad = vec![0u8; vm::SCRATCHPAD_BYTES];
    aes::fill_1r(&mut seed, &mut scratchpad);
    let mut machine = vm::Vm::new(cache, scratchpad);
    for _ in 0..7 {
        machine.run(&seed);
        seed = blake2b::hash512(&[&machine.register_file()]);
    }
    machine.run(&seed);
    let fingerprint = aes::hash_1r(&machine.scratchpad);
    machine.set_a(&fingerprint);
    blake2b::hash256(&machine.register_file())
}
