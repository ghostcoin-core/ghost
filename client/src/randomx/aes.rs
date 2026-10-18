//! One AES round in each direction, as the x86 `AESENC` and `AESDEC`
//! instructions compute it, and RandomX's AES generators and hash built on
//! them (RandomX specification, sections 3.2 to 3.4). Software only: the
//! client must build for targets without AES instructions.

const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

const fn sbox() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        // The multiplicative inverse is x^254 (zero maps to zero), by
        // square and multiply.
        let mut inv = 1u8;
        let mut base = x as u8;
        let mut e = 254u32;
        while e != 0 {
            if e & 1 != 0 {
                inv = gmul(inv, base);
            }
            base = gmul(base, base);
            e >>= 1;
        }
        let s = inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63;
        table[x] = s;
        x += 1;
    }
    table
}

const fn inverse(table: &[u8; 256]) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        out[table[x] as usize] = x as u8;
        x += 1;
    }
    out
}

const fn mul_table(factor: u8) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        out[x] = gmul(x as u8, factor);
        x += 1;
    }
    out
}

static SBOX: [u8; 256] = sbox();
static INV_SBOX: [u8; 256] = inverse(&sbox());
static MUL2: [u8; 256] = mul_table(2);
static MUL3: [u8; 256] = mul_table(3);
static MUL9: [u8; 256] = mul_table(9);
static MUL11: [u8; 256] = mul_table(11);
static MUL13: [u8; 256] = mul_table(13);
static MUL14: [u8; 256] = mul_table(14);

pub type Block = [u8; 16];

/// `AESENC`: ShiftRows, SubBytes, MixColumns, then XOR with the key.
pub fn aesenc(state: &Block, key: &Block) -> Block {
    let mut t = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            t[r + 4 * c] = SBOX[state[r + 4 * ((c + r) % 4)] as usize];
        }
    }
    let mut out = [0u8; 16];
    for c in 0..4 {
        let [a0, a1, a2, a3] = [t[4 * c], t[4 * c + 1], t[4 * c + 2], t[4 * c + 3]].map(usize::from);
        out[4 * c] = MUL2[a0] ^ MUL3[a1] ^ t[4 * c + 2] ^ t[4 * c + 3] ^ key[4 * c];
        out[4 * c + 1] = t[4 * c] ^ MUL2[a1] ^ MUL3[a2] ^ t[4 * c + 3] ^ key[4 * c + 1];
        out[4 * c + 2] = t[4 * c] ^ t[4 * c + 1] ^ MUL2[a2] ^ MUL3[a3] ^ key[4 * c + 2];
        out[4 * c + 3] = MUL3[a0] ^ t[4 * c + 1] ^ t[4 * c + 2] ^ MUL2[a3] ^ key[4 * c + 3];
    }
    out
}

/// `AESDEC`: InvShiftRows, InvSubBytes, InvMixColumns, then XOR with the key.
pub fn aesdec(state: &Block, key: &Block) -> Block {
    let mut t = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            t[r + 4 * c] = INV_SBOX[state[r + 4 * ((c + 4 - r) % 4)] as usize];
        }
    }
    let mut out = [0u8; 16];
    for c in 0..4 {
        let [a0, a1, a2, a3] = [t[4 * c], t[4 * c + 1], t[4 * c + 2], t[4 * c + 3]].map(usize::from);
        out[4 * c] = MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3] ^ key[4 * c];
        out[4 * c + 1] = MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3] ^ key[4 * c + 1];
        out[4 * c + 2] = MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3] ^ key[4 * c + 2];
        out[4 * c + 3] = MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3] ^ key[4 * c + 3];
    }
    out
}

/// A 128-bit constant written as the reference writes it for
/// `_mm_set_epi32`: the most significant 32-bit word first.
const fn words(w3: u32, w2: u32, w1: u32, w0: u32) -> Block {
    let mut out = [0u8; 16];
    let ws = [w0, w1, w2, w3];
    let mut i = 0;
    while i < 4 {
        let bytes = ws[i].to_le_bytes();
        out[4 * i] = bytes[0];
        out[4 * i + 1] = bytes[1];
        out[4 * i + 2] = bytes[2];
        out[4 * i + 3] = bytes[3];
        i += 1;
    }
    out
}

/// AesGenerator1R keys: Blake2b-512 of "RandomX AesGenerator1R keys".
pub const GEN_1R_KEYS: [Block; 4] = [
    words(0xb4f44917, 0xdbb5552b, 0x62716609, 0x6daca553),
    words(0x0da1dc4e, 0x1725d378, 0x846a710d, 0x6d7caf07),
    words(0x3e20e345, 0xf4c0794f, 0x9f947ec6, 0x3f1262f1),
    words(0x49169154, 0x16314c88, 0xb1ba317c, 0x6aef8135),
];

/// AesGenerator4R keys: Blake2b-512 of "RandomX AesGenerator4R keys 0-3",
/// then of "RandomX AesGenerator4R keys 4-7".
pub const GEN_4R_KEYS: [Block; 8] = [
    words(0x99e5d23f, 0x2f546d2b, 0xd1833ddb, 0x6421aadd),
    words(0xa5dfcde5, 0x06f79d53, 0xb6913f55, 0xb20e3450),
    words(0x171c02bf, 0x0aa4679f, 0x515e7baf, 0x5c3ed904),
    words(0xd8ded291, 0xcd673785, 0xe78f5d08, 0x85623763),
    words(0x229effb4, 0x3d518b6d, 0xe3d6a7a6, 0xb5826f73),
    words(0xb272b7d2, 0xe9024d4e, 0x9c10b3d9, 0xc7566bf3),
    words(0xf63befa7, 0x2ba9660a, 0xf765a38b, 0xf273c9e7),
    words(0xc0b0762d, 0x0c06d1fd, 0x915839de, 0x7a7cd609),
];

/// AesHash1R initial state: Blake2b-512 of "RandomX AesHash1R state".
pub const HASH_1R_STATE: [Block; 4] = [
    words(0xd7983aad, 0xcc82db47, 0x9fa856de, 0x92b52c0d),
    words(0xace78057, 0xf59e125a, 0x15c7b798, 0x338d996e),
    words(0xe8a07ce4, 0x5079506b, 0xae62c7d0, 0x6a770017),
    words(0x7e994948, 0x79a10005, 0x07ad828d, 0x630a240c),
];

/// AesHash1R extra keys: Blake2b-256 of "RandomX AesHash1R xkeys".
pub const HASH_1R_XKEYS: [Block; 2] = [
    words(0x06890201, 0x90dc56bf, 0x8b24949f, 0xf6fa8389),
    words(0xed18f99b, 0xee1043c6, 0x51f4e03c, 0x61b263d1),
];

fn split(state: &[u8; 64]) -> [Block; 4] {
    let mut out = [[0u8; 16]; 4];
    for (i, block) in out.iter_mut().enumerate() {
        block.copy_from_slice(&state[16 * i..16 * i + 16]);
    }
    out
}

fn join(blocks: &[Block; 4]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, block) in blocks.iter().enumerate() {
        out[16 * i..16 * i + 16].copy_from_slice(block);
    }
    out
}

/// AesGenerator1R: fills `out` (a multiple of 64 bytes) from `state` and
/// leaves the generator's final state in `state`.
pub fn fill_1r(state: &mut [u8; 64], out: &mut [u8]) {
    let mut s = split(state);
    for chunk in out.chunks_exact_mut(64) {
        s[0] = aesdec(&s[0], &GEN_1R_KEYS[0]);
        s[1] = aesenc(&s[1], &GEN_1R_KEYS[1]);
        s[2] = aesdec(&s[2], &GEN_1R_KEYS[2]);
        s[3] = aesenc(&s[3], &GEN_1R_KEYS[3]);
        chunk.copy_from_slice(&join(&s));
    }
    *state = join(&s);
}

/// AesGenerator4R: fills `out` (a multiple of 64 bytes) from `state`.
pub fn fill_4r(state: &[u8; 64], out: &mut [u8]) {
    let k = &GEN_4R_KEYS;
    let mut s = split(state);
    for chunk in out.chunks_exact_mut(64) {
        for round in 0..4 {
            s[0] = aesdec(&s[0], &k[round]);
            s[1] = aesenc(&s[1], &k[round]);
            s[2] = aesdec(&s[2], &k[round + 4]);
            s[3] = aesenc(&s[3], &k[round + 4]);
        }
        chunk.copy_from_slice(&join(&s));
    }
}

/// AesHash1R: the 64-byte fingerprint of `input` (a multiple of 64 bytes).
pub fn hash_1r(input: &[u8]) -> [u8; 64] {
    let mut s = HASH_1R_STATE;
    for chunk in input.chunks_exact(64) {
        let x = split(chunk.try_into().unwrap());
        s[0] = aesenc(&s[0], &x[0]);
        s[1] = aesdec(&s[1], &x[1]);
        s[2] = aesenc(&s[2], &x[2]);
        s[3] = aesdec(&s[3], &x[3]);
    }
    for key in &HASH_1R_XKEYS {
        s[0] = aesenc(&s[0], key);
        s[1] = aesdec(&s[1], key);
        s[2] = aesenc(&s[2], key);
        s[3] = aesdec(&s[3], key);
    }
    join(&s)
}
