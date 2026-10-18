//! Blake2b (RFC 7693), unkeyed, with any output length from 1 to 64 bytes.
//! RandomX uses it for the first hash of the input, between programs, for the
//! final hash and inside Argon2d and the Blake2 generator.

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// A Blake2b hash in progress.
pub struct Blake2b {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    counter: u128,
    out_len: usize,
}

impl Blake2b {
    /// Starts a hash with `out_len` bytes of output (1 to 64).
    pub fn new(out_len: usize) -> Self {
        assert!((1..=64).contains(&out_len), "Blake2b output is 1 to 64 bytes");
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ out_len as u64;
        Self { h, buf: [0; 128], buf_len: 0, counter: 0, out_len }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buf_len == 128 {
                self.counter += 128;
                let block = self.buf;
                self.compress(&block, false);
                self.buf_len = 0;
            }
            let take = (128 - self.buf_len).min(input.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&input[..take]);
            self.buf_len += take;
            input = &input[take..];
        }
    }

    /// Writes the hash into `out`, which must be `out_len` bytes long.
    pub fn finalize(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.out_len);
        self.counter += self.buf_len as u128;
        self.buf[self.buf_len..].fill(0);
        let block = self.buf;
        self.compress(&block, true);
        for (chunk, word) in out.chunks_mut(8).zip(self.h.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
    }

    fn compress(&mut self, block: &[u8; 128], last: bool) {
        let mut m = [0u64; 16];
        for (word, bytes) in m.iter_mut().zip(block.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.counter as u64;
        v[13] ^= (self.counter >> 64) as u64;
        if last {
            v[14] = !v[14];
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The 64-byte Blake2b hash of the concatenated parts.
pub fn hash512(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Blake2b::new(64);
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 64];
    hasher.finalize(&mut out);
    out
}

/// The 32-byte Blake2b hash of `input`.
pub fn hash256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::new(32);
    hasher.update(input);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Argon2's variable-length hash `H'` (RFC 9106, section 3.3) for outputs
/// longer than 64 bytes.
pub fn hash_long(out: &mut [u8], parts: &[&[u8]]) {
    debug_assert!(out.len() > 64);
    let len = (out.len() as u32).to_le_bytes();
    let mut all: Vec<&[u8]> = vec![&len];
    all.extend_from_slice(parts);
    let mut v = hash512(&all);
    out[..32].copy_from_slice(&v[..32]);
    let mut pos = 32;
    while out.len() - pos > 64 {
        v = hash512(&[&v]);
        out[pos..pos + 32].copy_from_slice(&v[..32]);
        pos += 32;
    }
    let rest = out.len() - pos;
    let mut last = Blake2b::new(rest);
    last.update(&v);
    last.finalize(&mut out[pos..]);
}
