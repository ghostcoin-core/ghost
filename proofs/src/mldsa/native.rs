//! ML-DSA-44 verification (FIPS 204, `ML-DSA.Verify`, algorithms 3 and 8)
//! computed natively, step by step, keeping every value the chunk circuit
//! needs as a witness: the decoded signature, the matrix, the challenge
//! polynomial and `w'_approx`.
//!
//! SHAKE-128 and SHAKE-256 are the Keccak-f\[1600\] sponge of FIPS 202 over
//! the pinned `p3_keccak` permutation; the arithmetic is modulo
//! `q = 8,380,417` on integers.

use alloc::vec::Vec;

use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

/// The modulus `q`.
pub const Q: u32 = 8_380_417;
/// Coefficients of a polynomial.
pub const N: usize = 256;
/// Rows of the matrix `A` (ML-DSA-44).
pub const K: usize = 4;
/// Columns of the matrix `A` (ML-DSA-44).
pub const L: usize = 4;
/// Nonzero coefficients of the challenge polynomial.
pub const TAU: usize = 39;
/// `tau * eta`.
pub const BETA: u32 = 78;
/// The range of `z`'s coefficients.
pub const GAMMA1: u32 = 1 << 17;
/// The low-order rounding range, `(q - 1) / 88`.
pub const GAMMA2: u32 = (Q - 1) / 88;
/// The most hint bits a signature may set.
pub const OMEGA: usize = 80;
/// Bits dropped from `t`.
pub const D: u32 = 13;
/// Bytes of a public key.
pub const PUBLIC_KEY_BYTES: usize = 1312;
/// Bytes of a signature.
pub const SIGNATURE_BYTES: usize = 2420;
/// Bytes of the commitment hash `c~` (`lambda / 4`).
pub const C_TILDE_BYTES: usize = 32;
/// Rate of SHAKE-128 in bytes.
pub const SHAKE128_RATE: usize = 168;
/// Rate of SHAKE-256 in bytes.
pub const SHAKE256_RATE: usize = 136;

/// `zeta = 1753`, the 512th root of unity modulo `q`.
const ZETA: u64 = 1753;

/// The Keccak-f\[1600\] permutation of the pinned library on 25 lanes.
pub fn keccak_f(state: &mut [u64; 25]) {
    KeccakF.permute_mut(state);
}

/// A SHAKE sponge (FIPS 202) with the domain byte `0x1F`, counting the
/// permutations it runs.
#[derive(Clone)]
pub struct Shake {
    state: [u64; 25],
    rate: usize,
    /// Bytes absorbed into the current block, or squeezed from it.
    pos: usize,
    squeezing: bool,
    permutations: usize,
}

impl Shake {
    pub fn new(rate: usize) -> Self {
        Self {
            state: [0; 25],
            rate,
            pos: 0,
            squeezing: false,
            permutations: 0,
        }
    }

    pub fn shake128() -> Self {
        Self::new(SHAKE128_RATE)
    }

    pub fn shake256() -> Self {
        Self::new(SHAKE256_RATE)
    }

    fn xor_byte(&mut self, at: usize, b: u8) {
        self.state[at / 8] ^= u64::from(b) << (8 * (at % 8));
    }

    fn byte(&self, at: usize) -> u8 {
        (self.state[at / 8] >> (8 * (at % 8))) as u8
    }

    fn permute(&mut self) {
        keccak_f(&mut self.state);
        self.permutations += 1;
    }

    pub fn absorb(&mut self, data: &[u8]) {
        debug_assert!(!self.squeezing);
        for &b in data {
            self.xor_byte(self.pos, b);
            self.pos += 1;
            if self.pos == self.rate {
                self.permute();
                self.pos = 0;
            }
        }
    }

    fn finish(&mut self) {
        if !self.squeezing {
            self.xor_byte(self.pos, 0x1F);
            self.xor_byte(self.rate - 1, 0x80);
            self.permute();
            self.pos = 0;
            self.squeezing = true;
        }
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.finish();
        for o in out {
            if self.pos == self.rate {
                self.permute();
                self.pos = 0;
            }
            *o = self.byte(self.pos);
            self.pos += 1;
        }
    }

    pub fn squeeze_vec(&mut self, n: usize) -> Vec<u8> {
        let mut out = alloc::vec![0u8; n];
        self.squeeze(&mut out);
        out
    }

    /// The permutations run so far.
    pub fn permutations(&self) -> usize {
        self.permutations
    }
}

/// SHAKE-256 of `data`, `n` bytes.
pub fn shake256(data: &[&[u8]], n: usize) -> Vec<u8> {
    let mut h = Shake::shake256();
    for d in data {
        h.absorb(d);
    }
    h.squeeze_vec(n)
}

const fn brv8(k: usize) -> usize {
    (k as u8).reverse_bits() as usize
}

fn pow_mod(mut b: u64, mut e: u64) -> u32 {
    let mut acc = 1u64;
    b %= u64::from(Q);
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * b % u64::from(Q);
        }
        b = b * b % u64::from(Q);
        e >>= 1;
    }
    acc as u32
}

/// `zetas[k] = zeta^brv8(k) mod q`, the twiddle factors of the NTT.
pub fn zetas() -> [u32; N] {
    core::array::from_fn(|k| pow_mod(ZETA, brv8(k) as u64))
}

fn mul(a: u32, b: u32) -> u32 {
    (u64::from(a) * u64::from(b) % u64::from(Q)) as u32
}

fn add(a: u32, b: u32) -> u32 {
    (a + b) % Q
}

fn sub(a: u32, b: u32) -> u32 {
    (a + Q - b) % Q
}

/// The NTT of FIPS 204, algorithm 41, on canonical coefficients.
pub fn ntt(w: &[u32; N]) -> [u32; N] {
    let z = zetas();
    let mut w = *w;
    let mut m = 0;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            m += 1;
            for j in start..start + len {
                let t = mul(z[m], w[j + len]);
                w[j + len] = sub(w[j], t);
                w[j] = add(w[j], t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
    w
}

/// The inverse NTT of FIPS 204, algorithm 42.
pub fn ntt_inverse(w: &[u32; N]) -> [u32; N] {
    let z = zetas();
    let mut w = *w;
    let mut m = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            m -= 1;
            let zeta = Q - z[m];
            for j in start..start + len {
                let t = w[j];
                w[j] = add(t, w[j + len]);
                w[j + len] = mul(zeta, sub(t, w[j + len]));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    const F: u32 = 8_347_681;
    w.map(|x| mul(F, x))
}

/// A coefficient from three bytes (FIPS 204, algorithm 14): `None` when it
/// is not below `q`.
pub fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Option<u32> {
    let z = u32::from(b0) | u32::from(b1) << 8 | u32::from(b2 & 0x7F) << 16;
    (z < Q).then_some(z)
}

/// `RejNTTPoly(rho || s || r)` (FIPS 204, algorithm 30): the polynomial and
/// how many three-byte candidates it read.
pub fn rej_ntt_poly(rho: &[u8; 32], s: u8, r: u8) -> ([u32; N], usize) {
    let mut g = Shake::shake128();
    g.absorb(rho);
    g.absorb(&[s, r]);
    let mut out = [0u32; N];
    let mut j = 0;
    let mut read = 0;
    while j < N {
        let mut b = [0u8; 3];
        g.squeeze(&mut b);
        read += 1;
        if let Some(a) = coeff_from_three_bytes(b[0], b[1], b[2]) {
            out[j] = a;
            j += 1;
        }
    }
    (out, read)
}

/// `ExpandA(rho)` (FIPS 204, algorithm 32), with the most candidates any
/// entry read.
pub fn expand_a(rho: &[u8; 32]) -> ([[[u32; N]; L]; K], usize) {
    let mut a = [[[0u32; N]; L]; K];
    let mut most = 0;
    for (r, row) in a.iter_mut().enumerate() {
        for (s, entry) in row.iter_mut().enumerate() {
            let (p, read) = rej_ntt_poly(rho, s as u8, r as u8);
            *entry = p;
            most = most.max(read);
        }
    }
    (a, most)
}

/// `SampleInBall(c~)` (FIPS 204, algorithm 29), with coefficients in
/// `{-1, 0, 1}`, and the index of the last squeezed byte it read.
pub fn sample_in_ball(c_tilde: &[u8; C_TILDE_BYTES]) -> ([i8; N], usize) {
    let mut h = Shake::shake256();
    h.absorb(c_tilde);
    let signs = h.squeeze_vec(8);
    let signs = u64::from_le_bytes(signs.try_into().expect("eight bytes"));
    let mut c = [0i8; N];
    let mut read = 8;
    for i in N - TAU..N {
        let mut j;
        loop {
            let mut b = [0u8; 1];
            h.squeeze(&mut b);
            read += 1;
            j = usize::from(b[0]);
            if j <= i {
                break;
            }
        }
        c[i] = c[j];
        c[j] = if signs >> (i + TAU - N) & 1 == 1 { -1 } else { 1 };
    }
    (c, read - 1)
}

/// `Decompose(r)` (FIPS 204, algorithm 36): `(r1, r0)` with `r0` centred.
pub fn decompose(r: u32) -> (u32, i32) {
    let r = r % Q;
    let two_gamma2 = 2 * GAMMA2 as i32;
    let mut r0 = (r as i32) % two_gamma2;
    if r0 > GAMMA2 as i32 {
        r0 -= two_gamma2;
    }
    if r as i32 - r0 == Q as i32 - 1 {
        (0, r0 - 1)
    } else {
        (((r as i32 - r0) / two_gamma2) as u32, r0)
    }
}

/// `UseHint(h, r)` (FIPS 204, algorithm 40).
pub fn use_hint(h: bool, r: u32) -> u32 {
    let m = (Q - 1) / (2 * GAMMA2);
    let (r1, r0) = decompose(r);
    if h && r0 > 0 {
        (r1 + 1) % m
    } else if h {
        (r1 + m - 1) % m
    } else {
        r1
    }
}

/// A decoded public key: `rho` and `t1`.
#[derive(Clone)]
pub struct PublicKey {
    pub rho: [u8; 32],
    pub t1: [[u32; N]; K],
}

/// `pkDecode` (FIPS 204, algorithm 23).
pub fn decode_public_key(pk: &[u8; PUBLIC_KEY_BYTES]) -> PublicKey {
    let rho: [u8; 32] = pk[..32].try_into().expect("32 bytes");
    let mut t1 = [[0u32; N]; K];
    for (r, poly) in t1.iter_mut().enumerate() {
        for (i, c) in poly.iter_mut().enumerate() {
            let bit = 320 * 8 * r + 10 * i;
            *c = read_bits(&pk[32..], bit, 10);
        }
    }
    PublicKey { rho, t1 }
}

fn read_bits(bytes: &[u8], at: usize, n: usize) -> u32 {
    (0..n).fold(0u32, |acc, k| {
        let b = at + k;
        acc | u32::from(bytes[b / 8] >> (b % 8) & 1) << k
    })
}

/// A decoded signature: `c~`, `z` (centred) and the hint bits.
#[derive(Clone)]
pub struct DecodedSignature {
    pub c_tilde: [u8; C_TILDE_BYTES],
    pub z: [[i32; N]; L],
    pub h: [[bool; N]; K],
}

/// `sigDecode` (FIPS 204, algorithm 27) with `HintBitUnpack` (algorithm 21):
/// `None` for a malformed hint.
pub fn decode_signature(sig: &[u8; SIGNATURE_BYTES]) -> Option<DecodedSignature> {
    let c_tilde: [u8; C_TILDE_BYTES] = sig[..C_TILDE_BYTES].try_into().expect("32 bytes");
    let zb = &sig[C_TILDE_BYTES..C_TILDE_BYTES + 32 * 18 * L];
    let mut z = [[0i32; N]; L];
    for (s, poly) in z.iter_mut().enumerate() {
        for (i, c) in poly.iter_mut().enumerate() {
            let v = read_bits(zb, 576 * 8 * s + 18 * i, 18);
            *c = GAMMA1 as i32 - v as i32;
        }
    }
    let y = &sig[C_TILDE_BYTES + 32 * 18 * L..];
    debug_assert_eq!(y.len(), OMEGA + K);
    let mut h = [[false; N]; K];
    let mut index = 0usize;
    for (i, row) in h.iter_mut().enumerate() {
        let end = usize::from(y[OMEGA + i]);
        if end < index || end > OMEGA {
            return None;
        }
        let first = index;
        while index < end {
            if index > first && y[index - 1] >= y[index] {
                return None;
            }
            row[usize::from(y[index])] = true;
            index += 1;
        }
    }
    if y[index..OMEGA].iter().any(|&b| b != 0) {
        return None;
    }
    Some(DecodedSignature { c_tilde, z, h })
}

/// `M' = 0 || |ctx| || ctx || M` (FIPS 204, algorithm 3).
pub fn message_prime(ctx: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = alloc::vec![0u8, ctx.len() as u8];
    m.extend_from_slice(ctx);
    m.extend_from_slice(msg);
    m
}

/// Everything a verification computes that the chunk circuit takes as a
/// witness or checks against.
#[derive(Clone)]
pub struct Verification {
    pub pk: PublicKey,
    pub sig: DecodedSignature,
    /// `w'_approx = NTT^-1(A z^ - c^ t1^ 2^d)`, canonical.
    pub w_approx: [[u32; N]; K],
    /// `w1' = UseHint(h, w'_approx)`.
    pub w1: [[u32; N]; K],
    /// The candidates the longest `RejNTTPoly` read, and the last byte
    /// `SampleInBall` read (its index in the squeezed stream).
    pub most_candidates: usize,
    pub last_ball_byte: usize,
    /// `SHAKE256(pk, 32)`: the key identity.
    pub key_id: [u8; 32],
    /// The permutations the verification ran.
    pub permutations: usize,
}

/// Why a verification failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The context is longer than 255 bytes.
    Context,
    /// The hint is not a valid encoding.
    Hint,
    /// `||z||_inf >= gamma1 - beta`.
    Norm,
    /// `c~ != c~'`.
    Commitment,
}

/// `ML-DSA.Verify(pk, M, sigma, ctx)` (FIPS 204, algorithm 3), keeping its
/// intermediate values.
pub fn verify(
    pk_bytes: &[u8; PUBLIC_KEY_BYTES],
    msg: &[u8],
    sig_bytes: &[u8; SIGNATURE_BYTES],
    ctx: &[u8],
) -> Result<Verification, Refusal> {
    match compute(pk_bytes, msg, sig_bytes, ctx)? {
        (v, None) => Ok(v),
        (_, Some(r)) => Err(r),
    }
}

/// The values a verification computes, with the check it fails, if any:
/// `Err` only when the signature does not decode (or the context is too
/// long), so nothing can be computed.
pub fn compute(
    pk_bytes: &[u8; PUBLIC_KEY_BYTES],
    msg: &[u8],
    sig_bytes: &[u8; SIGNATURE_BYTES],
    ctx: &[u8],
) -> Result<(Verification, Option<Refusal>), Refusal> {
    if ctx.len() > 255 {
        return Err(Refusal::Context);
    }
    let pk = decode_public_key(pk_bytes);
    let sig = decode_signature(sig_bytes).ok_or(Refusal::Hint)?;
    let mut perms = 0;
    let (a, most_candidates) = expand_a(&pk.rho);
    // Five SHAKE-128 blocks a matrix entry when no entry reads more.
    perms += K * L * most_candidates.div_ceil(SHAKE128_RATE / 3);
    let mut tr_sponge = Shake::shake256();
    tr_sponge.absorb(pk_bytes);
    let tr = tr_sponge.squeeze_vec(64);
    perms += tr_sponge.permutations();
    let mut mu_sponge = Shake::shake256();
    mu_sponge.absorb(&tr);
    mu_sponge.absorb(&message_prime(ctx, msg));
    let mu = mu_sponge.squeeze_vec(64);
    perms += mu_sponge.permutations();
    let (c, last_ball_byte) = sample_in_ball(&sig.c_tilde);
    perms += last_ball_byte / SHAKE256_RATE + 1;

    let to_q = |x: i32| -> u32 { (x.rem_euclid(Q as i32)) as u32 };
    let z_hat: [[u32; N]; L] = core::array::from_fn(|s| ntt(&sig.z[s].map(to_q)));
    let c_hat = ntt(&c.map(|x| to_q(i32::from(x))));
    let mut w_approx = [[0u32; N]; K];
    let mut w1 = [[0u32; N]; K];
    for r in 0..K {
        let t_hat = ntt(&pk.t1[r].map(|t| t << D));
        let mut acc = [0u32; N];
        for i in 0..N {
            let mut v = 0u32;
            for s in 0..L {
                v = add(v, mul(a[r][s][i], z_hat[s][i]));
            }
            acc[i] = sub(v, mul(c_hat[i], t_hat[i]));
        }
        w_approx[r] = ntt_inverse(&acc);
        for i in 0..N {
            w1[r][i] = use_hint(sig.h[r][i], w_approx[r][i]);
        }
    }
    let mut packed = Vec::with_capacity(K * N * 6 / 8);
    let mut bits = 0u64;
    let mut nbits = 0;
    for poly in &w1 {
        for &x in poly {
            bits |= u64::from(x) << nbits;
            nbits += 6;
            while nbits >= 8 {
                packed.push(bits as u8);
                bits >>= 8;
                nbits -= 8;
            }
        }
    }
    let mut c_sponge = Shake::shake256();
    c_sponge.absorb(&mu);
    c_sponge.absorb(&packed);
    let c_tilde2 = c_sponge.squeeze_vec(C_TILDE_BYTES);
    perms += c_sponge.permutations();
    let bound = (GAMMA1 - BETA) as i32;
    let refusal = if sig.z.iter().flatten().any(|&x| x.abs() >= bound) {
        Some(Refusal::Norm)
    } else if c_tilde2[..] != sig.c_tilde[..] {
        Some(Refusal::Commitment)
    } else {
        None
    };
    let key_id: [u8; 32] = tr[..32].try_into().expect("32 bytes");
    let v = Verification {
        pk,
        sig,
        w_approx,
        w1,
        most_candidates,
        last_ball_byte,
        key_id,
        permutations: perms,
    };
    Ok((v, refusal))
}

/// The key identity of a public key: `SHAKE256(pk, 32)`, the first half of
/// `tr`.
pub fn key_identity(pk: &[u8; PUBLIC_KEY_BYTES]) -> [u8; 32] {
    shake256(&[pk], 32).try_into().expect("32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ntt_inverts() {
        let w: [u32; N] = core::array::from_fn(|i| (i as u32 * 7919 + 13) % Q);
        assert_eq!(ntt_inverse(&ntt(&w)), w);
    }

    #[test]
    fn decompose_recomposes() {
        for r in [0, 1, GAMMA2, GAMMA2 + 1, 2 * GAMMA2, Q - 1, Q - GAMMA2, Q - 2] {
            let (r1, r0) = decompose(r);
            let back = (r1 as i64 * 2 * GAMMA2 as i64 + r0 as i64).rem_euclid(Q as i64);
            assert_eq!(back as u32, r);
            assert!(r1 < 44 && r0 > -(GAMMA2 as i32) - 1 && r0 <= GAMMA2 as i32);
        }
    }

    #[test]
    fn shake_matches_known_digests() {
        // SHAKE-256 and SHAKE-128 of the empty string (FIPS 202 examples).
        assert_eq!(shake256(&[], 4), [0x46, 0xb9, 0xdd, 0x2b]);
        let mut s = Shake::shake128();
        assert_eq!(s.squeeze_vec(4), [0x7f, 0x9c, 0x2b, 0xa4]);
    }
}
