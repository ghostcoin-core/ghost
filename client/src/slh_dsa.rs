//! SLH-DSA-SHAKE-128s (FIPS 205), pure mode: the rescue key of a rescue-key
//! account (spec 09, sections 5.1, 5.2 and 9).
//!
//! The parameter set of FIPS 205, table 2: `n = 16`, `h = 63`, `d = 7`,
//! `h' = 9`, `a = 12`, `k = 14`, `lg_w = 4`, `m = 30`, every hash SHAKE256
//! (section 11.1) on `tiny-keccak`. The functions follow the algorithms of
//! FIPS 205 by name and number:
//!
//! ```text
//! (SK, PK)  = slh_keygen_internal(SK.seed, SK.prf, PK.seed)       algorithm 18
//! M'        = 0x00 || len(ctx) as 1 byte || ctx || M              algorithms 22, 24
//! signature = slh_sign_internal(M', SK, opt_rand)                 algorithm 19
//! valid     = slh_verify_internal(M', signature, PK)              algorithm 20
//! ```
//!
//! Signing is hedged: `opt_rand` is 16 fresh bytes from the caller's
//! generator (FIPS 205, section 10.2.1, "hedged variant").
//!
//! # Secrets
//!
//! [`SigningKey`] has no `Debug`, `Display`, `Clone` or serialisation and
//! overwrites `SK.seed` and `SK.prf` with zeros when dropped. Every WOTS+ and
//! FORS secret value is wiped after use. The SHAKE256 states of `tiny-keccak`
//! are not wiped (see the crate documentation).

use rand_core::CryptoRng;
use tiny_keccak::{Hasher, Shake};

use crate::wipe::wipe;

/// Security parameter: the bytes of every hash value and seed.
pub const N: usize = 16;
/// FIPS 205 encoding of a public key, `PK.seed || PK.root`.
pub const PUBLIC_KEY_BYTES: usize = 2 * N;
/// Signature length: `n * (1 + k * (1 + a) + h + d * len)` = 7,856.
pub const SIGNATURE_BYTES: usize = N * (1 + K * (1 + A) + H + D * LEN);

/// Total tree height.
const H: usize = 63;
/// Layers of the hypertree.
const D: usize = 7;
/// Height of one XMSS tree.
const HP: usize = H / D;
/// Height of one FORS tree.
const A: usize = 12;
/// FORS trees.
const K: usize = 14;
/// Bits of one WOTS+ digit.
const LG_W: u32 = 4;
/// WOTS+ chain length.
const W: u32 = 1 << LG_W;
/// Bytes of `H_msg`.
const M: usize = 30;
/// WOTS+ message digits.
const LEN1: usize = 8 * N / LG_W as usize;
/// WOTS+ checksum digits.
const LEN2: usize = 3;
/// WOTS+ chains.
const LEN: usize = LEN1 + LEN2;

/// Bytes of the FORS message digest, `ceil(k * a / 8)`.
const MD_BYTES: usize = (K * A).div_ceil(8);
/// Bytes of the tree index in the digest, `ceil((h - h / d) / 8)`.
const TREE_BYTES: usize = (H - HP).div_ceil(8);
/// Bytes of the leaf index in the digest, `ceil(h / (8 d))`.
const LEAF_BYTES: usize = HP.div_ceil(8);
/// One FORS signature, `k * (1 + a) * n` bytes.
const FORS_BYTES: usize = K * (1 + A) * N;
/// One XMSS signature, a WOTS+ signature and an authentication path.
const XMSS_BYTES: usize = (LEN + HP) * N;

const _: () = assert!(SIGNATURE_BYTES == 7856);
const _: () = assert!(MD_BYTES + TREE_BYTES + LEAF_BYTES == M);

// Address types (FIPS 205, section 4.2).
const WOTS_HASH: u32 = 0;
const WOTS_PK: u32 = 1;
const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

/// The 32-byte address `ADRS` of FIPS 205, section 4.2: the layer, the tree
/// address (12 bytes), the type and three type-dependent words.
#[derive(Clone, Copy)]
struct Adrs([u8; 32]);

impl Adrs {
    fn new() -> Self {
        Self([0; 32])
    }

    fn word(&mut self, at: usize, v: u32) {
        self.0[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }

    fn set_layer_address(&mut self, layer: u32) {
        self.word(0, layer);
    }

    fn set_tree_address(&mut self, tree: u64) {
        self.0[4..8].fill(0);
        self.0[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    fn set_type_and_clear(&mut self, ty: u32) {
        self.word(16, ty);
        self.0[20..32].fill(0);
    }

    fn set_key_pair_address(&mut self, i: u32) {
        self.word(20, i);
    }

    fn key_pair_address(&self) -> u32 {
        u32::from_be_bytes(self.0[20..24].try_into().expect("4 bytes"))
    }

    /// The chain address, or the tree height: the same word.
    fn set_chain_address(&mut self, i: u32) {
        self.word(24, i);
    }

    fn set_tree_height(&mut self, z: u32) {
        self.word(24, z);
    }

    /// The hash address, or the tree index: the same word.
    fn set_hash_address(&mut self, i: u32) {
        self.word(28, i);
    }

    fn set_tree_index(&mut self, i: u32) {
        self.word(28, i);
    }

    fn tree_index(&self) -> u32 {
        u32::from_be_bytes(self.0[28..32].try_into().expect("4 bytes"))
    }
}

/// SHAKE256 over the parts, `out.len()` bytes.
fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut hasher = Shake::v256();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize(out);
}

/// `F`, `H`, `T_l` and `PRF` of FIPS 205, section 11.1: SHAKE256 over
/// `PK.seed || ADRS || input`, `n` bytes. (`PRF`'s input is `SK.seed`.)
fn thash(pk_seed: &[u8; N], adrs: &Adrs, input: &[&[u8]]) -> [u8; N] {
    let mut hasher = Shake::v256();
    hasher.update(pk_seed);
    hasher.update(&adrs.0);
    for part in input {
        hasher.update(part);
    }
    let mut out = [0u8; N];
    hasher.finalize(&mut out);
    out
}

/// `base_2b(X, b, out_len)` (FIPS 205, algorithm 4): `out.len()` integers of
/// `b` bits, read big-endian from `x`.
fn base_2b(x: &[u8], b: u32, out: &mut [u32]) {
    let mut at = 0;
    let mut bits = 0u32;
    let mut total = 0u64;
    for digit in out.iter_mut() {
        while bits < b {
            total = total << 8 | u64::from(x[at]);
            at += 1;
            bits += 8;
        }
        bits -= b;
        *digit = (total >> bits) as u32 & ((1 << b) - 1);
    }
}

/// The WOTS+ digits of a message with its checksum (FIPS 205, algorithms 7
/// and 8).
fn wots_digits(m: &[u8; N]) -> [u32; LEN] {
    let mut msg = [0u32; LEN];
    base_2b(m, LG_W, &mut msg[..LEN1]);
    let csum: u32 = msg[..LEN1].iter().map(|&d| W - 1 - d).sum();
    // csum << ((8 - (len2 * lg_w) mod 8) mod 8), then toByte(csum, 2).
    let shifted = csum << ((8 - (LEN2 as u32 * LG_W) % 8) % 8);
    let bytes = u16::try_from(shifted).expect("the checksum fits two bytes").to_be_bytes();
    base_2b(&bytes, LG_W, &mut msg[LEN1..]);
    msg
}

/// `chain(X, i, s, PK.seed, ADRS)` (FIPS 205, algorithm 5).
fn chain(x: &[u8; N], i: u32, s: u32, pk_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let mut tmp = *x;
    for j in i..i + s {
        adrs.set_hash_address(j);
        tmp = thash(pk_seed, adrs, &[&tmp]);
    }
    tmp
}

/// The secret value of WOTS+ chain `i` (FIPS 205, algorithms 6 and 7).
fn wots_sk(sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &Adrs, i: u32) -> [u8; N] {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.key_pair_address());
    sk_adrs.set_chain_address(i);
    thash(pk_seed, &sk_adrs, &[sk_seed])
}

/// `T_len` over the chain ends: the WOTS+ public key.
fn wots_compress(ends: &[u8; LEN * N], pk_seed: &[u8; N], adrs: &Adrs) -> [u8; N] {
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(WOTS_PK);
    pk_adrs.set_key_pair_address(adrs.key_pair_address());
    thash(pk_seed, &pk_adrs, &[ends])
}

/// `wots_pkGen(SK.seed, PK.seed, ADRS)` (FIPS 205, algorithm 6).
fn wots_pk_gen(sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let mut ends = [0u8; LEN * N];
    for i in 0..LEN as u32 {
        let mut sk = wots_sk(sk_seed, pk_seed, adrs, i);
        adrs.set_chain_address(i);
        let end = chain(&sk, 0, W - 1, pk_seed, adrs);
        wipe(&mut sk);
        ends[i as usize * N..][..N].copy_from_slice(&end);
    }
    wots_compress(&ends, pk_seed, adrs)
}

/// `wots_sign(M, SK.seed, PK.seed, ADRS)` (FIPS 205, algorithm 7) into `out`.
fn wots_sign(m: &[u8; N], sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &mut Adrs, out: &mut [u8]) {
    let msg = wots_digits(m);
    for (i, &digit) in msg.iter().enumerate() {
        let mut sk = wots_sk(sk_seed, pk_seed, adrs, i as u32);
        adrs.set_chain_address(i as u32);
        let value = chain(&sk, 0, digit, pk_seed, adrs);
        wipe(&mut sk);
        out[i * N..][..N].copy_from_slice(&value);
    }
}

/// `wots_pkFromSig(sig, M, PK.seed, ADRS)` (FIPS 205, algorithm 8).
fn wots_pk_from_sig(sig: &[u8], m: &[u8; N], pk_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let msg = wots_digits(m);
    let mut ends = [0u8; LEN * N];
    for (i, &digit) in msg.iter().enumerate() {
        adrs.set_chain_address(i as u32);
        let value: &[u8; N] = sig[i * N..][..N].try_into().expect("n bytes");
        let end = chain(value, digit, W - 1 - digit, pk_seed, adrs);
        ends[i * N..][..N].copy_from_slice(&end);
    }
    wots_compress(&ends, pk_seed, adrs)
}

/// `xmss_node(SK.seed, i, z, PK.seed, ADRS)` (FIPS 205, algorithm 9).
fn xmss_node(sk_seed: &[u8; N], i: u32, z: u32, pk_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    if z == 0 {
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair_address(i);
        return wots_pk_gen(sk_seed, pk_seed, adrs);
    }
    let left = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
    let right = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
    adrs.set_type_and_clear(TREE);
    adrs.set_tree_height(z);
    adrs.set_tree_index(i);
    thash(pk_seed, adrs, &[&left, &right])
}

/// `xmss_sign(M, SK.seed, idx, PK.seed, ADRS)` (FIPS 205, algorithm 10)
/// into `out`, `XMSS_BYTES` long.
fn xmss_sign(m: &[u8; N], sk_seed: &[u8; N], idx: u32, pk_seed: &[u8; N], adrs: &mut Adrs, out: &mut [u8]) {
    for j in 0..HP as u32 {
        let k = (idx >> j) ^ 1;
        let node = xmss_node(sk_seed, k, j, pk_seed, adrs);
        out[(LEN + j as usize) * N..][..N].copy_from_slice(&node);
    }
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair_address(idx);
    wots_sign(m, sk_seed, pk_seed, adrs, &mut out[..LEN * N]);
}

/// `xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)` (FIPS 205, algorithm 11).
fn xmss_pk_from_sig(idx: u32, sig: &[u8], m: &[u8; N], pk_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair_address(idx);
    let mut node = wots_pk_from_sig(&sig[..LEN * N], m, pk_seed, adrs);
    adrs.set_type_and_clear(TREE);
    adrs.set_tree_index(idx);
    for k in 0..HP {
        let auth = &sig[(LEN + k) * N..][..N];
        adrs.set_tree_height(k as u32 + 1);
        node = if (idx >> k) & 1 == 0 {
            adrs.set_tree_index(adrs.tree_index() / 2);
            thash(pk_seed, adrs, &[&node, auth])
        } else {
            adrs.set_tree_index((adrs.tree_index() - 1) / 2);
            thash(pk_seed, adrs, &[auth, &node])
        };
    }
    node
}

/// `ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)` (FIPS 205,
/// algorithm 12) into `out`, `D * XMSS_BYTES` long.
fn ht_sign(m: &[u8; N], sk_seed: &[u8; N], pk_seed: &[u8; N], mut idx_tree: u64, mut idx_leaf: u32, out: &mut [u8]) {
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    let mut root = *m;
    for j in 0..D {
        if j > 0 {
            idx_leaf = (idx_tree & ((1 << HP) - 1)) as u32;
            idx_tree >>= HP;
            adrs.set_layer_address(j as u32);
            adrs.set_tree_address(idx_tree);
        }
        let sig = &mut out[j * XMSS_BYTES..][..XMSS_BYTES];
        xmss_sign(&root, sk_seed, idx_leaf, pk_seed, &mut adrs, sig);
        if j < D - 1 {
            root = xmss_pk_from_sig(idx_leaf, sig, &root, pk_seed, &mut adrs);
        }
    }
}

/// `ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)` (FIPS 205,
/// algorithm 13).
fn ht_verify(m: &[u8; N], sig: &[u8], pk_seed: &[u8; N], mut idx_tree: u64, mut idx_leaf: u32, pk_root: &[u8; N]) -> bool {
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    let mut node = *m;
    for j in 0..D {
        if j > 0 {
            idx_leaf = (idx_tree & ((1 << HP) - 1)) as u32;
            idx_tree >>= HP;
            adrs.set_layer_address(j as u32);
            adrs.set_tree_address(idx_tree);
        }
        node = xmss_pk_from_sig(idx_leaf, &sig[j * XMSS_BYTES..][..XMSS_BYTES], &node, pk_seed, &mut adrs);
    }
    node == *pk_root
}

/// `fors_skGen(SK.seed, PK.seed, ADRS, idx)` (FIPS 205, algorithm 14).
fn fors_sk_gen(sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &Adrs, idx: u32) -> [u8; N] {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(FORS_PRF);
    sk_adrs.set_key_pair_address(adrs.key_pair_address());
    sk_adrs.set_tree_index(idx);
    thash(pk_seed, &sk_adrs, &[sk_seed])
}

/// `fors_node(SK.seed, i, z, PK.seed, ADRS)` (FIPS 205, algorithm 15).
fn fors_node(sk_seed: &[u8; N], i: u32, z: u32, pk_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    if z == 0 {
        let mut sk = fors_sk_gen(sk_seed, pk_seed, adrs, i);
        adrs.set_tree_height(0);
        adrs.set_tree_index(i);
        let node = thash(pk_seed, adrs, &[&sk]);
        wipe(&mut sk);
        return node;
    }
    let left = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
    let right = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
    adrs.set_tree_height(z);
    adrs.set_tree_index(i);
    thash(pk_seed, adrs, &[&left, &right])
}

fn fors_indices(md: &[u8]) -> [u32; K] {
    let mut indices = [0u32; K];
    base_2b(md, A as u32, &mut indices);
    indices
}

/// `fors_sign(md, SK.seed, PK.seed, ADRS)` (FIPS 205, algorithm 16) into
/// `out`, `FORS_BYTES` long.
fn fors_sign(md: &[u8], sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &mut Adrs, out: &mut [u8]) {
    for (i, &index) in fors_indices(md).iter().enumerate() {
        let tree = &mut out[i * (1 + A) * N..][..(1 + A) * N];
        let mut sk = fors_sk_gen(sk_seed, pk_seed, adrs, ((i as u32) << A) + index);
        tree[..N].copy_from_slice(&sk);
        wipe(&mut sk);
        for j in 0..A as u32 {
            let s = (index >> j) ^ 1;
            let node = fors_node(sk_seed, ((i as u32) << (A as u32 - j)) + s, j, pk_seed, adrs);
            tree[(1 + j as usize) * N..][..N].copy_from_slice(&node);
        }
    }
}

/// `fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)` (FIPS 205, algorithm 17).
fn fors_pk_from_sig(sig: &[u8], md: &[u8], pk_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let mut roots = [0u8; K * N];
    for (i, &index) in fors_indices(md).iter().enumerate() {
        let tree = &sig[i * (1 + A) * N..][..(1 + A) * N];
        adrs.set_tree_height(0);
        adrs.set_tree_index(((i as u32) << A) + index);
        let mut node = thash(pk_seed, adrs, &[&tree[..N]]);
        for j in 0..A {
            let auth = &tree[(1 + j) * N..][..N];
            adrs.set_tree_height(j as u32 + 1);
            node = if (index >> j) & 1 == 0 {
                adrs.set_tree_index(adrs.tree_index() / 2);
                thash(pk_seed, adrs, &[&node, auth])
            } else {
                adrs.set_tree_index((adrs.tree_index() - 1) / 2);
                thash(pk_seed, adrs, &[auth, &node])
            };
        }
        roots[i * N..][..N].copy_from_slice(&node);
    }
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(FORS_ROOTS);
    pk_adrs.set_key_pair_address(adrs.key_pair_address());
    thash(pk_seed, &pk_adrs, &[&roots])
}

/// `H_msg(R, PK.seed, PK.root, M)` split into the FORS digest, the tree index
/// and the leaf index (FIPS 205, algorithms 19 and 20).
fn digest(r: &[u8], pk_seed: &[u8; N], pk_root: &[u8; N], m_prime: &[&[u8]]) -> ([u8; MD_BYTES], u64, u32) {
    let mut parts: Vec<&[u8]> = vec![r, pk_seed, pk_root];
    parts.extend_from_slice(m_prime);
    let mut digest = [0u8; M];
    shake(&parts, &mut digest);
    let md: [u8; MD_BYTES] = digest[..MD_BYTES].try_into().expect("md bytes");
    let tree = digest[MD_BYTES..MD_BYTES + TREE_BYTES]
        .iter()
        .fold(0u64, |t, &b| t << 8 | u64::from(b));
    let leaf = digest[MD_BYTES + TREE_BYTES..]
        .iter()
        .fold(0u32, |t, &b| t << 8 | u32::from(b));
    (md, tree & ((1 << (H - HP)) - 1), leaf & ((1 << HP) - 1))
}

/// The pure-mode prefix of FIPS 205, algorithms 22 and 24: `0x00`, then the
/// context's length as one byte. `None` if the context is over 255 bytes.
fn pure_prefix(context: &[u8]) -> Option<[u8; 2]> {
    Some([0, u8::try_from(context.len()).ok()?])
}

/// An SLH-DSA-SHAKE-128s secret key: `SK.seed`, `SK.prf`, `PK.seed` and
/// `PK.root`, wiped on drop.
pub struct SigningKey {
    sk_seed: [u8; N],
    sk_prf: [u8; N],
    pk_seed: [u8; N],
    pk_root: [u8; N],
}

impl SigningKey {
    /// `slh_keygen_internal(SK.seed, SK.prf, PK.seed)` (FIPS 205,
    /// algorithm 18): the root of the top XMSS tree. The caller wipes its
    /// copies of the seeds.
    pub fn from_seeds(sk_seed: &[u8; N], sk_prf: &[u8; N], pk_seed: &[u8; N]) -> Self {
        let mut adrs = Adrs::new();
        adrs.set_layer_address(D as u32 - 1);
        let pk_root = xmss_node(sk_seed, 0, HP as u32, pk_seed, &mut adrs);
        Self { sk_seed: *sk_seed, sk_prf: *sk_prf, pk_seed: *pk_seed, pk_root }
    }

    /// The FIPS 205 encoding of the public key, `PK.seed || PK.root`.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let mut pk = [0u8; PUBLIC_KEY_BYTES];
        pk[..N].copy_from_slice(&self.pk_seed);
        pk[N..].copy_from_slice(&self.pk_root);
        pk
    }

    /// `slh_sign(M, ctx, SK)` (FIPS 205, algorithm 22), hedged: `opt_rand`
    /// is 16 bytes from the caller's generator. `None` if the context is
    /// over 255 bytes.
    pub fn sign<R: CryptoRng + ?Sized>(&self, message: &[u8], context: &[u8], rng: &mut R) -> Option<Box<[u8; SIGNATURE_BYTES]>> {
        let mut opt_rand = [0u8; N];
        rng.fill_bytes(&mut opt_rand);
        let signature = self.sign_with(message, context, &opt_rand);
        wipe(&mut opt_rand);
        signature
    }

    /// The deterministic variant (`opt_rand = PK.seed`), for the vectors
    /// only: wallets sign hedged.
    #[cfg(test)]
    pub(crate) fn sign_deterministic(&self, message: &[u8], context: &[u8]) -> Option<Box<[u8; SIGNATURE_BYTES]>> {
        self.sign_with(message, context, &self.pk_seed)
    }

    /// `slh_sign_internal(M', SK, opt_rand)` (FIPS 205, algorithm 19).
    fn sign_with(&self, message: &[u8], context: &[u8], opt_rand: &[u8; N]) -> Option<Box<[u8; SIGNATURE_BYTES]>> {
        let prefix = pure_prefix(context)?;
        let m_prime: [&[u8]; 3] = [&prefix, context, message];
        let mut sig = Box::new([0u8; SIGNATURE_BYTES]);
        // R = PRF_msg(SK.prf, opt_rand, M').
        let mut r = [0u8; N];
        shake(&[&self.sk_prf, opt_rand, &prefix, context, message], &mut r);
        sig[..N].copy_from_slice(&r);
        let (md, idx_tree, idx_leaf) = digest(&r, &self.pk_seed, &self.pk_root, &m_prime);
        let mut adrs = Adrs::new();
        adrs.set_tree_address(idx_tree);
        adrs.set_type_and_clear(FORS_TREE);
        adrs.set_key_pair_address(idx_leaf);
        let (fors, ht) = sig[N..].split_at_mut(FORS_BYTES);
        fors_sign(&md, &self.sk_seed, &self.pk_seed, &mut adrs, fors);
        let pk_fors = fors_pk_from_sig(fors, &md, &self.pk_seed, &mut adrs);
        ht_sign(&pk_fors, &self.sk_seed, &self.pk_seed, idx_tree, idx_leaf, ht);
        Some(sig)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        wipe(&mut self.sk_seed);
        wipe(&mut self.sk_prf);
    }
}

/// `slh_verify(M, SIG, ctx, PK)` (FIPS 205, algorithm 24): whether
/// `signature` is a valid pure-mode signature of `message` under `context`
/// by `public_key`. A signature of the wrong length or a context over 255
/// bytes is not valid.
pub fn verify(public_key: &[u8; PUBLIC_KEY_BYTES], message: &[u8], context: &[u8], signature: &[u8]) -> bool {
    let Some(prefix) = pure_prefix(context) else {
        return false;
    };
    if signature.len() != SIGNATURE_BYTES {
        return false;
    }
    let pk_seed: &[u8; N] = public_key[..N].try_into().expect("n bytes");
    let pk_root: &[u8; N] = public_key[N..].try_into().expect("n bytes");
    let (r, rest) = signature.split_at(N);
    let (fors, ht) = rest.split_at(FORS_BYTES);
    let (md, idx_tree, idx_leaf) = digest(r, pk_seed, pk_root, &[&prefix, context, message]);
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair_address(idx_leaf);
    let pk_fors = fors_pk_from_sig(fors, &md, pk_seed, &mut adrs);
    ht_verify(&pk_fors, ht, pk_seed, idx_tree, idx_leaf, pk_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn base_2b_reads_big_endian_digits() {
        let mut out = [0u32; 4];
        base_2b(&[0x12, 0x34], 4, &mut out);
        assert_eq!(out, [1, 2, 3, 4]);
        let mut out = [0u32; 2];
        base_2b(&[0xab, 0xcd, 0xef], 12, &mut out);
        assert_eq!(out, [0xabc, 0xdef]);
    }

    /// Bytes 32..80 of the counting seed's rescue-key output at index 0 and
    /// the values CIRCL v1.6.5 gives for them (client/tests/rescue_accounts.rs).
    #[test]
    fn deterministic_signature_matches_circl() {
        let seeds: [u8; 48] = core::array::from_fn(|i| {
            let h = "a98fac9598fb219191231f18fdad940a91985477e37e1ddb9e82ce5dc0322e8c1fe1f8b250b35d2c15c14f58d2e6f3af";
            u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()
        });
        let key = SigningKey::from_seeds(
            seeds[..16].try_into().unwrap(),
            seeds[16..32].try_into().unwrap(),
            seeds[32..].try_into().unwrap(),
        );
        assert_eq!(hex(&key.public_key()), "1fe1f8b250b35d2c15c14f58d2e6f3af8a4f5764636428f7a109e83d82d0bc62");
        let message: [u8; 32] = core::array::from_fn(|i| i as u8);
        let sig = key.sign_deterministic(&message, b"ghost/tx/v1").unwrap();
        use sha2::{Digest, Sha256};
        assert_eq!(hex(&Sha256::digest(&sig[..])), "3169dd6a3009ef4c854a484d60e72dde2f902dab3a3d213ac745ecc23f02e242");
        assert!(verify(&key.public_key(), &message, b"ghost/tx/v1", &sig[..]));
        assert!(!verify(&key.public_key(), &message, b"ghost/tx/v2", &sig[..]));
    }
}
