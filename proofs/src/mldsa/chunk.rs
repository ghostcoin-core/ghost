//! The circuit of a chunk: for each slot, one ML-DSA-44 verification of
//! FIPS 204 (`ML-DSA.Verify` with the context `ghost/tx/v1`), and the running
//! digest of the slots' transactions.
//!
//! Per verification, in the order the circuit builds it:
//!
//! 1. `tr = SHAKE256(pk, 64)`; the key identity is its first 32 bytes and
//!    must equal the transaction's.
//! 2. `mu = SHAKE256(tr || 0 || |ctx| || ctx || M, 64)`, `M` the
//!    transaction's message.
//! 3. `c = SampleInBall(c~)`, one SHAKE-256 block.
//! 4. `A^ = ExpandA(rho)`, sixteen `RejNTTPoly` of five SHAKE-128 blocks.
//! 5. `t1` unpacked from the key, times `2^13`; `z` from the signature with
//!    `||z||_inf < gamma1 - beta`.
//! 6. The NTTs of `z`, `c`, `t1 2^13` and of `w'_approx` (a witness), and
//!    `NTT(w'_approx) = A^ NTT(z) - NTT(c) NTT(t1 2^13)` coefficient by
//!    coefficient: the same `w'_approx` as `NTT^-1` gives, since the NTT is a
//!    bijection.
//! 7. `w1' = UseHint(h, w'_approx)` with at most `omega` hint bits, and
//!    `c~' = SHAKE256(mu || w1Encode(w1'), 32)` equal to `c~`.
//!
//! A slot past the chunk's count verifies a copy of the last transaction,
//! which counts for nothing.

use alloc::vec::Vec;

use p3_field::PrimeCharacteristicRing;

use super::native::{self, K, L, N};
use super::tables::{HINT_COEFFS, lane_ef};
use crate::layers::bundle::{LAYER_PUBLICS, absorb_child, active_bits, layer_wires, select_digest, sum};
use crate::layers::circuit::{Circuit, Wire};
use crate::layers::{EF, F};

/// Lanes of a public key.
const PK_LANES: usize = native::PUBLIC_KEY_BYTES / 8;

/// A byte of a sponge's input: a constant or a base wire holding a byte.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Byte {
    Const(u8),
    Wire(Wire),
}

/// An input of a sponge: a whole lane wire (at a multiple of eight bytes) or
/// one byte.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Input {
    Lane(Wire),
    Byte(Byte),
}

/// A lane wire from eight bytes: a constant when every byte is; else its
/// limbs from the bytes and a packing row.
fn lane_from_bytes(c: &mut Circuit, bytes: &[Byte; 8]) -> Wire {
    if let Some(v) = bytes.iter().enumerate().try_fold(0u64, |acc, (i, b)| match b {
        Byte::Const(x) => Some(acc | u64::from(*x) << (8 * i)),
        Byte::Wire(_) => None,
    }) {
        return c.constant(lane_ef(v));
    }
    let mut limbs = [Wire(0); 8];
    for (l, limb) in limbs.iter_mut().enumerate().take(4) {
        *limb = match (bytes[2 * l], bytes[2 * l + 1]) {
            (Byte::Const(a), Byte::Const(b)) => c.const_base(F::from_u32(u32::from(a) | u32::from(b) << 8)),
            (Byte::Wire(a), Byte::Const(b)) => c.add_const(a, EF::from(F::from_u32(u32::from(b) << 8))),
            (Byte::Const(a), Byte::Wire(b)) => {
                let k = c.const_base(F::from_u8(a));
                c.mul_const_add(b, EF::from(F::from_u32(256)), k)
            }
            (Byte::Wire(a), Byte::Wire(b)) => c.mul_const_add(b, EF::from(F::from_u32(256)), a),
        };
    }
    let zero = c.zero();
    for limb in limbs.iter_mut().skip(4) {
        *limb = zero;
    }
    c.from_coefficients(&limbs)
}

/// SHAKE with `rate` bytes over `input` (padded with `0x1F` and `0x80`),
/// squeezing `out` lanes: Keccak-f\[1600\] rows of the Keccak table, the
/// absorbed lanes XORed in by the XOR table.
pub(crate) fn shake(c: &mut Circuit, rate: usize, input: &[Input], out: usize) -> Vec<Wire> {
    // Lay the input out byte by byte, lanes at their offsets.
    let mut items: Vec<Option<Input>> = Vec::new();
    for &i in input {
        match i {
            Input::Lane(_) => {
                assert_eq!(items.len() % 8, 0, "a lane at a multiple of eight bytes");
                items.push(Some(i));
                items.extend([None; 7]);
            }
            Input::Byte(_) => items.push(Some(i)),
        }
    }
    let len = items.len();
    let blocks = len / rate + 1;
    let mut pad = alloc::vec![0u8; blocks * rate - len];
    pad[0] = 0x1F;
    *pad.last_mut().expect("a padding byte") |= 0x80;
    items.extend(pad.iter().map(|&b| Some(Input::Byte(Byte::Const(b)))));
    let lanes: Vec<Wire> = items
        .chunks(8)
        .map(|chunk| match chunk[0] {
            Some(Input::Lane(w)) => w,
            _ => {
                let bytes: [Byte; 8] = core::array::from_fn(|k| match chunk[k] {
                    Some(Input::Byte(b)) => b,
                    _ => unreachable!("a lane starts only at its offset"),
                });
                lane_from_bytes(c, &bytes)
            }
        })
        .collect();
    let rate_lanes = rate / 8;
    let zero = c.zero();
    let mut state = [zero; 25];
    for (b, block) in lanes.chunks(rate_lanes).enumerate() {
        let mut pre = state;
        for (i, &lane) in block.iter().enumerate() {
            pre[i] = if b == 0 {
                lane
            } else if lane == zero {
                state[i]
            } else {
                c.ml_xor(state[i], lane)
            };
        }
        state = c.ml_keccak(pre);
    }
    let mut squeezed = Vec::with_capacity(out);
    loop {
        squeezed.extend_from_slice(&state[..rate_lanes.min(out - squeezed.len())]);
        if squeezed.len() == out {
            return squeezed;
        }
        state = c.ml_keccak(state);
    }
}

/// The NTT of FIPS 204, algorithm 41, in butterfly rows.
pub(crate) fn ntt(c: &mut Circuit, input: &[Wire]) -> Vec<Wire> {
    let zetas = native::zetas();
    let mut w = input.to_vec();
    let mut m = 0;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            m += 1;
            for j in start..start + len {
                let (a, b) = c.ml_butterfly(w[j], w[j + len], zetas[m]);
                w[j] = a;
                w[j + len] = b;
            }
            start += 2 * len;
        }
        len /= 2;
    }
    w
}

/// What a slot verifies: the transaction (account, key identity, message)
/// and the key and signature with what a verification computes from them.
#[derive(Clone)]
pub(crate) struct SlotWitness {
    pub(crate) account: [u8; 20],
    pub(crate) key_id: [u8; 32],
    pub(crate) message: Vec<u8>,
    pub(crate) pk: [u8; native::PUBLIC_KEY_BYTES],
    pub(crate) c_tilde: [u8; native::C_TILDE_BYTES],
    pub(crate) z: [[i32; N]; L],
    pub(crate) h: [[bool; N]; K],
    pub(crate) w_approx: [[u32; N]; K],
}

impl SlotWitness {
    /// A slot of the circuit's shape alone, every value zero.
    pub(crate) fn blank(message_len: usize) -> Self {
        Self {
            account: [0; 20],
            key_id: [0; 32],
            message: alloc::vec![0; message_len],
            pk: [0; native::PUBLIC_KEY_BYTES],
            c_tilde: [0; native::C_TILDE_BYTES],
            z: [[0; N]; L],
            h: [[false; N]; K],
            w_approx: [[0; N]; K],
        }
    }

    /// The transaction's content: account, key identity, message, a byte a
    /// value.
    pub(crate) fn content(&self) -> Vec<F> {
        super::tx_content(&self.account, &self.key_id, &self.message)
    }
}

fn lanes_of(c: &mut Circuit, bytes: &[u8]) -> Vec<Wire> {
    bytes
        .chunks(8)
        .map(|b| c.hint(lane_ef(u64::from_le_bytes(b.try_into().expect("eight bytes")))))
        .collect()
}

/// One ML-DSA-44 verification of the transaction whose content wires are
/// `content` (account, key identity, message).
pub(crate) fn verify_slot(c: &mut Circuit, w: &SlotWitness, content: &[Wire]) {
    let pk = lanes_of(c, &w.pk);
    debug_assert_eq!(pk.len(), PK_LANES);
    let c_tilde = lanes_of(c, &w.c_tilde);

    // tr, and the key identity.
    let pk_in: Vec<Input> = pk.iter().map(|&l| Input::Lane(l)).collect();
    let tr = shake(c, native::SHAKE256_RATE, &pk_in, 8);
    for lane in 0..4 {
        let bytes: [Byte; 8] = core::array::from_fn(|i| Byte::Wire(content[20 + 8 * lane + i]));
        let id = lane_from_bytes(c, &bytes);
        c.assert_eq(id, tr[lane]);
    }

    // mu over M' = 0 || |ctx| || ctx || M.
    let mut mu_in: Vec<Input> = tr.iter().map(|&l| Input::Lane(l)).collect();
    let ctx = super::TX_CONTEXT;
    mu_in.push(Input::Byte(Byte::Const(0)));
    mu_in.push(Input::Byte(Byte::Const(ctx.len() as u8)));
    mu_in.extend(ctx.iter().map(|&b| Input::Byte(Byte::Const(b))));
    mu_in.extend(content[52..].iter().map(|&b| Input::Byte(Byte::Wire(b))));
    let mu = shake(c, native::SHAKE256_RATE, &mu_in, 8);

    // c = SampleInBall(c~).
    let ball_in: Vec<Input> = c_tilde.iter().map(|&l| Input::Lane(l)).collect();
    let ball_lanes = shake(c, native::SHAKE256_RATE, &ball_in, 17);
    let cc = c.ml_ball(core::array::from_fn(|i| ball_lanes[i]));

    // A^ = ExpandA(rho).
    let mut a = Vec::with_capacity(K);
    for r in 0..K {
        let mut row = Vec::with_capacity(L);
        for s in 0..L {
            let mut input: Vec<Input> = pk[..4].iter().map(|&l| Input::Lane(l)).collect();
            input.push(Input::Byte(Byte::Const(s as u8)));
            input.push(Input::Byte(Byte::Const(r as u8)));
            let lanes = shake(c, native::SHAKE128_RATE, &input, super::tables::EXPAND_LANES);
            row.push(c.ml_expand(lanes));
        }
        a.push(row);
    }

    // t1 2^13, z and w'_approx.
    let mut t1: Vec<Vec<Wire>> = alloc::vec![Vec::with_capacity(N); K];
    for row in 0..32 {
        let lanes: [Wire; 5] = core::array::from_fn(|k| pk[4 + 5 * row + k]);
        let coeffs = c.ml_t1(lanes);
        t1[row / 8].extend_from_slice(&coeffs);
    }
    let z: Vec<Vec<Wire>> = (0..L).map(|s| (0..N).map(|i| c.ml_z(w.z[s][i])).collect()).collect();
    let wp: Vec<Vec<Wire>> =
        (0..K).map(|r| (0..N).map(|i| c.hint_base(F::from_u32(w.w_approx[r][i]))).collect()).collect();

    // The NTTs and the NTT-domain identity.
    let z_hat: Vec<Vec<Wire>> = z.iter().map(|p| ntt(c, p)).collect();
    let c_hat = ntt(c, &cc);
    for r in 0..K {
        let t_hat = ntt(c, &t1[r]);
        let w_hat = ntt(c, &wp[r]);
        for i in 0..N {
            c.ml_mac([
                a[r][0][i], a[r][1][i], a[r][2][i], a[r][3][i], z_hat[0][i], z_hat[1][i], z_hat[2][i], z_hat[3][i],
                c_hat[i], t_hat[i], w_hat[i],
            ]);
        }
    }

    // w1' = UseHint(h, w'_approx), encoded: four hint rows of eight
    // coefficients give twelve 16-bit limbs, three lanes. At most omega hint
    // bits are set. c~' against c~.
    let mut c2_in: Vec<Input> = mu.iter().map(|&l| Input::Lane(l)).collect();
    let mut hints = c.zero();
    let zero = c.zero();
    for r in 0..K {
        for group in 0..N / 32 {
            let mut limbs = Vec::with_capacity(12);
            for part in 0..4 {
                let at = 32 * group + HINT_COEFFS * part;
                let ws: [Wire; HINT_COEFFS] = core::array::from_fn(|k| wp[r][at + k]);
                let hs: [bool; HINT_COEFFS] = core::array::from_fn(|k| w.h[r][at + k]);
                let (ls, count) = c.ml_hint(ws, hs);
                limbs.extend_from_slice(&ls);
                hints = c.add(hints, count);
            }
            for lane in limbs.chunks(4) {
                let lw = c.from_coefficients(&[lane[0], lane[1], lane[2], lane[3], zero, zero, zero, zero]);
                c2_in.push(Input::Lane(lw));
            }
        }
    }
    let omega = c.const_base(F::from_usize(native::OMEGA));
    let slack = c.sub(omega, hints);
    let bits = c.bits_low(slack, 7);
    let back = c.from_bits(&bits);
    c.assert_eq(back, slack);
    let c2 = shake(c, native::SHAKE256_RATE, &c2_in, 4);
    for (&x, &y) in c2.iter().zip(&c_tilde) {
        c.assert_eq(x, y);
    }
}

/// The chunk circuit: the layer public values `publics` (binding, digests,
/// count), then one verification a slot of `slots`, the first `count` of
/// them active and absorbed into the running digest in order.
pub(crate) fn chunk_circuit(c: &mut Circuit, publics: &[F; LAYER_PUBLICS], slots: &[SlotWitness], count: usize) {
    let p = layer_wires(c, publics);
    let active = active_bits(c, slots.len(), count);
    let mut d = p.start;
    for (slot, &bit) in slots.iter().zip(&active) {
        let content: Vec<Wire> = slot.content().iter().map(|&v| c.hint_base(v)).collect();
        verify_slot(c, slot, &content);
        let next = absorb_child(c, &d, &content);
        d = select_digest(c, bit, &next, &d);
    }
    let total = sum(c, &active);
    for i in 0..d.len() {
        c.assert_eq(d[i], p.end[i]);
    }
    c.assert_eq(total, p.count);
}
