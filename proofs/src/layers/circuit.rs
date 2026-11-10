//! A verifier circuit: wires carrying values of the degree-8 extension, and
//! three kinds of rows that constrain them.
//!
//! - An arithmetic row: `a * b + c = out` in the extension.
//! - A permutation row: 24 base wires in, the width-24 Poseidon2 of them out.
//! - A bits row: a base wire and its 31 canonical bits.
//!
//! A base value is a wire whose upper seven coefficients are zero; the
//! permutation and bits rows read their wires that way, which pins those
//! coefficients to zero. A constant is a wire the verifier key fixes, a public
//! value a wire the proof's public values fix.
//!
//! The builder computes every wire's value as it goes, from the hints it is
//! given, and records the first constraint those values break. Building the
//! same circuit from the same shape with other hints gives the same rows: the
//! rows never depend on a value.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};

use super::poseidon2::{self, WIDTH};
use super::{EF, F, coeffs, from_coeffs};

/// A wire of the circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Wire(pub(crate) u32);

/// Bits of a canonical BabyBear value.
pub(crate) const BITS: usize = 31;

/// `a * b + c = out`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ArithRow {
    pub(crate) a: Wire,
    pub(crate) b: Wire,
    pub(crate) c: Wire,
    pub(crate) out: Wire,
}

/// `output = Poseidon2(input)`, the first two 9-lane blocks of the input
/// exchanged when `swap` is a bit set to one. Only the output lanes the
/// circuit reads have wires.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PermRow {
    pub(crate) input: [Wire; WIDTH],
    pub(crate) output: [Option<Wire>; WIDTH],
    pub(crate) swap: Option<Wire>,
    values: [F; WIDTH],
}

/// A lane of state: a wire, or an output lane of a permutation row that has
/// no wire until something reads it.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Lane {
    Wire(Wire),
    Out(usize, usize),
}

/// `ext` is the extension value whose coefficients are `coeffs`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PackRow {
    pub(crate) ext: Wire,
    pub(crate) coeffs: [Wire; 8],
}

/// The lanes the swap of a permutation row exchanges: `0..SWAP` with
/// `SWAP..2 * SWAP`, the two children of a Merkle node.
pub(crate) const SWAP: usize = 9;

/// `x = sum bits[i] 2^i`, each bit 0 or 1, below the modulus. Only the bits
/// the circuit reads have wires.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BitsRow {
    pub(crate) x: Wire,
    pub(crate) bits: [Option<Wire>; BITS],
}

/// A circuit under construction, with the value of every wire.
pub(crate) struct Circuit {
    values: Vec<EF>,
    consts: Vec<(Wire, EF)>,
    const_index: BTreeMap<[u32; 8], Wire>,
    publics: Vec<Wire>,
    arith: Vec<ArithRow>,
    perms: Vec<PermRow>,
    bits: Vec<BitsRow>,
    packs: Vec<PackRow>,
    /// The rows of the ML-DSA tables, empty in a layer's circuit.
    pub(crate) ml: crate::mldsa::tables::MlRows,
    failure: Option<String>,
    /// The wires whose values [`Self::drop_values`] dropped.
    dropped: usize,
}

fn key(c: EF) -> [u32; 8] {
    let cs = coeffs(&c);
    core::array::from_fn(|i| cs[i].as_canonical_u32())
}

impl Circuit {
    pub(crate) fn new() -> Self {
        let mut c = Self {
            values: Vec::new(),
            consts: Vec::new(),
            const_index: BTreeMap::new(),
            publics: Vec::new(),
            arith: Vec::new(),
            perms: Vec::new(),
            bits: Vec::new(),
            packs: Vec::new(),
            ml: crate::mldsa::tables::MlRows::default(),
            failure: None,
            dropped: 0,
        };
        // Wires 0 and 1 are the constants zero and one.
        c.constant(EF::ZERO);
        c.constant(EF::ONE);
        c
    }

    fn fresh(&mut self, v: EF) -> Wire {
        let w = Wire(u32::try_from(self.values.len()).expect("fewer than 2^32 wires"));
        self.values.push(v);
        w
    }

    /// Record that the values break a constraint; the first one is kept.
    pub(crate) fn fail(&mut self, what: impl FnOnce() -> String) {
        if self.failure.is_none() {
            self.failure = Some(what());
        }
    }

    /// The first constraint the values break, if any.
    pub(crate) fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    pub(crate) fn num_wires(&self) -> usize {
        self.values.len().max(self.dropped)
    }

    /// Drop every wire's value, keeping the rows, the constants, the public
    /// wires and the wire count: all a key's preprocessed columns are written
    /// from. A blank circuit's values are most of it, and nothing reads them
    /// once it is keyed; no wire may be added or read afterwards.
    pub(crate) fn drop_values(&mut self) {
        self.dropped = self.num_wires();
        self.values = Vec::new();
    }

    pub(crate) fn value(&self, w: Wire) -> EF {
        self.values[w.0 as usize]
    }

    /// The first coefficient of a wire's value.
    pub(crate) fn base_value(&self, w: Wire) -> F {
        coeffs(&self.value(w))[0]
    }

    pub(crate) fn consts(&self) -> &[(Wire, EF)] {
        &self.consts
    }

    pub(crate) fn publics(&self) -> &[Wire] {
        &self.publics
    }

    pub(crate) fn arith_rows(&self) -> &[ArithRow] {
        &self.arith
    }

    pub(crate) fn perm_rows(&self) -> &[PermRow] {
        &self.perms
    }

    pub(crate) fn bits_rows(&self) -> &[BitsRow] {
        &self.bits
    }

    pub(crate) fn pack_rows(&self) -> &[PackRow] {
        &self.packs
    }

    /// Constrain `ext` to be the extension value with coefficients `cs`.
    pub(crate) fn pack_into(&mut self, cs: [Wire; 8], ext: Wire) {
        let v = from_coeffs(|i| self.base_value(cs[i]));
        if v != self.value(ext) {
            let w = ext.0;
            self.fail(|| alloc::format!("wire {w} does not have the packed coefficients"));
        }
        self.packs.push(PackRow { ext, coeffs: cs });
    }

    /// A wire the prover chooses; only the rows that read it constrain it.
    pub(crate) fn hint(&mut self, v: EF) -> Wire {
        self.fresh(v)
    }

    /// A base wire the prover chooses. It is a base value only once a
    /// permutation or bits row reads it, or [`Self::assert_base`] is applied.
    pub(crate) fn hint_base(&mut self, v: F) -> Wire {
        self.fresh(EF::from(v))
    }

    /// A wire fixed by the verifier key.
    pub(crate) fn constant(&mut self, c: EF) -> Wire {
        let k = key(c);
        if let Some(&w) = self.const_index.get(&k) {
            return w;
        }
        let w = self.fresh(c);
        self.consts.push((w, c));
        self.const_index.insert(k, w);
        w
    }

    pub(crate) fn const_base(&mut self, c: F) -> Wire {
        self.constant(EF::from(c))
    }

    pub(crate) fn zero(&mut self) -> Wire {
        self.constant(EF::ZERO)
    }

    pub(crate) fn one(&mut self) -> Wire {
        self.constant(EF::ONE)
    }

    /// A base wire fixed by the next public value of the proof.
    pub(crate) fn public(&mut self, v: F) -> Wire {
        let w = self.fresh(EF::from(v));
        self.publics.push(w);
        w
    }

    /// Constrain `a * b + c = out`.
    pub(crate) fn assert_mul_add(&mut self, a: Wire, b: Wire, c: Wire, out: Wire) {
        self.arith.push(ArithRow { a, b, c, out });
        let lhs = self.value(a) * self.value(b) + self.value(c);
        if lhs != self.value(out) {
            let n = self.arith.len() - 1;
            self.fail(|| alloc::format!("arithmetic row {n} does not hold"));
        }
    }

    /// `a * b + c`.
    pub(crate) fn mul_add(&mut self, a: Wire, b: Wire, c: Wire) -> Wire {
        let v = self.value(a) * self.value(b) + self.value(c);
        let out = self.fresh(v);
        self.arith.push(ArithRow { a, b, c, out });
        out
    }

    pub(crate) fn add(&mut self, a: Wire, b: Wire) -> Wire {
        let one = self.one();
        self.mul_add(a, one, b)
    }

    pub(crate) fn sub(&mut self, a: Wire, b: Wire) -> Wire {
        let neg_one = self.constant(-EF::ONE);
        self.mul_add(b, neg_one, a)
    }

    pub(crate) fn mul(&mut self, a: Wire, b: Wire) -> Wire {
        let zero = self.zero();
        self.mul_add(a, b, zero)
    }

    pub(crate) fn neg(&mut self, a: Wire) -> Wire {
        let neg_one = self.constant(-EF::ONE);
        let zero = self.zero();
        self.mul_add(a, neg_one, zero)
    }

    pub(crate) fn mul_const(&mut self, a: Wire, k: EF) -> Wire {
        let k = self.constant(k);
        let zero = self.zero();
        self.mul_add(a, k, zero)
    }

    pub(crate) fn add_const(&mut self, a: Wire, k: EF) -> Wire {
        let k = self.constant(k);
        let one = self.one();
        self.mul_add(a, one, k)
    }

    /// `a * k + c` for a constant `k`.
    pub(crate) fn mul_const_add(&mut self, a: Wire, k: EF, c: Wire) -> Wire {
        let k = self.constant(k);
        self.mul_add(a, k, c)
    }

    pub(crate) fn square(&mut self, a: Wire) -> Wire {
        self.mul(a, a)
    }

    /// Constrain `a = b`.
    pub(crate) fn assert_eq(&mut self, a: Wire, b: Wire) {
        let one = self.one();
        let zero = self.zero();
        self.assert_mul_add(a, one, zero, b);
    }

    pub(crate) fn assert_zero(&mut self, a: Wire) {
        let zero = self.zero();
        self.assert_eq(a, zero);
    }

    /// Constrain a wire to equal a constant.
    pub(crate) fn assert_const(&mut self, a: Wire, k: EF) {
        let k = self.constant(k);
        self.assert_eq(a, k);
    }

    /// Constrain a wire to be a base value: its bits row reads it as one.
    pub(crate) fn assert_base(&mut self, a: Wire) {
        self.bits(a);
    }

    /// The inverse of a nonzero wire; a zero one breaks the circuit.
    pub(crate) fn inv(&mut self, a: Wire) -> Wire {
        let v = self.value(a);
        let inv = v.try_inverse().unwrap_or(EF::ZERO);
        let w = self.fresh(inv);
        let zero = self.zero();
        let one = self.one();
        self.assert_mul_add(a, w, zero, one);
        w
    }

    pub(crate) fn div(&mut self, a: Wire, b: Wire) -> Wire {
        let inv = self.inv(b);
        self.mul(a, inv)
    }

    /// `if bit { a } else { b }`, for a wire known to be 0 or 1.
    pub(crate) fn select(&mut self, bit: Wire, a: Wire, b: Wire) -> Wire {
        let d = self.sub(a, b);
        self.mul_add(d, bit, b)
    }

    /// The width-24 Poseidon2 of 24 base wires, with wires for the first
    /// `outputs` output lanes; with `swap`, a bit wire, the lanes `0..9` and
    /// `9..18` of the input are exchanged first when it is one.
    fn perm_values(&self, input: &[Wire; WIDTH], swap: Option<Wire>) -> [F; WIDTH] {
        let mut values: [F; WIDTH] = core::array::from_fn(|i| self.base_value(input[i]));
        if let Some(s) = swap
            && self.base_value(s) == F::ONE
        {
            for j in 0..SWAP {
                values.swap(j, j + SWAP);
            }
        }
        poseidon2::permute(values)
    }

    /// A permutation row whose first output lanes are the existing wires
    /// `outs`: the row constrains them.
    pub(crate) fn perm_into(&mut self, input: [Wire; WIDTH], outs: &[Wire], swap: Option<Wire>) {
        let out = self.perm_values(&input, swap);
        let mut output = [None; WIDTH];
        for (i, &w) in outs.iter().enumerate() {
            if EF::from(out[i]) != self.value(w) {
                let n = self.perms.len();
                self.fail(|| alloc::format!("permutation row {n} does not give its outputs"));
            }
            output[i] = Some(w);
        }
        self.perms.push(PermRow {
            input,
            output,
            swap,
            values: out,
        });
    }

    pub(crate) fn perm_with(&mut self, input: [Wire; WIDTH], outputs: usize, swap: Option<Wire>) -> Vec<Wire> {
        let out = self.perm_values(&input, swap);
        let mut output = [None; WIDTH];
        let mut wires = Vec::with_capacity(outputs);
        for i in 0..outputs {
            let w = self.fresh(EF::from(out[i]));
            output[i] = Some(w);
            wires.push(w);
        }
        self.perms.push(PermRow {
            input,
            output,
            swap,
            values: out,
        });
        wires
    }

    /// The width-24 Poseidon2 of 24 base wires, its output lanes left
    /// without wires until [`Self::lane`] reads them.
    pub(crate) fn perm_lazy(&mut self, input: [Wire; WIDTH]) -> [Lane; WIDTH] {
        let row = self.perms.len();
        self.perm_with(input, 0, None);
        core::array::from_fn(|i| Lane::Out(row, i))
    }

    /// The wire of a lane, made when first read.
    pub(crate) fn lane(&mut self, l: Lane) -> Wire {
        match l {
            Lane::Wire(w) => w,
            Lane::Out(row, i) => {
                if let Some(w) = self.perms[row].output[i] {
                    return w;
                }
                let w = self.fresh(EF::from(self.perms[row].values[i]));
                self.perms[row].output[i] = Some(w);
                w
            }
        }
    }

    /// The width-24 Poseidon2 of 24 base wires.
    pub(crate) fn perm(&mut self, input: [Wire; WIDTH]) -> [Wire; WIDTH] {
        let out = self.perm_with(input, WIDTH, None);
        core::array::from_fn(|i| out[i])
    }

    /// The low `n` canonical bits of a base wire, least significant first.
    /// All 31 are checked; only these `n` have wires.
    pub(crate) fn bits_low(&mut self, x: Wire, n: usize) -> Vec<Wire> {
        let v = self.base_value(x).as_canonical_u32();
        if self.value(x) != EF::from(self.base_value(x)) {
            let w = x.0;
            self.fail(|| alloc::format!("wire {w} read as a base value is not one"));
        }
        let mut bits = [None; BITS];
        let mut wires = Vec::with_capacity(n);
        for (i, b) in bits.iter_mut().enumerate().take(n) {
            let w = self.fresh(EF::from(F::from_u32((v >> i) & 1)));
            *b = Some(w);
            wires.push(w);
        }
        self.bits.push(BitsRow { x, bits });
        wires
    }

    /// The 31 canonical bits of a base wire, least significant first.
    pub(crate) fn bits(&mut self, x: Wire) -> [Wire; BITS] {
        let b = self.bits_low(x, BITS);
        core::array::from_fn(|i| b[i])
    }

    /// An extension wire from its eight base coefficients.
    pub(crate) fn from_coefficients(&mut self, cs: &[Wire]) -> Wire {
        let cs: [Wire; 8] = core::array::from_fn(|i| cs[i]);
        let v = from_coeffs(|i| self.base_value(cs[i]));
        let ext = self.fresh(v);
        self.pack_into(cs, ext);
        ext
    }

    /// The eight base coefficients of an extension value, as hints the caller
    /// recombines with [`Self::from_coefficients`].
    pub(crate) fn coefficient_hints(&mut self, v: EF) -> [Wire; 8] {
        let cs = coeffs(&v).to_vec();
        core::array::from_fn(|i| self.hint_base(cs[i]))
    }

    /// An extension value the prover supplies, as base coefficient wires and
    /// the extension wire they make.
    pub(crate) fn ext_hint(&mut self, v: EF) -> ([Wire; 8], Wire) {
        let coeffs = self.coefficient_hints(v);
        let w = self.from_coefficients(&coeffs);
        (coeffs, w)
    }

    /// `x^(2^k)`.
    pub(crate) fn pow2k(&mut self, x: Wire, k: usize) -> Wire {
        let mut y = x;
        for _ in 0..k {
            y = self.square(y);
        }
        y
    }

    /// `x^e` for a constant exponent.
    pub(crate) fn pow_const(&mut self, x: Wire, e: u64) -> Wire {
        let mut acc = self.one();
        let mut base = x;
        let mut e = e;
        let mut first = true;
        while e > 0 {
            if e & 1 == 1 {
                acc = if first { base } else { self.mul(acc, base) };
                first = false;
            }
            e >>= 1;
            if e > 0 {
                base = self.square(base);
            }
        }
        acc
    }

    /// `g^(sum bits[i] 2^i)` for a constant base field `g`, the bits being
    /// wires known to be 0 or 1.
    pub(crate) fn pow_bits_const(&mut self, g: F, bits: &[Wire]) -> Wire {
        let mut acc = self.one();
        let mut power = g;
        for &b in bits {
            // acc *= 1 + b * (power - 1)
            let one = self.one();
            let factor = self.mul_const_add(b, EF::from(power - F::ONE), one);
            acc = self.mul(acc, factor);
            power = power.square();
        }
        acc
    }

    /// `sum bits[i] 2^i` for wires known to be 0 or 1.
    pub(crate) fn from_bits(&mut self, bits: &[Wire]) -> Wire {
        let mut acc = self.zero();
        for &b in bits.iter().rev() {
            acc = self.mul_const_add(acc, EF::from(F::TWO), b);
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_follow_the_rows_and_a_broken_row_is_recorded() {
        let mut c = Circuit::new();
        let a = c.hint(EF::from(F::from_u8(6)));
        let b = c.hint(EF::from(F::from_u8(7)));
        let p = c.mul(a, b);
        assert_eq!(c.value(p), EF::from(F::from_u8(42)));
        let bits = c.bits(p);
        let back = c.from_bits(&bits);
        assert_eq!(c.value(back), c.value(p));
        assert!(c.failure().is_none());
        let wrong = c.const_base(F::from_u8(41));
        c.assert_eq(p, wrong);
        assert!(c.failure().is_some());
    }
}
