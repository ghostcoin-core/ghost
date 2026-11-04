//! The opening argument of the scale configuration, verified inside a
//! circuit: the duplex-sponge transcript, the salted Merkle openings, hiding
//! FRI with binary folding and a constant final polynomial.
//!
//! Every step follows the library's verifier at the pinned revision
//! (`p3_fri::TwoAdicFriPcs::verify` under `HidingFriPcs`, `verify_fri`,
//! `open_inputs`, `fold_query`): the same sponge calls in the same order, the
//! same leaves and the same folding. The pruned multiproofs of the proof are
//! expanded into one full path per query, each checked against its root.

use alloc::vec;
use alloc::vec::Vec;

use p3_challenger::CanObserve;
use p3_challenger::fs::{DomainSeparator, FieldUnit};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_matrix::Dimensions;

use super::circuit::{Circuit, Lane, Wire};
use super::poseidon2::WIDTH;
use super::{EF, F, coeffs};
use crate::scale::{PcsProof, SCALE_RANDOM_CODEWORDS, SCALE_SALT_ELEMS, ScaleChallenger, scale_restore_paths};
use crate::stark::{FriShape, fri_parameters};

/// Elements of a digest.
pub(crate) const DIGEST: usize = 9;
/// Rate of the sponge.
pub(crate) const RATE: usize = 15;

/// A digest in the circuit.
pub(crate) type Digest = [Wire; DIGEST];

/// An extension value with its eight base coefficient wires.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExtVal {
    pub(crate) coeffs: [Wire; 8],
    pub(crate) ext: Wire,
}

impl ExtVal {
    /// A value the prover supplies.
    pub(crate) fn hint(c: &mut Circuit, v: EF) -> Self {
        let (coeffs, ext) = c.ext_hint(v);
        Self { coeffs, ext }
    }

    /// Coefficient wires for an extension wire the circuit computed.
    pub(crate) fn split(c: &mut Circuit, ext: Wire) -> Self {
        let v = c.value(ext);
        let coeffs = c.coefficient_hints(v);
        c.pack_into(coeffs, ext);
        Self { coeffs, ext }
    }
}

/// The base field elements a domain separator seeds a sponge with.
pub(crate) fn seed_elements(ds: &DomainSeparator<FieldUnit<F>>) -> Vec<F> {
    struct Sink(Vec<F>);
    impl CanObserve<F> for Sink {
        fn observe(&mut self, value: F) {
            self.0.push(value);
        }
    }
    let mut sink = Sink(Vec::new());
    ds.seed(&mut sink);
    sink.0
}

/// The duplex challenger of the scale configuration, in the circuit.
#[derive(Clone)]
pub(crate) struct CircuitChallenger {
    state: [Lane; WIDTH],
    input: Vec<Wire>,
    output: Vec<Lane>,
}

impl CircuitChallenger {
    /// The circuit's copy of a challenger whose state is a constant: one that
    /// has only absorbed constants so far.
    pub(crate) fn from_native(c: &mut Circuit, native: &ScaleChallenger) -> Self {
        Self {
            state: core::array::from_fn(|i| Lane::Wire(c.const_base(native.sponge_state[i]))),
            input: native.input_buffer.iter().map(|&x| c.const_base(x)).collect(),
            output: native.output_buffer.iter().map(|&x| Lane::Wire(c.const_base(x))).collect(),
        }
    }

    fn duplex(&mut self, c: &mut Circuit) {
        let n = self.input.len();
        for (i, w) in self.input.drain(..).enumerate() {
            self.state[i] = Lane::Wire(w);
        }
        if n > 0 {
            let zero = c.zero();
            for s in &mut self.state[n..RATE] {
                *s = Lane::Wire(zero);
            }
            let cap = c.lane(self.state[RATE]);
            self.state[RATE] = Lane::Wire(c.add_const(cap, EF::from(F::from_usize(n))));
        }
        let input: [Wire; WIDTH] = core::array::from_fn(|i| c.lane(self.state[i]));
        self.state = c.perm_lazy(input);
        self.output = self.state[..RATE].to_vec();
    }

    pub(crate) fn observe(&mut self, c: &mut Circuit, w: Wire) {
        self.output.clear();
        self.input.push(w);
        if self.input.len() == RATE {
            self.duplex(c);
        }
    }

    pub(crate) fn observe_all(&mut self, c: &mut Circuit, ws: &[Wire]) {
        for &w in ws {
            self.observe(c, w);
        }
    }

    pub(crate) fn observe_consts(&mut self, c: &mut Circuit, vals: &[F]) {
        for &v in vals {
            let w = c.const_base(v);
            self.observe(c, w);
        }
    }

    pub(crate) fn sample(&mut self, c: &mut Circuit) -> Wire {
        if !self.input.is_empty() || self.output.is_empty() {
            self.duplex(c);
        }
        let lane = self.output.pop().expect("a duplexing fills the output");
        c.lane(lane)
    }

    pub(crate) fn sample_ext(&mut self, c: &mut Circuit) -> ExtVal {
        let coeffs: [Wire; 8] = core::array::from_fn(|_| self.sample(c));
        let ext = c.from_coefficients(&coeffs);
        ExtVal { coeffs, ext }
    }

    /// The low `bits` bits of a sampled element, least significant first.
    pub(crate) fn sample_bits(&mut self, c: &mut Circuit, bits: usize) -> Vec<Wire> {
        let x = self.sample(c);
        c.bits_low(x, bits)
    }

    /// `GrindingChallenger::check_witness`: absorb the witness, then the low
    /// `bits` bits of the next sample must be zero.
    pub(crate) fn check_witness(&mut self, c: &mut Circuit, bits: usize, witness: Wire) {
        if bits == 0 {
            return;
        }
        self.observe(c, witness);
        for b in self.sample_bits(c, bits) {
            c.assert_zero(b);
        }
    }
}

/// The leaf hash: the padding-free sponge of rate 15 over the values.
pub(crate) fn hash_values(c: &mut Circuit, values: &[Wire]) -> Digest {
    let zero = c.zero();
    let mut state = [Lane::Wire(zero); WIDTH];
    // One permutation per block of the rate; a lane gets a wire only when the
    // next block keeps it or it is the digest.
    for chunk in values.chunks(RATE) {
        for (s, &v) in state.iter_mut().zip(chunk) {
            *s = Lane::Wire(v);
        }
        let input: [Wire; WIDTH] = core::array::from_fn(|i| c.lane(state[i]));
        state = c.perm_lazy(input);
    }
    core::array::from_fn(|i| c.lane(state[i]))
}

/// A Merkle node: the permutation of the two children, truncated.
pub(crate) fn compress(c: &mut Circuit, left: &Digest, right: &Digest) -> Digest {
    compress_swapped(c, left, right, None)
}

/// [`compress`] of `(left, right)`, or of `(right, left)` when `swap` is a
/// bit set to one.
pub(crate) fn compress_swapped(c: &mut Circuit, left: &Digest, right: &Digest, swap: Option<Wire>) -> Digest {
    let zero = c.zero();
    let input: [Wire; WIDTH] = core::array::from_fn(|i| {
        if i < DIGEST {
            left[i]
        } else if i < 2 * DIGEST {
            right[i - DIGEST]
        } else {
            zero
        }
    });
    let out = c.perm_with(input, DIGEST, swap);
    core::array::from_fn(|i| out[i])
}

/// Check one opening against a Merkle root: `levels` holds, tallest first,
/// the log height of each group of equally tall matrices and the salted rows
/// of that group flattened, the tallest at the leaf; `index_bits` the leaf
/// index, least significant first; `siblings` one digest a level.
pub(crate) fn verify_path(
    c: &mut Circuit,
    root: &Digest,
    levels: &[(usize, Vec<Wire>)],
    index_bits: &[Wire],
    siblings: &[Digest],
) {
    let log_max = levels[0].0;
    debug_assert_eq!(index_bits.len(), log_max);
    debug_assert_eq!(siblings.len(), log_max);
    let mut digest = hash_values(c, &levels[0].1);
    let mut next = 1;
    if log_max == 0 {
        for i in 0..DIGEST {
            c.assert_eq(digest[i], root[i]);
        }
        return;
    }
    for level in 0..log_max {
        let height = log_max - level - 1;
        let injects = next < levels.len() && levels[next].0 == height;
        let last = level + 1 == log_max && !injects;
        // The node is the right child when its index bit is one; the last
        // compression's outputs are the root's own wires.
        let input = node_input(c, &digest, &siblings[level]);
        if last {
            c.perm_into(input, root, Some(index_bits[level]));
            return;
        }
        let out = c.perm_with(input, DIGEST, Some(index_bits[level]));
        digest = core::array::from_fn(|i| out[i]);
        if injects {
            let injected = hash_values(c, &levels[next].1);
            next += 1;
            let input = node_input(c, &digest, &injected);
            if level + 1 == log_max {
                c.perm_into(input, root, None);
                return;
            }
            digest = compress(c, &digest, &injected);
        }
    }
}

/// The permutation input of a Merkle node: the two children, then zeros.
fn node_input(c: &mut Circuit, left: &Digest, right: &Digest) -> [Wire; WIDTH] {
    let zero = c.zero();
    core::array::from_fn(|i| {
        if i < DIGEST {
            left[i]
        } else if i < 2 * DIGEST {
            right[i - DIGEST]
        } else {
            zero
        }
    })
}

/// A digest the prover supplies.
pub(crate) fn digest_hint(c: &mut Circuit, d: &[F]) -> Digest {
    core::array::from_fn(|i| c.hint_base(d.get(i).copied().unwrap_or(F::ZERO)))
}

/// One matrix of an opening claim: the log size of its domain and, for each
/// point it is opened at, the point and the claimed values (before the
/// hiding columns).
pub(crate) struct ClaimMat {
    pub(crate) log_domain: usize,
    pub(crate) points: Vec<(Wire, Vec<ExtVal>)>,
}

/// One commitment of an opening claim.
pub(crate) struct ClaimRound {
    pub(crate) commit: Digest,
    pub(crate) mats: Vec<ClaimMat>,
    /// A preprocessed commitment carries no hiding columns.
    pub(crate) preprocessed: bool,
}

/// `(x, g, n)` for an exponent's bits: `g^(rev(bits))` where the bits are
/// the index bits `b_lo .. b_hi`, least significant first.
fn pow_rev(c: &mut Circuit, g: F, index_bits: &[Wire]) -> Wire {
    let reversed: Vec<Wire> = index_bits.iter().rev().copied().collect();
    c.pow_bits_const(g, &reversed)
}

/// Verify an opening argument of the scale configuration at FRI shape `fri`
/// against `rounds`, continuing the transcript `ch`. `proof` is `None` when
/// only the circuit's rows are wanted.
pub(crate) fn verify_pcs(
    c: &mut Circuit,
    ch: &mut CircuitChallenger,
    fri: &FriShape,
    rounds: &[ClaimRound],
    proof: Option<&PcsProof>,
) {
    let num_random = SCALE_RANDOM_CODEWORDS;
    // The hiding columns join every claim of a non-preprocessed round.
    let mut claims: Vec<Vec<Vec<Vec<ExtVal>>>> = Vec::with_capacity(rounds.len());
    for (r, round) in rounds.iter().enumerate() {
        let mut mats = Vec::with_capacity(round.mats.len());
        for (m, mat) in round.mats.iter().enumerate() {
            let mut points = Vec::with_capacity(mat.points.len());
            for (p, (_, values)) in mat.points.iter().enumerate() {
                let extra = if round.preprocessed { 0 } else { num_random };
                let mut all = values.clone();
                for k in 0..extra {
                    let v = proof
                        .and_then(|pr| pr.0.get(r)?.get(m)?.get(p)?.get(k).copied())
                        .unwrap_or(EF::ZERO);
                    all.push(ExtVal::hint(c, v));
                }
                points.push(all);
            }
            mats.push(points);
        }
        claims.push(mats);
    }

    // The PCS transcript: its seed, every claimed value, the batch grind and
    // the batching challenge.
    let pcs_shape = p3_fri::PcsShape {
        claimed_evaluation_counts: claims
            .iter()
            .map(|mats| mats.iter().map(|points| points.iter().map(Vec::len).collect()).collect())
            .collect(),
        batch_pow_bits: fri.batch_pow_bits,
    };
    ch.observe_consts(c, &seed_elements(&pcs_shape.domain_separator::<F, EF>()));
    for mats in &claims {
        for points in mats {
            for values in points {
                for v in values {
                    ch.observe_all(c, &v.coeffs);
                }
            }
        }
    }
    let fri_proof = proof.map(|p| &p.1);
    let batch_pow = c.hint_base(fri_proof.map_or(F::ZERO, |f| f.batch_pow_witness));
    ch.check_witness(c, fri.batch_pow_bits, batch_pow);
    let alpha = ch.sample_ext(c);

    // The FRI transcript.
    let log_blowup = fri.log_blowup;
    let log_heights: Vec<Vec<usize>> = rounds
        .iter()
        .map(|r| r.mats.iter().map(|m| m.log_domain + log_blowup).collect())
        .collect();
    let log_max = log_heights.iter().flatten().copied().max().expect("something is committed");
    let num_rounds = log_max - log_blowup;
    let params = fri_parameters(fri, ());
    let fri_shape = p3_fri::FriShape::with_schedule(&params, vec![1; num_rounds], log_max);
    ch.observe_consts(c, &seed_elements(&fri_shape.domain_separator::<F, EF>()));
    let mut commits = Vec::with_capacity(num_rounds);
    let mut betas = Vec::with_capacity(num_rounds);
    for r in 0..num_rounds {
        let commit = fri_proof
            .and_then(|f| f.commit_phase_commits.get(r))
            .map(|cap| cap.roots().first().map(|d| d.to_vec()).unwrap_or_default())
            .unwrap_or_default();
        let commit = digest_hint(c, &commit);
        ch.observe_all(c, &commit);
        commits.push(commit);
        betas.push(ch.sample_ext(c).ext);
    }
    let final_poly = ExtVal::hint(c, fri_proof.and_then(|f| f.final_poly.first().copied()).unwrap_or(EF::ZERO));
    ch.observe_all(c, &final_poly.coeffs);
    let query_pow = c.hint_base(fri_proof.map_or(F::ZERO, |f| f.query_pow_witness));
    ch.check_witness(c, fri.query_pow_bits, query_pow);
    let index_bits: Vec<Vec<Wire>> = (0..fri.num_queries).map(|_| ch.sample_bits(c, log_max)).collect();
    let indices: Vec<usize> = index_bits
        .iter()
        .map(|bits| {
            bits.iter()
                .enumerate()
                .map(|(i, &b)| (c.base_value(b).as_canonical_u32() as usize) << i)
                .sum()
        })
        .collect();

    // Powers of alpha for the longest ladder of one height.
    let mut ladder: alloc::collections::BTreeMap<usize, usize> = alloc::collections::BTreeMap::new();
    for (r, mats) in claims.iter().enumerate() {
        for (m, points) in mats.iter().enumerate() {
            for values in points {
                *ladder.entry(log_heights[r][m]).or_insert(0) += values.len();
            }
        }
    }
    let max_ladder = ladder.values().copied().max().unwrap_or(0);
    let mut alpha_pows = Vec::with_capacity(max_ladder);
    let mut pow = c.one();
    for _ in 0..max_ladder {
        alpha_pows.push(pow);
        pow = c.mul(pow, alpha.ext);
    }
    // Each opening point's ladder offset and `sum alpha^(off + i) p_i(z)`.
    let mut offsets: alloc::collections::BTreeMap<usize, usize> = alloc::collections::BTreeMap::new();
    let mut at_z: Vec<Vec<Vec<(usize, Wire)>>> = Vec::new();
    for (r, mats) in claims.iter().enumerate() {
        let mut per_mat = Vec::new();
        for (m, points) in mats.iter().enumerate() {
            let mut per_point = Vec::new();
            for values in points {
                let off = offsets.entry(log_heights[r][m]).or_insert(0);
                let start = *off;
                *off += values.len();
                let mut acc = c.zero();
                for (i, v) in values.iter().enumerate() {
                    acc = c.mul_add(alpha_pows[start + i], v.ext, acc);
                }
                per_point.push((start, acc));
            }
            per_mat.push(per_point);
        }
        at_z.push(per_mat);
    }

    // The input openings: rows, salts and one path per query and batch.
    let input_openings = fri_proof.map(|f| &f.input_openings);
    let mut input_rows: Vec<Vec<Vec<Vec<F>>>> = Vec::with_capacity(rounds.len());
    let mut input_salts: Vec<Vec<Vec<Vec<F>>>> = Vec::with_capacity(rounds.len());
    let mut input_paths: Vec<Vec<Vec<[F; DIGEST]>>> = Vec::with_capacity(rounds.len());
    for (r, mats) in claims.iter().enumerate() {
        let widths: Vec<usize> = mats.iter().map(|points| points.first().map_or(0, Vec::len)).collect();
        let batch_log = log_heights[r].iter().copied().max().unwrap_or(0);
        let shift = log_max - batch_log;
        let batch = input_openings.and_then(|o| o.get(r));
        let rows: Vec<Vec<Vec<F>>> = (0..fri.num_queries)
            .map(|q| {
                widths
                    .iter()
                    .enumerate()
                    .map(|(m, &w)| {
                        let row = batch.and_then(|b| b.opened_values.get(q)?.get(m).cloned()).unwrap_or_default();
                        (0..w).map(|i| row.get(i).copied().unwrap_or(F::ZERO)).collect()
                    })
                    .collect()
            })
            .collect();
        let salts: Vec<Vec<Vec<F>>> = (0..fri.num_queries)
            .map(|q| {
                (0..widths.len())
                    .map(|m| {
                        let salt = batch.and_then(|b| b.opening_proof.0.get(q)?.get(m).cloned()).unwrap_or_default();
                        (0..SCALE_SALT_ELEMS).map(|i| salt.get(i).copied().unwrap_or(F::ZERO)).collect()
                    })
                    .collect()
            })
            .collect();
        let paths = batch
            .and_then(|b| {
                let dims: Vec<Dimensions> = widths
                    .iter()
                    .zip(&log_heights[r])
                    .map(|(&w, &lh)| Dimensions {
                        width: w + SCALE_SALT_ELEMS,
                        height: 1 << lh,
                    })
                    .collect();
                let salted: Vec<Vec<Vec<F>>> = rows
                    .iter()
                    .zip(&salts)
                    .map(|(qr, qs)| qr.iter().zip(qs).map(|(row, salt)| [row.clone(), salt.clone()].concat()).collect())
                    .collect();
                let reduced: Vec<usize> = indices.iter().map(|&i| i >> shift).collect();
                scale_restore_paths(&dims, &reduced, &salted, &b.opening_proof.1)
            })
            .unwrap_or_else(|| vec![vec![[F::ZERO; DIGEST]; batch_log]; fri.num_queries]);
        input_rows.push(rows);
        input_salts.push(salts);
        input_paths.push(paths);
    }

    let g = F::GENERATOR;
    // Every query's batches: their paths, and one reduced opening a height.
    let mut reduced_by_query: Vec<alloc::collections::BTreeMap<usize, Wire>> = Vec::with_capacity(fri.num_queries);
    let min_log = log_heights.iter().flatten().copied().min().unwrap_or(log_max);
    for (q, bits) in index_bits.iter().enumerate() {
        let mut reduced: alloc::collections::BTreeMap<usize, Wire> = alloc::collections::BTreeMap::new();
        // The query's point at each height: x_h = g * y_h with
        // y_h = g_h^rev(index >> (H - h), h), and y_(h - 1) = y_h^2.
        let mut xs: alloc::collections::BTreeMap<usize, Wire> = alloc::collections::BTreeMap::new();
        let mut y = pow_rev(c, F::two_adic_generator(log_max), bits);
        for h in (min_log..=log_max).rev() {
            if h < log_max {
                y = c.square(y);
            }
            let x = c.mul_const(y, EF::from(g));
            xs.insert(h, x);
        }
        for (r, mats) in claims.iter().enumerate() {
            let batch_log = log_heights[r].iter().copied().max().unwrap_or(0);
            let shift = log_max - batch_log;
            let mut row_wires: Vec<Vec<Wire>> = Vec::with_capacity(mats.len());
            let mut salt_wires: Vec<Vec<Wire>> = Vec::with_capacity(mats.len());
            for m in 0..mats.len() {
                row_wires.push(input_rows[r][q][m].iter().map(|&v| c.hint_base(v)).collect());
                salt_wires.push(input_salts[r][q][m].iter().map(|&v| c.hint_base(v)).collect());
            }
            // The leaf and injection levels, tallest first, in commit order.
            let mut order: Vec<usize> = (0..mats.len()).collect();
            order.sort_by_key(|&m| core::cmp::Reverse(log_heights[r][m]));
            let mut levels: Vec<(usize, Vec<Wire>)> = Vec::new();
            for &m in &order {
                let lh = log_heights[r][m];
                let mut salted = row_wires[m].clone();
                salted.extend_from_slice(&salt_wires[m]);
                match levels.last_mut() {
                    Some((h, vals)) if *h == lh => vals.extend(salted),
                    _ => levels.push((lh, salted)),
                }
            }
            let path: Vec<Digest> = input_paths[r][q].iter().map(|d| digest_hint(c, d)).collect();
            verify_path(c, &rounds[r].commit, &levels, &bits[shift..], &path);

            for (m, points) in mats.iter().enumerate() {
                let lh = log_heights[r][m];
                let x = xs[&lh];
                for (p, values) in points.iter().enumerate() {
                    let (start, sum_at_z) = at_z[r][m][p];
                    let mut sum_at_x = c.zero();
                    for (i, &v) in row_wires[m].iter().enumerate().take(values.len()) {
                        sum_at_x = c.mul_add(alpha_pows[start + i], v, sum_at_x);
                    }
                    let z = rounds[r].mats[m].points[p].0;
                    let denom = c.sub(z, x);
                    let inv = c.inv(denom);
                    let diff = c.sub(sum_at_z, sum_at_x);
                    let acc = match reduced.get(&lh) {
                        Some(&w) => w,
                        None => c.zero(),
                    };
                    let next = c.mul_add(diff, inv, acc);
                    reduced.insert(lh, next);
                }
            }
        }
        reduced_by_query.push(reduced);
    }

    // Fold every query down to the final polynomial, a round at a time: a
    // round's multiproof expands only once every query's pair is known.
    let commit_openings = fri_proof.map(|f| &f.commit_phase_openings);
    let mut folded: Vec<Wire> = reduced_by_query
        .iter()
        .map(|r| *r.get(&log_max).expect("the tallest height has a reduced opening"))
        .collect();
    let half = EF::from(F::TWO.inverse());
    // 1 / s of each round, s = g_(H - r)^rev(index >> (r + 1), H - r - 1):
    // the first by exponentiation, then 1/s_(r+1) = (-1)^b_(r+1) (1/s_r)^2.
    let mut s_inv: Vec<Wire> = index_bits
        .iter()
        .map(|bits| pow_rev(c, F::two_adic_generator(log_max).inverse(), &bits[1..]))
        .collect();
    for r in 0..num_rounds {
        let log_folded = log_max - r - 1;
        let step = commit_openings.and_then(|o| o.get(r));
        let mut pairs: Vec<(ExtVal, ExtVal)> = Vec::with_capacity(fri.num_queries);
        let mut salts: Vec<Vec<F>> = Vec::with_capacity(fri.num_queries);
        for q in 0..fri.num_queries {
            let bits = &index_bits[q];
            let bit = bits[r];
            let sib = step
                .and_then(|s| s.sibling_values.get(q)?.first().copied())
                .unwrap_or(EF::ZERO);
            let sibling = ExtVal::hint(c, sib);
            let lo = c.select(bit, sibling.ext, folded[q]);
            let hi = c.select(bit, folded[q], sibling.ext);
            let lo_c = ExtVal::split(c, lo);
            let hi_c = ExtVal::split(c, hi);
            if r > 0 {
                let sq = c.square(s_inv[q]);
                let t = c.mul(sq, bits[r]);
                s_inv[q] = c.mul_const_add(t, -EF::TWO, sq);
            }
            let sum = c.add(lo, hi);
            let even = c.mul_const(sum, half);
            let diff = c.sub(lo, hi);
            let t = c.mul(diff, betas[r]);
            let t = c.mul(t, s_inv[q]);
            let mut next = c.mul_const_add(t, half, even);
            if let Some(&ro) = reduced_by_query[q].get(&log_folded) {
                let beta_sq = c.square(betas[r]);
                next = c.mul_add(beta_sq, ro, next);
            }
            folded[q] = next;
            pairs.push((lo_c, hi_c));
            let salt = step
                .and_then(|s| s.opening_proof.0.get(q)?.first().cloned())
                .unwrap_or_default();
            salts.push((0..SCALE_SALT_ELEMS).map(|i| salt.get(i).copied().unwrap_or(F::ZERO)).collect());
        }
        let leaves: Vec<Vec<F>> = pairs
            .iter()
            .zip(&salts)
            .map(|((lo, hi), salt)| {
                let mut leaf: Vec<F> = coeffs(&c.value(lo.ext)).to_vec();
                leaf.extend_from_slice(coeffs(&c.value(hi.ext)));
                leaf.extend_from_slice(salt);
                leaf
            })
            .collect();
        let paths = step
            .and_then(|s| {
                let dims = [Dimensions {
                    width: 16 + SCALE_SALT_ELEMS,
                    height: 1 << log_folded,
                }];
                let salted: Vec<Vec<Vec<F>>> = leaves.iter().map(|l| vec![l.clone()]).collect();
                let parents: Vec<usize> = indices.iter().map(|&i| i >> (r + 1)).collect();
                scale_restore_paths(&dims, &parents, &salted, &s.opening_proof.1)
            })
            .unwrap_or_else(|| vec![vec![[F::ZERO; DIGEST]; log_folded]; fri.num_queries]);
        for q in 0..fri.num_queries {
            let (lo, hi) = pairs[q];
            let mut leaf: Vec<Wire> = lo.coeffs.to_vec();
            leaf.extend_from_slice(&hi.coeffs);
            leaf.extend(salts[q].iter().map(|&v| c.hint_base(v)));
            let path: Vec<Digest> = paths[q].iter().map(|d| digest_hint(c, d)).collect();
            verify_path(c, &commits[r], &[(log_folded, leaf)], &index_bits[q][r + 1..], &path);
        }
    }
    for f in folded {
        c.assert_eq(f, final_poly.ext);
    }
}
