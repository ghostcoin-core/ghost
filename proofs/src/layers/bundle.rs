//! The layers themselves: batch, root and shrink, their binding tags, their
//! running digest and their circuits.
//!
//! Every layer has the same public values: its binding (the chain
//! identifier's eight bytes, the protocol version's two, the statement
//! version), the running digest before its reveals, the running digest after
//! them and their count.
//!
//! - A batch verifies up to `capacity` child proofs of one AIR and shape (a
//!   reveal proof, or the stand-in of a test). Each child's chain identifier
//!   and versions, among its public values, must equal the batch's binding.
//! - A root verifies up to `capacity` batch proofs of one key, and a shrink
//!   one root proof. Each child's binding is the layer's own, the first
//!   child starts from the layer's starting digest, each next one from where
//!   the one before ended, and the counts add up.
//!
//! The running digest is `d' = compress(d, H(public values of the child))`
//! with the leaf hash `H` and the node compression of the scale
//! configuration, so a node computes it from the block's ordered reveals.
//!
//! Every layer's transcript absorbs its tag before anything else: the layer
//! kind, its index among its parent's children, the protocol and statement
//! versions, the chain identifier and the digest of its children's verifier
//! key. That digest is a constant of the circuit, so it sits in the
//! preprocessed constant columns of the wire table. For a layer child the
//! circuit also recomputes that digest from the child key's words, its
//! preprocessed commitment among them, and absorbs the same commitment where
//! the child's own transcript absorbs it.

use alloc::vec::Vec;

use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicAirBuilder, SymbolicExpr, capture_symbolic_constraints};
use p3_air::{Air, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

use super::circuit::{Circuit, Wire};
use super::pcs::{DIGEST, Digest, RATE, compress, hash_values};
use super::poseidon2::{self, WIDTH};
use super::verifier::{
    LayerProof, LayerSpec, TableConstraints, UniProof, UniShape, log_quotient_chunks, verify_layer, verify_uni,
};
use super::{EF, F};

/// Elements of a binding among a layer's public values: the chain
/// identifier's eight bytes, the protocol version's two, the statement
/// version.
pub(crate) const BINDING_ELEMS: usize = 11;
/// Public values of every layer: binding, starting digest, ending digest,
/// count.
pub(crate) const LAYER_PUBLICS: usize = BINDING_ELEMS + 2 * DIGEST + 1;

/// A native digest.
pub(crate) type NativeDigest = [F; DIGEST];

/// The padding-free sponge of the scale configuration, natively.
pub(crate) fn native_hash(values: &[F]) -> NativeDigest {
    let mut state = [F::ZERO; WIDTH];
    let mut absorbed = 0;
    for &v in values {
        state[absorbed] = v;
        absorbed += 1;
        if absorbed == RATE {
            state = poseidon2::permute(state);
            absorbed = 0;
        }
    }
    if absorbed > 0 {
        state = poseidon2::permute(state);
    }
    core::array::from_fn(|i| state[i])
}

/// The node compression of the scale configuration, natively.
pub(crate) fn native_compress(left: &NativeDigest, right: &NativeDigest) -> NativeDigest {
    let mut input = [F::ZERO; WIDTH];
    input[..DIGEST].copy_from_slice(left);
    input[DIGEST..2 * DIGEST].copy_from_slice(right);
    let out = poseidon2::permute(input);
    core::array::from_fn(|i| out[i])
}

/// The running digest after `contents`, from `start`.
pub(crate) fn native_running_digest(start: &NativeDigest, contents: &[Vec<F>]) -> NativeDigest {
    contents.iter().fold(*start, |d, c| native_compress(&d, &native_hash(c)))
}

/// What kind of layer a proof is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerKind {
    Batch = 1,
    Root = 2,
    Shrink = 3,
    /// A chunk of ML-DSA-44 verifications ([`crate::mldsa`]): the child of a
    /// batch of chunks.
    Chunk = 4,
}

/// The label every tag starts with: "ghost-layers" as an element of three
/// bytes per limb.
const TAG_LABEL: [u32; 4] = [0x0067_686f, 0x0073_742d, 0x006c_6179, 0x0065_7273];

/// What a layer's transcript absorbs before anything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerTag {
    pub kind: LayerKind,
    /// The layer's position among its parent's children.
    pub index: u32,
    pub protocol_version: [u8; 2],
    pub statement_version: u8,
    pub chain_id: [u8; 8],
    /// The digest of the verifier key of the layer's children.
    pub child_key: [u32; DIGEST],
}

impl LayerTag {
    pub(crate) fn elements(&self) -> Vec<F> {
        let mut out: Vec<F> = TAG_LABEL.iter().map(|&x| F::from_u32(x)).collect();
        out.push(F::from_u32(self.kind as u32));
        out.push(F::from_u32(self.index));
        out.extend(self.protocol_version.iter().map(|&b| F::from_u8(b)));
        out.push(F::from_u8(self.statement_version));
        out.extend(self.chain_id.iter().map(|&b| F::from_u8(b)));
        out.extend(self.child_key.iter().map(|&x| F::from_u32(x)));
        out
    }
}

/// A native digest as canonical integers.
pub(crate) fn digest_u32(d: &NativeDigest) -> [u32; DIGEST] {
    core::array::from_fn(|i| d[i].as_canonical_u32())
}

/// The digest of a uni-STARK child's verifier key: its shape and every
/// constraint of its AIR, hashed node by node, with its periodic columns.
pub(crate) fn uni_key_digest<A>(air: &A, shape: &UniShape) -> NativeDigest
where
    A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
{
    let mut words: Vec<F> = Vec::new();
    let mut push = |x: usize| words.push(F::from_usize(x));
    push(1); // a uni-STARK child of the scale configuration
    push(shape.log_height);
    push(shape.fri.log_blowup);
    push(shape.fri.num_queries);
    push(shape.fri.query_pow_bits);
    push(shape.fri.batch_pow_bits);
    push(air.width());
    push(air.num_public_values());
    push(usize::from(!air.main_next_row_columns().is_empty()));
    push(log_quotient_chunks(air, shape.log_height));
    let layout = p3_air::symbolic::AirLayout {
        preprocessed_width: 0,
        main_width: air.width(),
        num_public_values: air.num_public_values(),
        num_periodic_columns: air.num_periodic_columns(),
        ..Default::default()
    };
    let constraints = capture_symbolic_constraints::<F, F>(layout, |b| air.eval(b));
    // Number every node once, children first, and write each as an opcode
    // and its operands.
    let mut ids: alloc::collections::BTreeMap<usize, usize> = alloc::collections::BTreeMap::new();
    let key = |e: &SymbolicExpr<BaseLeaf<F>>| e as *const SymbolicExpr<BaseLeaf<F>> as usize;
    let mut roots = Vec::new();
    for root in constraints.base_constraints() {
        let mut stack: Vec<(&SymbolicExpr<BaseLeaf<F>>, bool)> = alloc::vec![(root, false)];
        while let Some((node, expanded)) = stack.pop() {
            if ids.contains_key(&key(node)) {
                continue;
            }
            let children: Vec<&SymbolicExpr<BaseLeaf<F>>> = match node {
                SymbolicExpr::Leaf(_) => Vec::new(),
                SymbolicExpr::Add { x, y, .. } | SymbolicExpr::Sub { x, y, .. } | SymbolicExpr::Mul { x, y, .. } => {
                    alloc::vec![&**x, &**y]
                }
                SymbolicExpr::Neg { x, .. } => alloc::vec![&**x],
            };
            if !expanded && !children.is_empty() {
                stack.push((node, true));
                stack.extend(children.into_iter().map(|c| (c, false)));
                continue;
            }
            let id = ids.len();
            let child = |e: &SymbolicExpr<BaseLeaf<F>>| F::from_usize(ids[&key(e)]);
            match node {
                SymbolicExpr::Leaf(leaf) => match leaf {
                    BaseLeaf::Constant(k) => words.extend([F::from_u8(1), *k]),
                    BaseLeaf::IsFirstRow => words.push(F::from_u8(2)),
                    BaseLeaf::IsLastRow => words.push(F::from_u8(3)),
                    BaseLeaf::IsTransition => words.push(F::from_u8(4)),
                    BaseLeaf::Variable(v) => {
                        let (kind, offset) = match v.entry {
                            BaseEntry::Main { offset } => (5, offset),
                            BaseEntry::Preprocessed { offset } => (6, offset),
                            BaseEntry::Periodic => (7, 0),
                            BaseEntry::Public => (8, 0),
                        };
                        words.extend([F::from_u8(kind), F::from_usize(offset), F::from_usize(v.index)]);
                    }
                },
                SymbolicExpr::Add { x, y, .. } => words.extend([F::from_u8(9), child(x), child(y)]),
                SymbolicExpr::Sub { x, y, .. } => words.extend([F::from_u8(10), child(x), child(y)]),
                SymbolicExpr::Mul { x, y, .. } => words.extend([F::from_u8(11), child(x), child(y)]),
                SymbolicExpr::Neg { x, .. } => words.extend([F::from_u8(12), child(x)]),
            }
            ids.insert(key(node), id);
        }
        roots.push(F::from_usize(ids[&key(root)]));
    }
    words.push(F::from_usize(roots.len()));
    words.extend(roots);
    for col in air.periodic_columns().iter() {
        words.push(F::from_usize(col.len()));
        words.extend(col.iter().copied());
    }
    native_hash(&words)
}

/// The running digest in the circuit: `d' = compress(d, H(contents))`.
pub(crate) fn absorb_child(c: &mut Circuit, d: &Digest, contents: &[Wire]) -> Digest {
    let h = hash_values(c, contents);
    compress(c, d, &h)
}

/// `if bit { a } else { b }`, a digest at a time.
pub(crate) fn select_digest(c: &mut Circuit, bit: Wire, a: &Digest, b: &Digest) -> Digest {
    core::array::from_fn(|i| c.select(bit, a[i], b[i]))
}

/// Active-slot bits: each 0 or 1, never a 1 after a 0, `count` ones.
pub(crate) fn active_bits(c: &mut Circuit, capacity: usize, count: usize) -> Vec<Wire> {
    let mut bits = Vec::with_capacity(capacity);
    for i in 0..capacity {
        let b = c.hint_base(F::from_bool(i < count));
        // b (b - 1) = 0
        let b1 = c.add_const(b, -EF::ONE);
        let p = c.mul(b, b1);
        c.assert_zero(p);
        if let Some(&prev) = bits.last() {
            // b (1 - prev) = 0
            let one = c.one();
            let not_prev = c.sub(one, prev);
            let q = c.mul(b, not_prev);
            c.assert_zero(q);
        }
        bits.push(b);
    }
    bits
}

/// The sum of wires.
pub(crate) fn sum(c: &mut Circuit, ws: &[Wire]) -> Wire {
    let mut acc = c.zero();
    for &w in ws {
        acc = c.add(acc, w);
    }
    acc
}

/// One child of a batch: its proof and its public values.
pub(crate) struct UniChild<'a> {
    pub(crate) proof: &'a UniProof,
    pub(crate) publics: &'a [F],
}

/// A layer's public values in the circuit: its first wires after the
/// constants zero and one, as the wire table requires.
pub(crate) struct LayerWires {
    pub(crate) binding: [Wire; BINDING_ELEMS],
    pub(crate) start: Digest,
    pub(crate) end: Digest,
    pub(crate) count: Wire,
}

/// Make a layer's public values from their native values (zeros when only
/// the rows are wanted).
pub(crate) fn layer_wires(c: &mut Circuit, publics: &[F; LAYER_PUBLICS]) -> LayerWires {
    let mut next = publics.iter().copied();
    let mut public = |c: &mut Circuit| {
        let v = next.next().expect("one value a public");
        c.public(v)
    };
    LayerWires {
        binding: core::array::from_fn(|_| public(c)),
        start: core::array::from_fn(|_| public(c)),
        end: core::array::from_fn(|_| public(c)),
        count: public(c),
    }
}

/// The public values of a layer from its binding elements and its claim.
pub(crate) fn layer_publics(
    binding: &[F; BINDING_ELEMS],
    start: &NativeDigest,
    end: &NativeDigest,
    count: usize,
) -> [F; LAYER_PUBLICS] {
    let mut out = [F::ZERO; LAYER_PUBLICS];
    out[..BINDING_ELEMS].copy_from_slice(binding);
    out[BINDING_ELEMS..BINDING_ELEMS + DIGEST].copy_from_slice(start);
    out[BINDING_ELEMS + DIGEST..BINDING_ELEMS + 2 * DIGEST].copy_from_slice(end);
    out[LAYER_PUBLICS - 1] = F::from_usize(count);
    out
}

/// The running digest has reached the layer's ending digest, and the active
/// children's counts add up to its count.
fn close_layer(c: &mut Circuit, p: &LayerWires, d: &Digest, total: Wire) {
    for i in 0..DIGEST {
        c.assert_eq(d[i], p.end[i]);
    }
    c.assert_eq(total, p.count);
}

/// The batch circuit: `capacity` slots of uni-STARK children of `air` at
/// `shape`, the first `children.len()` of them active. In a slot past the
/// active ones the circuit verifies a copy of the last child, which counts
/// for nothing. `binding_slots` are the positions, among a child's public
/// values, of the chain identifier's bytes, the protocol version's and the
/// statement version, in the binding's order: each must equal the batch's
/// binding. `child_key` is the digest of the children's verifier key, a
/// constant of the circuit. `children` is `None` when only the rows are
/// wanted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn batch_circuit<A>(
    c: &mut Circuit,
    air: &A,
    shape: &UniShape,
    binding_slots: &[usize; BINDING_ELEMS],
    child_key: &NativeDigest,
    capacity: usize,
    publics: &[F; LAYER_PUBLICS],
    children: Option<&[UniChild<'_>]>,
) where
    A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
{
    let p = layer_wires(c, publics);
    for &k in child_key {
        c.const_base(k);
    }
    let count = children.map_or(capacity, <[_]>::len);
    let mut d = p.start;
    let active = active_bits(c, capacity, count);
    let n_pub = air.num_public_values();
    for (slot, &bit) in active.iter().enumerate() {
        let child = children.and_then(|ch| ch.get(slot.min(ch.len().saturating_sub(1))));
        let publics: Vec<Wire> = (0..n_pub)
            .map(|i| c.hint_base(child.and_then(|ch| ch.publics.get(i).copied()).unwrap_or(F::ZERO)))
            .collect();
        // The child's chain identifier and versions are the batch's.
        for (j, &at) in binding_slots.iter().enumerate() {
            c.assert_eq(publics[at], p.binding[j]);
        }
        verify_uni(c, air, shape, &publics, child.map(|ch| ch.proof));
        let next = absorb_child(c, &d, &publics);
        d = select_digest(c, bit, &next, &d);
    }
    let total = sum(c, &active);
    close_layer(c, &p, &d, total);
}

/// One child of a root or a shrink: its proof, its index among the layer's
/// children (the one its tag names) and its public values.
pub(crate) struct LayerChild<'a> {
    pub(crate) proof: &'a LayerProof,
    pub(crate) index: u32,
    pub(crate) publics: &'a [F; LAYER_PUBLICS],
}

/// The words of a layer key its digest hashes: its kind, its FRI shape, its
/// public value count, each table's lanes and height, its preprocessed
/// commitment and the digest of its children's key.
pub(crate) fn key_words(
    kind: LayerKind,
    shape: super::LayerShape,
    num_publics: usize,
    tables: &[(usize, usize)],
    commitment: &NativeDigest,
    child_key: &NativeDigest,
) -> Vec<F> {
    let mut words = alloc::vec![
        F::from_u32(kind as u32),
        F::from_usize(shape.log_blowup),
        F::from_usize(shape.num_queries),
        F::from_usize(num_publics),
    ];
    for &(lanes, height) in tables {
        words.push(F::from_usize(lanes));
        words.push(F::from_usize(height));
    }
    words.extend_from_slice(commitment);
    words.extend_from_slice(child_key);
    words
}

/// A layer spec's key words.
pub(crate) fn spec_words(spec: &LayerSpec) -> Vec<F> {
    let tables: Vec<(usize, usize)> = spec.airs.iter().map(|a| (a.lanes(), a.height())).collect();
    key_words(
        spec.kind,
        spec.shape,
        spec.airs[0].num_publics(),
        &tables,
        &spec.commitment,
        &spec.child_key,
    )
}

/// The circuit of a root or a shrink: `capacity` slots of layer children of
/// `child`, the first `children.len()` of them active; in a slot past the
/// active ones the circuit verifies a copy of the last child, which counts
/// for nothing. `children` is `None` when only the rows are wanted.
pub(crate) fn layer_circuit(
    c: &mut Circuit,
    child: &LayerSpec,
    cons: &[TableConstraints],
    capacity: usize,
    publics: &[F; LAYER_PUBLICS],
    children: Option<&[LayerChild<'_>]>,
) {
    let p = layer_wires(c, publics);
    // The digest of the children's key, a constant, is the hash of the key's
    // words: its shape, its tables and its preprocessed commitment, the same
    // constant wires the children's transcripts absorb below.
    let words: Vec<Wire> = spec_words(child).iter().map(|&w| c.const_base(w)).collect();
    let digest = hash_values(c, &words);
    for (i, &k) in child.key_digest.iter().enumerate() {
        let k = c.const_base(k);
        c.assert_eq(digest[i], k);
    }
    let label: Vec<Wire> = TAG_LABEL.iter().map(|&x| c.const_base(F::from_u32(x))).collect();
    let kind = c.const_base(F::from_u32(child.kind as u32));
    let grandchild: Vec<Wire> = child.child_key.iter().map(|&x| c.const_base(x)).collect();

    let count = children.map_or(capacity, <[_]>::len);
    let mut d = p.start;
    let mut total = c.zero();
    let active = active_bits(c, capacity, count);
    for (slot, &bit) in active.iter().enumerate() {
        let entry = children.and_then(|ch| ch.get(slot.min(ch.len().saturating_sub(1))));
        let value = |i: usize| entry.map_or(F::ZERO, |e| e.publics[i]);
        let start: Digest = core::array::from_fn(|i| c.hint_base(value(BINDING_ELEMS + i)));
        let end: Digest = core::array::from_fn(|i| c.hint_base(value(BINDING_ELEMS + DIGEST + i)));
        let child_count = c.hint_base(value(LAYER_PUBLICS - 1));
        // The child's binding is the layer's own.
        let mut child_publics: Vec<Wire> = p.binding.to_vec();
        child_publics.extend_from_slice(&start);
        child_publics.extend_from_slice(&end);
        child_publics.push(child_count);
        // An active slot's child is the slot's own: its tag names the slot.
        let index = c.hint_base(F::from_u32(entry.map_or(slot as u32, |e| e.index)));
        let off = c.add_const(index, -EF::from(F::from_usize(slot)));
        let off = c.mul(off, bit);
        c.assert_zero(off);
        // The child's tag, in `LayerTag::elements` order: label, kind, index,
        // protocol version, statement version, chain identifier, the key of
        // the child's own children.
        let mut tag = label.clone();
        tag.push(kind);
        tag.push(index);
        tag.extend_from_slice(&p.binding[8..10]);
        tag.push(p.binding[10]);
        tag.extend_from_slice(&p.binding[..8]);
        tag.extend_from_slice(&grandchild);
        verify_layer(c, child, cons, &tag, &child_publics, entry.map(|e| e.proof));
        // An active child starts where the one before it ended.
        for i in 0..DIGEST {
            let gap = c.sub(start[i], d[i]);
            let gap = c.mul(gap, bit);
            c.assert_zero(gap);
        }
        d = select_digest(c, bit, &end, &d);
        total = c.mul_add(bit, child_count, total);
    }
    close_layer(c, &p, &d, total);
}
