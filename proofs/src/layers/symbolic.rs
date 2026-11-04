//! A child AIR's constraints, evaluated inside the circuit at the
//! out-of-domain point.
//!
//! The constraints come from the library's own symbolic evaluation of the AIR
//! (`p3_air` symbolic expressions, with the LogUp constraints of
//! `p3_lookup` for a batch child), so the circuit evaluates exactly what the
//! native verifier folds. Shared subexpressions are evaluated once, and
//! constants are folded before they reach a row.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use p3_air::symbolic::{BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression};
use p3_field::PrimeCharacteristicRing;

use super::circuit::{Circuit, Wire};
use super::{EF, F};

/// A value during evaluation: a constant not yet in the circuit, or a wire.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Val {
    Const(EF),
    Wire(Wire),
}

impl Val {
    pub(crate) fn wire(self, c: &mut Circuit) -> Wire {
        match self {
            Self::Const(k) => c.constant(k),
            Self::Wire(w) => w,
        }
    }
}

fn add(c: &mut Circuit, a: Val, b: Val) -> Val {
    match (a, b) {
        (Val::Const(x), Val::Const(y)) => Val::Const(x + y),
        (Val::Const(k), Val::Wire(w)) | (Val::Wire(w), Val::Const(k)) => {
            if k == EF::ZERO {
                Val::Wire(w)
            } else {
                Val::Wire(c.add_const(w, k))
            }
        }
        (Val::Wire(x), Val::Wire(y)) => Val::Wire(c.add(x, y)),
    }
}

fn neg(c: &mut Circuit, a: Val) -> Val {
    match a {
        Val::Const(x) => Val::Const(-x),
        Val::Wire(w) => Val::Wire(c.neg(w)),
    }
}

fn sub(c: &mut Circuit, a: Val, b: Val) -> Val {
    match (a, b) {
        (Val::Const(x), Val::Const(y)) => Val::Const(x - y),
        (Val::Wire(w), Val::Const(k)) => {
            if k == EF::ZERO {
                Val::Wire(w)
            } else {
                Val::Wire(c.add_const(w, -k))
            }
        }
        (Val::Const(k), Val::Wire(w)) => {
            // k - w = w * (-1) + k
            let kw = c.constant(k);
            Val::Wire(c.mul_const_add(w, -EF::ONE, kw))
        }
        (Val::Wire(x), Val::Wire(y)) => Val::Wire(c.sub(x, y)),
    }
}

fn mul(c: &mut Circuit, a: Val, b: Val) -> Val {
    match (a, b) {
        (Val::Const(x), Val::Const(y)) => Val::Const(x * y),
        (Val::Const(k), Val::Wire(w)) | (Val::Wire(w), Val::Const(k)) => {
            if k == EF::ZERO {
                Val::Const(EF::ZERO)
            } else if k == EF::ONE {
                Val::Wire(w)
            } else {
                Val::Wire(c.mul_const(w, k))
            }
        }
        (Val::Wire(x), Val::Wire(y)) => Val::Wire(c.mul(x, y)),
    }
}

/// Evaluate a symbolic expression whose leaves `leaf` maps to values, sharing
/// every node reached through `memo` (keyed by node address, valid while the
/// expressions live).
pub(crate) fn eval_expr<A>(
    c: &mut Circuit,
    root: &SymbolicExpr<A>,
    leaf: &mut dyn FnMut(&mut Circuit, &A) -> Val,
    memo: &mut BTreeMap<usize, Val>,
) -> Val {
    let key = |e: &SymbolicExpr<A>| e as *const SymbolicExpr<A> as usize;
    // An explicit stack: constraint trees can be deep.
    let mut stack: Vec<(&SymbolicExpr<A>, bool)> = Vec::new();
    stack.push((root, false));
    while let Some((node, expanded)) = stack.pop() {
        if memo.contains_key(&key(node)) {
            continue;
        }
        let children: Vec<&SymbolicExpr<A>> = match node {
            SymbolicExpr::Leaf(_) => Vec::new(),
            SymbolicExpr::Add { x, y, .. } | SymbolicExpr::Sub { x, y, .. } | SymbolicExpr::Mul { x, y, .. } => {
                alloc::vec![&**x, &**y]
            }
            SymbolicExpr::Neg { x, .. } => alloc::vec![&**x],
        };
        if !expanded && !children.is_empty() {
            stack.push((node, true));
            for ch in children {
                if !memo.contains_key(&key(ch)) {
                    stack.push((ch, false));
                }
            }
            continue;
        }
        let get = |memo: &BTreeMap<usize, Val>, e: &SymbolicExpr<A>| memo[&key(e)];
        let v = match node {
            SymbolicExpr::Leaf(a) => leaf(c, a),
            SymbolicExpr::Add { x, y, .. } => {
                let (a, b) = (get(memo, x), get(memo, y));
                add(c, a, b)
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let (a, b) = (get(memo, x), get(memo, y));
                sub(c, a, b)
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let (a, b) = (get(memo, x), get(memo, y));
                mul(c, a, b)
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = get(memo, x);
                neg(c, a)
            }
        };
        memo.insert(key(node), v);
    }
    memo[&key(root)]
}

/// The values the constraints of one AIR read at the out-of-domain point.
pub(crate) struct OodValues {
    pub(crate) main_local: Vec<Wire>,
    pub(crate) main_next: Vec<Wire>,
    pub(crate) prep_local: Vec<Wire>,
    pub(crate) prep_next: Vec<Wire>,
    pub(crate) periodic: Vec<Wire>,
    pub(crate) publics: Vec<Wire>,
    pub(crate) perm_local: Vec<Wire>,
    pub(crate) perm_next: Vec<Wire>,
    pub(crate) challenges: Vec<Wire>,
    pub(crate) perm_values: Vec<Wire>,
    pub(crate) is_first_row: Wire,
    pub(crate) is_last_row: Wire,
    pub(crate) is_transition: Wire,
}

fn base_leaf(v: &OodValues, a: &BaseLeaf<F>) -> Val {
    match a {
        BaseLeaf::Constant(k) => Val::Const(EF::from(*k)),
        BaseLeaf::IsFirstRow => Val::Wire(v.is_first_row),
        BaseLeaf::IsLastRow => Val::Wire(v.is_last_row),
        BaseLeaf::IsTransition => Val::Wire(v.is_transition),
        BaseLeaf::Variable(var) => Val::Wire(match var.entry {
            BaseEntry::Main { offset: 0 } => v.main_local[var.index],
            BaseEntry::Main { .. } => v.main_next[var.index],
            BaseEntry::Preprocessed { offset: 0 } => v.prep_local[var.index],
            BaseEntry::Preprocessed { .. } => v.prep_next[var.index],
            BaseEntry::Periodic => v.periodic[var.index],
            BaseEntry::Public => v.publics[var.index],
        }),
    }
}

/// A value during [`fold_constraints_linear`]: `sum_i k_i w_i + k`, kept as
/// its terms until a product or the fold needs it as one wire.
#[derive(Clone, Debug)]
struct Lin {
    terms: Vec<(Wire, EF)>,
    k: EF,
}

/// Terms a linear value keeps before it is made one wire: a bound on the
/// memory the evaluation holds, at no cost in rows (each term is added once
/// either way).
const LIN_TERMS: usize = 32;

impl Lin {
    fn constant(k: EF) -> Self {
        Self { terms: Vec::new(), k }
    }

    fn wire(w: Wire) -> Self {
        Self {
            terms: alloc::vec![(w, EF::ONE)],
            k: EF::ZERO,
        }
    }

    fn scaled(&self, s: EF) -> Self {
        if s == EF::ZERO {
            return Self::constant(EF::ZERO);
        }
        Self {
            terms: self.terms.iter().map(|&(w, k)| (w, k * s)).collect(),
            k: self.k * s,
        }
    }

    /// The value as one wire and a coefficient, when it is one term.
    fn single(&self) -> Option<(Wire, EF)> {
        match self.terms.as_slice() {
            [(w, k)] if self.k == EF::ZERO => Some((*w, *k)),
            _ => None,
        }
    }

    /// The value as one wire: a row a term, none for a constant or a lone
    /// wire, and one more for a constant beside terms. The terms' wire is
    /// made once for every value with the same terms (`cache`), so
    /// `x`, `x - 2` and `x - 4` share it.
    fn materialize(&self, c: &mut Circuit, cache: &mut LinCache) -> Wire {
        if self.terms.is_empty() {
            return c.constant(self.k);
        }
        let base = match self.terms.as_slice() {
            [(w, k)] if *k == EF::ONE => *w,
            _ => {
                let key: Vec<(u32, [u32; 8])> = self.terms.iter().map(|&(w, k)| (w.0, ef_key(k))).collect();
                if let Some(&w) = cache.get(&key) {
                    w
                } else {
                    let mut it = self.terms.iter();
                    let &(w0, k0) = it.next().expect("a term");
                    let mut acc = if k0 == EF::ONE { w0 } else { c.mul_const(w0, k0) };
                    for &(w, k) in it {
                        acc = if k == EF::ONE { c.add(w, acc) } else { c.mul_const_add(w, k, acc) };
                    }
                    cache.insert(key, acc);
                    acc
                }
            }
        };
        if self.k == EF::ZERO { base } else { c.add_const(base, self.k) }
    }

    /// The sum, its terms merged by wire; made into one wire past
    /// [`LIN_TERMS`] terms.
    fn add(&self, other: &Self, c: &mut Circuit, cache: &mut LinCache) -> Self {
        let mut terms = Vec::with_capacity(self.terms.len() + other.terms.len());
        let (mut i, mut j) = (0, 0);
        while i < self.terms.len() || j < other.terms.len() {
            let take_self = j == other.terms.len() || (i < self.terms.len() && self.terms[i].0 < other.terms[j].0);
            let take_other = i == self.terms.len() || (j < other.terms.len() && other.terms[j].0 < self.terms[i].0);
            if take_self {
                terms.push(self.terms[i]);
                i += 1;
            } else if take_other {
                terms.push(other.terms[j]);
                j += 1;
            } else {
                let k = self.terms[i].1 + other.terms[j].1;
                if k != EF::ZERO {
                    terms.push((self.terms[i].0, k));
                }
                i += 1;
                j += 1;
            }
        }
        let k = self.k + other.k;
        if terms.len() > LIN_TERMS {
            let w = Self { terms, k: EF::ZERO }.materialize(c, cache);
            return Self {
                terms: alloc::vec![(w, EF::ONE)],
                k,
            };
        }
        Self { terms, k }
    }
}

/// The wires linear values were made into, by their terms.
type LinCache = BTreeMap<Vec<(u32, [u32; 8])>, Wire>;

fn ef_key(k: EF) -> [u32; 8] {
    use p3_field::PrimeField32;
    let cs = super::coeffs(&k);
    core::array::from_fn(|i| cs[i].as_canonical_u32())
}

/// Evaluate a symbolic expression into a linear value, sharing every node
/// through `memo` and every wire a value was made into through `cache`.
fn eval_lin<A>(
    c: &mut Circuit,
    root: &SymbolicExpr<A>,
    leaf: &mut dyn FnMut(&mut Circuit, &A) -> Lin,
    memo: &mut BTreeMap<usize, alloc::rc::Rc<Lin>>,
    cache: &mut LinCache,
) -> alloc::rc::Rc<Lin> {
    let key = |e: &SymbolicExpr<A>| e as *const SymbolicExpr<A> as usize;
    let mut stack: Vec<(&SymbolicExpr<A>, bool)> = Vec::new();
    stack.push((root, false));
    while let Some((node, expanded)) = stack.pop() {
        if memo.contains_key(&key(node)) {
            continue;
        }
        let children: Vec<&SymbolicExpr<A>> = match node {
            SymbolicExpr::Leaf(_) => Vec::new(),
            SymbolicExpr::Add { x, y, .. } | SymbolicExpr::Sub { x, y, .. } | SymbolicExpr::Mul { x, y, .. } => {
                alloc::vec![&**x, &**y]
            }
            SymbolicExpr::Neg { x, .. } => alloc::vec![&**x],
        };
        if !expanded && !children.is_empty() {
            stack.push((node, true));
            for ch in children {
                if !memo.contains_key(&key(ch)) {
                    stack.push((ch, false));
                }
            }
            continue;
        }
        let v = match node {
            SymbolicExpr::Leaf(a) => leaf(c, a),
            SymbolicExpr::Add { x, y, .. } => {
                let (a, b) = (memo[&key(x)].clone(), memo[&key(y)].clone());
                a.add(&b, c, cache)
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let (a, b) = (memo[&key(x)].clone(), memo[&key(y)].clone());
                a.add(&b.scaled(-EF::ONE), c, cache)
            }
            SymbolicExpr::Neg { x, .. } => memo[&key(x)].scaled(-EF::ONE),
            SymbolicExpr::Mul { x, y, .. } => {
                let (a, b) = (memo[&key(x)].clone(), memo[&key(y)].clone());
                if a.terms.is_empty() {
                    b.scaled(a.k)
                } else if b.terms.is_empty() {
                    a.scaled(b.k)
                } else {
                    let mut operand = |c: &mut Circuit, v: &Lin| -> (Wire, EF) {
                        match v.single() {
                            Some(s) => s,
                            None => (v.materialize(c, cache), EF::ONE),
                        }
                    };
                    let (wa, ka) = operand(c, &a);
                    let (wb, kb) = operand(c, &b);
                    let p = c.mul(wa, wb);
                    Lin::wire(p).scaled(ka * kb)
                }
            }
        };
        memo.insert(key(node), alloc::rc::Rc::new(v));
    }
    memo[&key(root)].clone()
}

fn base_lin(v: &OodValues, a: &BaseLeaf<F>) -> Lin {
    match base_leaf(v, a) {
        Val::Const(k) => Lin::constant(k),
        Val::Wire(w) => Lin::wire(w),
    }
}

/// [`fold_constraints`] with fewer rows: sums and constant multiples are
/// kept as linear values and made into a wire only where a product or the
/// fold reads them, so a weighted sum of `n` terms costs `n` rows. The same
/// fold, for the tables of a chunk proof.
pub(crate) fn fold_constraints_linear(
    c: &mut Circuit,
    base: &[SymbolicExpression<F>],
    ext: &[SymbolicExpr<ExtLeaf<F, EF>>],
    order: &[(bool, usize)],
    v: &OodValues,
    alpha: Wire,
) -> Wire {
    let mut memo_base: BTreeMap<usize, alloc::rc::Rc<Lin>> = BTreeMap::new();
    let mut wires_base: LinCache = BTreeMap::new();
    let mut memo_ext: BTreeMap<usize, alloc::rc::Rc<Lin>> = BTreeMap::new();
    let mut wires_ext: LinCache = BTreeMap::new();
    let mut acc: Option<Wire> = None;
    for &(is_base, i) in order {
        let value = if is_base {
            eval_lin(c, &base[i], &mut |_c, a| base_lin(v, a), &mut memo_base, &mut wires_base)
        } else {
            let mut leaf = |c: &mut Circuit, a: &ExtLeaf<F, EF>| -> Lin {
                match a {
                    ExtLeaf::ExtConstant(k) => Lin::constant(*k),
                    ExtLeaf::Base(e) => {
                        let lin = eval_lin(c, e, &mut |_c, b| base_lin(v, b), &mut memo_base, &mut wires_base);
                        (*lin).clone()
                    }
                    ExtLeaf::ExtVariable(var) => Lin::wire(match var.entry {
                        ExtEntry::Permutation { offset: 0 } => v.perm_local[var.index],
                        ExtEntry::Permutation { .. } => v.perm_next[var.index],
                        ExtEntry::Challenge => v.challenges[var.index],
                        ExtEntry::PermutationValue => v.perm_values[var.index],
                    }),
                }
            };
            eval_lin(c, &ext[i], &mut leaf, &mut memo_ext, &mut wires_ext)
        };
        // acc = acc * alpha + value
        let value_w = value.materialize(c, &mut wires_ext);
        acc = Some(match acc {
            None => value_w,
            Some(a) => c.mul_add(a, alpha, value_w),
        });
    }
    acc.unwrap_or_else(|| c.zero())
}

/// `sum_i alpha^(n - 1 - i) C_i` over the constraints in their global order:
/// the fold the native verifier's Horner accumulation computes. `order`
/// lists, for each global index, whether it is a base constraint and its
/// position in its own list.
pub(crate) fn fold_constraints(
    c: &mut Circuit,
    base: &[SymbolicExpression<F>],
    ext: &[SymbolicExpr<ExtLeaf<F, EF>>],
    order: &[(bool, usize)],
    v: &OodValues,
    alpha: Wire,
) -> Wire {
    let mut memo_base: BTreeMap<usize, Val> = BTreeMap::new();
    let mut memo_ext: BTreeMap<usize, Val> = BTreeMap::new();
    let mut acc = Val::Const(EF::ZERO);
    for &(is_base, i) in order {
        let value = if is_base {
            eval_expr(c, &base[i], &mut |_c, a| base_leaf(v, a), &mut memo_base)
        } else {
            let mut leaf = |c: &mut Circuit, a: &ExtLeaf<F, EF>| -> Val {
                match a {
                    ExtLeaf::ExtConstant(k) => Val::Const(*k),
                    ExtLeaf::Base(e) => eval_expr(c, e, &mut |_c, b| base_leaf(v, b), &mut memo_base),
                    ExtLeaf::ExtVariable(var) => Val::Wire(match var.entry {
                        ExtEntry::Permutation { offset: 0 } => v.perm_local[var.index],
                        ExtEntry::Permutation { .. } => v.perm_next[var.index],
                        ExtEntry::Challenge => v.challenges[var.index],
                        ExtEntry::PermutationValue => v.perm_values[var.index],
                    }),
                }
            };
            eval_expr(c, &ext[i], &mut leaf, &mut memo_ext)
        };
        // acc = acc * alpha + value
        let acc_w = acc.wire(c);
        let value_w = value.wire(c);
        acc = Val::Wire(c.mul_add(acc_w, alpha, value_w));
    }
    acc.wire(c)
}
