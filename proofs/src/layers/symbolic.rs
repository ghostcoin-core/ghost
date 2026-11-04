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
