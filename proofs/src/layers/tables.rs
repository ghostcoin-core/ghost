//! The five tables a circuit is proven with, as AIRs of one batch STARK, and
//! the LogUp bus that routes wire values between them.
//!
//! Every message on the bus is `(wire, v0, .., v7)`. The wire table receives
//! each wire once, with the number of times the other tables read it; the
//! arithmetic, permutation, bits and packing tables send every wire they read.
//! The wire identifiers of every row are preprocessed columns, so the verifier
//! key (the preprocessed commitment) fixes the circuit. A base value is sent
//! with its upper seven coefficients as the constant zero.
//!
//! The wire and arithmetic tables hold `lanes` entries a row, so a circuit of
//! many wires stays within the tallest trace the field's two-adic subgroup
//! allows at its blowup: wire `w` sits in row `w / lanes`, lane `w % lanes`.
//!
//! | Table | Preprocessed | Main |
//! |---|---|---|
//! | wires | the row number; a constant flag and value a lane; one selector per public value | the value and the read count, a lane |
//! | arithmetic | four wire numbers and an enable flag, a lane | `a`, `b`, `c`, `out`, eight coefficients each, a lane |
//! | permutation | 24 input and 24 output wire numbers, their enables, the swap wire | the 450 Poseidon2 columns, the inputs as sent, the swap bit |
//! | bits | the value's and 31 bits' wire numbers, an enable flag | 31 bits, one helper |
//! | packing | the extension wire and its eight coefficient wires, an enable flag | the eight coefficients |
//!
//! A circuit's public values are its first wires after the constants zero and
//! one: public `j` is wire `2 + j`, so its lane is fixed by the table's shape.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_batch_stark::{BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch};
use p3_field::extension::BinomiallyExtendable;
use p3_field::{PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_lookup::{Count, InteractionBuilder, Lookups};
use p3_matrix::dense::RowMajorMatrix;

use super::circuit::{BITS, Circuit, SWAP};
use super::poseidon2::{self, PERM_COLS, WIDTH};
use super::{EF, F, coeffs};
use crate::ProofError;
use crate::mldsa::tables::MlTable;
use crate::scale::{ScaleConfig, layer_config, tagged_challenger};
use crate::stark::FriShape;

/// The bus every wire value travels on.
pub(crate) const BUS: &str = "wire";
/// Coefficients of an extension value.
const D: usize = 8;
/// The wire of a circuit's first public value.
pub(crate) const FIRST_PUBLIC: usize = 2;
/// The most lanes a row of the wire or arithmetic table holds.
const MAX_LANES: usize = 64;

/// Which table an AIR is, in batch order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Table {
    Wires,
    Arith,
    Perm,
    Bits,
    Pack,
    /// A table of an ML-DSA chunk ([`crate::mldsa::tables`]), after the five.
    Ml(MlTable),
}

pub(crate) const TABLES: [Table; 5] = [Table::Wires, Table::Arith, Table::Perm, Table::Bits, Table::Pack];

/// One table of a circuit: which it is, its lanes, its height, its public
/// value count and, for a table that is proven or committed, its
/// preprocessed columns. A table known by its shape alone (to plan a layer
/// above it) has none.
#[derive(Clone)]
pub(crate) struct TableAir {
    table: Table,
    num_publics: usize,
    lanes: usize,
    height: usize,
    preprocessed: Option<Arc<RowMajorMatrix<F>>>,
}

impl TableAir {
    /// A table known by its shape alone.
    pub(crate) fn shape(table: Table, num_publics: usize, lanes: usize, height: usize) -> Self {
        Self {
            table,
            num_publics,
            lanes,
            height,
            preprocessed: None,
        }
    }

    pub(crate) fn table(&self) -> Table {
        self.table
    }

    pub(crate) fn height(&self) -> usize {
        self.height
    }

    pub(crate) fn lanes(&self) -> usize {
        self.lanes
    }

    pub(crate) fn num_publics(&self) -> usize {
        self.num_publics
    }

    /// Whether the table's constraints read the next row: only some ML-DSA
    /// tables do.
    pub(crate) fn reads_next(&self) -> bool {
        match self.table {
            Table::Ml(t) => crate::mldsa::tables::reads_next(t),
            _ => false,
        }
    }
}

/// Input lanes a permutation row may exchange, with the values it was sent
/// kept in their own columns.
const SENT: usize = 2 * SWAP;

/// Main columns of a wire-table lane: the value's coefficients, the reads.
const WIRE_LANE: usize = D + 1;
/// Preprocessed columns of a wire-table lane: the constant flag and value.
const WIRE_PREP_LANE: usize = 1 + D;
/// Main columns of an arithmetic lane.
const ARITH_LANE: usize = 4 * D;
/// Preprocessed columns of an arithmetic lane: four wires and the enable.
const ARITH_PREP_LANE: usize = 5;

pub(crate) fn main_width(table: Table, lanes: usize) -> usize {
    match table {
        Table::Wires => WIRE_LANE * lanes,
        Table::Arith => ARITH_LANE * lanes,
        // The permutation's columns, the 18 inputs as sent, the swap bit.
        Table::Perm => PERM_COLS + SENT + 1,
        Table::Bits => BITS + 1,
        Table::Pack => D,
        Table::Ml(t) => crate::mldsa::tables::main_width(t),
    }
}

pub(crate) fn preprocessed_width(table: Table, lanes: usize, num_publics: usize) -> usize {
    match table {
        Table::Wires => 1 + WIRE_PREP_LANE * lanes + num_publics,
        Table::Arith => ARITH_PREP_LANE * lanes,
        // Input wires, output wires, output enables, the swap wire and its
        // enable, the row enable.
        Table::Perm => 3 * WIDTH + 3,
        // The value's wire, the bit wires, the bit enables, the row enable.
        Table::Bits => 2 * BITS + 2,
        // The extension wire, the eight coefficient wires, the row enable.
        Table::Pack => 1 + D + 1,
        Table::Ml(t) => crate::mldsa::tables::preprocessed_width(t),
    }
}

impl BaseAir<F> for TableAir {
    fn width(&self) -> usize {
        main_width(self.table, self.lanes)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.preprocessed.as_deref().cloned()
    }

    fn preprocessed_width(&self) -> usize {
        preprocessed_width(self.table, self.lanes, self.num_publics)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        if self.reads_next() { (0..BaseAir::<F>::width(self)).collect() } else { Vec::new() }
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn num_public_values(&self) -> usize {
        if self.table == Table::Wires { self.num_publics } else { 0 }
    }
}

/// `a * b` in the extension, coefficient by coefficient.
fn ext_mul<E: PrimeCharacteristicRing + Clone + core::ops::Mul<F, Output = E>>(a: &[E], b: &[E]) -> Vec<E> {
    let w = <F as BinomiallyExtendable<D>>::W;
    let mut out: Vec<E> = (0..D).map(|_| E::ZERO).collect();
    for i in 0..D {
        for j in 0..D {
            let p = a[i].clone() * b[j].clone();
            if i + j < D {
                out[i + j] = out[i + j].clone() + p;
            } else {
                out[i + j - D] = out[i + j - D].clone() + p * w;
            }
        }
    }
    out
}

impl<AB> Air<AB> for TableAir
where
    AB: InteractionBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        if let Table::Ml(t) = self.table {
            crate::mldsa::tables::eval(t, builder);
            return;
        }
        let prep: Vec<AB::Expr> = builder.preprocessed().current_slice().iter().map(|&v| v.into()).collect();
        let local: Vec<AB::Expr> = builder.main().current_slice().iter().map(|&v| v.into()).collect();
        let zero = || AB::Expr::ZERO;
        let k = self.lanes;
        // A wire read as an extension value.
        let send_ext = |builder: &mut AB, id: &AB::Expr, coeffs: &[AB::Expr], en: &AB::Expr| {
            let fields: Vec<AB::Expr> = core::iter::once(id.clone()).chain(coeffs.iter().cloned()).collect();
            builder.push_interaction(BUS, fields, Count::bounded(en.clone(), 1));
        };
        // A wire read as a base value.
        let send_base = |builder: &mut AB, id: &AB::Expr, x: &AB::Expr, en: &AB::Expr| {
            let mut fields = vec![id.clone(), x.clone()];
            fields.extend((1..D).map(|_| zero()));
            builder.push_interaction(BUS, fields, Count::bounded(en.clone(), 1));
        };
        match self.table {
            Table::Wires => {
                let row = prep[0].clone();
                for l in 0..k {
                    let is_const = prep[1 + WIRE_PREP_LANE * l].clone();
                    let consts = &prep[2 + WIRE_PREP_LANE * l..1 + WIRE_PREP_LANE * (l + 1)];
                    let v = &local[WIRE_LANE * l..WIRE_LANE * l + D];
                    for c in 0..D {
                        builder.assert_zero(is_const.clone() * (v[c].clone() - consts[c].clone()));
                    }
                }
                let sels = &prep[1 + WIRE_PREP_LANE * k..];
                let publics: Vec<AB::Expr> = builder.public_values().iter().map(|&p| p.into()).collect();
                for (j, (sel, public)) in sels.iter().zip(&publics).enumerate() {
                    // Public `j` is wire `2 + j`: a base value in its lane.
                    let lane = (FIRST_PUBLIC + j) % k;
                    let v = &local[WIRE_LANE * lane..WIRE_LANE * lane + D];
                    builder.assert_zero(sel.clone() * (v[0].clone() - public.clone()));
                    for coeff in &v[1..] {
                        builder.assert_zero(sel.clone() * coeff.clone());
                    }
                }
                for l in 0..k {
                    let id = row.clone() * F::from_usize(k) + F::from_usize(l);
                    let v = &local[WIRE_LANE * l..WIRE_LANE * l + D];
                    let mult = local[WIRE_LANE * l + D].clone();
                    let fields: Vec<AB::Expr> = core::iter::once(id).chain(v.iter().cloned()).collect();
                    builder.push_interaction(BUS, fields, Count::provided(-mult));
                }
            }
            Table::Arith => {
                for l in 0..k {
                    let p = &prep[ARITH_PREP_LANE * l..ARITH_PREP_LANE * (l + 1)];
                    let m = &local[ARITH_LANE * l..ARITH_LANE * (l + 1)];
                    let en = p[4].clone();
                    let (a, b, c, out) = (&m[0..D], &m[D..2 * D], &m[2 * D..3 * D], &m[3 * D..4 * D]);
                    let product = ext_mul(a, b);
                    for t in 0..D {
                        builder.assert_zero(product[t].clone() + c[t].clone() - out[t].clone());
                    }
                    for (i, coeffs) in [a, b, c, out].into_iter().enumerate() {
                        send_ext(builder, &p[i], coeffs, &en);
                    }
                }
            }
            Table::Perm => {
                let en = prep[3 * WIDTH + 2].clone();
                let swap_en = prep[3 * WIDTH + 1].clone();
                let perm = &local[..PERM_COLS];
                let sent = &local[PERM_COLS..PERM_COLS + SENT];
                let swap = local[PERM_COLS + SENT].clone();
                let mut constraints = Vec::new();
                poseidon2::eval_row(perm, |e| constraints.push(e));
                for e in constraints {
                    builder.assert_zero(e);
                }
                // The permutation's input is the sent input, its two blocks
                // exchanged when the swap bit is one; with no swap wire the
                // bit is zero.
                for j in 0..SENT {
                    let partner = if j < SWAP { j + SWAP } else { j - SWAP };
                    let actual = perm[poseidon2::input_columns().start + j].clone();
                    builder.assert_zero(
                        actual - sent[j].clone() - swap.clone() * (sent[partner].clone() - sent[j].clone()),
                    );
                }
                builder.assert_zero(swap.clone() * (AB::Expr::ONE - swap_en.clone()));
                for (i, col) in poseidon2::input_columns().enumerate() {
                    let x = if i < SENT { &sent[i] } else { &perm[col] };
                    send_base(builder, &prep[i], x, &en);
                }
                for (i, col) in poseidon2::output_columns().enumerate() {
                    send_base(builder, &prep[WIDTH + i], &perm[col], &prep[2 * WIDTH + i]);
                }
                send_base(builder, &prep[3 * WIDTH], &swap, &swap_en);
            }
            Table::Bits => {
                let en = prep[2 * BITS + 1].clone();
                let bits = &local[..BITS];
                let t = local[BITS].clone();
                for b in bits {
                    builder.assert_zero(b.clone() * (b.clone() - AB::Expr::ONE));
                }
                // Canonical: when bits 27 to 30 are all set the low 27 are clear.
                builder.assert_zero(t.clone() - bits[27].clone() * bits[28].clone() * bits[29].clone());
                let mut low = zero();
                for (i, b) in bits.iter().enumerate().take(27) {
                    low = low + b.clone() * F::from_u32(1 << i);
                }
                builder.assert_zero(t * bits[30].clone() * low);
                let mut x = zero();
                for (i, b) in bits.iter().enumerate() {
                    x = x + b.clone() * F::from_u32(1 << i);
                }
                send_base(builder, &prep[0], &x, &en);
                for (i, b) in bits.iter().enumerate() {
                    send_base(builder, &prep[1 + i], b, &prep[1 + BITS + i]);
                }
            }
            Table::Pack => {
                // The extension wire's coefficients are the eight base wires.
                let en = prep[1 + D].clone();
                let v = &local[..D];
                send_ext(builder, &prep[0], v, &en);
                for (k, coeff) in v.iter().enumerate() {
                    send_base(builder, &prep[1 + k], coeff, &en);
                }
            }
            Table::Ml(_) => {}
        }
    }
}

/// Smallest height every table of a layer keeps: the hiding budget of the
/// library, `2 * (D * points + num_queries)` with two opening points.
pub(crate) fn min_height(fri: &FriShape) -> usize {
    (2 * (D * 2 + fri.num_queries)).next_power_of_two()
}

/// Log of the tallest trace a proof at `fri` may have: its extension by the
/// zero-knowledge doubling and the blowup must stay within the two-adic
/// subgroup of the field.
pub(crate) fn max_log_height(fri: &FriShape) -> usize {
    F::TWO_ADICITY - fri.log_blowup - 1
}

fn height_for(rows: usize, fri: &FriShape) -> usize {
    rows.next_power_of_two().max(min_height(fri))
}

fn wire_id(w: super::circuit::Wire) -> F {
    F::from_u32(w.0)
}

/// The entries of each table of a circuit: wires, arithmetic rows,
/// permutation rows, bits rows and packing rows.
pub(crate) fn table_rows(circuit: &Circuit) -> [usize; 5] {
    [
        circuit.num_wires(),
        circuit.arith_rows().len(),
        circuit.perm_rows().len(),
        circuit.bits_rows().len(),
        circuit.pack_rows().len(),
    ]
}

/// Each table's lanes and height for `rows` entries at `fri`: the fewest
/// lanes (a power of two) that keep the table no taller than `2^max_log`.
/// Only the wire and arithmetic tables take more than one lane.
pub(crate) fn plan(rows: [usize; 5], fri: &FriShape, max_log: usize) -> Result<[(usize, usize); 5], ProofError> {
    let mut out = [(1, 0); 5];
    for (i, &n) in rows.iter().enumerate() {
        let multi = matches!(TABLES[i], Table::Wires | Table::Arith);
        let mut lanes = 1;
        loop {
            let h = height_for(n.div_ceil(lanes), fri);
            if h.trailing_zeros() as usize <= max_log {
                out[i] = (lanes, h);
                break;
            }
            if !multi || lanes >= MAX_LANES {
                return Err(ProofError::Proving);
            }
            lanes *= 2;
        }
    }
    Ok(out)
}

/// The tables of a circuit, with their preprocessed columns: everything the
/// verifier key depends on, each table no taller than `2^max_log` (and the
/// field's limit at `fri`). Refuses a circuit whose public values are not
/// its first wires after the constants, or one too large.
pub(crate) fn table_airs_within(
    circuit: &Circuit,
    fri: &FriShape,
    max_log: usize,
) -> Result<Vec<TableAir>, ProofError> {
    let num_publics = circuit.publics().len();
    if circuit.publics().iter().enumerate().any(|(j, w)| w.0 as usize != FIRST_PUBLIC + j) {
        return Err(ProofError::Proving);
    }
    let plans = plan(table_rows(circuit), fri, max_log.min(max_log_height(fri)))?;
    let mut airs = Vec::with_capacity(TABLES.len());
    for (table, (lanes, height)) in TABLES.into_iter().zip(plans) {
        let width = preprocessed_width(table, lanes, num_publics);
        let mut m = vec![F::ZERO; height * width];
        match table {
            Table::Wires => {
                for r in 0..height {
                    m[r * width] = F::from_usize(r);
                }
                for &(w, c) in circuit.consts() {
                    let (r, l) = (w.0 as usize / lanes, w.0 as usize % lanes);
                    let at = r * width + 1 + WIRE_PREP_LANE * l;
                    m[at] = F::ONE;
                    for (t, &coeff) in coeffs(&c).iter().enumerate() {
                        m[at + 1 + t] = coeff;
                    }
                }
                for j in 0..num_publics {
                    let r = (FIRST_PUBLIC + j) / lanes;
                    m[r * width + 1 + WIRE_PREP_LANE * lanes + j] = F::ONE;
                }
            }
            Table::Arith => {
                for (i, row) in circuit.arith_rows().iter().enumerate() {
                    let at = (i / lanes) * width + ARITH_PREP_LANE * (i % lanes);
                    for (t, w) in [row.a, row.b, row.c, row.out].into_iter().enumerate() {
                        m[at + t] = wire_id(w);
                    }
                    m[at + 4] = F::ONE;
                }
            }
            Table::Perm => {
                for (r, row) in circuit.perm_rows().iter().enumerate() {
                    for i in 0..WIDTH {
                        m[r * width + i] = wire_id(row.input[i]);
                        if let Some(w) = row.output[i] {
                            m[r * width + WIDTH + i] = wire_id(w);
                            m[r * width + 2 * WIDTH + i] = F::ONE;
                        }
                    }
                    if let Some(s) = row.swap {
                        m[r * width + 3 * WIDTH] = wire_id(s);
                        m[r * width + 3 * WIDTH + 1] = F::ONE;
                    }
                    m[r * width + 3 * WIDTH + 2] = F::ONE;
                }
            }
            Table::Bits => {
                for (r, row) in circuit.bits_rows().iter().enumerate() {
                    m[r * width] = wire_id(row.x);
                    for i in 0..BITS {
                        if let Some(w) = row.bits[i] {
                            m[r * width + 1 + i] = wire_id(w);
                            m[r * width + 1 + BITS + i] = F::ONE;
                        }
                    }
                    m[r * width + 2 * BITS + 1] = F::ONE;
                }
            }
            Table::Pack => {
                for (r, row) in circuit.pack_rows().iter().enumerate() {
                    m[r * width] = wire_id(row.ext);
                    for k in 0..D {
                        m[r * width + 1 + k] = wire_id(row.coeffs[k]);
                    }
                    m[r * width + 1 + D] = F::ONE;
                }
            }
            Table::Ml(t) => m = crate::mldsa::tables::preprocessed(t, &circuit.ml, height).values,
        }
        airs.push(TableAir {
            table,
            num_publics,
            lanes,
            height,
            preprocessed: Some(Arc::new(RowMajorMatrix::new(m, width))),
        });
    }
    Ok(airs)
}

/// The tables of a circuit with ML-DSA rows: the five of [`table_airs_within`]
/// (with one lane a row when they fit), then the ten ML-DSA tables, each as
/// tall as its rows need, at least the smallest height `fri` allows.
pub(crate) fn table_airs_with_ml(
    circuit: &Circuit,
    fri: &FriShape,
    max_log: usize,
) -> Result<Vec<TableAir>, ProofError> {
    let mut airs = table_airs_within(circuit, fri, max_log)?;
    let num_publics = circuit.publics().len();
    let limit = max_log.min(max_log_height(fri));
    for t in crate::mldsa::tables::ML_TABLES {
        let height = height_for(circuit.ml.entries(t), fri);
        if height.trailing_zeros() as usize > limit {
            return Err(ProofError::Proving);
        }
        let prep = crate::mldsa::tables::preprocessed(t, &circuit.ml, height);
        airs.push(TableAir {
            table: Table::Ml(t),
            num_publics,
            lanes: 1,
            height,
            preprocessed: Some(Arc::new(prep)),
        });
    }
    Ok(airs)
}

/// The main traces of a circuit's tables, from its wire values.
pub(crate) fn table_traces(circuit: &Circuit, airs: &[TableAir]) -> Vec<RowMajorMatrix<F>> {
    let mut reads = vec![0u32; circuit.num_wires()];
    crate::mldsa::tables::count_reads(circuit, &mut reads);
    for row in circuit.arith_rows() {
        for w in [row.a, row.b, row.c, row.out] {
            reads[w.0 as usize] += 1;
        }
    }
    for row in circuit.perm_rows() {
        for w in row.input.iter().chain(row.output.iter().flatten()).chain(row.swap.iter()) {
            reads[w.0 as usize] += 1;
        }
    }
    for row in circuit.bits_rows() {
        reads[row.x.0 as usize] += 1;
        for w in row.bits.iter().flatten() {
            reads[w.0 as usize] += 1;
        }
    }
    for row in circuit.pack_rows() {
        for w in core::iter::once(&row.ext).chain(&row.coeffs) {
            reads[w.0 as usize] += 1;
        }
    }
    let coeffs = |v: EF| -> Vec<F> { coeffs(&v).to_vec() };
    airs.iter()
        .map(|air| {
            let height = air.height();
            if let Table::Ml(t) = air.table {
                return crate::mldsa::tables::trace(t, circuit, height);
            }
            let lanes = air.lanes;
            let width = main_width(air.table, lanes);
            let mut m = vec![F::ZERO; height * width];
            match air.table {
                Table::Wires => {
                    for (w, &n) in reads.iter().enumerate() {
                        let at = (w / lanes) * width + WIRE_LANE * (w % lanes);
                        let wire = super::circuit::Wire(w as u32);
                        m[at..at + D].copy_from_slice(&coeffs(circuit.value(wire)));
                        m[at + D] = F::from_u32(n);
                    }
                }
                Table::Arith => {
                    for (i, row) in circuit.arith_rows().iter().enumerate() {
                        let at = (i / lanes) * width + ARITH_LANE * (i % lanes);
                        for (t, w) in [row.a, row.b, row.c, row.out].into_iter().enumerate() {
                            m[at + t * D..at + (t + 1) * D].copy_from_slice(&coeffs(circuit.value(w)));
                        }
                    }
                }
                Table::Perm => {
                    let rows = circuit.perm_rows();
                    let padding = poseidon2::permute_row([F::ZERO; WIDTH]);
                    for r in 0..height {
                        let row = &mut m[r * width..(r + 1) * width];
                        match rows.get(r) {
                            Some(p) => {
                                let sent: [F; WIDTH] = core::array::from_fn(|i| circuit.base_value(p.input[i]));
                                let swap = p.swap.map_or(F::ZERO, |s| circuit.base_value(s));
                                let mut actual = sent;
                                if swap == F::ONE {
                                    for j in 0..SWAP {
                                        actual.swap(j, j + SWAP);
                                    }
                                }
                                row[..PERM_COLS].copy_from_slice(&poseidon2::permute_row(actual));
                                row[PERM_COLS..PERM_COLS + SENT].copy_from_slice(&sent[..SENT]);
                                row[PERM_COLS + SENT] = swap;
                            }
                            None => row[..PERM_COLS].copy_from_slice(&padding),
                        }
                    }
                }
                Table::Bits => {
                    for (r, row) in circuit.bits_rows().iter().enumerate() {
                        let v = circuit.base_value(row.x).as_canonical_u32();
                        let bits: Vec<F> = (0..BITS).map(|i| F::from_u32((v >> i) & 1)).collect();
                        m[r * width..r * width + BITS].copy_from_slice(&bits);
                        m[r * width + BITS] = bits[27] * bits[28] * bits[29];
                    }
                }
                Table::Pack => {
                    for (r, row) in circuit.pack_rows().iter().enumerate() {
                        for k in 0..D {
                            m[r * width + k] = circuit.base_value(row.coeffs[k]);
                        }
                    }
                }
                Table::Ml(_) => {}
            }
            RowMajorMatrix::new(m, width)
        })
        .collect()
}

/// The public values of each table: the wire table carries the circuit's.
pub(crate) fn table_publics(circuit: &Circuit, airs: &[TableAir]) -> Vec<Vec<F>> {
    airs.iter()
        .map(|air| match air.table {
            Table::Wires => circuit.publics().iter().map(|&w| circuit.base_value(w)).collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// Extended trace degree bits of each table, zero knowledge included.
pub(crate) fn degree_bits(airs: &[TableAir]) -> Vec<usize> {
    airs.iter().map(|a| a.height().trailing_zeros() as usize + 1).collect()
}

/// A circuit's verifier key and the prover's copy of its preprocessed data.
pub(crate) struct CircuitKey {
    pub(crate) airs: Vec<TableAir>,
    pub(crate) prover_data: ProverData<ScaleConfig>,
}

impl CircuitKey {
    pub(crate) fn common(&self) -> &CommonData<ScaleConfig> {
        &self.prover_data.common
    }
}

/// Commit to a circuit's preprocessed columns. The salts of that commitment
/// come from a fixed seed, so anyone rebuilds the same key from the circuit.
pub(crate) fn setup(airs: Vec<TableAir>, fri: &FriShape) -> Result<CircuitKey, ProofError> {
    if airs.iter().any(|a| a.preprocessed.is_none()) {
        return Err(ProofError::Proving);
    }
    let config = layer_config([0; 32], fri, tagged_challenger(&[]))?;
    let prover_data =
        ProverData::from_airs_and_degrees(&config, &airs, &degree_bits(&airs)).map_err(|_| ProofError::Proving)?;
    Ok(CircuitKey { airs, prover_data })
}

/// The lookups the library derives for tables of these shapes: the same as
/// for the committed tables, since they depend on the tables' constraints,
/// not their heights. Derived from all-zero tables of the smallest height.
pub(crate) fn lookups_for(airs: &[TableAir], fri: &FriShape) -> Result<Vec<Lookups<F>>, ProofError> {
    let h = min_height(fri);
    let small: Vec<TableAir> = airs
        .iter()
        .map(|a| {
            let width = preprocessed_width(a.table, a.lanes, a.num_publics);
            TableAir {
                height: h,
                preprocessed: Some(Arc::new(RowMajorMatrix::new(vec![F::ZERO; h * width], width))),
                ..a.clone()
            }
        })
        .collect();
    let config = layer_config([0; 32], fri, tagged_challenger(&[]))?;
    let data =
        ProverData::from_airs_and_degrees(&config, &small, &degree_bits(&small)).map_err(|_| ProofError::Proving)?;
    Ok(data.common.lookups)
}

/// Prove a circuit's tables under a transcript seeded with `tag`.
pub(crate) fn prove(
    key: &CircuitKey,
    circuit: &Circuit,
    fri: &FriShape,
    tag: &[F],
    zk_seed: [u8; 32],
) -> Result<BatchProof<ScaleConfig>, ProofError> {
    let config = layer_config(zk_seed, fri, tagged_challenger(tag))?;
    let traces = table_traces(circuit, &key.airs);
    let publics = table_publics(circuit, &key.airs);
    let trace_refs: Vec<&RowMajorMatrix<F>> = traces.iter().collect();
    let instances = StarkInstance::new_multiple(&key.airs, &trace_refs, &publics);
    prove_batch(&config, &instances, &key.prover_data).map_err(|_| ProofError::Proving)
}

/// Verify a proof of a circuit's tables against its key, the public values
/// and the tag its transcript was seeded with.
pub(crate) fn verify(
    airs: &[TableAir],
    common: &CommonData<ScaleConfig>,
    proof: &BatchProof<ScaleConfig>,
    publics: &[F],
    fri: &FriShape,
    tag: &[F],
) -> Result<(), ProofError> {
    let config = layer_config([0; 32], fri, tagged_challenger(tag))?;
    let public_values: Vec<Vec<F>> = airs
        .iter()
        .map(|a| if a.table == Table::Wires { publics.to_vec() } else { Vec::new() })
        .collect();
    if publics.len() != airs[0].num_publics {
        return Err(ProofError::Rejected);
    }
    if proof.degree_bits != degree_bits(airs) {
        return Err(ProofError::MalformedProof);
    }
    verify_batch(&config, airs, proof, &public_values, common).map_err(|_| ProofError::Rejected)
}

const _: () = assert!(<EF as p3_field::BasedVectorSpace<F>>::DIMENSION == D);
