//! The whole-bundle security write-up, docs/scale/bundle-security.md, against
//! a fresh run.
//!
//! The run has two parts, kept apart in every table:
//!
//! - the pinned library's estimator (`ProvenSecurity`, `ConjecturedSecurity`)
//!   at the real shape of a reveal and of the batch, root and shrink layers,
//!   planned from the real circuits ([`layers::estimate_pipeline`]);
//! - the formulas of the stage 2 design's "Whole-bundle proven security
//!   bound", evaluated at those same shapes, and summed over the bundle.
//!
//! Every table the run produces is printed (run scripts/bundle-security.sh,
//! or this test with `--nocapture`), and the page's tables must equal them
//! row for row. The formula's whole-bundle sum must reach 128 classical and
//! 64 quantum bits.

use std::sync::OnceLock;

use ghost_proofs::layers::{self, LayerShape, PipelineEstimate, ProofEstimate, RevealChild};
use ghost_proofs::{SCALE_CHALLENGE_FIELD_BITS, SCALE_COLLISION_RESISTANCE_BITS, SCALE_DIGEST_BITS};

/// The page this test holds to the run.
const PAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/scale/bundle-security.md");

/// The bundle of the design: one aggregator holding all 3,500 reveals of a
/// block, in batches of 32, one root and one shrink.
const REVEALS: usize = 3_500;
const PER_BATCH: usize = 32;
const BATCHES: usize = REVEALS.div_ceil(PER_BATCH);

/// The requirement: 128 classical bits and NIST Category 1 (64 quantum bits).
const TARGET_CLASSICAL: f64 = 128.0;
const TARGET_QUANTUM: f64 = 64.0;

/// The design's Johnson-regime parameter.
const JOHNSON_M: f64 = 16.0;
/// BabyBear.
const P: f64 = 2_013_265_921.0;

/// Tables of the page written by hand, not produced by the run: the
/// obligations (checked by benchmarks/scale/labels.py --obligations) and the
/// theorems beside each term.
const HAND_WRITTEN: [&str; 2] = ["| Obligation |", "| Term |"];

// --------------------------------------------------------------------------
// The design's formulas.

/// -log2 of the sum of 2^-b: terms added as probabilities.
fn combine(bits: &[f64]) -> f64 {
    let least = bits.iter().copied().fold(f64::INFINITY, f64::min);
    least - bits.iter().map(|b| (least - b).exp2()).sum::<f64>().log2()
}

fn field_bits() -> f64 {
    8.0 * P.log2()
}

/// Proven bits a FRI query, Johnson regime: -log2(sqrt(rho)(1 + 1/(2m))).
fn query_bits(log_blowup: usize) -> f64 {
    log_blowup as f64 / 2.0 - (1.0 + 1.0 / (2.0 * JOHNSON_M)).log2()
}

/// Which constants the proximity term is taken with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Constants {
    /// The design's: `(M - 1)` batched functions and `R` rounds.
    Design,
    /// As Lemma 8.2 of BCIKS states its rounds: `(M - 1/2)` and the sum of
    /// the folding arities (`2R` at arity 2).
    Stated,
}

/// The commit-phase and batching term:
/// `((m + 1/2)^7 / (3 rho^(3/2))) n^2 (M - 1) / |F|` plus
/// `(2m + 1)(n + 1) R / (sqrt(rho) |F|)`.
fn proximity_bits(lde_log: usize, functions: usize, log_blowup: usize, rounds: usize, arity_log: usize, c: Constants) -> f64 {
    let m = JOHNSON_M;
    let rho = (-(log_blowup as f64)).exp2();
    let n = (lde_log as f64).exp2();
    let (batched, folds) = match c {
        Constants::Design => ((functions.max(2) - 1) as f64, rounds as f64),
        Constants::Stated => (functions.max(2) as f64 - 0.5, (rounds << arity_log) as f64),
    };
    let first = (m + 0.5).powi(7) / (3.0 * rho.powf(1.5)) * n * n * batched;
    let second = (2.0 * m + 1.0) * (n + 1.0) * folds / rho.sqrt();
    field_bits() - (first + second).log2()
}

/// One proof's terms under the design's rules: the query term and the
/// proximity term, each with its grinding at half; quantum halves the
/// round-by-round bits and keeps grinding at half.
#[derive(Clone, Copy, Debug)]
struct Terms {
    query_classical: f64,
    proximity_classical: f64,
    classical: f64,
    quantum: f64,
}

fn terms_at(
    lde_log: usize,
    functions: usize,
    queries: usize,
    log_blowup: usize,
    rounds: usize,
    arity_log: usize,
    query_pow: usize,
    batch_pow: usize,
    c: Constants,
) -> Terms {
    let q = queries as f64 * query_bits(log_blowup);
    let prox = proximity_bits(lde_log, functions, log_blowup, rounds, arity_log, c);
    let (g, b) = (query_pow as f64 / 2.0, batch_pow as f64 / 2.0);
    Terms {
        query_classical: q + g,
        proximity_classical: prox + b,
        classical: combine(&[q + g, prox + b]),
        quantum: combine(&[q / 2.0 + g, prox / 2.0 + b]),
    }
}

fn terms(e: &ProofEstimate, c: Constants) -> Terms {
    terms_at(
        e.lde_log(),
        e.num_batched_functions,
        e.num_queries,
        e.log_blowup,
        e.fri_rounds(),
        e.max_log_arity,
        e.query_pow_bits,
        e.batch_pow_bits,
        c,
    )
}

/// The digest's terms, counted once: half its bits classically, a third of
/// them against a quantum attacker (ePrint 2019/834 as the design uses it).
fn digest_terms() -> (f64, f64) {
    let d = SCALE_DIGEST_BITS as f64;
    (d / 2.0, d / 3.0)
}

// --------------------------------------------------------------------------
// The run.

struct Run {
    leaf: ProofEstimate,
    layers: PipelineEstimate,
}

impl Run {
    /// Each proof of the bundle with its name and its count.
    fn proofs(&self) -> [(&'static str, usize, &ProofEstimate); 4] {
        [
            ("leaf, a reveal", REVEALS, &self.leaf),
            ("batch", BATCHES, &self.layers.batch),
            ("root", 1, &self.layers.root),
            ("shrink", 1, &self.layers.shrink),
        ]
    }

    fn total_proofs(&self) -> usize {
        self.proofs().iter().map(|p| p.1).sum()
    }

    /// The formula's whole-bundle sum, classical and quantum.
    fn bundle(&self, c: Constants) -> (f64, f64) {
        let (dc, dq) = digest_terms();
        let mut classical = vec![dc];
        let mut quantum = vec![dq];
        for (_, count, e) in self.proofs() {
            let t = terms(e, c);
            classical.push(t.classical - (count as f64).log2());
            quantum.push(t.quantum - (count as f64).log2());
        }
        (combine(&classical), combine(&quantum))
    }

    /// The library's proven figures added over the bundle the same way, the
    /// quantum figure half the proven one (the crate's convention). Capped,
    /// each figure already holds the collision term; uncapped, the digest's
    /// terms are added once, as the formula adds them.
    fn library_bundle(&self, capped: bool) -> (f64, f64) {
        let (mut classical, mut quantum) = if capped {
            (Vec::new(), Vec::new())
        } else {
            let (dc, dq) = digest_terms();
            (vec![dc], vec![dq])
        };
        for (_, count, e) in self.proofs() {
            let bits = if capped { e.proven_bits_half_grinding } else { e.proven_bits_uncapped };
            classical.push(bits as f64 - (count as f64).log2());
            quantum.push((bits / 2) as f64 - (count as f64).log2());
        }
        (combine(&classical), combine(&quantum))
    }
}

fn run() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| {
        let leaf = layers::reveal_estimate().expect("the estimator runs on the reveal");
        let child = RevealChild::new(LayerShape::WIDE.num_queries);
        let layers = layers::estimate_pipeline(
            &child,
            LayerShape::WIDE,
            child.log_height(),
            PER_BATCH,
            BATCHES,
            LayerShape::WIDE,
            LayerShape::SHRINK,
        )
        .expect("the real pipeline plans");
        Run { leaf, layers }
    })
}

// --------------------------------------------------------------------------
// The tables.

fn thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn below(library: f64, formula: f64) -> String {
    if library < formula { format!("yes, by {:.2} bits", formula - library) } else { "no".to_string() }
}

fn tables(r: &Run) -> Vec<Vec<String>> {
    let mut shapes = vec![
        "| Proof (measured: the shapes of the built circuits, as the estimator takes them) | Proofs in the bundle | Log blowup, queries, grinding on queries and batching | Tables | Degree bits | FRI rounds | Constraints | Largest constraint degree | Quotient chunks | Batched functions |".to_string(),
        "|---|---|---|---|---|---|---|---|---|---|".to_string(),
    ];
    for (name, count, e) in r.proofs() {
        shapes.push(format!(
            "| {name} (measured) | {} | {}, {}, {} and {} | {} | {} | {} | {} | {} | {} | {} |",
            thousands(count),
            e.log_blowup,
            e.num_queries,
            e.query_pow_bits,
            e.batch_pow_bits,
            e.tables,
            e.degree_bits,
            e.fri_rounds(),
            thousands(e.num_constraints),
            e.max_constraint_degree,
            e.num_quotient_chunks,
            thousands(e.num_batched_functions),
        ));
    }

    let mut estimator = vec![
        "| Proof (measured: the pinned estimator's output, whole bits) | Conjectured | Conjectured, grinding at half | Proven, unique decoding | Proven, list decoding | Proven, the library's figure | Proven, grinding at half | Proven, grinding at half, collision cap lifted | The same, field three bits smaller |".to_string(),
        "|---|---|---|---|---|---|---|---|---|".to_string(),
    ];
    for (name, _, e) in r.proofs() {
        estimator.push(format!(
            "| {name} (measured) | {} | {} | {} | {} | {} | {} | {} | {} |",
            e.conjectured_bits,
            e.conjectured_bits_half_grinding,
            e.proven_unique_decoding_bits,
            e.proven_list_decoding_bits,
            e.proven_bits,
            e.proven_bits_half_grinding,
            e.proven_bits_uncapped,
            e.proven_bits_uncapped_field_less_3,
        ));
    }

    let mut formula = vec![
        "| Proof (modeled: the design's formulas at the measured shapes) | Proofs in the bundle | Query term, classical | Proximity term, classical | Classical bits each | Quantum bits each |".to_string(),
        "|---|---|---|---|---|---|".to_string(),
    ];
    for (name, count, e) in r.proofs() {
        let t = terms(e, Constants::Design);
        formula.push(format!(
            "| {name} (modeled) | {} | {:.2} | {:.2} | {:.2} | {:.2} |",
            thousands(count),
            t.query_classical,
            t.proximity_classical,
            t.classical,
            t.quantum
        ));
    }
    let (dc, dq) = digest_terms();
    formula.push(format!(
        "| Poseidon2 digest of {SCALE_DIGEST_BITS} bits, counted once (modeled) | 1 | | | {dc:.2} | {dq:.2} |"
    ));
    let (bc, bq) = r.bundle(Constants::Design);
    formula.push(format!(
        "| Whole bundle, {} proofs (modeled) | | | | {bc:.2} | {bq:.2} |",
        thousands(r.total_proofs())
    ));
    let (sc, sq) = r.bundle(Constants::Stated);
    formula.push(format!(
        "| Whole bundle, the round terms as Lemma 8.2 of BCIKS states them (modeled) | | | | {sc:.2} | {sq:.2} |"
    ));

    let mut compare = vec![
        "| Figure (measured: the library; modeled: the formula) | The library's proven figure, grinding at half | The design's formula | The library's figure below the formula |".to_string(),
        "|---|---|---|---|".to_string(),
    ];
    for (name, _, e) in r.proofs() {
        let t = terms(e, Constants::Design);
        for (how, bits) in [("as the library caps it", e.proven_bits_half_grinding), ("collision cap lifted", e.proven_bits_uncapped)] {
            let (lc, lq) = (bits as f64, (bits / 2) as f64);
            compare.push(format!(
                "| {name}, classical, {how} (measured and modeled) | {lc:.2} | {:.2} | {} |",
                t.classical,
                below(lc, t.classical)
            ));
            compare.push(format!(
                "| {name}, quantum, {how} (measured and modeled) | {lq:.2} | {:.2} | {} |",
                t.quantum,
                below(lq, t.quantum)
            ));
        }
    }
    for (how, capped) in [("each proof as the library caps it", true), ("collision cap lifted, the digest once", false)] {
        let (lc, lq) = r.library_bundle(capped);
        compare.push(format!(
            "| Whole bundle, classical, {how} (measured and modeled) | {lc:.2} | {bc:.2} | {} |",
            below(lc, bc)
        ));
        compare.push(format!(
            "| Whole bundle, quantum, {how} (measured and modeled) | {lq:.2} | {bq:.2} | {} |",
            below(lq, bq)
        ));
    }

    vec![shapes, estimator, formula, compare]
}

// --------------------------------------------------------------------------
// The page against the run.

/// The tables of a markdown text: runs of lines starting with `|`.
fn tables_of(text: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with('|') {
            cur.push(line.trim().to_string());
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Every table of the run is on the page with exactly the same rows, and
/// every table of the page is either one of the run's or a hand-written one.
fn compare(page: &str, run: &[Vec<String>]) -> Result<(), String> {
    let on_page = tables_of(page);
    for table in run {
        let header = &table[0];
        let Some(found) = on_page.iter().find(|t| &t[0] == header) else {
            return Err(format!("the page lacks the table {header}"));
        };
        for (i, row) in table.iter().enumerate() {
            match found.get(i) {
                Some(r) if r == row => {}
                Some(r) => return Err(format!("row {i} of {header} differs:\n run:  {row}\n page: {r}")),
                None => return Err(format!("the page lacks row {i} of {header}: {row}")),
            }
        }
        if found.len() > table.len() {
            return Err(format!("the page has a row the run does not: {}", found[table.len()]));
        }
    }
    for t in &on_page {
        let ours = run.iter().any(|r| r[0] == t[0]);
        let hand = HAND_WRITTEN.iter().any(|h| t[0].starts_with(h));
        if !ours && !hand {
            return Err(format!("a table the run does not produce: {}", t[0]));
        }
    }
    Ok(())
}

/// The run, printed table by table, then held to the page.
#[test]
fn the_page_matches_the_estimator_run() {
    let r = run();
    let produced = tables(r);
    for table in &produced {
        println!();
        for row in table {
            println!("{row}");
        }
    }
    println!();
    let page = std::fs::read_to_string(PAGE).expect("docs/scale/bundle-security.md exists");
    if let Err(e) = compare(&page, &produced) {
        panic!("docs/scale/bundle-security.md differs from the run: {e}");
    }
}

/// The formula's whole-bundle sum reaches the requirement at the real
/// shapes, with the design's constants and with Lemma 8.2's.
#[test]
fn the_whole_bundle_sum_meets_128_classical_and_64_quantum_bits() {
    let r = run();
    for c in [Constants::Design, Constants::Stated] {
        let (classical, quantum) = r.bundle(c);
        assert!(classical >= TARGET_CLASSICAL, "classical {classical:.2} below 128");
        assert!(quantum >= TARGET_QUANTUM, "quantum {quantum:.2} below 64");
    }
}

/// The estimates are at the parameters of the prover and the layers: the
/// scale configuration's field, digest and grinding, blowup 2^3 with 96
/// queries for the reveal, batch and root, 2^5 with 56 for the shrink, and
/// the heights the plan gives each layer.
#[test]
fn the_estimates_are_at_the_real_parameters() {
    let r = run();
    for (_, _, e) in r.proofs() {
        assert_eq!((e.challenge_field_bits, e.collision_resistance_bits), (SCALE_CHALLENGE_FIELD_BITS, SCALE_COLLISION_RESISTANCE_BITS));
        assert_eq!((e.query_pow_bits, e.batch_pow_bits), (16, 16));
        assert_eq!((e.log_final_poly_len, e.max_log_arity), (0, 1));
        // The cap only lowers a figure, and a smaller field cannot raise one.
        assert!(e.proven_bits <= e.collision_resistance_bits, "{e:?}");
        assert!(e.proven_bits_half_grinding <= e.proven_bits, "{e:?}");
        assert!(e.proven_bits_half_grinding <= e.proven_bits_uncapped, "{e:?}");
        assert!(e.proven_bits_uncapped_field_less_3 <= e.proven_bits_uncapped, "{e:?}");
        assert!(e.proven_bits_uncapped < layers::UNCAPPED_COLLISION_BITS, "{e:?}");
    }
    let wide = (LayerShape::WIDE.log_blowup, LayerShape::WIDE.num_queries);
    let shrink = (LayerShape::SHRINK.log_blowup, LayerShape::SHRINK.num_queries);
    assert_eq!(wide, (3, 96));
    assert_eq!(shrink, (5, 56));
    assert_eq!((r.leaf.log_blowup, r.leaf.num_queries, r.leaf.tables), (3, 96, 1));
    assert_eq!((r.layers.batch.log_blowup, r.layers.batch.num_queries), wide);
    assert_eq!((r.layers.root.log_blowup, r.layers.root.num_queries), wide);
    assert_eq!((r.layers.shrink.log_blowup, r.layers.shrink.num_queries), shrink);
    let plan = &r.layers.plan;
    for (layer, e) in [(&plan.batch, &r.layers.batch), (&plan.root, &r.layers.root), (&plan.shrink, &r.layers.shrink)] {
        assert_eq!(e.tables, layer.heights.len());
        let tallest = layer.heights.iter().copied().max().unwrap();
        assert_eq!(e.degree_bits, tallest.trailing_zeros() as usize + 1);
        // Every table's main and preprocessed columns are batched at least
        // once: more functions than the widest table has lanes.
        assert!(e.num_batched_functions > layer.lanes.iter().sum::<usize>(), "{e:?}");
    }
    // The reveal: 2,048 rows doubled for zero knowledge.
    assert_eq!(r.leaf.degree_bits, 12);
    assert_eq!(BATCHES, 110);
    assert_eq!(r.total_proofs(), 3_612);
}

/// The leaf's estimate is the scale gate's: the same parameters give the
/// same figures as `scale_coin_reveal_v2_estimate`.
#[test]
fn the_leaf_estimate_is_the_scale_gates() {
    let r = run();
    let gate = ghost_proofs::scale_coin_reveal_v2_estimate().expect("the scale gate passes");
    assert_eq!(r.leaf.conjectured_bits, gate.conjectured_bits);
    assert_eq!(r.leaf.conjectured_bits_half_grinding, gate.conjectured_bits_half_grinding);
    assert_eq!(r.leaf.proven_bits, gate.proven_bits);
}

/// The formula is the design's: at the design's modeled leaf (a codeword of
/// 2^15, 7,716 functions, 12 rounds) it gives the design's 147.74 classical
/// and 77.87 quantum bits.
#[test]
fn the_formula_reproduces_the_designs_leaf_row() {
    let t = terms_at(15, 7_716, 96, 3, 12, 1, 16, 16, Constants::Design);
    assert_eq!(format!("{:.2} {:.2}", t.classical, t.quantum), "147.74 77.87");
    // Lemma 8.2's stated round terms can only cost bits.
    let s = terms_at(15, 7_716, 96, 3, 12, 1, 16, 16, Constants::Stated);
    assert!(s.proximity_classical < t.proximity_classical);
    // The sum adds probabilities: two equal terms lose one bit.
    assert!((combine(&[100.0, 100.0]) - 99.0).abs() < 1e-12);
}

/// The comparison fails on a changed, missing or extra row, a missing
/// table and a table the run does not produce, and passes on the same page.
#[test]
fn a_page_that_differs_from_the_run_is_refused() {
    let run = vec![vec!["| A (modeled) | x |".to_string(), "|---|---|".to_string(), "| a (modeled) | 1 |".to_string()]];
    let good = "# T\n\n| A (modeled) | x |\n|---|---|\n| a (modeled) | 1 |\n\n| Obligation | Status |\n|---|---|\n";
    assert_eq!(compare(good, &run), Ok(()));
    let changed = good.replace("| a (modeled) | 1 |", "| a (modeled) | 2 |");
    assert!(compare(&changed, &run).is_err());
    let extra = good.replace("| a (modeled) | 1 |\n", "| a (modeled) | 1 |\n| b (modeled) | 3 |\n");
    assert!(compare(&extra, &run).is_err());
    let missing_row = good.replace("| a (modeled) | 1 |\n", "");
    assert!(compare(&missing_row, &run).is_err());
    assert!(compare("# T\n\nNo tables.\n", &run).is_err());
    let unknown = format!("{good}\n| Other | y |\n|---|---|\n");
    assert!(compare(&unknown, &run).is_err());
}
