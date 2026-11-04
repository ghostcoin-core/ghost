//! The recursion layers of the scale build: batch, root and shrink.

use ghost_proofs::layers::{self, BindingSlots, ChildAir, Claim, LayerShape};
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::{BabyBear, default_babybear_poseidon2_24};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;

type F = BabyBear;

/// Layer proving runs one test at a time to bound memory.
static PROVING: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write a progress line with the process's peak memory to the standard
/// error, uncaptured, so a run killed for memory shows where it was.
fn progress(what: &str) {
    use std::io::Write;
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let peak = status.lines().find(|l| l.starts_with("VmHWM:")).unwrap_or("VmHWM: unknown");
    let _ = writeln!(std::io::stderr(), "PROGRESS {what}: {}", peak.trim());
}

/// Public values of a stand-in child before its own: the binding it was
/// made under (chain identifier, protocol version, statement version).
const BOUND: usize = 11;

/// The binding of the tests' bundles.
const BINDING: layers::Binding = layers::Binding {
    chain_id: *b"testnet1",
    protocol_version: [0, 2],
    statement_version: 2,
};

/// The binding as a stand-in child's first public values.
fn binding_values(b: &layers::Binding) -> Vec<F> {
    let mut out: Vec<F> = b.chain_id.iter().chain(&b.protocol_version).map(|&x| F::from_u8(x)).collect();
    out.push(F::from_u8(b.statement_version));
    out
}

/// The stand-in child AIR: two columns `(a, b)` stepping `(a, b) -> (b, a +
/// b)`, its public values the binding it was made under, then the first row
/// and the last `b`.
struct Fib;

impl ChildAir for Fib {
    fn width(&self) -> usize {
        2
    }

    fn num_public_values(&self) -> usize {
        BOUND + 3
    }

    fn binding_slots(&self) -> BindingSlots {
        BindingSlots::consecutive(0)
    }

    fn eval<AB: AirBuilder<F = BabyBear>>(&self, builder: &mut AB) {
        let main = builder.main();
        let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
        let (next_a, next_b) = (main.next_slice()[0], main.next_slice()[1]);
        let pv = builder.public_values().to_vec();
        builder.when_first_row().assert_eq(a, pv[BOUND]);
        builder.when_first_row().assert_eq(b, pv[BOUND + 1]);
        builder.when_transition().assert_eq(next_a, b);
        builder.when_transition().assert_eq(next_b, a.into() + b.into());
        builder.when_last_row().assert_eq(b, pv[BOUND + 2]);
    }
}

/// A trace of [`Fib`] of `2^log_height` rows from `(a, b)`, with its public
/// values under `binding`.
fn fib_trace_on(binding: &layers::Binding, log_height: usize, a: u32, b: u32) -> (RowMajorMatrix<F>, Vec<F>) {
    let n = 1 << log_height;
    let mut cells = Vec::with_capacity(2 * n);
    let (mut x, mut y) = (F::from_u32(a), F::from_u32(b));
    for _ in 0..n {
        cells.extend([x, y]);
        (x, y) = (y, x + y);
    }
    let last = cells[2 * n - 1];
    let mut publics = binding_values(binding);
    publics.extend([F::from_u32(a), F::from_u32(b), last]);
    (RowMajorMatrix::new(cells, 2), publics)
}

fn fib_trace(log_height: usize, a: u32, b: u32) -> (RowMajorMatrix<F>, Vec<F>) {
    fib_trace_on(&BINDING, log_height, a, b)
}

/// The test shape of every proof below: blowup 2^3 and two queries.
const TEST: LayerShape = LayerShape {
    log_blowup: 3,
    num_queries: 2,
};

/// The shape of the largest batches below: blowup 2^2, enough for the
/// tables' degree-3 constraints, and two queries, to bound proving memory.
const LEAN: LayerShape = LayerShape {
    log_blowup: 2,
    num_queries: 2,
};

/// The smallest child proofs: blowup 2^2 and one query.
const SMALL: LayerShape = LayerShape {
    log_blowup: 2,
    num_queries: 1,
};

/// The permutation table's rows compute the library's width-24 Poseidon2.
#[test]
fn the_permutation_table_computes_the_library_poseidon2() {
    let library = default_babybear_poseidon2_24();
    let mut seed = 0x5eed_u64;
    for _ in 0..16 {
        let input: [u32; 24] = core::array::from_fn(|_| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) as u32 % 0x7800_0001
        });
        let (ours, satisfied) = layers::poseidon2_table_permutation(input);
        let expected = library.permute(input.map(F::from_u32));
        assert_eq!(ours, expected.map(|x| x.as_canonical_u32()));
        assert!(satisfied);
    }
    assert_eq!(layers::POSEIDON2_PERMUTATION_COLUMNS, 450);
}

/// The tables prove and verify a circuit with one lane a row and with the
/// wire and arithmetic tables packed into several.
#[test]
fn the_tables_prove_and_verify_a_circuit() {
    let lanes = layers::table_roundtrip_check().unwrap();
    assert!(lanes[0] > 1 && lanes[1] > 1, "the packed tables take several lanes: {lanes:?}");
}

/// `n` stand-in children over `2^log_height` rows, each with its public
/// values.
fn fib_children(n: usize, log_height: usize) -> Vec<(Vec<u8>, Vec<F>)> {
    fib_children_at(n, log_height, TEST)
}

/// [`fib_children`] proven at `shape`.
fn fib_children_at(n: usize, log_height: usize, shape: LayerShape) -> Vec<(Vec<u8>, Vec<F>)> {
    (0..n)
        .map(|i| {
            let (trace, publics) = fib_trace(log_height, 1 + i as u32, 2 + 3 * i as u32);
            let proof = layers::prove_child(&Fib, trace, &publics, shape, [i as u8; 32]).unwrap();
            (proof, publics)
        })
        .collect()
}

#[test]
fn a_batch_proves_its_children_and_their_order() {
    use std::io::Write;
    let _guard = one_at_a_time();
    let t = std::time::Instant::now();
    let log_height = TEST.min_height().trailing_zeros() as usize;
    let key = layers::batch_key(&Fib, TEST, log_height, 4, TEST).unwrap();
    let t_key = t.elapsed();
    let children = fib_children(3, log_height);
    let t_children = t.elapsed();
    let contents: Vec<Vec<F>> = children.iter().map(|(_, p)| p.clone()).collect();
    let start = layers::START_DIGEST;
    let proof = layers::prove_batch(&key, &Fib, &BINDING, 0, &start, &children, [9; 32]).unwrap();
    let t_proof = t.elapsed();
    let _ = writeln!(
        std::io::stderr(),
        "DIAG key {t_key:?} children {t_children:?} proof {t_proof:?} heights {:?} bytes {}",
        key.table_heights(),
        proof.len()
    );
    layers::verify_batch(&key, &BINDING, 0, &start, &contents, &proof).unwrap();
    let mut swapped = contents.clone();
    swapped.swap(0, 1);
    assert!(layers::verify_batch(&key, &BINDING, 0, &start, &swapped, &proof).is_err());
    assert!(layers::verify_batch(&key, &BINDING, 0, &start, &contents[..2], &proof).is_err());
    assert!(layers::verify_batch(&key, &BINDING, 1, &start, &contents, &proof).is_err());
}

/// Another stand-in: the same width and public values as [`Fib`], stepping
/// `(a, b) -> (b, a + 2b)`. Its verifier key differs from [`Fib`]'s.
struct Pell;

impl ChildAir for Pell {
    fn width(&self) -> usize {
        2
    }

    fn num_public_values(&self) -> usize {
        BOUND + 3
    }

    fn binding_slots(&self) -> BindingSlots {
        BindingSlots::consecutive(0)
    }

    fn eval<AB: AirBuilder<F = BabyBear>>(&self, builder: &mut AB) {
        let main = builder.main();
        let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
        let (next_a, next_b) = (main.next_slice()[0], main.next_slice()[1]);
        let pv = builder.public_values().to_vec();
        builder.when_first_row().assert_eq(a, pv[BOUND]);
        builder.when_first_row().assert_eq(b, pv[BOUND + 1]);
        builder.when_transition().assert_eq(next_a, b);
        builder.when_transition().assert_eq(next_b, a.into() + b.into() + b.into());
        builder.when_last_row().assert_eq(b, pv[BOUND + 2]);
    }
}

fn pell_child(log_height: usize) -> (Vec<u8>, Vec<F>) {
    let n = 1 << log_height;
    let mut cells = Vec::with_capacity(2 * n);
    let (mut x, mut y) = (F::ONE, F::TWO);
    for _ in 0..n {
        cells.extend([x, y]);
        (x, y) = (y, x + y + y);
    }
    let mut publics = binding_values(&BINDING);
    publics.extend([F::ONE, F::TWO, cells[2 * n - 1]]);
    let proof = layers::prove_child(&Pell, RowMajorMatrix::new(cells, 2), &publics, TEST, [77; 32]).unwrap();
    (proof, publics)
}

/// A batch proof is bound to the chain, the protocol and statement versions,
/// its index and its children's verifier key: changing any one of them, or
/// slipping in a child made under another key, fails verification. A child
/// made on another chain or under other versions is refused inside the
/// circuit: its own public values name them, and they must equal the
/// batch's binding.
#[test]
fn a_batch_is_bound_to_its_binding_and_its_childrens_key() {
    let _guard = one_at_a_time();
    let log_height = TEST.min_height().trailing_zeros() as usize;
    let key = layers::batch_key(&Fib, TEST, log_height, 2, TEST).unwrap();
    let children = fib_children(2, log_height);
    let contents: Vec<Vec<F>> = children.iter().map(|(_, p)| p.clone()).collect();
    let start = layers::START_DIGEST;
    let proof = layers::prove_batch(&key, &Fib, &BINDING, 0, &start, &children, [5; 32]).unwrap();
    layers::verify_batch(&key, &BINDING, 0, &start, &contents, &proof).unwrap();

    let other_chain = layers::Binding {
        chain_id: *b"testnet2",
        ..BINDING
    };
    let other_protocol = layers::Binding {
        protocol_version: [0, 3],
        ..BINDING
    };
    let other_statement = layers::Binding {
        statement_version: 3,
        ..BINDING
    };
    for binding in [other_chain, other_protocol, other_statement] {
        assert!(layers::verify_batch(&key, &binding, 0, &start, &contents, &proof).is_err(), "{binding:?}");
    }

    // A child made under another chain or other versions, batched with an
    // honest one under this binding: refused by the honest prover, and
    // refused by the verifier when proven anyway under this binding's tag.
    for binding in [other_chain, other_protocol, other_statement] {
        let (trace, publics) = fib_trace_on(&binding, log_height, 1, 2);
        let foreign = (layers::prove_child(&Fib, trace, &publics, TEST, [11; 32]).unwrap(), publics);
        layers::verify_child(&Fib, &foreign.1, &foreign.0, TEST).unwrap();
        let mixed = vec![children[0].clone(), foreign.clone()];
        let mixed_contents = vec![contents[0].clone(), foreign.1.clone()];
        assert_eq!(
            layers::prove_batch(&key, &Fib, &BINDING, 0, &start, &mixed, [12; 32]),
            Err(ghost_proofs::ProofError::Rejected),
            "{binding:?}"
        );
        if binding == other_chain {
            let tag = key.tag(&BINDING, 0);
            let forged = layers::prove_batch_unchecked(&key, &Fib, &tag, &start, &mixed, [12; 32]).unwrap();
            assert!(layers::verify_batch(&key, &BINDING, 0, &start, &mixed_contents, &forged).is_err());
            assert!(layers::verify_batch(&key, &other_chain, 0, &start, &mixed_contents, &forged).is_err());
        }
    }

    // A proof made under a tag naming another children's key is refused.
    let mut tag = key.tag(&BINDING, 0);
    tag.child_key[0] ^= 1;
    let forged = layers::prove_batch_unchecked(&key, &Fib, &tag, &start, &children, [6; 32]).unwrap();
    assert!(layers::verify_batch(&key, &BINDING, 0, &start, &contents, &forged).is_err());

    // A child proven under another verifier key: another AIR, then another
    // shape. The honest prover refuses both; proven anyway, the batch fails.
    let pell = pell_child(log_height);
    let mixed = vec![children[0].clone(), pell.clone()];
    let mixed_contents = vec![contents[0].clone(), pell.1.clone()];
    assert!(layers::prove_batch(&key, &Fib, &BINDING, 0, &start, &mixed, [7; 32]).is_err());
    let tag = key.tag(&BINDING, 0);
    let forged = layers::prove_batch_unchecked(&key, &Fib, &tag, &start, &mixed, [7; 32]).unwrap();
    assert!(layers::verify_batch(&key, &BINDING, 0, &start, &mixed_contents, &forged).is_err());
    let pell_key = layers::batch_key(&Pell, TEST, log_height, 2, TEST).unwrap();
    assert_ne!(pell_key.child_key(), key.child_key());

    let wider = LayerShape {
        log_blowup: 4,
        num_queries: 2,
    };
    let (trace, publics) = fib_trace(log_height, 1, 2);
    let other_shape = layers::prove_child(&Fib, trace, &publics, wider, [8; 32]).unwrap();
    let mixed = vec![children[0].clone(), (other_shape, publics)];
    assert!(layers::prove_batch(&key, &Fib, &BINDING, 0, &start, &mixed, [8; 32]).is_err());
}

/// A bundle of 32 stand-in children verifies, and a changed, reordered,
/// added or dropped child fails verification.
#[test]
fn a_bundle_of_32_verifies_and_its_contents_are_fixed() {
    let _guard = one_at_a_time();
    // The 32 children are small proofs (blowup 2^2, one query) and the batch
    // is proven at blowup 2^2, enough for its tables' degree-3 constraints,
    // so the 32-slot circuit proves within the 6 GiB of a test sandbox.
    let log_height = SMALL.min_height().trailing_zeros() as usize;
    progress("bundle of 32: start");
    let key = layers::batch_key(&Fib, SMALL, log_height, 32, LEAN).unwrap();
    progress(&format!("bundle of 32: key, table heights {:?}", key.table_heights()));
    assert_eq!(key.capacity(), 32);
    let children = fib_children_at(32, log_height, SMALL);
    let contents: Vec<Vec<F>> = children.iter().map(|(_, p)| p.clone()).collect();
    let start = layers::START_DIGEST;
    let proof = layers::prove_batch(&key, &Fib, &BINDING, 3, &start, &children, [4; 32]).unwrap();
    progress("bundle of 32: proven");
    layers::verify_batch(&key, &BINDING, 3, &start, &contents, &proof).unwrap();
    assert_eq!(
        layers::batch_public_values(&BINDING, &start, &contents).last(),
        Some(&F::from_u32(32)),
        "the batch exposes its count"
    );

    let mut reordered = contents.clone();
    reordered.swap(7, 21);
    assert!(layers::verify_batch(&key, &BINDING, 3, &start, &reordered, &proof).is_err());
    let mut dropped = contents.clone();
    dropped.remove(12);
    assert!(layers::verify_batch(&key, &BINDING, 3, &start, &dropped, &proof).is_err());
    let mut added = contents.clone();
    added.push(contents[0].clone());
    assert!(layers::verify_batch(&key, &BINDING, 3, &start, &added, &proof).is_err());
    let mut changed = contents.clone();
    changed[30][BOUND + 2] += F::ONE;
    assert!(layers::verify_batch(&key, &BINDING, 3, &start, &changed, &proof).is_err());
    let other_start = layers::running_digest(&start, &contents[..1]);
    assert!(layers::verify_batch(&key, &BINDING, 3, &other_start, &contents, &proof).is_err());
}

/// A prover that claims a changed child, a child dropped or one added, and
/// proves the circuit anyway, is refused against what it claimed.
#[test]
fn a_batch_claiming_other_children_than_it_verified_fails() {
    let _guard = one_at_a_time();
    let log_height = TEST.min_height().trailing_zeros() as usize;
    let key = layers::batch_key(&Fib, TEST, log_height, 3, TEST).unwrap();
    let children = fib_children(3, log_height);
    let start = layers::START_DIGEST;
    let tag = key.tag(&BINDING, 0);
    let mut changed = children.clone();
    changed[1].1[BOUND + 2] += F::ONE;
    let changed_contents: Vec<Vec<F>> = changed.iter().map(|(_, p)| p.clone()).collect();
    let forged = layers::prove_batch_unchecked(&key, &Fib, &tag, &start, &changed, [2; 32]).unwrap();
    assert!(layers::verify_batch(&key, &BINDING, 0, &start, &changed_contents, &forged).is_err());
}

/// A batch of one real version 2 coin reveal verifies, and a changed reveal
/// fails verification. A real reveal made on testnet2, batched under a
/// testnet1 binding, is refused: by the honest prover, and, proven anyway,
/// by the verifier under the testnet1 tag.
#[test]
fn a_bundle_of_one_real_reveal_verifies() {
    use ghost_proofs::*;
    let _guard = one_at_a_time();
    let shape = ScaleShape {
        num_queries: TEST.num_queries,
        digest_elems: 9,
    };
    let params = ChainParams {
        chain_id: *b"testnet1",
        version: PROTOCOL_VERSION_2,
        domain: [0x47; 32],
    };
    progress("bundle of one reveal: start");
    let (tx, proof) = reveal_fixture::prove(&params, shape);
    verify_coin_reveal_v2_scale_shaped(&params, &tx, &proof, shape).unwrap();
    progress("bundle of one reveal: reveal proven");
    let child = layers::RevealChild::new(TEST.num_queries);
    let publics = layers::RevealChild::public_values(&params, &tx);
    let binding = layers::Binding::of(&params);
    assert_eq!(binding.chain_id, *b"testnet1");
    let key = layers::batch_key(&child, TEST, child.log_height(), 1, LEAN).unwrap();
    progress(&format!("bundle of one reveal: key, table heights {:?}", key.table_heights()));
    let start = layers::START_DIGEST;
    let children = vec![(proof.as_bytes().to_vec(), publics.clone())];
    let batch = layers::prove_batch(&key, &child, &binding, 0, &start, &children, [3; 32]).unwrap();
    progress("bundle of one reveal: proven");
    layers::verify_batch(&key, &binding, 0, &start, &[publics.clone()], &batch).unwrap();

    let mut other = tx.clone();
    other.fee[31] ^= 1;
    let changed = layers::RevealChild::public_values(&params, &other);
    assert_ne!(changed, publics);
    assert!(layers::verify_batch(&key, &binding, 0, &start, &[changed], &batch).is_err());
    let other_chain = ChainParams {
        chain_id: *b"testnet2",
        ..params
    };
    let elsewhere = layers::RevealChild::public_values(&other_chain, &tx);
    assert!(layers::verify_batch(&key, &binding, 0, &start, &[elsewhere], &batch).is_err());

    // A real reveal proven on testnet2, with its own public values, batched
    // under the testnet1 binding.
    let (tx2, proof2) = reveal_fixture::prove(&other_chain, shape);
    verify_coin_reveal_v2_scale_shaped(&other_chain, &tx2, &proof2, shape).unwrap();
    let publics2 = layers::RevealChild::public_values(&other_chain, &tx2);
    let foreign = vec![(proof2.as_bytes().to_vec(), publics2.clone())];
    assert_eq!(
        layers::prove_batch(&key, &child, &binding, 0, &start, &foreign, [13; 32]),
        Err(ProofError::Rejected),
        "the honest prover refuses a testnet2 reveal under a testnet1 binding"
    );
    progress("bundle of one reveal: testnet2 reveal refused");
    let tag = key.tag(&binding, 0);
    let forged = layers::prove_batch_unchecked(&key, &child, &tag, &start, &foreign, [13; 32]).unwrap();
    progress("bundle of one reveal: testnet2 reveal proven anyway");
    assert!(layers::verify_batch(&key, &binding, 0, &start, &[publics2.clone()], &forged).is_err());
    let binding2 = layers::Binding::of(&other_chain);
    assert!(layers::verify_batch(&key, &binding2, 0, &start, &[publics2], &forged).is_err());
}

mod reveal_fixture {
    use ghost_proofs::*;

    fn path() -> [[u8; 32]; TREE_DEPTH] {
        let mut path = [[0u8; 32]; TREE_DEPTH];
        let mut empty = empty_leaf();
        for (level, sibling) in path.iter_mut().enumerate() {
            *sibling = empty;
            empty = tree_node(Tree::Coin, level as u8, &empty, &empty);
        }
        path[0] = [9; 32];
        path
    }

    /// A plain salted coin of 1,000,000 at position 5, revealed for 600,000
    /// and a fee of 21, proven at `shape`.
    pub fn prove(params: &ChainParams, shape: ScaleShape) -> (CoinRevealV2, Proof) {
        let o = SaltedCoinOpening {
            s: [1; 32],
            r: [2; 32],
            b: [3; 32],
            salt: [0xa5; SALT_BYTES],
            v: amount_word(1_000_000),
            position: 5,
            path: path(),
        };
        let remainder = SaltedCoinRemainder {
            s: [1; 32],
            r: [2; 32],
            b: [4; 32],
            salt: [0x3c; SALT_BYTES],
            v: amount_word(1_000_000 - 600_000 - 21),
        };
        let leaf = coin_commitment_v2(&coin_fingerprint_v2(&o.s, &o.r, &o.b, &o.salt, &EMPTY_RULE), &o.v);
        let request = CoinRevealV2Request {
            root: merkle_root(Tree::Coin, &leaf, o.position, &o.path),
            recipient: [0x11; 20],
            out: amount_word(600_000),
            fee: amount_word(21),
            remainder_note: [0x33; NOTE_V3_BYTES],
        };
        prove_coin_reveal_v2_scale_shaped(
            params,
            &o,
            &InputRule::plain(),
            &remainder,
            &EMPTY_RULE,
            &request,
            [0x6c; 32],
            shape,
        )
        .expect("an honest reveal proves")
    }
}

/// The cost of one width-24 Poseidon2 permutation of the pinned library on
/// one core of the machine the tests run on, written to the standard error.
#[test]
fn time_one_poseidon2_permutation() {
    use std::io::Write;
    // No layer proves while the permutation is timed.
    let _guard = one_at_a_time();
    let perm = default_babybear_poseidon2_24();
    let mut state = [F::ONE; 24];
    for _ in 0..10_000 {
        perm.permute_mut(&mut state);
    }
    let n = 1_000_000u32;
    let t = std::time::Instant::now();
    for _ in 0..n {
        perm.permute_mut(std::hint::black_box(&mut state));
    }
    let ns = t.elapsed().as_nanos() as f64 / f64::from(n);
    let _ = writeln!(std::io::stderr(), "MEASURED poseidon2 ns per permutation {ns:.1} ({:?})", state[0]);
    assert!(ns > 0.0);
}

#[test]
fn a_child_proof_verifies_inside_a_circuit() {
    let log_height = TEST.min_height().trailing_zeros() as usize;
    let (trace, publics) = fib_trace(log_height, 1, 2);
    let proof = layers::prove_child(&Fib, trace, &publics, TEST, [1; 32]).unwrap();
    layers::verify_child(&Fib, &publics, &proof, TEST).unwrap();
    let rows = layers::child_in_circuit_check(&Fib, &publics, &proof, TEST, log_height, 0).unwrap();
    assert!(rows.0 > 0 && rows.1 > 0);
    let mut changed = publics.clone();
    changed[BOUND + 2] += F::ONE;
    assert!(layers::child_in_circuit_check(&Fib, &changed, &proof, TEST, log_height, 0).is_err());
    // An opened row, the final polynomial, an opened trace value, a folding
    // sibling and a quotient chunk: changing any one breaks the circuit.
    for part in 1..=5 {
        let outcome = layers::child_in_circuit_check(&Fib, &publics, &proof, TEST, log_height, part);
        assert!(outcome.is_err(), "change {part} went unnoticed");
    }
}

/// Two batches of two stand-in children each, a root over both (its wire
/// and arithmetic tables packed into several lanes) and a shrink of the
/// root: each verifies against the claim a node computes from the four
/// reveals in order, and nothing else. The batch proof verifies inside the
/// root's circuit, and a changed part of it breaks that circuit. The shrink
/// proof fits the 1,310,720-byte proof field and the size bound its key
/// gives, as do the batch and root proofs theirs.
#[test]
fn a_root_and_a_shrink_prove_an_aggregators_batches() {
    use std::io::Write;
    let _guard = one_at_a_time();
    let log_height = SMALL.min_height().trailing_zeros() as usize;
    let start = layers::START_DIGEST;
    let batch_key = layers::batch_key(&Fib, SMALL, log_height, 2, LEAN).unwrap();
    let children = fib_children_at(4, log_height, SMALL);
    let contents: Vec<Vec<F>> = children.iter().map(|(_, p)| p.clone()).collect();
    let claim0 = Claim::of(&start, &contents[..2]);
    let claim1 = Claim::of(&claim0.end, &contents[2..]);
    let whole = Claim::of(&start, &contents);
    assert_eq!(Claim::joined(&[claim0, claim1]), Some(whole));
    let b0 = layers::prove_batch(&batch_key, &Fib, &BINDING, 0, &start, &children[..2], [21; 32]).unwrap();
    let b1 = layers::prove_batch(&batch_key, &Fib, &BINDING, 1, &claim0.end, &children[2..], [22; 32]).unwrap();
    layers::verify_batch(&batch_key, &BINDING, 1, &claim0.end, &contents[2..], &b1).unwrap();
    progress(&format!("pipeline: batches, table heights {:?}", batch_key.table_heights()));

    // The in-circuit verifier of a batch proof, alone.
    layers::layer_in_circuit_check(&batch_key, &BINDING, 0, &claim0, &b0, 0).unwrap();
    for part in 1..=6 {
        let outcome = layers::layer_in_circuit_check(&batch_key, &BINDING, 0, &claim0, &b0, part);
        assert!(outcome.is_err(), "change {part} of a batch proof went unnoticed");
    }
    assert!(layers::layer_in_circuit_check(&batch_key, &BINDING, 1, &claim0, &b0, 0).is_err());
    assert!(layers::layer_in_circuit_check(&batch_key, &BINDING, 0, &claim1, &b0, 0).is_err());
    let other_chain = layers::Binding {
        chain_id: *b"testnet2",
        ..BINDING
    };
    assert!(layers::layer_in_circuit_check(&batch_key, &other_chain, 0, &claim0, &b0, 0).is_err());

    // The root, its tables packed into lanes of at most 2^15 rows.
    let root_key = layers::root_key_within(&batch_key, 2, LEAN, 15).unwrap();
    let lanes = root_key.table_lanes();
    assert!(lanes[0] > 1, "the root's wire table is packed: {lanes:?}");
    assert!(layers::derived_lookups_match(&root_key));
    assert!(layers::derived_lookups_match(&batch_key));
    progress(&format!("pipeline: root key, table heights {:?} lanes {lanes:?}", root_key.table_heights()));
    let batches = vec![(b0.clone(), claim0), (b1.clone(), claim1)];
    let root = layers::prove_layer(&root_key, &batch_key, &BINDING, 0, &batches, [23; 32]).unwrap();
    progress("pipeline: root proven");
    layers::verify_layer(&root_key, &BINDING, 0, &whole, &root).unwrap();
    // A root of one batch is a root of one batch's claim only.
    let mut short = whole;
    short.count -= 1;
    assert!(layers::verify_layer(&root_key, &BINDING, 0, &short, &root).is_err());
    assert!(layers::verify_layer(&root_key, &BINDING, 0, &claim0, &root).is_err());
    assert!(layers::verify_layer(&root_key, &BINDING, 1, &whole, &root).is_err());
    assert!(layers::verify_layer(&root_key, &other_chain, 0, &whole, &root).is_err());
    // Batches out of order: refused, and proven anyway, refused against the
    // claim they make.
    let swapped = vec![(b1.clone(), claim1), (b0.clone(), claim0)];
    assert!(layers::prove_layer(&root_key, &batch_key, &BINDING, 0, &swapped, [24; 32]).is_err());
    let tag = root_key.tag(&BINDING, 0);
    let forged = layers::prove_layer_unchecked(&root_key, &batch_key, &tag, &swapped, [24; 32]).unwrap();
    let forged_claim = Claim::joined(&[claim1, claim0]).unwrap();
    assert!(layers::verify_layer(&root_key, &BINDING, 0, &forged_claim, &forged).is_err());
    assert!(layers::verify_layer(&root_key, &BINDING, 0, &whole, &forged).is_err());
    // A batch claiming other reveals than it proved.
    let mut lying = claim1;
    lying.end[0] ^= 1;
    assert!(
        layers::prove_layer(&root_key, &batch_key, &BINDING, 0, &[(b0.clone(), claim0), (b1.clone(), lying)], [25; 32])
            .is_err()
    );
    progress("pipeline: root refusals");

    // The shrink of the root.
    let shrink_key = layers::shrink_key(&root_key, LEAN).unwrap();
    progress(&format!("pipeline: shrink key, table heights {:?}", shrink_key.table_heights()));
    let shrink = layers::prove_layer(&shrink_key, &root_key, &BINDING, 0, &[(root.clone(), whole)], [26; 32]).unwrap();
    progress("pipeline: shrink proven");
    layers::verify_layer(&shrink_key, &BINDING, 0, &whole, &shrink).unwrap();
    assert!(layers::verify_layer(&shrink_key, &BINDING, 0, &claim0, &shrink).is_err());
    assert!(layers::verify_layer(&shrink_key, &other_chain, 0, &whole, &shrink).is_err());
    assert!(layers::verify_layer(&root_key, &BINDING, 0, &whole, &shrink).is_err());
    // A shrink of a root made under another binding is refused.
    assert!(
        layers::prove_layer(&shrink_key, &root_key, &other_chain, 0, &[(root.clone(), whole)], [27; 32]).is_err()
    );

    let bounds = [
        (b0.len(), layers::proof_size_bound(&batch_key)),
        (root.len(), layers::proof_size_bound(&root_key)),
        (shrink.len(), layers::proof_size_bound(&shrink_key)),
    ];
    let _ = writeln!(std::io::stderr(), "DIAG pipeline proof bytes and bounds {bounds:?}");
    for (bytes, bound) in bounds {
        assert!(bytes <= bound, "a proof of {bytes} bytes over its bound of {bound}");
    }
    assert!(shrink.len() <= layers::PROOF_FIELD_BYTES);
}

/// The real pipeline, planned without proving: a batch of 32 version 2 coin
/// reveals at 96 queries, a root over 44 such batches, both at blowup 2^3
/// with 96 queries, and a shrink at blowup 2^5 with 56 queries. Every table
/// fits the field's two-adic limit at its blowup, and the shrink proof's
/// size bound, computed from the shrink's own tables (built over the root's
/// real heights and widths), is within the 1,310,720-byte proof field.
#[test]
fn the_real_shrink_fits_the_proof_field() {
    use std::io::Write;
    let _guard = one_at_a_time();
    let child = layers::RevealChild::new(LayerShape::WIDE.num_queries);
    let plan = layers::plan_pipeline(
        &child,
        LayerShape::WIDE,
        child.log_height(),
        32,
        44,
        LayerShape::WIDE,
        LayerShape::SHRINK,
    )
    .unwrap();
    let _ = writeln!(std::io::stderr(), "DIAG real pipeline plan {plan:?}");
    progress("real pipeline planned");
    for (layer, shape) in [
        (&plan.batch, LayerShape::WIDE),
        (&plan.root, LayerShape::WIDE),
        (&plan.shrink, LayerShape::SHRINK),
    ] {
        for &h in &layer.heights {
            assert!(h.trailing_zeros() as usize <= shape.max_log_height(), "{layer:?}");
        }
    }
    assert!(
        plan.shrink_bytes_bound <= layers::PROOF_FIELD_BYTES,
        "the shrink proof may take {} bytes",
        plan.shrink_bytes_bound
    );
}
