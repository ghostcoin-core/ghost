//! The benchmark of the recursion layers, on the machine it runs on:
//!
//! ```text
//! env RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN=1.99.1 cargo test --release --locked \
//!     --manifest-path proofs/Cargo.toml --test layers_bench -- --ignored --nocapture
//! ```
//!
//! It names the machine from /proc/cpuinfo, /proc/meminfo and the hostname,
//! times one width-24 Poseidon2 permutation of the pinned library on one
//! core, proves 8 real version 2 coin reveals at 96 queries, plans the real
//! pipeline at the design's chosen shape (`layers::REVEALS_PER_BATCH` and
//! `layers::BATCHES_PER_ROOT`: a batch of the 8 reveals, a root over 29
//! batches, both at blowup 2^3 with 96 queries, and a shrink at blowup 2^5
//! with 56 queries), then runs each stage in turn: the batch key and 29 batch
//! proofs (each over the same 8 reveals, chained from where the one before
//! ended), the root
//! key and proof, the shrink key and proof. Each stage prints its seconds and
//! the process's peak memory (VmHWM) against the 128 GiB machine ceiling,
//! labelled measured. Each planned layer prints its streamed prover's
//! modeled peak memory by part against the same ceiling. A stage whose
//! modeled prover memory exceeds the machine's memory is not run: it prints
//! not yet established, with the modeled figure, and so does every stage
//! after it. The layers themselves read no clock or file; only this test
//! does.

use std::time::Instant;

use ghost_proofs::ffi::{
    GHOST_PROOFS_ACCEPTED, ROOT_KEY_BYTES, RootPath, root_inputs_to_bytes, root_key_to_bytes, verify_bundle_root_bytes,
};
use ghost_proofs::layers::{self, Claim, LayerShape};
use ghost_proofs::*;
use p3_baby_bear::{BabyBear, default_babybear_poseidon2_24};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;

/// The machine ceiling of the stage 2 design.
const CEILING_GIB: f64 = 128.0;
/// Reveals a batch verifies, and batches a root verifies, in the design.
const PER_BATCH: usize = layers::REVEALS_PER_BATCH;
const BATCHES: usize = layers::BATCHES_PER_ROOT;

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

fn proc_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The machine's total memory in bytes (MemTotal).
fn machine_bytes() -> f64 {
    let kib: f64 = proc_file("/proc/meminfo")
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    kib * 1024.0
}

/// The machine: CPU model (or the CPU implementer when the kernel names no
/// model), core count, total memory and hostname.
fn machine() -> String {
    let cpuinfo = proc_file("/proc/cpuinfo");
    let field = |name: &str| {
        cpuinfo
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split(':').nth(1))
            .map(|v| v.trim().to_string())
    };
    let model = field("model name")
        .or_else(|| field("CPU implementer").map(|i| format!("CPU implementer {i}")))
        .unwrap_or_else(|| "unknown CPU".into());
    let cores = cpuinfo.lines().filter(|l| l.starts_with("processor")).count();
    let host = proc_file("/proc/sys/kernel/hostname");
    format!(
        "{} ({model}, {cores} cores, {:.1} GiB, {})",
        host.trim(),
        machine_bytes() / GIB,
        std::env::consts::ARCH
    )
}

/// The process's peak resident memory in GiB (VmHWM).
fn peak_gib() -> f64 {
    let kib: f64 = proc_file("/proc/self/status")
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    kib / 1024.0 / 1024.0
}

fn permutation_ns() -> f64 {
    let perm = default_babybear_poseidon2_24();
    let mut state = [BabyBear::ONE; 24];
    for _ in 0..100_000 {
        perm.permute_mut(&mut state);
    }
    let n = 10_000_000u32;
    let t = Instant::now();
    for _ in 0..n {
        perm.permute_mut(std::hint::black_box(&mut state));
    }
    t.elapsed().as_nanos() as f64 / f64::from(n)
}

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

/// Reveal `i`: a plain salted coin of 1,000,000 revealed for 600,000 with a
/// fee of `21 + i`.
fn reveal(params: &ChainParams, i: u8) -> (CoinRevealV2, Proof) {
    let (o, remainder, request, zk) = reveal_inputs(i);
    prove_coin_reveal_v2_scale(params, &o, &InputRule::plain(), &remainder, &EMPTY_RULE, &request, zk)
        .expect("an honest reveal proves")
}

/// [`reveal`] at the small test shape: two queries and a nine element digest.
fn reveal_small(params: &ChainParams, i: u8) -> (CoinRevealV2, Proof) {
    let (o, remainder, request, zk) = reveal_inputs(i);
    let shape = ScaleShape {
        num_queries: SMALL_QUERIES,
        digest_elems: 9,
    };
    prove_coin_reveal_v2_scale_shaped(
        params,
        &o,
        &InputRule::plain(),
        &remainder,
        &EMPTY_RULE,
        &request,
        zk,
        shape,
    )
    .expect("an honest reveal proves")
}

fn reveal_inputs(i: u8) -> (SaltedCoinOpening, SaltedCoinRemainder, CoinRevealV2Request, [u8; 32]) {
    let o = SaltedCoinOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        salt: [0xa5; SALT_BYTES],
        v: amount_word(1_000_000),
        position: 5,
        path: path(),
    };
    let fee = 21 + u128::from(i);
    let remainder = SaltedCoinRemainder {
        s: [1; 32],
        r: [2; 32],
        b: [4 + i; 32],
        salt: [0x3c; SALT_BYTES],
        v: amount_word(1_000_000 - 600_000 - fee),
    };
    let leaf = coin_commitment_v2(&coin_fingerprint_v2(&o.s, &o.r, &o.b, &o.salt, &EMPTY_RULE), &o.v);
    let request = CoinRevealV2Request {
        root: merkle_root(Tree::Coin, &leaf, o.position, &o.path),
        recipient: [0x11; 20],
        out: amount_word(600_000),
        fee: amount_word(fee),
        remainder_note: [0x33; NOTE_V3_BYTES],
    };
    let mut zk = [0x6c; 32];
    zk[0] = i;
    (o, remainder, request, zk)
}

/// Whether a stage of `modeled` prover bytes fits the machine; prints the
/// reason when it does not.
fn fits(stage: &str, modeled: usize, machine: f64) -> bool {
    let need = modeled as f64 / GIB;
    if modeled as f64 <= machine {
        println!("modeled: {stage} needs about {need:.1} GiB, within the machine's {:.1} GiB", machine / GIB);
        true
    } else {
        println!(
            "not yet established: {stage}, which needs about {need:.1} GiB (modeled), more than the machine's {:.1} GiB \
             (the design's ceiling is {CEILING_GIB} GiB)",
            machine / GIB
        );
        false
    }
}

fn measured(stage: &str, t: Instant, bytes: Option<usize>) {
    let bytes = bytes.map_or(String::new(), |b| format!(", {b} bytes"));
    println!(
        "measured: {stage} in {:.1} s{bytes}, peak {:.2} GiB of the {CEILING_GIB} GiB ceiling",
        t.elapsed().as_secs_f64(),
        peak_gib()
    );
}

/// Times the shrink's verification this many times.
const VERIFY_RUNS: usize = 20;
/// Queries of the small test shape.
const SMALL_QUERIES: usize = 2;
/// The files `GHOST_ROOT_PROOF_OUT` receives.
const PROOF_FILE: &str = "shrink_proof.bin";
const KEY_FILE: &str = "root_key.bin";
const INPUTS_FILE: &str = "root_inputs.bin";

/// The median and the worst of the times.
fn median_and_worst(mut times: Vec<f64>) -> (f64, f64) {
    times.sort_by(f64::total_cmp);
    let n = times.len();
    let median = if n % 2 == 1 { times[n / 2] } else { (times[n / 2 - 1] + times[n / 2]) / 2.0 };
    (median, times[n - 1])
}

/// Verifies the shrink `VERIFY_RUNS` times and prints the median and worst
/// time in milliseconds, with the machine line.
fn time_verification(key: &layers::LayerKey, binding: &layers::Binding, claim: &Claim, shrink: &[u8]) -> (f64, f64) {
    let times: Vec<f64> = (0..VERIFY_RUNS)
        .map(|_| {
            let t = Instant::now();
            layers::verify_layer(key, binding, 0, claim, shrink).expect("the shrink verifies");
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    let (median, worst) = median_and_worst(times);
    println!(
        "measured: shrink verification over {VERIFY_RUNS} runs: median {median:.1} ms, worst {worst:.1} ms \
         (machine: {})",
        machine()
    );
    (median, worst)
}

/// The directory named by `GHOST_ROOT_PROOF_OUT`, if any.
fn out_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("GHOST_ROOT_PROOF_OUT").filter(|d| !d.is_empty()).map(std::path::PathBuf::from)
}

/// Writes the shrink proof (in its zero-padded proof field), the verifier key
/// bytes and the root inputs bytes into `dir`, for the node's own verifier.
fn write_root_proof(
    dir: &std::path::Path,
    key: &layers::LayerKey,
    binding: &layers::Binding,
    items: &[Vec<u8>],
    shrink: &[u8],
) {
    std::fs::create_dir_all(dir).expect("the output directory is made");
    let key_bytes = root_key_to_bytes(key, RootPath::Bundle).expect("the shrink key has root key bytes");
    let inputs = root_inputs_to_bytes(binding, items);
    assert!(shrink.len() <= PROOF_FIELD_BYTES);
    let mut field = shrink.to_vec();
    field.resize(PROOF_FIELD_BYTES, 0);
    std::fs::write(dir.join(PROOF_FILE), &field).expect("the proof is written");
    std::fs::write(dir.join(KEY_FILE), key_bytes).expect("the key is written");
    std::fs::write(dir.join(INPUTS_FILE), &inputs).expect("the inputs are written");
    println!(
        "measured: wrote {PROOF_FILE} ({} bytes), {KEY_FILE} ({} bytes), {INPUTS_FILE} ({} bytes) to {}",
        field.len(),
        key_bytes.len(),
        inputs.len(),
        dir.display()
    );
}

/// What follows a proven shrink: the timed verifications, then the files when
/// `out` names a directory.
fn finish_shrink(
    key: &layers::LayerKey,
    binding: &layers::Binding,
    claim: &Claim,
    items: &[Vec<u8>],
    shrink: &[u8],
    out: Option<&std::path::Path>,
) -> (f64, f64) {
    let timing = time_verification(key, binding, claim, shrink);
    if let Some(dir) = out {
        write_root_proof(dir, key, binding, items, shrink);
    }
    timing
}

/// The same timing and writing at the small test shape: one reveal through a
/// batch, a root and a shrink, with the files reloaded and verified through
/// the node's interface.
#[test]
fn layers_benchmark_small() {
    let small = LayerShape {
        log_blowup: 3,
        num_queries: SMALL_QUERIES,
    };
    let lean = LayerShape {
        log_blowup: 2,
        num_queries: 1,
    };
    let params = ChainParams {
        chain_id: *b"testnet1",
        version: PROTOCOL_VERSION_2,
        domain: [0x47; 32],
    };
    let binding = layers::Binding::of(&params);
    let child = layers::RevealChild::new(SMALL_QUERIES);
    let (tx, proof) = reveal_small(&params, 0);
    let publics = layers::RevealChild::public_values(&params, &tx);
    let item = coin_reveal_v2_public_values(&params, &tx);
    let claim = Claim::of(&layers::START_DIGEST, std::slice::from_ref(&publics));

    let mut batch_key = layers::batch_key(&child, small, child.log_height(), 1, lean).expect("the batch key builds");
    let children = vec![(proof.as_bytes().to_vec(), publics)];
    let batch = layers::prove_batch(&batch_key, &child, &binding, 0, &layers::START_DIGEST, &children, [31; 32])
        .expect("the batch proves");
    batch_key.release_prover_data();
    let mut root_key = layers::root_key(&batch_key, 1, lean).expect("the root key builds");
    let root = layers::prove_layer(&root_key, &batch_key, &binding, 0, &[(batch, claim)], [32; 32])
        .expect("the root proves");
    root_key.release_prover_data();
    let shrink_key = layers::shrink_key(&root_key, lean).expect("the shrink key builds");
    let shrink = layers::prove_layer(&shrink_key, &root_key, &binding, 0, &[(root, claim)], [33; 32])
        .expect("the shrink proves");

    let dir = std::env::temp_dir().join(format!("layers_bench_small_{}", std::process::id()));
    let started = Instant::now();
    let items = vec![item];
    let (median, worst) = finish_shrink(&shrink_key, &binding, &claim, &items, &shrink, Some(&dir));
    assert!(median > 0.0 && worst >= median);
    assert!(started.elapsed().as_secs() < 30, "the timing and writing take well under a minute");

    let proof_file = std::fs::read(dir.join(PROOF_FILE)).expect("the proof file reloads");
    let key_file = std::fs::read(dir.join(KEY_FILE)).expect("the key file reloads");
    let inputs_file = std::fs::read(dir.join(INPUTS_FILE)).expect("the inputs file reloads");
    assert_eq!(proof_file.len(), PROOF_FIELD_BYTES);
    assert_eq!(&proof_file[..shrink.len()], &shrink[..]);
    assert_eq!(key_file.len(), ROOT_KEY_BYTES);
    assert_eq!(inputs_file, root_inputs_to_bytes(&binding, &items));
    assert_eq!(verify_bundle_root_bytes(&key_file, &inputs_file, &proof_file), GHOST_PROOFS_ACCEPTED);

    let mut damaged = proof_file.clone();
    damaged[shrink.len() / 2] ^= 1;
    assert_ne!(verify_bundle_root_bytes(&key_file, &inputs_file, &damaged), GHOST_PROOFS_ACCEPTED);
    let mut other = inputs_file.clone();
    *other.last_mut().unwrap() ^= 1;
    assert_ne!(verify_bundle_root_bytes(&key_file, &other, &proof_file), GHOST_PROOFS_ACCEPTED);
    std::fs::remove_dir_all(&dir).expect("the test directory is removed");
}

#[test]
#[ignore = "the layers benchmark: run with -- --ignored --nocapture"]
fn layers_benchmark() {
    let machine_mem = machine_bytes();
    println!("machine: {}", machine());
    println!("measured: {:.1} ns per Poseidon2 permutation (one core)", permutation_ns());

    let params = ChainParams {
        chain_id: *b"testnet1",
        version: PROTOCOL_VERSION_2,
        domain: [0x47; 32],
    };
    let binding = layers::Binding::of(&params);
    let child = layers::RevealChild::new(SCALE_NUM_QUERIES);

    let t = Instant::now();
    let plan = layers::plan_pipeline(
        &child,
        LayerShape::WIDE,
        child.log_height(),
        PER_BATCH,
        BATCHES,
        LayerShape::WIDE,
        LayerShape::SHRINK,
    )
    .expect("the real pipeline plans");
    measured("planning the real pipeline", t, None);
    for (name, layer) in [("batch", &plan.batch), ("root", &plan.root), ("shrink", &plan.shrink)] {
        let m = &layer.memory;
        let gib = |b: usize| b as f64 / GIB;
        println!(
            "measured: {name} circuit entries {:?}, table lanes {:?}, heights {:?}; modeled prover memory {:.1} GiB \
             at its peak, {} the {CEILING_GIB} GiB ceiling (streamed prover: circuit {:.1}, key {:.1}, committed \
             coefficients {:.1}, opening phase {:.1}, block {:.1} GiB)",
            layer.entries,
            layer.lanes,
            layer.heights,
            gib(m.peak),
            if m.peak as u64 <= layers::PROVER_CEILING_BYTES { "within" } else { "above" },
            gib(m.circuit),
            gib(m.key),
            gib(m.committed),
            gib(m.opening_phase),
            gib(m.block),
        );
    }
    println!("measured: shrink proof size bound {} bytes", plan.shrink_bytes_bound);

    let t = Instant::now();
    let reveals: Vec<(CoinRevealV2, Proof)> = (0..PER_BATCH as u8).map(|i| reveal(&params, i)).collect();
    measured(&format!("{PER_BATCH} reveal proofs"), t, None);
    let children: Vec<(Vec<u8>, Vec<BabyBear>)> = reveals
        .iter()
        .map(|(tx, proof)| (proof.as_bytes().to_vec(), layers::RevealChild::public_values(&params, tx)))
        .collect();
    let contents: Vec<Vec<BabyBear>> = children.iter().map(|(_, p)| p.clone()).collect();

    if !fits(&format!("a batch of {PER_BATCH} real reveals"), plan.batch.modeled_prover_bytes, machine_mem) {
        println!("not yet established: the root over {BATCHES} batches and the shrink, which need the batches first");
        return;
    }
    let t = Instant::now();
    let mut batch_key = layers::batch_key(&child, LayerShape::WIDE, child.log_height(), PER_BATCH, LayerShape::WIDE)
        .expect("the batch key builds");
    measured("batch key", t, None);
    let mut batches: Vec<(Vec<u8>, Claim)> = Vec::with_capacity(BATCHES);
    let mut start = layers::START_DIGEST;
    for i in 0..BATCHES {
        let t = Instant::now();
        let proof = layers::prove_batch(&batch_key, &child, &binding, i as u32, &start, &children, [i as u8; 32])
            .expect("the batch proves");
        if i == 0 {
            measured(&format!("batch of {PER_BATCH} real reveals"), t, Some(proof.len()));
            layers::verify_batch(&batch_key, &binding, 0, &start, &contents, &proof).expect("the batch verifies");
        }
        let claim = Claim::of(&start, &contents);
        start = claim.end;
        batches.push((proof, claim));
    }
    let whole = Claim::joined(&batches.iter().map(|(_, c)| *c).collect::<Vec<_>>()).expect("the batches chain");

    if !fits(&format!("the root over {BATCHES} batches"), plan.root.modeled_prover_bytes, machine_mem) {
        println!("not yet established: the shrink, which needs the root first");
        return;
    }
    // The root reads only the batch key's shapes and commitment, so the
    // batch prover's data is dropped first, as the model counts it.
    batch_key.release_prover_data();
    let t = Instant::now();
    let mut root_key = layers::root_key(&batch_key, BATCHES, LayerShape::WIDE).expect("the root key builds");
    let root = layers::prove_layer(&root_key, &batch_key, &binding, 0, &batches, [0x52; 32]).expect("the root proves");
    measured(&format!("root over {BATCHES} batches, key included"), t, Some(root.len()));
    layers::verify_layer(&root_key, &binding, 0, &whole, &root).expect("the root verifies");

    if !fits("the shrink", plan.shrink.modeled_prover_bytes, machine_mem) {
        return;
    }
    root_key.release_prover_data();
    let t = Instant::now();
    let shrink_key = layers::shrink_key(&root_key, LayerShape::SHRINK).expect("the shrink key builds");
    let shrink = layers::prove_layer(&shrink_key, &root_key, &binding, 0, &[(root, whole)], [0x53; 32])
        .expect("the shrink proves");
    measured("shrink, key included", t, Some(shrink.len()));
    layers::verify_layer(&shrink_key, &binding, 0, &whole, &shrink).expect("the shrink verifies");
    assert!(shrink.len() <= layers::PROOF_FIELD_BYTES);
    // The root's inputs as the node builds them: every batch's reveals in order.
    let batch_items: Vec<Vec<u8>> = reveals.iter().map(|(tx, _)| coin_reveal_v2_public_values(&params, tx)).collect();
    let items: Vec<Vec<u8>> = (0..BATCHES).flat_map(|_| batch_items.iter().cloned()).collect();
    finish_shrink(&shrink_key, &binding, &whole, &items, &shrink, out_dir().as_deref());
}
