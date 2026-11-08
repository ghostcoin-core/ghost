//! The benchmark of the recursion layers, on the machine it runs on:
//!
//! ```text
//! env RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN=1.99.1 cargo test --release --locked \
//!     --manifest-path proofs/Cargo.toml --test layers_bench -- --ignored --nocapture
//! ```
//!
//! It names the machine from /proc/cpuinfo, /proc/meminfo and the hostname,
//! times one width-24 Poseidon2 permutation of the pinned library on one
//! core, proves 32 real version 2 coin reveals at 96 queries, plans the real
//! pipeline (a batch of the 32 reveals, a root over 44 such batches, both at
//! blowup 2^3 with 96 queries, and a shrink at blowup 2^5 with 56 queries),
//! then runs each stage in turn: the batch key and 44 batch proofs (each over
//! the same 32 reveals, chained from where the one before ended), the root
//! key and proof, the shrink key and proof. Each stage prints its seconds and
//! the process's peak memory (VmHWM) against the 128 GiB machine ceiling,
//! labelled measured. Each planned layer prints its streamed prover's
//! modeled peak memory by part against the same ceiling. A stage whose
//! modeled prover memory exceeds the machine's memory is not run: it prints
//! not yet established, with the modeled figure, and so does every stage
//! after it. The layers themselves read no clock or file; only this test
//! does.

use std::time::Instant;

use ghost_proofs::layers::{self, Claim, LayerShape};
use ghost_proofs::*;
use p3_baby_bear::{BabyBear, default_babybear_poseidon2_24};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;

/// The machine ceiling of the stage 2 design.
const CEILING_GIB: f64 = 128.0;
/// Reveals a batch verifies, and batches a root verifies, in the design.
const PER_BATCH: usize = 32;
const BATCHES: usize = 44;

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
    prove_coin_reveal_v2_scale(params, &o, &InputRule::plain(), &remainder, &EMPTY_RULE, &request, zk)
        .expect("an honest reveal proves")
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
    measured("32 reveal proofs", t, None);
    let children: Vec<(Vec<u8>, Vec<BabyBear>)> = reveals
        .iter()
        .map(|(tx, proof)| (proof.as_bytes().to_vec(), layers::RevealChild::public_values(&params, tx)))
        .collect();
    let contents: Vec<Vec<BabyBear>> = children.iter().map(|(_, p)| p.clone()).collect();

    if !fits("a batch of 32 real reveals", plan.batch.modeled_prover_bytes, machine_mem) {
        println!("not yet established: the root over 44 batches and the shrink, which need the batches first");
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
            measured("batch of 32 real reveals", t, Some(proof.len()));
            layers::verify_batch(&batch_key, &binding, 0, &start, &contents, &proof).expect("the batch verifies");
        }
        let claim = Claim::of(&start, &contents);
        start = claim.end;
        batches.push((proof, claim));
    }
    let whole = Claim::joined(&batches.iter().map(|(_, c)| *c).collect::<Vec<_>>()).expect("44 batches");

    if !fits("the root over 44 batches", plan.root.modeled_prover_bytes, machine_mem) {
        println!("not yet established: the shrink, which needs the root first");
        return;
    }
    // The root reads only the batch key's shapes and commitment, so the
    // batch prover's data is dropped first, as the model counts it.
    batch_key.release_prover_data();
    let t = Instant::now();
    let mut root_key = layers::root_key(&batch_key, BATCHES, LayerShape::WIDE).expect("the root key builds");
    let root = layers::prove_layer(&root_key, &batch_key, &binding, 0, &batches, [0x52; 32]).expect("the root proves");
    measured("root over 44 batches, key included", t, Some(root.len()));
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
}
