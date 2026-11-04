//! The benchmark of the recursion layers, on the machine it runs on:
//!
//! ```text
//! env RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN=1.99.1 cargo test --release --locked \
//!     --manifest-path proofs/Cargo.toml --test layers_bench -- --ignored --nocapture
//! ```
//!
//! It names the machine from /proc/cpuinfo, /proc/meminfo and the hostname,
//! times one width-24 Poseidon2 permutation of the pinned library on one
//! core, then proves a real batch of 32 version 2 coin reveals at the layers'
//! shape (blowup 2^3, 96 queries) and reports its seconds and the process's
//! peak memory (VmHWM) against the 128 GiB machine ceiling. Every figure is
//! printed with the label measured. The layers themselves read no clock or
//! file; only this test does.

use std::time::Instant;

use ghost_proofs::layers::{self, LayerShape};
use ghost_proofs::*;
use p3_baby_bear::{BabyBear, default_babybear_poseidon2_24};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;

/// The machine ceiling of the stage 2 design.
const CEILING_GIB: f64 = 128.0;

fn proc_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
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
    let mem_kib: f64 = proc_file("/proc/meminfo")
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let host = proc_file("/proc/sys/kernel/hostname");
    format!(
        "{} ({model}, {cores} cores, {:.1} GiB, {})",
        host.trim(),
        mem_kib / 1024.0 / 1024.0,
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

#[test]
#[ignore = "the layers benchmark: run with -- --ignored --nocapture"]
fn layers_benchmark() {
    println!("machine: {}", machine());
    println!("measured: {:.1} ns per Poseidon2 permutation (one core)", permutation_ns());

    let params = ChainParams {
        chain_id: *b"testnet1",
        version: PROTOCOL_VERSION_2,
        domain: [0x47; 32],
    };
    let t = Instant::now();
    let reveals: Vec<(CoinRevealV2, Proof)> = (0..32).map(|i| reveal(&params, i)).collect();
    println!("measured: 32 reveal proofs in {:.1} s", t.elapsed().as_secs_f64());

    let child = layers::RevealChild::new(SCALE_NUM_QUERIES);
    let binding = layers::Binding::of(&params);
    let t = Instant::now();
    let key = layers::batch_key(&child, LayerShape::WIDE, child.log_height(), 32, LayerShape::WIDE)
        .expect("the batch key builds");
    println!(
        "measured: batch key in {:.1} s, table heights {:?}, peak {:.2} GiB",
        t.elapsed().as_secs_f64(),
        key.table_heights(),
        peak_gib()
    );
    let children: Vec<(Vec<u8>, Vec<BabyBear>)> = reveals
        .iter()
        .map(|(tx, proof)| (proof.as_bytes().to_vec(), layers::RevealChild::public_values(&params, tx)))
        .collect();
    let contents: Vec<Vec<BabyBear>> = children.iter().map(|(_, p)| p.clone()).collect();
    let t = Instant::now();
    let batch = layers::prove_batch(&key, &child, &binding, 0, &layers::START_DIGEST, &children, [1; 32])
        .expect("the batch proves");
    println!(
        "measured: batch of 32 real reveals in {:.1} s, {} bytes, peak {:.2} GiB of the {CEILING_GIB} GiB ceiling",
        t.elapsed().as_secs_f64(),
        batch.len(),
        peak_gib()
    );
    layers::verify_batch(&key, &binding, 0, &layers::START_DIGEST, &contents, &batch).expect("the batch verifies");
    println!("not yet established: root over 44 batches and shrink (those layers are not built yet)");
}
