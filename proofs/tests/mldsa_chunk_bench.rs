//! The benchmark of the ML-DSA-44 chunk proof, on the machine it runs on:
//!
//! ```text
//! env RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN=1.99.1 cargo test --release --locked \
//!     --manifest-path proofs/Cargo.toml --test mldsa_chunk_bench -- --ignored --nocapture
//! ```
//!
//! It names the machine from /proc/cpuinfo, /proc/meminfo and the hostname,
//! counts the Keccak-f\[1600\] permutations and main-trace cells of one
//! verification from the built tables, then builds the key of a chunk of the
//! design's 32 verifications at blowup 2^3 with 96 queries and proves one
//! chunk of 32 valid signatures (the 32-byte known-answer vectors, repeated),
//! printing its seconds and the process's peak memory (VmHWM), labelled
//! measured. A chunk whose modeled prover memory exceeds the machine's is not
//! proven: it prints not yet established with the modeled figure.
//!
//! Seconds per block of 3,500 transactions is 110 chunks times the measured
//! seconds per chunk plus the fold seconds of the recursion benchmark
//! (proofs/tests/layers_bench.rs) on the same machine, a sum of measured
//! figures; it is printed only when every part was measured.

use std::time::Instant;

use ghost_proofs::layers::{self, LayerShape};
use ghost_proofs::mldsa::{self, SignedTx};

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
/// Transactions a block holds, and chunks of 32 they fill.
const BLOCK_TXS: usize = 3_500;
const BLOCK_CHUNKS: usize = BLOCK_TXS.div_ceil(mldsa::DESIGN_CHUNK);

const VECTORS: &str = include_str!("data/ml_dsa_44_vectors.txt");

fn proc_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn machine_bytes() -> f64 {
    let kib: f64 = proc_file("/proc/meminfo")
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    kib * 1024.0
}

/// The machine: CPU model (or implementer), cores, memory, hostname.
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

fn peak_gib() -> f64 {
    let kib: f64 = proc_file("/proc/self/status")
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    kib / 1024.0 / 1024.0
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hash_vectors() -> Vec<SignedTx> {
    let mut out = Vec::new();
    let (mut pk, mut msg) = (None, None);
    for line in VECTORS.lines() {
        if let Some(h) = line.strip_prefix("pk ") {
            pk = Some(unhex(h));
        } else if let Some(h) = line.strip_prefix("msg ") {
            msg = Some(unhex(h));
        } else if let Some(h) = line.strip_prefix("sig ") {
            let account = [out.len() as u8 + 1; 20];
            out.push(SignedTx::new(account, pk.take().unwrap(), msg.take().unwrap(), unhex(h)));
        }
    }
    out.retain(|t| t.message.len() == mldsa::TX_HASH_BYTES);
    out
}

#[test]
#[ignore = "the benchmark: run with -- --ignored --nocapture"]
fn chunk_benchmark() {
    println!("machine: {} (measured from /proc/cpuinfo and /proc/meminfo)", machine());
    let cost = mldsa::verification_cost(mldsa::TX_HASH_BYTES);
    println!(
        "per verification: {} Keccak-f[1600] permutations and {} main-trace cells (measured from the built tables; \
         the design models 101 and 750,000); rows per table {:?}",
        cost.permutations, cost.cells, cost.rows
    );
    let shape = LayerShape::WIDE;
    let t = Instant::now();
    let key = mldsa::chunk_key(mldsa::DESIGN_CHUNK, mldsa::TX_HASH_BYTES, shape).unwrap();
    println!(
        "chunk key of {} verifications: {:.1} s, table heights {:?}, peak {:.2} GiB (measured)",
        mldsa::DESIGN_CHUNK,
        t.elapsed().as_secs_f64(),
        key.table_heights(),
        peak_gib()
    );
    let need = key.modeled_prover_bytes() as f64 / GIB;
    if need > machine_bytes() / GIB {
        println!(
            "not yet established: seconds per chunk, whose prover needs about {need:.1} GiB (modeled), more than the \
             machine's {:.1} GiB",
            machine_bytes() / GIB
        );
        println!("not yet established: seconds per block of {BLOCK_TXS} transactions, which needs the chunk first");
        return;
    }
    let base = hash_vectors();
    let txs: Vec<SignedTx> = (0..mldsa::DESIGN_CHUNK).map(|i| base[i % base.len()].clone()).collect();
    let binding = layers::Binding {
        chain_id: *b"testnet1",
        protocol_version: [0, 2],
        statement_version: 2,
    };
    let t = Instant::now();
    let proof = mldsa::prove_chunk(&key, &binding, 0, &layers::START_DIGEST, &txs, [1; 32]).unwrap();
    let secs = t.elapsed().as_secs_f64();
    println!(
        "chunk of {}: {secs:.1} s, a proof of {} bytes, peak {:.2} GiB (measured; modeled prover memory {need:.1} GiB)",
        mldsa::DESIGN_CHUNK,
        proof.len(),
        peak_gib()
    );
    let values: Vec<_> = txs.iter().map(SignedTx::public_values).collect();
    mldsa::verify_chunk(&key, &binding, 0, &layers::START_DIGEST, &values, &proof).unwrap();
    println!(
        "{BLOCK_CHUNKS} chunks of a block: {:.1} s (a product of the measured seconds per chunk); seconds per block \
         adds the fold of the recursion benchmark, not yet established on this machine (layers-results.md)",
        BLOCK_CHUNKS as f64 * secs
    );
}
