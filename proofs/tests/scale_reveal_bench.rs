//! The scale build's reveal prover, timed: one version 2 coin reveal proved
//! with Poseidon2 commitments and transcript, the degree-8 extension and 96
//! queries, its wall time and the process's peak resident memory (`VmHWM` in
//! `/proc/self/status`) printed.
//!
//! The 10 s and 1 GiB ceilings of docs/scale/workload.md are a measured
//! floor, not an assertion: this test asserts only that both figures were
//! read and that the proof verifies. The figures of a run are recorded in
//! docs/scale/poseidon2-reveal-results.md. It is its own test binary, with
//! one test, so the peak is this proof's and not another test's.

use std::time::Instant;

use ghost_proofs::*;

/// The proving-time ceiling of workload.md, in seconds.
const CEILING_SECONDS: f64 = 10.0;
/// The proposed memory ceiling of workload.md, in KiB: 1 GiB.
const CEILING_KIB: u64 = 1 << 20;

/// Test-only zero-knowledge randomness; a real prover draws it from a secure
/// random source.
const ZK: [u8; 32] = [0x7d; 32];

/// Example chain constants of protocol version 2, not Ghost's.
fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_2,
        domain: [0x47; 32],
    }
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

/// The process's peak resident set in KiB, `VmHWM` of `/proc/self/status`,
/// or `None` where there is no such line.
fn peak_resident_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let mut words = line.split_whitespace().skip(1);
    let value = words.next()?.parse().ok()?;
    (words.next()? == "kB").then_some(value)
}

#[test]
fn scale_reveal_proving_time_and_peak_memory() {
    let opening = SaltedCoinOpening {
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
    let leaf = coin_commitment_v2(
        &coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, &EMPTY_RULE),
        &opening.v,
    );
    let request = CoinRevealV2Request {
        root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
        recipient: [0x11; 20],
        out: amount_word(600_000),
        fee: amount_word(21),
        remainder_note: [0x33; NOTE_V3_BYTES],
    };

    let start = Instant::now();
    let (tx, proof) =
        prove_coin_reveal_v2_scale(&params(), &opening, &InputRule::plain(), &remainder, &EMPTY_RULE, &request, ZK)
            .expect("an honest reveal proves at the scale configuration");
    let seconds = start.elapsed().as_secs_f64();
    let peak_kib = peak_resident_kib();

    let verify_start = Instant::now();
    let verified = verify_coin_reveal_v2_scale(&params(), &tx, &proof);
    let verify_seconds = verify_start.elapsed().as_secs_f64();

    println!(
        "scale reveal (measured): proving {seconds:.3} s against {CEILING_SECONDS} s; peak memory {} against \
         {CEILING_KIB} KiB; proof {} bytes; verifying {verify_seconds:.3} s; build {}",
        peak_kib.map_or_else(|| "unread".to_owned(), |kib| format!("{kib} KiB")),
        proof.as_bytes().len(),
        if cfg!(feature = "parallel") { "parallel" } else { "single-threaded" },
    );
    assert!(seconds > 0.0, "the wall time was read");
    assert!(peak_kib.is_some_and(|kib| kib > 0), "VmHWM was read from /proc/self/status");
    assert_eq!(verified, Ok(()));
}
