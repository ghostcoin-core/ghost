//! Native proving time of the coin reveal, both formats, against a
//! regression budget (docs/benchmarks/reveal-parameters.md).
//!
//! The budget, [`MEDIAN_BUDGET_MS`], is a coarse regression guard, loose on
//! purpose: it must hold on the GitHub-hosted x86_64 CI runner (median about
//! 4.5 s, no vector field arithmetic) as well as on the aarch64 build host
//! (quiet-machine medians about 1,190 ms, whose load swings proving time by
//! about 1.5 times), so it catches only a gross slowdown, not the loss of a
//! few per cent.
//! It holds on one thread (the default features), in the release profile.
//! The rest of the gap to the browser target is left for a threaded or SIMD
//! build. Each test makes one
//! warm-up proof, not counted, then [`PROOFS`] proofs with as many
//! zero-knowledge seeds, each timed and verified, and holds their median to
//! the budget.
//!
//! The tests time real work: run them alone (`--test-threads=1`) and in the
//! release profile, as the acceptance command does.

use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use ghost_proofs::*;

/// The most a median native proof may take, in milliseconds.
const MEDIAN_BUDGET_MS: f64 = 10000.0;

/// Proofs timed per test, after the warm-up.
const PROOFS: u8 = 9;

static PROVING: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only zero-knowledge randomness; a real prover draws it from a secure
/// random source.
fn zk(n: u8) -> [u8; 32] {
    let mut seed = [0x5au8; 32];
    seed[0] = n;
    seed
}

/// Example chain constants, not Ghost's.
fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
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

/// The request for a coin of 1,000,000 at position 5 under `leaf`, revealed
/// for 600,000 and a fee of 21.
fn request(leaf: &[u8; 32], position: u32, path: &[[u8; 32]; TREE_DEPTH]) -> RevealRequest {
    RevealRequest {
        root: merkle_root(Tree::Coin, leaf, position, path),
        recipient: [0x11; 20],
        out: amount_word(600_000),
        fee: amount_word(21),
        rule: EMPTY_RULE,
        remainder_note: [0x33; NOTE_BYTES],
    }
}

/// Time `prove` once to warm up and then [`PROOFS`] times, verifying each
/// proof, and return the median in milliseconds.
fn median_ms(name: &str, prove: impl Fn(u8) -> bool) -> f64 {
    assert!(prove(0), "{name}: the warm-up proof does not verify");
    let mut times: Vec<f64> = (1..=PROOFS)
        .map(|seed| {
            let start = Instant::now();
            let verified = prove(seed);
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            assert!(verified, "{name}: proof {seed} does not verify");
            ms
        })
        .collect();
    let every: Vec<String> = times.iter().map(|ms| format!("{ms:.1}")).collect();
    times.sort_by(f64::total_cmp);
    let median = times[times.len() / 2];
    println!(
        "{name}: median {median:.1} ms, slowest {:.1} ms, budget {MEDIAN_BUDGET_MS} ms; every proof (ms): {}",
        times[times.len() - 1],
        every.join("; ")
    );
    median
}

#[test]
fn coin_reveal_within_budget() {
    let _guard = one_at_a_time();
    let opening = CoinOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        v: amount_word(1_000_000),
        position: 5,
        path: path(),
    };
    let leaf = coin_commitment(&coin_fingerprint(&opening.s, &opening.r, &opening.b, &EMPTY_RULE), &opening.v);
    let request = request(&leaf, opening.position, &opening.path);
    let remainder = CoinRemainder {
        s: [1; 32],
        r: [2; 32],
        b: [4; 32],
        v: amount_word(1_000_000 - 600_000 - 21),
    };
    let median = median_ms("coin reveal", |seed| {
        let (tx, proof) = prove_coin_reveal(&params(), &opening, &remainder, &request, zk(seed)).expect("honest proof");
        verify_coin_reveal(&params(), &tx, &proof).is_ok()
    });
    assert!(median <= MEDIAN_BUDGET_MS, "coin reveal: median {median:.1} ms over the budget");
}

#[test]
fn salted_coin_reveal_within_budget() {
    let _guard = one_at_a_time();
    let opening = SaltedCoinOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        salt: [0xa5; SALT_BYTES],
        v: amount_word(1_000_000),
        position: 5,
        path: path(),
    };
    let fingerprint = coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, &EMPTY_RULE);
    let leaf = coin_commitment_v2(&fingerprint, &opening.v);
    let request = request(&leaf, opening.position, &opening.path);
    let remainder = SaltedCoinRemainder {
        s: [1; 32],
        r: [2; 32],
        b: [4; 32],
        salt: [0x3c; SALT_BYTES],
        v: amount_word(1_000_000 - 600_000 - 21),
    };
    let median = median_ms("salted coin reveal", |seed| {
        let (tx, proof) =
            prove_salted_coin_reveal(&params(), &opening, &remainder, &request, zk(seed)).expect("honest proof");
        verify_salted_coin_reveal(&params(), &tx, &proof).is_ok()
    });
    assert!(median <= MEDIAN_BUDGET_MS, "salted coin reveal: median {median:.1} ms over the budget");
}
