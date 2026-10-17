//! Verification cost for the node: time and memory of the native verifier on
//! a valid proof and on worst-case invalid proofs. Prints a Markdown table.
//!
//! The node rejects invalid proofs too, and an attacker chooses which kind it
//! sends, so the slowest rejection matters as much as the valid case. Every
//! case starts from one honest proof:
//!
//! - `valid`: the honest proof and public inputs;
//! - `wrong public input`: the lowest bit of the first binding digest limb
//!   flipped, which stays in range and so reaches the full verifier;
//! - `truncated by one byte`, `truncated to half`, `empty`;
//! - `one byte appended`: the honest proof with a trailing zero byte;
//! - `altered at the end`: one bit flipped in each of the last `--tail`
//!   bytes in turn (the last query's openings and the fields after them in
//!   postcard order); the slowest rejection is reported;
//! - `altered anywhere`: one bit flipped at `--sweep` offsets spread evenly
//!   over the whole proof; the slowest rejection is reported.
//!
//! Memory is the peak heap allocated during the call above what was live
//! before it, counted by a wrapper around the system allocator, so it covers
//! the verifier's own allocations (decoding included) on every thread.
//!
//! ```text
//! ghost-bench-verify [--candidate a|b] [--blowup 1|2|3|all] [--runs N]
//!                    [--tail N] [--sweep N] [--seed N] [--fixture DIR]
//! ```
//!
//! `--fixture DIR` also writes the honest proof (`proof.bin`) and public
//! inputs (`public_inputs.bin`, little-endian `u32`) of the last configuration
//! for the cgo prototype in `benchmarks/verify-ffi`.
//!
//! Exits with status 1 if the valid proof is rejected, if any altered,
//! truncated or mismatched proof is accepted, or if the verifier panics on
//! any input. The appended-byte case is reported either way: it is the same
//! statement and proof, so accepting it is an encoding question for the node,
//! not a soundness failure.

use std::alloc::{GlobalAlloc, Layout, System};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ghost_bench::{HashCandidate, Instance, os_seed};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(n: usize) {
    let now = CURRENT.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

fn shrink(n: usize) {
    CURRENT.fetch_sub(n, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        shrink(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size > layout.size() {
                grow(new_size - layout.size());
            } else {
                shrink(layout.size() - new_size);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

struct Args {
    candidate: HashCandidate,
    blowups: Vec<usize>,
    runs: usize,
    tail: usize,
    sweep: usize,
    seed: u64,
    fixture: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: ghost-bench-verify [--candidate a|b] [--blowup 1|2|3|all] [--runs N] \
         [--tail N] [--sweep N] [--seed N] [--fixture DIR]"
    );
    std::process::exit(2)
}

fn number(value: &str) -> usize {
    value.parse().unwrap_or_else(|_| usage())
}

fn parse_args() -> Args {
    // The chosen hash and its runnable blowups.
    let mut args = Args {
        candidate: HashCandidate::Keccak256,
        blowups: vec![2, 3],
        runs: 10,
        tail: 64,
        sweep: 256,
        seed: 1,
        fixture: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--candidate" => args.candidate = HashCandidate::parse(&value).unwrap_or_else(|| usage()),
            "--blowup" if value == "all" => args.blowups = vec![1, 2, 3],
            "--blowup" => args.blowups = vec![number(&value)],
            "--runs" => args.runs = number(&value).max(1),
            "--tail" => args.tail = number(&value),
            "--sweep" => args.sweep = number(&value),
            "--seed" => args.seed = number(&value) as u64,
            "--fixture" => args.fixture = Some(value),
            _ => usage(),
        }
    }
    args
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Accepted,
    Rejected,
    /// The verifier panicked. A node must never do this on a peer's input,
    /// and a panic cannot cross the cgo boundary.
    Panicked,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Panicked => "panicked",
        }
    }
}

/// One timed call: the outcome, milliseconds, peak heap bytes.
fn measure_once(instance: &Instance, pis: &[u32], proof: &[u8]) -> (Outcome, f64, usize) {
    let base = CURRENT.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let start = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| ghost_bench::verify(&instance.plan, pis, proof)));
    let ms = start.elapsed().as_secs_f64() * 1e3;
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(base);
    let outcome = match result {
        Ok(Ok(())) => Outcome::Accepted,
        Ok(Err(_)) => Outcome::Rejected,
        Err(_) => Outcome::Panicked,
    };
    (outcome, ms, peak)
}

struct Row {
    case: String,
    /// `None` when either outcome is acceptable as long as there is no panic.
    expected: Option<Outcome>,
    outcome: Outcome,
    median_ms: f64,
    largest_ms: f64,
    peak_bytes: usize,
}

impl Row {
    fn is_wrong(&self) -> bool {
        self.outcome == Outcome::Panicked || self.expected.is_some_and(|e| e != self.outcome)
    }
}

/// `runs` calls on one input; the outcome must be the same every time.
fn measure(
    case: &str,
    expected: Option<Outcome>,
    runs: usize,
    instance: &Instance,
    pis: &[u32],
    proof: &[u8],
) -> Row {
    let mut times = Vec::with_capacity(runs);
    let mut peak_bytes = 0;
    let mut outcome = None;
    for _ in 0..runs {
        let (o, ms, peak) = measure_once(instance, pis, proof);
        assert!(outcome.is_none_or(|prev| prev == o), "{case}: outcome changed between runs");
        outcome = Some(o);
        times.push(ms);
        peak_bytes = peak_bytes.max(peak);
    }
    times.sort_by(f64::total_cmp);
    Row {
        case: case.to_string(),
        expected,
        outcome: outcome.expect("at least one run"),
        median_ms: times[times.len() / 2],
        largest_ms: times[times.len() - 1],
        peak_bytes,
    }
}

fn flip(proof: &[u8], offset: usize) -> Vec<u8> {
    let mut p = proof.to_vec();
    p[offset] ^= 1;
    p
}

/// Tries a one-bit alteration at each offset. Any alteration that is not
/// rejected is reported at once; otherwise the slowest rejection is measured
/// `runs` times.
fn slowest_alteration(
    label: &str,
    offsets: impl Iterator<Item = usize>,
    runs: usize,
    instance: &Instance,
    proof: &[u8],
) -> Row {
    let pis = &instance.public_inputs;
    let mut slowest: Option<(usize, f64)> = None;
    for offset in offsets {
        let (outcome, ms, _) = measure_once(instance, pis, &flip(proof, offset));
        if outcome != Outcome::Rejected {
            let mut row = measure(label, Some(Outcome::Rejected), 1, instance, pis, &flip(proof, offset));
            row.case = format!("{label} (byte {offset} of {})", proof.len());
            return row;
        }
        if slowest.is_none_or(|(_, t)| ms > t) {
            slowest = Some((offset, ms));
        }
    }
    let (offset, _) = slowest.expect("at least one offset");
    let mut row = measure(label, Some(Outcome::Rejected), runs, instance, pis, &flip(proof, offset));
    row.case = format!("{label} (slowest: byte {offset} of {})", proof.len());
    row
}

fn write_fixture(dir: &str, instance: &Instance, proof: &[u8]) {
    std::fs::create_dir_all(dir).expect("fixture directory");
    std::fs::write(format!("{dir}/proof.bin"), proof).expect("write proof.bin");
    let pis: Vec<u8> = instance.public_inputs.iter().flat_map(|x| x.to_le_bytes()).collect();
    std::fs::write(format!("{dir}/public_inputs.bin"), pis).expect("write public_inputs.bin");
}

/// Peak resident memory of the whole process, where the system reports it.
fn process_peak_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn main() {
    let args = parse_args();
    let mut failures = 0;

    println!(
        "Build: {}, {} {}, threads {}, {} logical cores, {} runs per case.",
        ghost_bench::RUSTC_VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH,
        if cfg!(feature = "parallel") { "on" } else { "off" },
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        args.runs,
    );
    println!();
    println!(
        "| Candidate | Blowup | Case | Outcome | Verification median (ms) | Verification largest (ms) | Peak heap (KiB) |"
    );
    println!("|---|---|---|---|---|---|---|");

    for &log_blowup in &args.blowups {
        let instance = match Instance::new(args.candidate, log_blowup, args.seed, true) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("{} 2^{log_blowup}: {e}", args.candidate);
                continue;
            }
        };
        let proof = instance.prove(os_seed()).expect("honest proof");
        let pis = &instance.public_inputs;

        let mut wrong_pis = pis.clone();
        let (_, binding) = args
            .candidate
            .public_input_groups()
            .into_iter()
            .find(|(name, _)| *name == "binding digest")
            .expect("binding digest group");
        wrong_pis[binding.start] ^= 1;

        let mut appended = proof.clone();
        appended.push(0);

        let len = proof.len();
        let tail = args.tail.clamp(1, len);
        let sweep = args.sweep.clamp(1, len);
        let accept = Some(Outcome::Accepted);
        let reject = Some(Outcome::Rejected);
        let runs = args.runs;
        let rows = [
            measure("valid", accept, runs, &instance, pis, &proof),
            measure("wrong public input", reject, runs, &instance, &wrong_pis, &proof),
            measure("truncated by one byte", reject, runs, &instance, pis, &proof[..len - 1]),
            measure("truncated to half", reject, runs, &instance, pis, &proof[..len / 2]),
            measure("empty", reject, runs, &instance, pis, &[]),
            measure("one byte appended", None, runs, &instance, pis, &appended),
            slowest_alteration(
                &format!("altered at the end, last {tail} bytes"),
                (len - tail)..len,
                runs,
                &instance,
                &proof,
            ),
            slowest_alteration(
                &format!("altered anywhere, {sweep} offsets"),
                (0..sweep).map(|i| i * len / sweep),
                runs,
                &instance,
                &proof,
            ),
        ];

        for row in &rows {
            if row.is_wrong() {
                failures += 1;
            }
            println!(
                "| {} | 2^{log_blowup} | {} | {} | {:.2} | {:.2} | {:.1} |",
                args.candidate,
                row.case,
                row.outcome.name(),
                row.median_ms,
                row.largest_ms,
                row.peak_bytes as f64 / 1024.0,
            );
        }

        if let Some(dir) = &args.fixture {
            write_fixture(dir, &instance, &proof);
        }
    }

    println!();
    match process_peak_kib() {
        Some(kib) => println!("Process peak resident memory: {kib} KiB (proving included)."),
        None => println!("Process peak resident memory: not reported by this system."),
    }
    if failures > 0 {
        eprintln!("{failures} case(s) gave the wrong outcome");
        std::process::exit(1);
    }
}
