//! Native reference runner. Writes one JSON record per proof.
//!
//! These numbers are context only: they never count toward the 10-second
//! target, which is judged on browser measurements alone. Every record says
//! so (`"build": "native"`, `"counts_toward_target": false`).
//!
//! ```text
//! ghost-bench-native [--candidate a|b|all] [--blowup 1|2|3|all]
//!                    [--sessions N] [--warm N] [--seed N]
//!                    [--repo-commit HASH] [--out FILE]
//! ```

use std::io::Write;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ghost_bench::{HashCandidate, Instance, json, os_seed};

struct Args {
    candidates: Vec<HashCandidate>,
    blowups: Vec<usize>,
    sessions: usize,
    warm: usize,
    seed: u64,
    repo_commit: String,
    out: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: ghost-bench-native [--candidate a|b|all] [--blowup 1|2|3|all] \
         [--sessions N] [--warm N] [--seed N] [--repo-commit HASH] [--out FILE]"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut args = Args {
        candidates: HashCandidate::ALL.to_vec(),
        blowups: vec![1, 2, 3],
        sessions: 1,
        warm: 10,
        seed: now_ms(),
        repo_commit: String::from("unknown"),
        out: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--candidate" if value == "all" => args.candidates = HashCandidate::ALL.to_vec(),
            "--candidate" => {
                args.candidates = vec![HashCandidate::parse(&value).unwrap_or_else(|| usage())];
            }
            "--blowup" if value == "all" => args.blowups = vec![1, 2, 3],
            "--blowup" => args.blowups = vec![value.parse().unwrap_or_else(|_| usage())],
            "--sessions" => args.sessions = value.parse().unwrap_or_else(|_| usage()),
            "--warm" => args.warm = value.parse().unwrap_or_else(|_| usage()),
            "--seed" => args.seed = value.parse().unwrap_or_else(|_| usage()),
            "--repo-commit" => args.repo_commit = value,
            "--out" => args.out = Some(value),
            _ => usage(),
        }
    }
    args
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn base_record(args: &Args, session: usize) -> json::Object {
    let mut o = json::Object::new();
    o.str("build", "native")
        .bool("counts_toward_target", false)
        .str("device_class", "native-reference")
        .str("device", "native reference, not a browser")
        .str("os", &format!("{} {}", std::env::consts::OS, std::env::consts::ARCH))
        .num(
            "logical_cores",
            std::thread::available_parallelism().map_or(0, |n| n.get() as u64),
        )
        .bool("threads_used", cfg!(feature = "parallel"))
        .str("repository_commit", &args.repo_commit)
        .num("session", session as u64)
        .null("module_startup_ms")
        .null("peak_wasm_memory_bytes")
        .null("process_peak_memory_bytes");
    o
}

fn main() {
    let args = parse_args();
    let mut sink: Box<dyn Write> = match &args.out {
        Some(path) => Box::new(std::fs::File::create(path).expect("output file")),
        None => Box::new(std::io::stdout()),
    };
    let mut failures = 0;

    // Configurations are interleaved: every session visits each in turn.
    for session in 0..args.sessions {
        for &candidate in &args.candidates {
            for &log_blowup in &args.blowups {
                let seed = args.seed.wrapping_add(session as u64);
                let mut record = base_record(&args, session);
                record
                    .str("hash_candidate", candidate.name())
                    .num("log_blowup", log_blowup as u64);
                let instance = match Instance::new(candidate, log_blowup, seed, session % 2 == 0) {
                    Ok(i) => i,
                    Err(e) => {
                        record.str("outcome", "refused").str("reason", &e.to_string());
                        writeln!(sink, "{}", record.render()).expect("write record");
                        eprintln!("{candidate} 2^{log_blowup}: {e}");
                        continue;
                    }
                };
                for run in 0..=args.warm {
                    let mut r = instance.record_fields();
                    r.extend(&record);
                    r.num("run_index", run as u64)
                        .str("run_kind", if run == 0 { "cold" } else { "warm" })
                        .num("start_time_unix_ms", now_ms());
                    let zk_seed = os_seed();
                    let start = Instant::now();
                    let proved = instance.prove(zk_seed);
                    let proving_ms = start.elapsed().as_secs_f64() * 1e3;
                    match proved {
                        Ok(proof) => {
                            let start = Instant::now();
                            let verified = instance.verify(&proof);
                            let verify_ms = start.elapsed().as_secs_f64() * 1e3;
                            r.float("proving_ms", proving_ms)
                                .float("verification_ms", verify_ms)
                                .num("proof_bytes", proof.len() as u64)
                                .num("total_bytes", (proof.len() + instance.public_inputs_bytes()) as u64)
                                .bool("verified", verified.is_ok())
                                .str("outcome", if verified.is_ok() { "completed" } else { "failed" });
                            if let Err(e) = verified {
                                failures += 1;
                                r.str("reason", &e.to_string());
                            }
                        }
                        Err(e) => {
                            failures += 1;
                            r.str("outcome", "failed").str("reason", &e.to_string());
                        }
                    }
                    writeln!(sink, "{}", r.render()).expect("write record");
                }
                eprintln!("{candidate} 2^{log_blowup}: session {session} done");
            }
        }
    }
    if failures > 0 {
        eprintln!("{failures} run(s) failed");
        std::process::exit(1);
    }
}
