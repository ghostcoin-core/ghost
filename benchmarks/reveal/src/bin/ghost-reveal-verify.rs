//! Verify, natively, salted coin reveal proofs made in the browser worker.
//!
//! Reads proof files written by the benchmark driver: one proof per line,
//! `<label> TAB <public fields, hex> TAB <proof, hex>`, the public fields as
//! `ghost_reveal_bench::encode_reveal` writes them. Each proof is checked with
//! `ghost_proofs::verify_salted_coin_reveal` and the benchmark's chain
//! constants,
//! and one JSON line is printed per proof:
//! `{"label":"...","native_verified":true}`.
//!
//! Exits 1 if any proof does not verify, a line cannot be read, or a file
//! holds no proof at all.
//!
//! Usage: ghost-reveal-verify FILE...

use std::process::ExitCode;

use ghost_proofs::Proof;
use ghost_reveal_bench::{decode_reveal, verify};

fn hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn check(line: &str) -> (String, Result<(), String>) {
    let mut parts = line.split('\t');
    let label = parts.next().unwrap_or_default().to_string();
    let (Some(reveal), Some(proof), None) = (parts.next(), parts.next(), parts.next()) else {
        return (label, Err("expected three tab-separated fields".into()));
    };
    let Some(tx) = hex(reveal).as_deref().and_then(decode_reveal) else {
        return (label, Err("public fields do not decode".into()));
    };
    let Some(proof) = hex(proof) else {
        return (label, Err("proof is not hex".into()));
    };
    (label, verify(&tx, &Proof::from_bytes(proof)).map_err(|e| e.to_string()))
}

fn main() -> ExitCode {
    let files: Vec<String> = std::env::args().skip(1).collect();
    if files.is_empty() {
        eprintln!("usage: ghost-reveal-verify FILE...");
        return ExitCode::from(2);
    }
    let mut ok = true;
    for file in files {
        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{file}: {e}");
                return ExitCode::from(2);
            }
        };
        let mut checked = 0usize;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            checked += 1;
            let (label, result) = check(line);
            let label = label.replace('\\', "\\\\").replace('"', "\\\"");
            match result {
                Ok(()) => println!("{{\"label\":\"{label}\",\"native_verified\":true}}"),
                Err(reason) => {
                    ok = false;
                    let reason = reason.replace('"', "'");
                    println!("{{\"label\":\"{label}\",\"native_verified\":false,\"reason\":\"{reason}\"}}");
                }
            }
        }
        if checked == 0 {
            eprintln!("{file}: no proofs");
            ok = false;
        }
    }
    if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
