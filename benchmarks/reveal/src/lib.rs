//! The real coin reveal prover (statement S1 of `ghost-proofs`, the salted
//! coin reveal) for a browser background worker, and what a native verifier
//! needs to check the proofs it makes.
//!
//! The prover is `ghost_proofs::prove_salted_coin_reveal`, unchanged, in the
//! shipped configuration of decision 0003. This crate only adds:
//!
//! - [`Session`]: a valid witness of a salted (version 2) coin drawn from a
//!   seed, the way the benchmark plan asks (a random leaf position,
//!   pseudo-random sibling hashes, salts and the consistent root, the plan's
//!   fixed amounts). It is built before timing.
//! - [`encode_reveal`] and [`decode_reveal`]: the public fields of a coin
//!   reveal as bytes, so a proof made in the browser can be carried out of it
//!   and verified natively with `ghost_proofs::verify_salted_coin_reveal`.
//! - [`record_fields`]: the configuration fields of a result record, as JSON.
//! - On `wasm32` only, plain exported functions the worker calls through
//!   `WebAssembly.instantiate`, with no bindings generator.
//!
//! Zero-knowledge randomness always comes from the caller (the browser's
//! `crypto.getRandomValues` in the worker); it is never seeded here.

use ghost_proofs::{
    ChainParams, CoinReveal, EMPTY_RULE, NOTE_BYTES, PROTOCOL_VERSION_1, Proof, ProofError, RevealRequest,
    SALT_BYTES, SaltedCoinOpening, SaltedCoinRemainder, TREE_DEPTH, Tree, amount_word, coin_commitment_v2,
    coin_fingerprint_v2, keccak256, merkle_root, prove_salted_coin_reveal, shipped_configuration,
    verify_salted_coin_reveal,
};

#[cfg(target_arch = "wasm32")]
mod exports;

/// The Plonky3 revision `ghost-proofs` pins (decision 0003). A test checks it
/// against `proofs/Cargo.toml`.
pub const PLONKY3_REVISION: &str = "f98331687e47106a64ab82a77e2e1d0d66c9161b";
/// Compiler version and build flags of this build.
pub const RUSTC_VERSION: &str = env!("GHOST_REVEAL_RUSTC_VERSION");
pub const BUILD_FLAGS: &str = env!("GHOST_REVEAL_BUILD_FLAGS");

/// One GHOST in base units (18 decimals).
const GHOST: u128 = 1_000_000_000_000_000_000;
/// The plan's primary amounts: 1,000 GHOST in, 250 out, a fee of 0.001.
pub const AMOUNT_IN: u128 = 1_000 * GHOST;
pub const AMOUNT_OUT: u128 = 250 * GHOST;
pub const FEE: u128 = GHOST / 1_000;

/// Length of [`encode_reveal`]'s output.
pub const REVEAL_BYTES: usize = 32 * 3 + NOTE_BYTES + 20 + 32 * 3;

/// The chain constants both the browser prover and the native verifier use
/// for this benchmark. They are benchmark values, not a real chain's.
pub fn bench_params() -> ChainParams {
    ChainParams {
        chain_id: *b"ghostbch",
        version: PROTOCOL_VERSION_1,
        domain: keccak256(b"ghost benchmark domain, not a real chain"),
    }
}

/// Pseudo-random bytes from the witness seed: Keccak-256 over a label, the
/// seed and a counter. Only for building test witnesses.
fn draw(seed: u32, label: &str, i: u32) -> [u8; 32] {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(b"ghost-bench/reveal-witness/");
    msg.extend_from_slice(label.as_bytes());
    msg.extend_from_slice(&seed.to_le_bytes());
    msg.extend_from_slice(&i.to_le_bytes());
    keccak256(&msg)
}

/// A pseudo-random salt from the witness seed, as [`draw`] makes bytes.
fn draw_salt(seed: u32, label: &str) -> [u8; SALT_BYTES] {
    draw(seed, label, 0)[..SALT_BYTES].try_into().expect("salt bytes")
}

/// A valid witness and request for one session. Holds secrets, so it
/// implements no `Debug`.
pub struct Session {
    pub seed: u32,
    pub same_key: bool,
    opening: SaltedCoinOpening,
    remainder: SaltedCoinRemainder,
    request: RevealRequest,
}

impl Session {
    /// Draw a witness from `seed`. With `same_key` the remainder keeps the
    /// input's `s` and `r` (the outline's default); otherwise it goes to new
    /// ones (a claim to a new key). The cost is the same.
    pub fn new(seed: u32, same_key: bool) -> Self {
        let mut path = [[0u8; 32]; TREE_DEPTH];
        for (level, sibling) in path.iter_mut().enumerate() {
            *sibling = draw(seed, "sibling", level as u32);
        }
        let position = u32::from_le_bytes(draw(seed, "position", 0)[..4].try_into().expect("4 bytes"));
        let opening = SaltedCoinOpening {
            s: draw(seed, "s", 0),
            r: draw(seed, "r", 0),
            b: draw(seed, "b", 0),
            salt: draw_salt(seed, "salt"),
            v: amount_word(AMOUNT_IN),
            position,
            path,
        };
        let (s2, r2) = if same_key {
            (opening.s, opening.r)
        } else {
            (draw(seed, "s'", 0), draw(seed, "r'", 0))
        };
        let remainder = SaltedCoinRemainder {
            s: s2,
            r: r2,
            b: draw(seed, "b'", 0),
            salt: draw_salt(seed, "salt'"),
            v: amount_word(AMOUNT_IN - AMOUNT_OUT - FEE),
        };
        let fingerprint = coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, &EMPTY_RULE);
        let leaf = coin_commitment_v2(&fingerprint, &opening.v);
        let mut note = [0u8; NOTE_BYTES];
        for (i, chunk) in note.chunks_mut(32).enumerate() {
            chunk.copy_from_slice(&draw(seed, "note", i as u32)[..chunk.len()]);
        }
        let request = RevealRequest {
            root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
            recipient: draw(seed, "recipient", 0)[..20].try_into().expect("20 bytes"),
            out: amount_word(AMOUNT_OUT),
            fee: amount_word(FEE),
            rule: EMPTY_RULE,
            remainder_note: note,
        };
        Self { seed, same_key, opening, remainder, request }
    }

    /// Prove the reveal: the real prover, checks and trace generation
    /// included. `zk_randomness` must be 32 fresh bytes from a secure source.
    pub fn prove(&self, zk_randomness: [u8; 32]) -> Result<(CoinReveal, Proof), ProofError> {
        prove_salted_coin_reveal(&bench_params(), &self.opening, &self.remainder, &self.request, zk_randomness)
    }
}

/// Verify a salted coin reveal with the benchmark's chain constants.
pub fn verify(tx: &CoinReveal, proof: &Proof) -> Result<(), ProofError> {
    verify_salted_coin_reveal(&bench_params(), tx, proof)
}

/// The public fields of a coin reveal as bytes: root, marker, remainder,
/// remainder note, recipient, out, fee, rule.
pub fn encode_reveal(tx: &CoinReveal) -> Vec<u8> {
    let mut out = Vec::with_capacity(REVEAL_BYTES);
    for part in [&tx.root[..], &tx.marker, &tx.remainder, &tx.remainder_note, &tx.recipient, &tx.out, &tx.fee, &tx.rule] {
        out.extend_from_slice(part);
    }
    out
}

/// The inverse of [`encode_reveal`]; `None` for the wrong length.
pub fn decode_reveal(bytes: &[u8]) -> Option<CoinReveal> {
    if bytes.len() != REVEAL_BYTES {
        return None;
    }
    let mut at = 0;
    let mut take = |n: usize| {
        let part = &bytes[at..at + n];
        at += n;
        part
    };
    let a32 = |p: &[u8]| -> [u8; 32] { p.try_into().expect("32 bytes") };
    let root = a32(take(32));
    let marker = a32(take(32));
    let remainder = a32(take(32));
    let remainder_note = take(NOTE_BYTES).try_into().expect("note bytes");
    let recipient = take(20).try_into().expect("20 bytes");
    let out = a32(take(32));
    let fee = a32(take(32));
    let rule = a32(take(32));
    Some(CoinReveal { root, marker, remainder, remainder_note, recipient, out, fee, rule })
}

fn json_str(out: &mut String, key: &str, value: &str) {
    out.push_str(&format!("\"{key}\":\"{}\",", value.replace('\\', "\\\\").replace('"', "\\\"")));
}

fn json_num(out: &mut String, key: &str, value: u64) {
    out.push_str(&format!("\"{key}\":{value},"));
}

/// The configuration fields of a result record, as one JSON object, from the
/// configuration the library reports.
pub fn record_fields(session: &Session) -> Result<String, ProofError> {
    let c = shipped_configuration()?;
    if !c.zero_knowledge {
        return Err(ProofError::NotZeroKnowledge);
    }
    let (_, est) = c.statements[0];
    let mut o = String::from("{");
    json_str(&mut o, "statement", "coin-reveal");
    json_str(&mut o, "prover", "ghost-proofs prove_salted_coin_reveal (real statement S1, salted)");
    json_str(&mut o, "library", "Plonky3");
    json_str(&mut o, "library_repository", "https://github.com/Plonky3/Plonky3");
    json_str(&mut o, "library_revision", PLONKY3_REVISION);
    json_str(&mut o, "rustc_version", RUSTC_VERSION);
    json_str(&mut o, "build_flags", BUILD_FLAGS);
    json_str(&mut o, "hash_candidate", "keccak-256");
    json_str(
        &mut o,
        "configuration",
        &format!(
            "keccak-256/hiding-fri/blowup-2^{}/queries-{}/grinding-q{}-b{}-o0/ext-{}/zk",
            c.log_blowup, c.num_queries, c.query_pow_bits, c.batch_pow_bits, c.extension_degree
        ),
    );
    o.push_str("\"zero_knowledge\":true,");
    json_num(&mut o, "log_blowup", c.log_blowup as u64);
    json_num(&mut o, "blowup", 1 << c.log_blowup);
    json_num(&mut o, "num_queries", c.num_queries as u64);
    json_num(&mut o, "query_pow_bits", c.query_pow_bits as u64);
    json_num(&mut o, "batch_pow_bits", c.batch_pow_bits as u64);
    json_num(&mut o, "extension_degree", c.extension_degree as u64);
    json_num(&mut o, "collision_resistance_bits", c.commitment_collision_bits as u64);
    json_num(&mut o, "trace_height", est.trace_height as u64);
    json_num(&mut o, "trace_width", est.trace_width as u64);
    json_num(&mut o, "constraint_degree", est.constraint_degree as u64);
    json_num(&mut o, "conjectured_security_bits", est.conjectured_bits as u64);
    json_num(&mut o, "conjectured_security_bits_half_grinding", est.conjectured_bits_half_grinding as u64);
    json_num(&mut o, "conjectured_quantum_security_bits", est.conjectured_quantum_bits as u64);
    json_num(&mut o, "proven_security_bits", est.proven_bits as u64);
    json_num(&mut o, "proven_quantum_security_bits", est.proven_quantum_bits as u64);
    json_num(&mut o, "query_security_bits", c.query_bits as u64);
    json_num(&mut o, "salt_bits", c.salt_bits as u64);
    json_num(&mut o, "security_target_bits", 128);
    json_str(
        &mut o,
        "security_target_regime",
        "conjectured, queries alone and every term with grinding counted at half (spec 09, section 4.1)",
    );
    json_str(&mut o, "security_estimator", "library: p3-uni-stark StarkSecurityParams (p3-security)");
    json_num(&mut o, "witness_seed", u64::from(session.seed));
    o.push_str(&format!("\"same_key\":{},", session.same_key));
    json_num(&mut o, "public_inputs_bytes", REVEAL_BYTES as u64);
    o.pop();
    o.push('}');
    Ok(o)
}
