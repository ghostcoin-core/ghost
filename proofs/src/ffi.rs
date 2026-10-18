//! A C interface to the coin reveal verifier, so a node written in another
//! language links the same [`verify_coin_reveal`] the prover is checked
//! against.
//!
//! One function, [`ghost_verify_coin_reveal`], takes the chain parameters, the
//! public statement and the proof as pointer and length, and returns a status
//! code. Nothing unwinds into the caller: a panic inside becomes
//! [`GHOST_PROOFS_PANICKED`], which needs the library built with the default
//! `panic = "unwind"`. Only [`GHOST_PROOFS_ACCEPTED`] accepts; every other
//! status rejects.
//!
//! The header for C is `include/ghost_proofs.h` beside this crate; the two
//! must agree on every constant below.
//!
//! **Chain parameters**, [`CHAIN_PARAMS_BYTES`] bytes: `chain_id` (8),
//! `version` (2), `domain` (32), in that order.
//!
//! **Statement**, [`COIN_REVEAL_BYTES`] bytes: `root` (32), `marker` (32),
//! `remainder` (32), `remainder_note` ([`NOTE_BYTES`]), `recipient` (20),
//! `out` (32), `fee` (32), `rule` (32), in that order.
//!
//! **Proof**, 1 to [`PROOF_MAX_BYTES`] bytes: one serialized proof, which may
//! be followed by zero bytes, so a zero-padded proof field can be passed as it
//! is. A non-zero byte after the serialization is malformed, so one proof has
//! one encoding.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::{ChainParams, CoinReveal, NOTE_BYTES, Proof, ProofError, stark, verify_coin_reveal};

/// The proof verifies against the statement and the chain parameters.
pub const GHOST_PROOFS_ACCEPTED: i32 = 0;
/// The input is well formed and the verifier rejects it.
pub const GHOST_PROOFS_REJECTED: i32 = 1;
/// The proof is empty, too long, does not decode or has non-zero padding.
pub const GHOST_PROOFS_MALFORMED_INPUT: i32 = 2;
/// A null pointer, or parameters or a statement of the wrong length.
pub const GHOST_PROOFS_BAD_ARGUMENT: i32 = 3;
/// The verifier panicked; the panic was caught.
pub const GHOST_PROOFS_PANICKED: i32 = 4;

/// Length of the chain parameters.
pub const CHAIN_PARAMS_BYTES: usize = 8 + 2 + 32;
/// Length of the coin reveal statement.
pub const COIN_REVEAL_BYTES: usize = 32 + 32 + 32 + NOTE_BYTES + 20 + 32 + 32 + 32;
/// The longest proof buffer accepted, 2 MiB: room above a coin reveal proof
/// (about 1.19 MB) and a bound on what one call reads.
pub const PROOF_MAX_BYTES: usize = 2 * 1024 * 1024;

/// The chain parameters in the layout of the C interface.
pub fn chain_params_to_bytes(params: &ChainParams) -> [u8; CHAIN_PARAMS_BYTES] {
    let mut out = [0u8; CHAIN_PARAMS_BYTES];
    out[..8].copy_from_slice(&params.chain_id);
    out[8..10].copy_from_slice(&params.version);
    out[10..].copy_from_slice(&params.domain);
    out
}

/// Chain parameters from the layout of the C interface.
pub fn chain_params_from_bytes(bytes: &[u8; CHAIN_PARAMS_BYTES]) -> ChainParams {
    let mut r = Reader(bytes);
    ChainParams {
        chain_id: r.take(),
        version: r.take(),
        domain: r.take(),
    }
}

/// The coin reveal statement in the layout of the C interface.
pub fn coin_reveal_to_bytes(tx: &CoinReveal) -> [u8; COIN_REVEAL_BYTES] {
    let mut out = [0u8; COIN_REVEAL_BYTES];
    let fields: [&[u8]; 8] = [
        &tx.root,
        &tx.marker,
        &tx.remainder,
        &tx.remainder_note,
        &tx.recipient,
        &tx.out,
        &tx.fee,
        &tx.rule,
    ];
    let mut at = 0;
    for field in fields {
        out[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
    out
}

/// A coin reveal statement from the layout of the C interface.
pub fn coin_reveal_from_bytes(bytes: &[u8; COIN_REVEAL_BYTES]) -> CoinReveal {
    let mut r = Reader(bytes);
    CoinReveal {
        root: r.take(),
        marker: r.take(),
        remainder: r.take(),
        remainder_note: r.take(),
        recipient: r.take(),
        out: r.take(),
        fee: r.take(),
        rule: r.take(),
    }
}

/// Reads fixed-width fields in order from a buffer of exactly their total
/// length.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        head.try_into().expect("split_at gives N bytes")
    }
}

/// The safe core of [`ghost_verify_coin_reveal`], over slices.
pub fn verify_coin_reveal_bytes(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    catch_unwind(AssertUnwindSafe(|| verify_unguarded(params, statement, proof))).unwrap_or(GHOST_PROOFS_PANICKED)
}

fn verify_unguarded(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    let (Ok(params), Ok(statement)) = (
        <&[u8; CHAIN_PARAMS_BYTES]>::try_from(params),
        <&[u8; COIN_REVEAL_BYTES]>::try_from(statement),
    ) else {
        return GHOST_PROOFS_BAD_ARGUMENT;
    };
    if proof.is_empty() || proof.len() > PROOF_MAX_BYTES {
        return GHOST_PROOFS_MALFORMED_INPUT;
    }
    let Some(len) = stark::serialized_len(proof) else {
        return GHOST_PROOFS_MALFORMED_INPUT;
    };
    let (proof, padding) = proof.split_at(len);
    if padding.iter().any(|&b| b != 0) {
        return GHOST_PROOFS_MALFORMED_INPUT;
    }
    let params = chain_params_from_bytes(params);
    let tx = coin_reveal_from_bytes(statement);
    match verify_coin_reveal(&params, &tx, &Proof::from_bytes(proof.to_vec())) {
        Ok(()) => GHOST_PROOFS_ACCEPTED,
        Err(ProofError::MalformedProof) => GHOST_PROOFS_MALFORMED_INPUT,
        Err(_) => GHOST_PROOFS_REJECTED,
    }
}

/// Verifies a coin reveal proof against the statement and the chain
/// parameters.
///
/// # Safety
///
/// Each non-null pointer must point to at least its length of readable bytes
/// for the duration of the call. A null pointer is refused with
/// [`GHOST_PROOFS_BAD_ARGUMENT`], and a buffer of the wrong length is refused
/// before it is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_verify_coin_reveal(
    params: *const u8,
    params_len: usize,
    statement: *const u8,
    statement_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    catch_unwind(|| {
        if params.is_null() || statement.is_null() || proof.is_null() {
            return GHOST_PROOFS_BAD_ARGUMENT;
        }
        if params_len != CHAIN_PARAMS_BYTES || statement_len != COIN_REVEAL_BYTES {
            return GHOST_PROOFS_BAD_ARGUMENT;
        }
        if proof_len == 0 || proof_len > PROOF_MAX_BYTES {
            return GHOST_PROOFS_MALFORMED_INPUT;
        }
        // SAFETY: non-null, and the caller guarantees each length is readable.
        let (params, statement, proof) = unsafe {
            (
                std::slice::from_raw_parts(params, params_len),
                std::slice::from_raw_parts(statement, statement_len),
                std::slice::from_raw_parts(proof, proof_len),
            )
        };
        verify_coin_reveal_bytes(params, statement, proof)
    })
    .unwrap_or(GHOST_PROOFS_PANICKED)
}
