//! A C interface to the benchmark verifier, so the Go node can call the same
//! Plonky3 verifier the prover is checked against, through cgo.
//!
//! One function, [`ghost_verify`], takes the configuration, the public inputs
//! and the proof bytes, and returns a status code. It never unwinds into the
//! caller: a panic inside the verifier becomes [`GHOST_VERIFY_PANICKED`]. The
//! security plan of each configuration is computed once and kept.
//!
//! The header for C and Go is `ghost_verify.h` beside this crate.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, OnceLock};

use ghost_bench::{BenchError, HashCandidate, SecurityPlan};

pub const GHOST_VERIFY_ACCEPTED: i32 = 0;
pub const GHOST_VERIFY_REJECTED: i32 = 1;
pub const GHOST_VERIFY_MALFORMED_PROOF: i32 = 2;
pub const GHOST_VERIFY_MALFORMED_PUBLIC_INPUTS: i32 = 3;
pub const GHOST_VERIFY_BAD_CONFIGURATION: i32 = 4;
pub const GHOST_VERIFY_BAD_ARGUMENT: i32 = 5;
pub const GHOST_VERIFY_PANICKED: i32 = 6;

/// Candidate codes: 0 is Poseidon2, 1 is Keccak-256, the chosen hash.
fn candidate(code: u32) -> Option<HashCandidate> {
    match code {
        0 => Some(HashCandidate::Poseidon2),
        1 => Some(HashCandidate::Keccak256),
        _ => None,
    }
}

fn plan(candidate: HashCandidate, log_blowup: usize) -> Result<SecurityPlan, BenchError> {
    static PLANS: OnceLock<Mutex<HashMap<(HashCandidate, usize), SecurityPlan>>> = OnceLock::new();
    let plans = PLANS.get_or_init(Default::default);
    if let Some(p) = plans.lock().unwrap_or_else(|e| e.into_inner()).get(&(candidate, log_blowup)) {
        return Ok(p.clone());
    }
    let p = ghost_bench::plan(candidate, log_blowup)?;
    plans
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert((candidate, log_blowup), p.clone());
    Ok(p)
}

/// The safe core of [`ghost_verify`].
pub fn verify(candidate_code: u32, log_blowup: u32, public_inputs: &[u32], proof: &[u8]) -> i32 {
    let Some(candidate) = candidate(candidate_code) else {
        return GHOST_VERIFY_BAD_CONFIGURATION;
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let plan = plan(candidate, log_blowup as usize)?;
        ghost_bench::verify(&plan, public_inputs, proof)
    }));
    match result {
        Ok(Ok(())) => GHOST_VERIFY_ACCEPTED,
        Ok(Err(BenchError::Rejected(_))) => GHOST_VERIFY_REJECTED,
        Ok(Err(BenchError::MalformedProof(_))) => GHOST_VERIFY_MALFORMED_PROOF,
        Ok(Err(BenchError::MalformedPublicInputs)) => GHOST_VERIFY_MALFORMED_PUBLIC_INPUTS,
        Ok(Err(_)) => GHOST_VERIFY_BAD_CONFIGURATION,
        Err(_) => GHOST_VERIFY_PANICKED,
    }
}

/// Verifies `proof` against `public_inputs` for one configuration.
///
/// # Safety
///
/// `public_inputs` must point to `public_inputs_len` readable `u32` values and
/// `proof` to `proof_len` readable bytes, for the duration of the call. Either
/// pointer may be null only when its length is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_verify(
    candidate: u32,
    log_blowup: u32,
    public_inputs: *const u32,
    public_inputs_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    if (public_inputs.is_null() && public_inputs_len != 0) || (proof.is_null() && proof_len != 0) {
        return GHOST_VERIFY_BAD_ARGUMENT;
    }
    let public_inputs = if public_inputs_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(public_inputs, public_inputs_len) }
    };
    let proof = if proof_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(proof, proof_len) }
    };
    verify(candidate, log_blowup, public_inputs, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_bench::{Instance, os_seed};

    #[test]
    fn the_c_interface_accepts_a_good_proof_and_rejects_bad_ones() {
        let instance = Instance::new(HashCandidate::Keccak256, 2, 11, true).unwrap();
        let proof = instance.prove(os_seed()).unwrap();
        let pis = &instance.public_inputs;
        let call = |pis: &[u32], proof: &[u8]| unsafe {
            ghost_verify(1, 2, pis.as_ptr(), pis.len(), proof.as_ptr(), proof.len())
        };

        assert_eq!(call(pis, &proof), GHOST_VERIFY_ACCEPTED);

        let mut altered = proof.clone();
        let last = altered.len() - 2;
        altered[last] ^= 1;
        assert_ne!(call(pis, &altered), GHOST_VERIFY_ACCEPTED);

        assert_ne!(call(pis, &proof[..proof.len() - 1]), GHOST_VERIFY_ACCEPTED);
        assert_ne!(call(pis, &[]), GHOST_VERIFY_ACCEPTED);

        let mut wrong = pis.clone();
        wrong[0] ^= 1;
        assert_ne!(call(&wrong, &proof), GHOST_VERIFY_ACCEPTED);
    }

    #[test]
    fn bad_arguments_are_refused_without_reading_them() {
        let refused = unsafe { ghost_verify(1, 2, std::ptr::null(), 4, std::ptr::null(), 0) };
        assert_eq!(refused, GHOST_VERIFY_BAD_ARGUMENT);
        assert_eq!(verify(9, 2, &[], &[]), GHOST_VERIFY_BAD_CONFIGURATION);
        assert_eq!(verify(1, 1, &[], &[]), GHOST_VERIFY_BAD_CONFIGURATION);
    }
}
