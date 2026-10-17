//! Correctness before speed (plan, Method step 1).
//!
//! A speed number from a build that fails any of these is discarded:
//!
//! - a good proof verifies;
//! - changing any public input makes verification fail;
//! - a witness that breaks conservation does not give a proof that verifies;
//! - a wrong Merkle path is rejected;
//! - two proofs with different randomness differ and both verify;
//! - the trace height is at or above the zero-knowledge minimum.
//!
//! Candidate A runs at the primary blowup 2^1. Candidate B runs at 2^2: its
//! Keccak circuit has degree 3, which zero-knowledge mode cannot fit in a
//! blowup of 2^1 (checked below).

use std::panic::{AssertUnwindSafe, catch_unwind};

use ghost_bench::witness::{AMOUNT_BITS, Witness};
use ghost_bench::{
    BenchError, HashCandidate, Instance, SecurityPlan, TARGET_CONJECTURED_BITS, os_seed, plan,
    prove, public_inputs, trace_commitment, verify, zk_min_trace_height,
};

const CASES: [(HashCandidate, usize); 2] = [(HashCandidate::Poseidon2, 1), (HashCandidate::Keccak256, 2)];

/// True when the statement cannot be proven: proving refuses or fails (a
/// debug build checks the constraints and panics), or the proof does not
/// verify.
fn rejected(plan: &SecurityPlan, witness: &Witness, pis: &[u32]) -> bool {
    let proved = catch_unwind(AssertUnwindSafe(|| prove(plan, witness, pis, os_seed())));
    match proved {
        Err(_) | Ok(Err(_)) => true,
        Ok(Ok(proof)) => verify(plan, pis, &proof).is_err(),
    }
}

#[test]
fn a_good_proof_verifies() {
    for (candidate, log_blowup) in CASES {
        for same_key in [true, false] {
            let instance = Instance::new(candidate, log_blowup, 101, same_key).unwrap();
            let proof = instance.prove(os_seed()).unwrap();
            instance
                .verify(&proof)
                .unwrap_or_else(|e| panic!("{candidate}, same key {same_key}: {e}"));
        }
    }
}

#[test]
fn changing_any_public_input_fails_verification() {
    for (candidate, log_blowup) in CASES {
        let instance = Instance::new(candidate, log_blowup, 202, true).unwrap();
        let proof = instance.prove(os_seed()).unwrap();
        instance.verify(&proof).unwrap();
        for (name, range) in candidate.public_input_groups() {
            for index in [range.start, range.end - 1] {
                let mut pis = instance.public_inputs.clone();
                pis[index] ^= 1;
                assert!(
                    verify(&instance.plan, &pis, &proof).is_err(),
                    "{candidate}: changing the {name} (element {index}) still verified"
                );
            }
        }
    }
}

#[test]
fn value_out_exceeding_value_in_is_rejected() {
    for (candidate, log_blowup) in CASES {
        let plan = plan(candidate, log_blowup).unwrap();
        let mut w = Witness::primary(303, true);
        w.amount_out = w.amount + 1;
        // The remainder wraps around 2^96, the only way its limbs could fit.
        w.remainder_amount = w.amount.wrapping_sub(w.amount_out + w.fee) & ((1u128 << AMOUNT_BITS) - 1);
        let pis = public_inputs(candidate, &w);
        assert!(rejected(&plan, &w, &pis), "{candidate}");
    }
}

#[test]
fn a_sum_off_by_one_at_a_limb_boundary_is_rejected() {
    for (candidate, log_blowup) in CASES {
        let plan = plan(candidate, log_blowup).unwrap();
        // Honest: 2^24 = 0 + (2^24 - 1) + 1. The remainder below is one too
        // many, which carries into the second limb.
        let mut w = Witness::primary(404, false);
        w.amount = 1 << 24;
        w.amount_out = 0;
        w.fee = 1;
        w.remainder_amount = 1 << 24;
        let pis = public_inputs(candidate, &w);
        assert!(rejected(&plan, &w, &pis), "{candidate}: one too many");

        w.remainder_amount = (1 << 24) - 2;
        let pis = public_inputs(candidate, &w);
        assert!(rejected(&plan, &w, &pis), "{candidate}: one too few");

        // The honest version of the same amounts proves.
        w.remainder_amount = (1 << 24) - 1;
        let pis = public_inputs(candidate, &w);
        assert!(!rejected(&plan, &w, &pis), "{candidate}: honest boundary case");
    }
}

#[test]
fn a_wrong_merkle_path_is_rejected() {
    for (candidate, log_blowup) in CASES {
        let plan = plan(candidate, log_blowup).unwrap();
        let honest = Witness::primary(505, true);
        let pis = public_inputs(candidate, &honest);

        let mut w = honest.clone();
        w.siblings[17][3] ^= 0x40;
        assert!(rejected(&plan, &w, &pis), "{candidate}: wrong sibling");

        let mut w = honest.clone();
        w.leaf_index ^= 1 << 9;
        assert!(rejected(&plan, &w, &pis), "{candidate}: wrong direction bit");
    }
}

#[test]
fn proofs_with_different_randomness_differ_and_both_verify() {
    for (candidate, log_blowup) in CASES {
        let instance = Instance::new(candidate, log_blowup, 606, true).unwrap();
        let first = instance.prove(os_seed()).unwrap();
        let second = instance.prove(os_seed()).unwrap();
        instance.verify(&first).unwrap();
        instance.verify(&second).unwrap();
        assert_ne!(first, second, "{candidate}");
        assert_ne!(
            trace_commitment(&instance.plan, &first).unwrap(),
            trace_commitment(&instance.plan, &second).unwrap(),
            "{candidate}: the trace commitments must differ"
        );
    }
}

#[test]
fn the_trace_height_is_at_or_above_the_zero_knowledge_minimum() {
    for (candidate, log_blowup) in [
        (HashCandidate::Poseidon2, 1),
        (HashCandidate::Poseidon2, 2),
        (HashCandidate::Poseidon2, 3),
        (HashCandidate::Keccak256, 2),
        (HashCandidate::Keccak256, 3),
    ] {
        let plan = plan(candidate, log_blowup).unwrap();
        assert_eq!(plan.zk_min_trace_height, zk_min_trace_height(plan.num_queries));
        assert!(
            plan.trace_height >= plan.zk_min_trace_height,
            "{candidate} 2^{log_blowup}: height {} below {}",
            plan.trace_height,
            plan.zk_min_trace_height
        );
    }
}

/// The minimum above is the library's own: a trace one size shorter than
/// it is refused by the hiding commitment scheme.
#[test]
fn the_library_refuses_a_trace_below_the_minimum() {
    let mut refused = 0;
    for log_blowup in 1..=3 {
        let mut plan = plan(HashCandidate::Poseidon2, log_blowup).unwrap();
        let shorter = plan.trace_height / 2;
        if shorter < ghost_bench::poseidon2::MIN_HEIGHT || shorter >= plan.zk_min_trace_height {
            continue;
        }
        plan.trace_height = shorter;
        let w = Witness::primary(707, true);
        let pis = public_inputs(HashCandidate::Poseidon2, &w);
        let result = prove(&plan, &w, &pis, os_seed());
        assert!(
            matches!(result, Err(BenchError::Proving(_))),
            "2^{log_blowup}: a {shorter}-row trace was not refused: {result:?}"
        );
        refused += 1;
    }
    assert!(refused > 0, "no configuration had a shorter trace to try");
}

#[test]
fn every_measured_configuration_meets_the_security_floor() {
    for candidate in HashCandidate::ALL {
        for log_blowup in 1..=3 {
            match plan(candidate, log_blowup) {
                Ok(plan) => {
                    assert!(plan.estimate.conjectured_bits >= TARGET_CONJECTURED_BITS);
                    assert!(plan.estimate.proven_bits <= plan.estimate.conjectured_bits);
                    assert!(plan.grinding.query <= 16 && plan.grinding.batch <= 16 && plan.grinding.ood <= 16);
                }
                Err(e) => assert!(
                    candidate == HashCandidate::Keccak256 && log_blowup == 1,
                    "{candidate} 2^{log_blowup} refused: {e}"
                ),
            }
        }
    }
}

#[test]
fn a_degree_three_circuit_is_refused_at_blowup_two() {
    assert!(matches!(
        plan(HashCandidate::Keccak256, 1),
        Err(BenchError::ConstraintDegreeTooHigh { degree: 3, log_blowup: 1 })
    ));
}

/// The query count comes from the estimate: one query fewer than planned
/// falls below the floor, and the prover refuses it before doing any work.
#[test]
fn one_query_fewer_is_refused_before_proving() {
    for (candidate, log_blowup) in CASES {
        let mut plan = plan(candidate, log_blowup).unwrap();
        plan.num_queries -= 1;
        let w = Witness::primary(808, true);
        let pis = public_inputs(candidate, &w);
        assert!(
            matches!(prove(&plan, &w, &pis, os_seed()), Err(BenchError::BelowSecurityFloor { .. })),
            "{candidate}"
        );
    }
    let a1 = plan(HashCandidate::Poseidon2, 1).unwrap();
    let a3 = plan(HashCandidate::Poseidon2, 3).unwrap();
    assert!(a3.num_queries < a1.num_queries, "a higher blowup needs fewer queries");
}
