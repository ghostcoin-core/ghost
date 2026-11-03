//! A lookup argument at the pinned Plonky3 revision, proven and verified with
//! the shipped configuration of [`crate::stark`].
//!
//! The recursion layers of docs/scale/stage2-design.md check child proofs in
//! their constraints, which needs a lookup or permutation argument: columns
//! committed after a challenge. `p3-uni-stark` has none; `p3-batch-stark`
//! with `p3-lookup` (LogUp) does. These tests prove that the pinned revision
//! provides one that works with the configuration Ghost ships: Keccak-256
//! commitments and transcript, hiding FRI, zero knowledge on. Nothing here is
//! part of the library: the two crates are development dependencies only.
//!
//! The AIR is a range lookup. Column 0 holds the queried values, column 1 the
//! table `0, 1, ..., n - 1` (fixed by its own constraints), column 2 how many
//! times each table row is queried. One local interaction sends every value
//! with count 1 and receives every table row with count `-mult`; the LogUp
//! running sum closes only if every value is in the table.

use alloc::vec;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

use crate::air::F;
use crate::stark::{Config, stark_config, zk_min_trace_height};

const LOG_HEIGHT: usize = 8;
const HEIGHT: usize = 1 << LOG_HEIGHT;
const WIDTH: usize = 3;

#[derive(Clone, Copy, Debug)]
struct RangeLookupAir;

impl<T> BaseAir<T> for RangeLookupAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl<AB> Air<AB> for RangeLookupAir
where
    AB: AirBuilder + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let (value, table, mult) = (local[0], local[1], local[2]);

        // The table is 0, 1, ..., n - 1.
        builder.when_first_row().assert_zero(table);
        builder.when_transition().assert_eq(next[1], table + AB::Expr::ONE);

        builder.push_local_interaction(vec![
            (vec![value.into()], Count::from(1)),
            (vec![table.into()], Count::provided(-mult.into())),
        ]);
    }
}

/// A trace whose values are `values` (one a row) and whose multiplicities
/// count the values that fall in the table; a value outside it is left
/// uncounted, so the lookup cannot balance.
fn trace(values: &[u64]) -> RowMajorMatrix<F> {
    assert_eq!(values.len(), HEIGHT);
    let mut mult = vec![0u64; HEIGHT];
    for &v in values {
        if let Some(m) = mult.get_mut(v as usize) {
            *m += 1;
        }
    }
    let mut cells = Vec::with_capacity(HEIGHT * WIDTH);
    for (row, &v) in values.iter().enumerate() {
        cells.extend([F::from_u64(v), F::from_u64(row as u64), F::from_u64(mult[row])]);
    }
    RowMajorMatrix::new(cells, WIDTH)
}

fn in_range_values() -> Vec<u64> {
    // Repeats and gaps, so the multiplicities are not all one.
    (0..HEIGHT as u64).map(|i| (i * i + 7) % (HEIGHT as u64 / 3)).collect()
}

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Setup,
    Prove,
    Verify,
}

/// Proves `trace` and verifies the proof with a separately built verifier
/// configuration.
fn prove_and_verify(trace: &RowMajorMatrix<F>) -> Result<(), Failure> {
    let prover_config: Config = stark_config([7; 32]).map_err(|_| Failure::Setup)?;
    let airs = [RangeLookupAir];
    let prover_data = ProverData::<Config>::from_airs_and_degrees(&prover_config, &airs, &[LOG_HEIGHT])
        .map_err(|_| Failure::Setup)?;
    let traces = [trace];
    let public_values = vec![Vec::new()];
    let instances = StarkInstance::new_multiple(&airs, &traces, &public_values);
    let proof = prove_batch(&prover_config, &instances, &prover_data).map_err(|_| Failure::Prove)?;
    // The lookup columns are committed (after their challenges), the proof
    // carries the AIR's LogUp terminal, and the randomization commitment of
    // zero knowledge is there.
    assert!(proof.commitments.permutation.is_some());
    assert!(proof.lookup_terminals.iter().all(Option::is_some));
    assert!(proof.commitments.random.is_some());

    let verifier_config: Config = stark_config([0; 32]).map_err(|_| Failure::Setup)?;
    verify_batch(&verifier_config, &airs, &proof, &public_values, &prover_data.common).map_err(|_| Failure::Verify)
}

#[test]
fn lookup_air_proves_and_verifies_with_the_shipped_configuration() {
    assert!(HEIGHT >= zk_min_trace_height());
    assert_eq!(prove_and_verify(&trace(&in_range_values())), Ok(()));
}

#[test]
fn lookup_air_refuses_a_value_outside_the_table() {
    let mut values = in_range_values();
    values[HEIGHT / 2] = HEIGHT as u64 + 5;
    let bad = trace(&values);
    let outcome = std::panic::catch_unwind(|| prove_and_verify(&bad));
    if cfg!(debug_assertions) {
        // The library's own lookup check panics while proving, and it must be
        // that check, not a failure anywhere else.
        let payload = match outcome {
            Err(payload) => payload,
            Ok(result) => panic!("the prover's lookup check did not fire: {result:?}"),
        };
        let message = match (payload.downcast_ref::<String>(), payload.downcast_ref::<&str>()) {
            (Some(text), _) => text.as_str(),
            (None, Some(text)) => text,
            (None, None) => "",
        };
        assert!(message.contains("Lookup mismatch"), "unexpected panic: {message}");
    } else {
        // The prover commits an unbalanced running sum and the verifier
        // refuses the proof.
        assert_eq!(outcome.ok(), Some(Err(Failure::Verify)));
    }
}
