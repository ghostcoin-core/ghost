//! The memory the streamed layer prover plans at the real shape of the stage
//! 2 design: a batch of 32 version 2 coin reveals at blowup 2^3 with 96
//! queries, a root over 44 such batches at the same shape, and a shrink of
//! that root at blowup 2^5 with 56 queries. Each layer's modeled peak
//! (`layers::ProverMemory`) is printed by part and must be within the 128 GiB
//! aggregator ceiling. Nothing is proven: the circuits are built for one, two
//! and three slots and their tables planned, as `plan_pipeline` does.

use std::io::Write;

use ghost_proofs::layers::{self, LayerShape, PlannedLayer};

const GIB: f64 = (1u64 << 30) as f64;

fn report(name: &str, layer: &PlannedLayer) {
    let m = &layer.memory;
    let gib = |b: usize| b as f64 / GIB;
    let _ = writeln!(
        std::io::stderr(),
        "modeled: {name}: tables {:?} lanes {:?}; circuit {:.1} GiB, key {:.1} GiB, committed coefficients {:.1} GiB, \
         traces phase {:.1} GiB, quotient phase {:.1} GiB, opening phase {:.1} GiB (openings and folding layers \
         {:.1} GiB above the coefficients), block {:.1} GiB; peak {:.1} GiB of the 128 GiB ceiling",
        layer.heights,
        layer.lanes,
        gib(m.circuit),
        gib(m.key),
        gib(m.committed),
        gib(m.traces_phase),
        gib(m.quotient_phase),
        gib(m.opening_phase),
        gib(m.opening_phase - m.committed),
        gib(m.block),
        gib(m.peak),
    );
}

/// The model holds for the prover the layers prove with: a small circuit
/// keyed and proven by the streamed prover, its extensions cut into blocks
/// down to a single row, gives the library's key and the library's proof
/// byte for byte, and the unchanged verifier accepts it.
fn the_streamed_prover_is_the_librarys() {
    let blocks = layers::streamed_prover_check(&[usize::MAX, 1 << 16, 1]).expect("the streamed prover agrees");
    let _ = writeln!(std::io::stderr(), "measured: main commitment blocks at each budget {blocks:?}");
    // Each table layout: one block, several, one row a block.
    for b in blocks.chunks(3) {
        assert_eq!(b[0], 1, "{blocks:?}");
        assert!(b[1] > 1 && b[2] > b[1], "{blocks:?}");
    }
}

#[test]
fn the_real_shape_batch_and_root_fit_the_128_gib_ceiling() {
    the_streamed_prover_is_the_librarys();
    let child = layers::RevealChild::new(LayerShape::WIDE.num_queries);
    let plan = layers::plan_pipeline(
        &child,
        LayerShape::WIDE,
        child.log_height(),
        32,
        44,
        LayerShape::WIDE,
        LayerShape::SHRINK,
    )
    .expect("the real pipeline plans");
    for (name, layer) in [("batch", &plan.batch), ("root", &plan.root), ("shrink", &plan.shrink)] {
        report(name, layer);
    }
    for (name, layer) in [("batch", &plan.batch), ("root", &plan.root), ("shrink", &plan.shrink)] {
        assert_eq!(layer.modeled_prover_bytes, layer.memory.peak, "{name}");
        assert!(
            layer.memory.peak as u64 <= layers::PROVER_CEILING_BYTES,
            "the {name} plans {:.1} GiB, above the 128 GiB ceiling",
            layer.memory.peak as f64 / GIB
        );
    }
}
