# Poseidon2 reveal prover: results

This page records the first runs of the scale build's reveal prover: item 1 of the build order of stage2-design.md, "Poseidon2 reveal prover". It follows the labels of workload.md: **measured** (actually run, the machine named), **modeled** (a formula or stated inputs) or **not yet established** (with what would produce it).

## What is proven

The statement is the version 2 coin reveal of the ordinary class, `proofs/src/reveal_v2.rs`, unchanged: the same AIR of 2,048 rows by 3,890 columns, the same public values and binding, and its own Keccak-256 hashes of the commitments, the marker and the binding inside the trace. Only the proof system around it changes, in `proofs/src/scale.rs`, beside the shipped Keccak configuration of `proofs/src/stark.rs`, which is untouched:

| Parameter | Shipped configuration | Scale configuration |
|---|---|---|
| Merkle commitments | Keccak-f\[1600\] sponge, 256-bit digest | Poseidon2 over BabyBear, width 24, sponge rate 15 and capacity 9, 9-element digest (279 bits); nodes by the truncated width-24 permutation |
| Transcript | Keccak-256 | Poseidon2 duplex sponge, width 24, rate 15 |
| Challenge field | degree-5 extension of BabyBear | degree-8 extension of BabyBear |
| Queries and blowup | 43 at blowup 2^3 | 96 at blowup 2^3 |
| Grinding | 16 bits on the queries, 16 before batching | 16 bits on the queries, 16 before batching |
| Zero-knowledge | hiding FRI, 5-element salts | hiding FRI, 5-element salts, 8 random codewords |

The prover and verifier are `prove_coin_reveal_v2_scale` and `verify_coin_reveal_v2_scale`. A proof of either configuration is rejected by the other's verifier (tested in `proofs/tests/scale_reveal.rs`). The new code uses no thread, clock, file or operating-system random source and compiles for `wasm32-unknown-unknown`; it is not yet exported from the web app's WebAssembly module.

## Proof size

| Figure | Value | Label |
|---|---|---|
| Proof of the honest plain reveal of `proofs/tests/scale_reveal.rs` | 2,060,987 bytes | measured, 2026-11-02, on the host below |
| Proof of the same reveal under the benchmark's zero-knowledge seed | 2,057,279 bytes | measured, 2026-11-02, on the host below |
| Proof of the same reveal, shipped Keccak configuration | 978,671 bytes | measured, 2026-11-02, on the host below |
| Reveal proof at 96 queries, stage2-design.md | 2,330,908 bytes | modeled |
| Proof field of a version 1 private transaction, spec 07 | 1,310,720 bytes | modeled: the shipped constant `PROOF_FIELD_BYTES` |

The two measured lengths differ only by the randomness: the pruned Merkle multiproofs carry fewer siblings when queries share a path. The measured proof is about 270 KB under the modeled length, and the test `the_proof_is_within_the_modeled_size` holds it to at most 2,330,908 bytes. It does not fit today's proof field of 1,310,720 bytes: the direct path of a single reveal needs the new transaction version that stage2-design.md names, or a reveal always bundled by an aggregator.

## Proving time and memory

`proofs/tests/scale_reveal_bench.rs` proves one reveal at the scale configuration in a fresh test process, reads the wall time and the process peak resident memory (`VmHWM` in `/proc/self/status`), and verifies the proof. It prints the figures; run it with `cargo test --locked --manifest-path proofs/Cargo.toml --test scale_reveal_bench -- --nocapture`. The proof is cold: the first in its process, with the security gate's estimate and the periodic columns' extensions computed inside the timed call.

Host: an aarch64 Linux virtual machine with 16 virtual CPUs on Apple silicon (CPU implementer 0x61, with the SHA3 and SME2 extensions); the guest does not expose the processor model. Native code, the `test` profile at `opt-level = 3`, single-threaded (the `parallel` feature off), toolchain 1.99.1.

| Figure | Run 1 | Run 2 | Ceiling of workload.md | Label |
|---|---|---|---|---|
| Proving time, one reveal, single thread | 3.48 s | 3.44 s | 10 s | measured, 2026-11-02, on the host above |
| Peak resident memory of the process | 579,852 KiB (566.3 MiB) | 579,852 KiB (566.3 MiB) | proposed 1 GiB (1,048,576 KiB) | measured, 2026-11-02, on the host above |
| Verifying time | 0.046 s | 0.046 s | none | measured, 2026-11-02, on the host above |

The host meets both ceilings: 3.48 s against 10 s, and 566.3 MiB against 1 GiB. The host is not a phone, and these are native figures, not WebAssembly in a browser, so they do not say whether a phone meets the ceilings.

## Not yet established

- The proving time and memory on the emulated mid-range phone and on named physical phones: not yet established; set by phone-protocol.md, steps 4 to 7, run with the new prover once it is exported from the web app's WebAssembly module. The host measurement above stands in for them here.
- The proving time with eight threads (the `parallel` feature): not yet established; set by the same benchmark built with `--features parallel`.
- The security write-up of the scale configuration: not yet established. The crate's gate runs the library's estimator on the reveal at these parameters (with the 247-bit challenge field and the 139-bit collision resistance of a 279-bit digest) and refuses it below 128 conjectured bits with grinding counted at half; the proven whole-bundle bound of stage2-design.md is not checked by it.
