# Reveal proof parameters for the post-quantum rule

The coin reveal proof moves from blowup 2^2 with 57 queries to **blowup 2^3
(rate 1/8) with 43 queries**, so that it meets the rule of
[specification 09, section 4.1](../spec/09-quantum-safe-accounts.md): 129
conjectured bits from the queries alone, and at least 128 for every term of the
library's estimator with grinding counted at half. This page records the native
measurements before and after the change, on the build machine.

**Result.** Proofs are about 19% smaller (median 957,516 bytes, from
1,187,533) and proving takes about 1.6 times as long (median 1.35 s, from
0.84 s), as decision 0003 measured for blowup 2^3. Verification is unchanged
at about 8 ms. Every proof is within the new bound of 1,053,331 bytes and the
proof field of 1,310,720 bytes.

## What was run

- The prover and verifier: `ghost_proofs::prove_coin_reveal` and
  `ghost_proofs::verify_coin_reveal`, the coin reveal, natively, single
  threaded (the `parallel` feature off), in the release profile of
  `proofs/Cargo.toml` (`opt-level = 3`, `codegen-units = 1`), run through
  `cargo test --release --locked`.
- The witness: the spec 01 example coin of 1 GHOST in the two-leaf coin tree of
  spec 05, the partial reveal of `[conservation-partial-reveal]` (the example
  of `proofs/tests/properties.rs`), trace 2,048 rows by 3,808 columns before
  zero-knowledge padding.
- Each configuration: one warm-up proof, not counted, then 9 proofs with 9
  different zero-knowledge seeds, each proved, timed, verified and timed. The
  proof length is the serialized proof before it is padded to the field.
- The same machine, toolchain and harness for both configurations, run one
  after the other on 2026-10-20. The "before" run is the parent commit's
  parameters; the "after" run is this change.

### Machine

| Item | Value |
|---|---|
| Machine | The build machine: an aarch64 Linux virtual machine (kernel 6.8.0) on Apple silicon (CPU implementer 0x61), 16 cores, 47 GiB of memory, in the build sandbox |
| Rust | rustc 1.99.1 (58cf8f9c3 2026-10-13), LLVM 23.1.1, host `aarch64-unknown-linux-gnu` |
| Library | Plonky3 `f98331687e47106a64ab82a77e2e1d0d66c9161b` |
| Threads | One: the prover is built without the `parallel` feature |

## Results

| Configuration | Proof size, median | Proof size, largest | Proving, median | Proving, slowest | Verifying, median | Verifying, slowest |
|---|---|---|---|---|---|---|
| Before: blowup 2^2, 57 queries | 1,187,533 bytes | 1,189,665 bytes | 835 ms | 868 ms | 8.58 ms | 9.34 ms |
| After: blowup 2^3, 43 queries | 957,516 bytes | 961,981 bytes | 1,352 ms | 1,375 ms | 8.08 ms | 10.61 ms |
| After / before | 0.81 | 0.81 | 1.62 | 1.58 | 0.94 | 1.14 |

The proof field, `PROOF_BYTES`, stays 1,310,720 bytes. The bound
`proof_length_bound` derives for the budget trace (2,048 rows by 3,808
columns) falls from 1,268,539 bytes to 1,053,331, 257,389 bytes below the
field (spec 07, section 3).

### Every proof

| Configuration | Proof sizes (bytes) |
|---|---|
| Before | 1,186,382; 1,189,087; 1,187,533; 1,188,203; 1,189,665; 1,188,239; 1,186,335; 1,186,270; 1,184,619 |
| After | 961,981; 960,023; 955,741; 957,516; 957,696; 954,991; 960,210; 957,174; 956,784 |

| Configuration | Proving times (ms) |
|---|---|
| Before | 801.3; 868.3; 825.7; 835.4; 856.5; 850.2; 804.0; 848.0; 789.7 |
| After | 1,366.4; 1,327.2; 1,370.6; 1,332.5; 1,361.4; 1,352.0; 1,374.6; 1,351.1; 1,304.4 |

| Configuration | Verifying times (ms) |
|---|---|
| Before | 8.58; 9.33; 8.42; 9.34; 9.29; 8.45; 9.17; 8.42; 8.32 |
| After | 7.94; 8.03; 10.61; 8.93; 8.00; 7.94; 8.39; 8.28; 8.08 |

## The salted coin reveal (version 2)

The reveal of a salted (version 2) commitment, `prove_salted_coin_reveal` and
`verify_salted_coin_reveal`, holds the 16-byte salt as a private witness in
16 carried columns, read by both the fingerprint and the marker. Its trace is
2,048 rows by **3,824 columns**, 16 more than the version 1 coin reveal's
3,808, which is unchanged. The budget `MAX_TRACE_WIDTH` rises from 3,808 to
3,824 for it; the height, the field, the queries, the rate and every other
parameter stay as above.

| Figure | Value |
|---|---|
| Trace width, version 1 coin reveal | 3,808 columns |
| Trace width, salted coin reveal | 3,824 columns |
| Bytes per extra column in `proof_length_bound` (2 challenges of 20 bytes, 43 queries of 4) | 212 |
| `proof_length_bound` at 2,048 by 3,824 | 1,056,723 bytes (from 1,053,331), 253,997 below the field |
| Salted proof measured (one proof, the largest made) | 960,087 bytes |
| Proof field, `PROOF_BYTES` | 1,310,720 bytes, unchanged |

The measured proof is the salted example of `proofs/tests/salted_reveal.rs`
(zero-knowledge seed 1), serialized before padding to the field, measured on
2026-10-21 in that test's run (debug assertions on, so not timed). It is in
the range of the version 1 proofs above (954,991 to 961,981 bytes): the 16
columns add at most 3,392 bytes to the bound.

## The salted data reveal and proof of holding (version 2)

The data reveal (S2) and the proof of holding (S3) of a salted (version 2)
data commitment, type `0x02 0x02`, are two statements beside the version 1
ones, `Statement::SaltedDataReveal` and `Statement::SaltedHold`. Each holds
the 16-byte salt as a private witness in 16 carried columns right after `b`,
read by both the data fingerprint and the data marker under their `v2` tags.
The public fields and binding layouts are those of version 1.

| Figure | Value |
|---|---|
| Trace, version 1 data reveal and proof of holding | 1,024 rows by 3,786 columns, unchanged |
| Trace, salted data reveal and proof of holding | 1,024 rows by **3,802 columns** |
| `MAX_TRACE_WIDTH` | 3,824 columns, unchanged: the salted coin reveal stays the widest statement |
| Proof field, `PROOF_BYTES` | 1,310,720 bytes, unchanged |

The widths are measured from the shipped configuration's report in
`proofs/tests/salted_data.rs`. No parameter changes; the conjectured bits
with grinding counted at half stay at least 128 for both, and their proof
length bound is below the budget trace's 1,056,723 bytes.

## Security figures

From the library's estimator (`p3-uni-stark` `StarkSecurityParams`, through
`p3-security`), for the coin reveal at the shipped trace size, width and
constraint degree. The data reveal and the proof of holding (1,024 rows by
3,786 columns) report the same totals. The quantum figures are half the
classical ones (the quantum Fiat–Shamir bound of spec 09, section 4.1).

| Figure | Before (2^2, 57) | After (2^3, 43) |
|---|---|---|
| Queries alone, `log2(1/rate) * queries` | 114 | 129 |
| Conjectured, classical | 128 | 128 |
| Conjectured, classical, grinding counted at half (the gate) | About 120, computed from the estimator's query formula (57 × 1.97 + 8), not run | 128 |
| Conjectured, quantum | 64 | 64 |
| Proven, classical | 72 | 80 |
| Proven, quantum (a goal, not gated) | 36 | 40 |

After the change, term by term, with the grinding at each site counted at half
(8 of the 16 bits at the queries and at the batching challenge):

| Term | Bits |
|---|---|
| FRI queries (random-words estimate, 43 queries at rate 1/8, plus 8) | 135 |
| Batched openings (7,716 functions over a 2^15 codeword in a field of about 2^154, plus 8) | 134 |
| DEEP-ALI, constraint composition and FRI folding | 138 or more |
| Keccak-256 collision resistance | 128 |

So the binding term is the hash's collision resistance, and every
extension-field term is above 128. With no grinding at all, the batching term
would be 126 bits and the query term 127: the rule needs the grinding it counts
at half there, which is why both sites keep 16 bits. The proven figure stays
below 64 quantum bits; spec 09, question 3 makes it a goal, not a gate.

The gate is `proofs/src/stark.rs`. The tests that hold it are
`shipped_configuration_meets_quantum_rule` (`proofs/tests/properties.rs`) and
`gate_refuses_a_configuration_below_the_quantum_rule` (`proofs/src/stark.rs`).

## Not measured here

Proving time on other devices and in WebAssembly is measured separately, in
[reveal-results.md](reveal-results.md). In the browser, measured 2026-10-21,
the 10-second proving target holds on the Mac Studio (warm median 2.72 s) but
not on the emulated mid-range phone, not a real device (warm median 13.15 s,
slowest cold proof 17.39 s).
