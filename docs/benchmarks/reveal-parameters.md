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
proof field of 1,310,720 bytes. Later changes to the prover alone bring the
median to about 1.2 s ([A faster prover at the same
parameters](#a-faster-prover-at-the-same-parameters), [Periodic columns
computed once](#periodic-columns-computed-once), [Leaf rows hashed one at a
time](#leaf-rows-hashed-one-at-a-time)), still over the 1,000 ms that the
browser target asks of this machine. `proofs/tests/prove_speed.rs` holds the
gain with a coarse regression budget of 10,000 ms ([The budget](#the-budget)); the
rest of the gap is left for a threaded or SIMD build.

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

## A faster prover at the same parameters

Measured 2026-10-21 on the same machine and toolchain, with
`proofs/tests/prove_speed.rs`: one warm-up proof, not counted, then 9 proofs
with 9 zero-knowledge seeds, each timed and verified, for the coin reveal and
the salted coin reveal (the same trace sizes as above), on one thread, in the
release profile. The parameters, the constraints, the proof format and the
verifier are unchanged, and so are the commitments: the transcript, and so
the proof made from a given seed, are the parent commit's.

What changed, in `proofs/src`:

- **The Merkle leaf hash** (`stark.rs`, `MerkleLeafHash`). The library hashes
  a committed row by streaming it through a generic serializer, packed rows
  transposed lane by lane. The new hasher computes the same digest straight
  from each row: field elements in their internal form, two to a 64-bit lane,
  the padding-free Keccak-f[1600] sponge at rate 136 bytes. The tree hands it
  whole rows, a vector's width at a time.
- **The permutation** (`hash.rs`, `keccak_f`). Keccak-f[1600] written round by
  round on a local copy of the state: 131 ns against 147 ns for the library's
  two-lane NEON permutation on this machine (aarch64 without the SHA3
  instructions), so it runs each lane there. Elsewhere the library's vector
  permutation is kept (SHA3 instructions, AVX2, AVX-512, wasm SIMD), so the
  browser build keeps the permutation it was measured with.
- **The constraint evaluation** (`air.rs`). The statement's constraints read
  the trace rows in place instead of copying both 3,808-column rows on every
  evaluation, and build only the next row's bytes that a link or a tree node
  reads. Every constraint is the same expression, in the same order.

The commitments are the library's: unit tests in `stark.rs` compare the leaf
hash with the library's for every row shape (empty, part blocks, whole
blocks, the salted reveal's committed width; one row, batches, packed rows)
and whole trees with the same salts, and the security gate checks the
permutation and the leaf hash against the library's on a probe before any
proof is made.

| Run | Coin reveal, median | Coin reveal, slowest | Salted coin reveal, median | Salted coin reveal, slowest |
|---|---|---|---|---|
| Before (the table above, 2026-10-20) | 1,352 ms | 1,375 ms | | |
| After, run 1 | 1,245 ms | 1,364 ms | 1,220 ms | 1,270 ms |
| After, run 2 | 1,196 ms | 1,215 ms | 1,209 ms | 1,412 ms |

The parent commit, timed here the same day with the same witness, took 1,363
to 1,410 ms a proof (5 proofs after a warm-up), so the change saves about
150 ms a proof, about 11%.

| Run | Coin reveal, every proof (ms) | Salted coin reveal, every proof (ms) |
|---|---|---|
| After, run 1 | 1,199.0; 1,179.2; 1,205.4; 1,244.1; 1,323.7; 1,363.8; 1,309.6; 1,345.7; 1,245.2 | 1,217.8; 1,212.1; 1,219.7; 1,261.7; 1,218.5; 1,229.7; 1,255.6; 1,269.7; 1,216.6 |
| After, run 2 | 1,196.6; 1,185.3; 1,193.0; 1,215.0; 1,185.1; 1,209.6; 1,214.6; 1,187.5; 1,195.6 | 1,189.1; 1,186.0; 1,162.9; 1,228.5; 1,180.7; 1,208.5; 1,238.7; 1,412.2; 1,268.8 |

### The budget

The browser takes about twice the native time (2.72 s warm in Chrome against
1.35 s native) and the phone of the browser measurement about four times the
Mac Studio, so the phone needs a native median of at most **1,000 ms** on this
machine. The best median measured is 1,196 ms (coin reveal) and 1,209 ms
(salted), about 200 ms over, so that floor is not met on one thread.

The `MEDIAN_BUDGET_MS` of `prove_speed.rs` is therefore a coarse regression
guard, **10,000 ms**, loose on purpose so that it holds on both machines
that run the test:

| Machine | Proving median (both coin reveals) |
| -- | --: |
| aarch64 build host (this page's measurements, quiet machine) | 1,191 ms and 1,154 ms |
| GitHub-hosted x86_64 CI runner (no vector field arithmetic) | about 4.5 s |

The shared build host's load also swings proving time by about 1.5 times, so
the test catches only a gross slowdown, and the quiet-machine medians of the
build host are the record of the prover's speed. The rest of the gap to 1,000 ms is left for a threaded or
SIMD build.

Where a proof's time goes after the change, from one profiled proof:

| Step | Time | Of which |
|---|---|---|
| Trace commitment | 805 to 855 ms | the 8-coset LDE of 4,096 rows by 3,813 columns, about 245 ms; the leaf hashes of its 32,768 rows, 3.7 million Keccak-f[1600] permutations at 131 ns, about 485 ms |
| Quotient values (16,384 rows) | about 195 ms | the library's fixed cost per row (row gathering, periodic columns, folding), about 83 ms; the Keccak-f constraints, about 68 ms; the statement's own, about 45 ms |
| Opening (out-of-domain values, FRI batching and folding, grinding) | 100 to 150 ms | |
| Quotient and randomization commitments | about 47 ms | |

Most of what is left is fixed by the parameters and the library. The
permutation count follows from the trace, the blowup and the hash; 131 ns is
the scalar floor here, and a faster permutation needs vector instructions
that safe Rust in this crate cannot call (the library's SHA3-instruction
kernel is not built for this target). The LDE, the opening and the
quotient's fixed cost are library code, and the constraint count and degree
are part of the proof's shape. The rest of the gap is left for a threaded or
SIMD build.

### Periodic columns computed once

Measured 2026-10-22 on the same machine and toolchain, with
`proofs/tests/prove_speed.rs` as above. The parameters, the constraints, the
proof format, the verifier and the commitments are unchanged.

A timeline of one coin reveal proof, taken with timers on the DFT, the leaf
hasher and the constraint evaluation (removed again), showed a cost the
profile above had folded into the quotient: before the quotient is evaluated,
the library extends every periodic column of the statement (its selectors and
byte constants, 290 columns of 2,048 rows for the coin reveal) to the
quotient domain with one single-column LDE each, on every proof, about 57 ms.
Those columns depend on the statement alone.

What changed, in `proofs/src/stark.rs`: the DFT of the configuration
(`MemoDft`) is the library's `Radix2DitParallel` for every batch transform,
with its twiddles shared by every configuration, and it remembers the LDE of
a single column, keyed by the column, the shift and the blowup, after the
library has computed it once: at most 64 MiB, the coin reveal's columns at
most a third of that. A unit test holds the periodic tables built through it
to the library's, cell by cell, for both coin reveals at two shifts and two
blowups, computed and remembered.

| Run | Coin reveal, median | Coin reveal, slowest | Salted coin reveal, median | Salted coin reveal, slowest |
|---|---|---|---|---|
| Before (parent commit, timed here the same day) | 1,244 ms | 1,354 ms | 1,266 ms | 1,375 ms |
| After, run 1 | 1,199 ms | 1,216 ms | 1,184 ms | 1,484 ms |
| After, run 2 | 1,191 ms | 1,234 ms | 1,154 ms | 1,182 ms |

| Run | Coin reveal, every proof (ms) | Salted coin reveal, every proof (ms) |
|---|---|---|
| After, run 1 | 1,165.3; 1,173.4; 1,198.8; 1,208.6; 1,172.3; 1,213.3; 1,216.0; 1,172.3; 1,201.7 | 1,154.5; 1,183.9; 1,175.6; 1,227.6; 1,158.9; 1,189.7; 1,191.2; 1,483.6; 1,183.1 |
| After, run 2 | 1,182.0; 1,201.9; 1,234.1; 1,220.1; 1,164.6; 1,218.9; 1,190.5; 1,164.9; 1,176.7 | 1,154.2; 1,181.7; 1,169.0; 1,152.8; 1,145.6; 1,144.1; 1,173.4; 1,177.3; 1,146.6 |

The 1,000 ms floor is still not met: the best medians are 1,191 ms and
1,154 ms, well within the 10,000 ms regression budget. The machine itself varies by several
per cent between runs (the same permutation measured 136 to 161 ns in one
day), so medians a few tens of milliseconds apart are not told apart.

Where a coin reveal proof's time goes before this change, from the timeline
(about 1,240 ms in all):

| Step | Time | Who decides it |
|---|---|---|
| Randomizing the trace for zero-knowledge, before the LDE | about 34 ms | the library |
| LDE of the 4,096-row randomized trace, 3,813 columns, to 32,768 rows | 250 to 290 ms | the library's DFT |
| Leaf hashes of the 32,768 rows (3.7 million permutations) and the tree | about 550 ms | the parameters and the hash |
| Periodic column LDEs | about 57 ms, now about 0 after the first proof | this change |
| Quotient values: the statement's constraints | about 67 ms | the constraints |
| Quotient values: the library's row gathering and folding | about 59 ms | the library |
| Quotient and randomization commitments | about 35 ms | the library |
| Opening (out-of-domain values, batching, FRI, both grindings) | about 175 ms | the library and the parameters |

Tried and dropped, measured with the same build:

- Keccak-f[1600] on vector registers beside the scalar one: plain Rust
  over pairs of lanes (left to the compiler) takes 154 ns a state, one scalar
  state and two such lanes interleaved round by round 142 to 145 ns, two
  scalar states interleaved 140 to 143 ns, against 136 ns for one scalar state.
  The NEON intrinsics themselves need `unsafe` to be called from this crate
  (they are `#[target_feature]` functions), and the SHA3 instructions, which
  the library's fastest aarch64 permutation uses, need a target feature the
  build does not enable, so neither is used.
- The scalar permutation unrolled by 2, 4 or all 24 rounds: 136 to 148 ns,
  no faster.

About 830 ms of the proof is fixed by the parameters and the library (the
leaf hashes at the scalar floor, the opening, the randomization, the
quotient's bookkeeping and the smaller commitments). Even if the LDE and the
constraint evaluation, the parts this crate could still rewrite, were made
30% and 40% faster (about 75 and 27 ms), a proof would take about 1,090 ms.
So the 1,000 ms floor is out of reach at these parameters on one thread of
this machine.

### Leaf rows hashed one at a time

Measured 2026-10-22, later the same day, on the same machine and toolchain,
with `proofs/tests/prove_speed.rs` as above. The parameters, the
constraints, the proof format, the verifier and the commitments are
unchanged.

On aarch64 without the SHA3 instructions the tree handed the leaf hasher
rows two at a time, which it wrote into a two-lane state, and every
permutation then copied each lane out, through `keccak_f` and back: about
200 loads and stores around each 131 ns permutation. What changed, in
`proofs/src/stark.rs` and `proofs/src/hash.rs`: on that target the leaf
hasher hashes each row on its own, the state passed from block to block by
value through the permutation inlined into the loop (`keccak_f_inline`),
and only the rate lanes read from the row. Elsewhere, the browser's wasm
build included, the hasher is unchanged. The unit tests that hold the leaf
hash to the library's, row shape by row shape, now run this path.

Timers on the leaf hasher, the DFT and the constraint evaluation in the
same build (removed again) gave, over the 20 proofs of one run:

| Step, per coin reveal proof | Before | After |
|---|---|---|
| Leaf hashes (`hash_many`), fastest proofs | 549 to 551 ms | 524 to 531 ms |
| LDE of the trace, fastest proofs | 275 to 284 ms | 267 to 281 ms, not changed |
| Constraint evaluation | about 70 ms | about 70 ms, not changed |

So the change saves about 20 to 25 ms a proof, 2%. The proof medians of the
day cannot show that much: the machine ran slower and less evenly than in
the runs above all day (with the timers in, the library's prove alone took
1,254 to 1,757 ms a coin reveal proof on the parent commit's code).

| Run | Coin reveal, median | Coin reveal, slowest | Salted coin reveal, median | Salted coin reveal, slowest |
|---|---|---|---|---|
| After, run 1 | 1,332 ms | 1,630 ms | 1,238 ms | 1,457 ms |
| After, run 2 | 1,305 ms | 1,357 ms | 1,256 ms | 1,387 ms |

| Run | Coin reveal, every proof (ms) | Salted coin reveal, every proof (ms) |
|---|---|---|
| After, run 1 | 1,184.8; 1,203.2; 1,331.5; 1,458.3; 1,629.6; 1,298.6; 1,435.0; 1,260.4; 1,340.1 | 1,295.8; 1,456.9; 1,190.1; 1,265.9; 1,237.7; 1,163.5; 1,188.6; 1,184.2; 1,242.0 |
| After, run 2 | 1,192.3; 1,240.6; 1,275.7; 1,304.8; 1,305.2; 1,355.6; 1,293.1; 1,314.7; 1,357.0 | 1,248.1; 1,204.8; 1,256.3; 1,298.9; 1,283.3; 1,258.3; 1,386.8; 1,246.3; 1,255.0 |

Tried and dropped, each checked against the library value for value and
timed in the same process as the code it would replace:

- **An LDE a strip of columns at a time.** The trace's coset LDE computed
  16 columns at a time (a 64-byte piece of each row): the strip gathered in
  bit-reversed row order, an inverse transform to its coefficients, then
  for each of the 8 cosets the coefficients weighted by the powers of the
  coset's shift and a forward transform whose bit-reversed output is the
  order the commitment stores. Its output was the library's, cell for cell,
  but it took 375 to 440 ms where the library's took 265 to 305 ms. The
  library's transform is close to the cost of its butterflies with the
  packed field arithmetic this crate can call, and the strips write the
  500 MB output a short piece of a row at a time.
- **Keccak-f[1600] with the rho rotations owed instead of applied.** Every
  rotation of a round moved into the second operand of an exclusive or or an
  and-not with a constant amount (which AArch64 computes in the same
  instruction), the rotations paid once after the 24th round. The result is
  the library's permutation, but it took 196 to 211 ns against 131 to 139 ns
  for the round-by-round one, and 233 to 251 ns with each round a separate
  function. The compiler already folds most of the rotations of the
  round-by-round permutation.

The best medians measured with the change are 1,305 ms (coin reveal) and
1,238 ms (salted), on the slow day; by the timers the change takes about
20 ms off the 1,191 ms and 1,154 ms measured before it. The 1,000 ms floor
is still not met. What is
left is as the timeline above describes: about 485 ms of permutations at the
scalar floor, about 275 ms of LDE at the library's floor, and about 350 ms
of library code (the randomization, the quotient's bookkeeping, the
smaller commitments, the opening and FRI).

### Outcome against the 1,000 ms floor

The 1,000 ms native floor is **not met** on one thread at the shipped
parameters (blowup 2^3, 43 queries, grinding unchanged):

| Proof | Before this work | Best median measured | Gap to 1,000 ms |
| -- | --: | --: | --: |
| Coin reveal | 1,352 ms | 1,191 ms | 191 ms |
| Salted coin reveal | not timed | 1,154 ms | 154 ms |

The revised decision of 2026-10-22 accepts this miss: the change ships the
measured gain, about 12% off the coin reveal's 1,352 ms, held by the 10,000 ms regression budget of `prove_speed.rs`. It is recorded
here, not as a stop of the work. The remaining gap of about 150 to 200 ms is
left to a separate change (a multi-thread or vector build of the prover),
and the browser figures are to be measured again after merge.

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
| Trace, salted data reveal | 1,024 rows by **3,802 columns** |
| Trace, salted proof of holding | **2,048 rows** (79 permutations: the low leaf of the absence witness and its 40 nodes up to `marker_set_root` added) by **3,802 columns** |
| `MAX_TRACE_WIDTH` | 3,824 columns, unchanged: the salted coin reveal stays the widest statement |
| Proof field, `PROOF_BYTES` | 1,310,720 bytes, unchanged |

The widths are measured from the shipped configuration's report in
`proofs/tests/salted_data.rs`; the salted proof of holding's 2,048 rows
follow from its schedule (1,896 rows padded to a power of two) and were not
re-measured. No parameter changes; the conjectured bits
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
