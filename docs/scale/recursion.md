# One Ghost reveal proof entering recursion: a cost proxy

This page measures what it costs, in a proxy, for one real Ghost coin reveal proof to enter recursion, for each of the three architectures of security.md, with the first (conversion) layer apart from later merges, and judges each against the aggregator ceilings of workload.md rather than by relative speed. It is part of the first stage (feasibility and security) of the scale work and follows the rules of designs.md. The test is benchmarks/reveal/tests/recursion_proxy.rs, the records it wrote are docs/scale/recursion-proxy.jsonl, and the fleet arithmetic is benchmarks/scale/recursion_costs.py, tested by benchmarks/tests/test_scale_recursion.py.

Every figure carries one of the labels of workload.md: measured (actually run, machine named), modeled (formula or stated inputs) or not yet established (with what would produce it). A figure of the proxy proof itself is labelled **measured (proxy)**; anything scaled from it is **modeled**.

**What the proxy is.** A recursive verifier of a Keccak leaf proof must compute, inside its own trace, every Keccak-f\[1600\] permutation the native verifier computes. The proxy proves exactly that many permutations with the pinned `p3-keccak-air` and nothing else. It proves the cost of re-proving a verifier's hash work, not a full recursive verifier: no FRI folding arithmetic, no constraint evaluation at the out-of-domain point, no binding of the child's statement, verifier key, contents, count, chain or versions. So every proxy figure is a lower bound on a real layer built from this AIR at these parameters, never the cost of a real recursive merge (all figures below are measured (proxy) or modeled on that basis). No figure on this page is a Plonky3-recursion or a leanMultisig measurement: neither can be built where this was written. <!-- no-figure -->

**Result.** Architecture (a), Keccak leaves to Keccak aggregation, misses the aggregator ceilings in the proxy already (modeled): a merge's hash work alone, at the shipped leaf parameters, is about 14.44 s on one 32-core machine at perfect speedup against the 0.3 s ceiling, its trace's low-degree extension alone is 164.875 GiB against 128 GiB, and one block's 3,499 merges need at least 1,263.03 s on 40 machines against a 30 s block (all modeled). Architectures (b) and (c) are not yet established: they need an in-circuit Poseidon2 verifier, which the pinned dependencies do not have.

## What was run

On 2026-10-24, one run of the quick path, on a Linux virtual machine on Apple silicon: aarch64, `/proc/cpuinfo` giving CPU implementer 0x61 (Apple) and part 0x000 with no model name, 16 logical CPUs, 47 GiB of memory, each run capped at 6 GiB by the sandbox (measured: read from the machine; the records carry the same CPU string). The prover ran on one thread: the crates are built without their `parallel` feature, as `ghost-proofs` ships.

```text
env RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN=1.99.1 GHOST_SCALE_QUICK=1 cargo test --release --locked --manifest-path benchmarks/reveal/Cargo.toml --test recursion_proxy
```

The test does three things. <!-- no-figure -->

1. It makes one real coin reveal proof with `Session` (witness seed 11) through the real prover, `prove_coin_reveal` in the shipped configuration, and verifies it with `verify_coin_reveal`. It decodes the proof's bytes as a proof of the shipped configuration rebuilt from the library's own types, and the decoded proof encodes back to the same bytes, so the types agree (measured: the test asserts it).
2. It counts the Keccak-f\[1600\] permutations a verifier of that proof performs, by role, derived from the shipped constants of `ghost-proofs` (43 queries, blowup 2^3, the trace of 2,048 rows by 3,808 columns, its constraint degree, 5 random codewords and 5 salt elements a leaf, 17 lanes a leaf permutation) and checked against an independent recount from the decoded proof's own vectors: every query's opened rows and salts, every folding round's siblings, every opened value and commitment. The two agree exactly (modeled: `ghost-proofs` exposes no hook that counts permutations while it verifies, so the count is a derivation, not a count of a run).
3. It proves that many permutations with `p3-keccak-air` and `p3-uni-stark` from the pinned Plonky3 revision f98331687e47106a64ab82a77e2e1d0d66c9161b, at the shipped leaf parameters (`keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk`, the configuration of decision 0003, rebuilt with the library's Keccak-f\[1600\] in the same padding-free sponge), once untimed and then five times timed, trace generation included, and records the median, the slowest and the proof bytes (measured (proxy)). It then verifies the proxy proof with permutations that count themselves, and checks the derivation against that count (below).

Permutations a verifier of the real reveal proof performs (modeled: derived and recounted from the proof, see step 2):

| Role | Per query | Permutations | Label |
|---|---|---|---|
| Merkle paths: two-to-one compressions, one permutation each | 147: three input trees of 15 levels, and the 12 folding trees of 14 down to 3 levels | 6,321 | modeled |
| Leaf hashes, 34 elements (17 lanes) a permutation | 130: the randomization row 1, the trace row of 3,818 elements 113, the 8 quotient chunks 4, one a folding round 12 | 5,590 | modeled |
| Keccak-256 transcript | about 155 KB absorbed, mostly the 7,701 opened values, and the samples | 1,159 | modeled |
| Total | | 13,070 | modeled |

The count is that of a verifier of fixed shape, as a recursive verifier's circuit must be: every query's leaves and full paths, nothing shared between queries. The native verifier shares path nodes between queries (pruned multiproofs), so it performs fewer. On the 2,048-row proxy proof, whose shape the test can count because it builds that configuration itself, the counting verifier performed 3,192 compressions, 3,979 leaf permutations and 820 transcript permutations (measured: counted while verifying, on the machine above) against 11,206 derived for a fixed shape (modeled). The test asserts that the derived compressions and leaf permutations are never fewer than the counted ones and that the transcript model, which leaves out the library's step labels and sampling retries, is at or under the counted transcript: 800 against 820 there (modeled against measured).

The proxy proofs of this run (measured (proxy), five warm repeats on the machine above, one prover thread):

| Layer | Permutations | Trace rows | Median | Slowest | Proof bytes | Label |
|---|---|---|---|---|---|---|
| Conversion, quick size | 85 | 2,048 | 0.864547 s | 0.868414 s | 710,529 | measured (proxy) |
| Merge, quick size | 170 | 4,096 | 1.766970 s | 1.781115 s | 729,881 | measured (proxy) |

These are the quick path's sizes, not the counted ones. The counted sizes are 13,070 permutations for the conversion layer and 26,140 for a merge, 524,288 and 1,048,576 rows of `p3-keccak-air`, whose low-degree extensions alone take 82.4375 GiB and 164.875 GiB at the shipped parameters (modeled: rows doubled for zero knowledge, times the blowup of 8, times 2,638 columns of 4 bytes), past the 6 GiB this run was allowed. So the figures at the counted sizes are modeled from the two proxies: the cost per row past the smaller one, 0.000440636 s (modeled: the difference of the medians over the difference of the rows, which removes what both pay whatever their size, such as the 16 + 16 bits of grinding), times the rows. Per-row cost does not fall as a trace grows (the transforms grow with the logarithm of the size, and memory traffic does not shrink), so the extrapolation is a lower bound on this machine (modeled).

| Layer | Permutations | Trace rows | One thread | Label |
|---|---|---|---|---|
| Conversion, counted size | 13,070 | 524,288 | 231.020419 s | modeled |
| Merge, counted size | 26,140 | 1,048,576 | 462.040838 s | modeled |

The full path, which would replace both rows above with measured (proxy) figures, is not yet established. It is the same command without `GHOST_SCALE_QUICK` and with `GHOST_SCALE_RECORDS_DIR=docs/scale`, on a machine with at least 192 GiB of memory (not yet established: the 164.875 GiB of the merge trace's extension is modeled, before the quotient and the Merkle trees); at one thread it would take about 15 minutes for the conversion proofs and 31 for the merge proofs, untimed run included (modeled from the rows above).

## Architecture (a): Keccak leaves, Keccak aggregation

Every layer is a STARK of the shipped configuration whose trace computes Keccak-f\[1600\] to verify its children, as the proxy does (modeled). The fleet figures, from benchmarks/scale/recursion_costs.py on the committed records, with the 32 cores of an aggregator machine used perfectly (a lower bound: the proxy ran on one thread) and the ceilings of workload.md (the rows of (b) and (c) are there because the script reports every architecture):

| Architecture | Layer | Record | Permutations | Trace rows | Seconds a proof, one machine | Machine-seconds a block | Least wall time on the machines | Trace LDE |
|---|---|---|---|---|---|---|---|---|
| (a) Keccak leaves, Keccak aggregation | conversion | modeled | 13,070 | 524,288 | 7.22 s (modeled) | 25,267.86 for 3,500 (modeled) | 631.70 s (modeled) | 82.438 GiB (modeled) |
| (a) Keccak leaves, Keccak aggregation | merge | modeled | 26,140 | 1,048,576 | 14.44 s (modeled) | 50,521.28 for 3,499 (modeled) | 1,263.03 s (modeled) | 164.875 GiB (modeled) |
| (b) Keccak leaves, Poseidon2 aggregation | conversion | none: not yet established | | | | | | |
| (b) Keccak leaves, Poseidon2 aggregation | merge | none: not yet established | | | | | | |
| (c) Poseidon2 leaves, Poseidon2 aggregation | conversion | none: not yet established | | | | | | |
| (c) Poseidon2 leaves, Poseidon2 aggregation | merge | none: not yet established | | | | | | |

- (a) Keccak leaves, Keccak aggregation: missed (modeled)

Against each ceiling (all modeled):

- Time for one merge, 0.3 s: a merge's hash work alone takes at least 14.44 s on one machine, 48 times the ceiling (modeled).
- Memory per machine, 128 GiB: the merge trace's low-degree extension alone is 164.875 GiB (modeled), so a merge at these parameters does not fit one machine; the conversion trace's 82.438 GiB does (modeled), before its other buffers.
- Machines, 40, and the 30 s block: one block's 3,499 merges need 50,521.28 machine-seconds and at least 1,263.03 s of wall time, and its 3,500 conversions 25,267.86 machine-seconds and at least 631.70 s more (modeled), where the 0.3 s ceiling allows 1,049.7 and 26.2425 (modeled in workload.md).

Later merges verify two proofs of a merge's own shape, not two reveal proofs: 40,228 permutations (modeled: the same derivation applied to a `p3-keccak-air` proof of 1,048,576 rows), which still fit 1,048,576 rows, so the tree's proofs settle at that trace height and every merge costs what the merge proxy above costs (modeled).

What the verdict does and does not rest on. It rests on the proxy being a lower bound: a real merge built from `p3-keccak-air` at these parameters has at least these rows and columns (modeled). It does not cover another arithmetization of Keccak-f\[1600\] (fewer columns, lookups, or a binary field), other layer parameters (a smaller blowup, or no hiding in the aggregation layers, which changes the security argument of security.md), or several threads that beat perfect speedup, which none can. security.md also asks for 92 queries rather than 43 for the whole bundle to reach its query-phase bound, which would raise the counted permutations further (modeled; the count at 92 queries is not yet established: the command is this test with the query constant changed, a change of proofs/ outside this piece). The leaf proof itself is also Keccak inside: its 2,048-row trace already runs `p3-keccak-air` on at most 85 permutations of its own (modeled), the same AIR the proxy uses.

## Architecture (b): Keccak leaves, Poseidon2 aggregation

The conversion layer verifies a Keccak leaf inside a trace whose own commitments and transcript are Poseidon2 over BabyBear width 24. Its in-circuit hash work is the leaf verifier's, whatever the outer hash: the same 13,070 Keccak-f\[1600\] permutations (modeled), so with `p3-keccak-air` at least 524,288 rows and an extension of at least 82.438 GiB at the shipped parameters (modeled lower bounds from the count above). Its proving time is not yet established: committing that trace with Poseidon2 instead of Keccak-256 changes the outer hashing, so the Keccak proxy's seconds do not carry over.

Everything after the conversion layer is not yet established for (b): a merge verifies Poseidon2 proofs, so it needs an in-circuit Poseidon2 verifier, and the pinned dependencies have none.

- Missing dependency: a Poseidon2 AIR. The pinned Plonky3 revision f98331687e47106a64ab82a77e2e1d0d66c9161b contains one (`p3-poseidon2-air`), but it is not among the crates proofs/Cargo.toml and benchmarks/Cargo.toml pin, and adding it is a new dependency outside this piece (not yet established).
- Missing dependency: Plonky3-recursion. Its main branch was at revision 3a69ba61f713c8400b14eb3d8f0e52caa13512c7 on 2026-10-24, and at that revision it depends on Plonky3 0.9.0-rc.2 from crates.io, not on the pinned revision, so it cannot verify proofs of this repository's configuration without moving proofs/ to that release (not yet established). It is Poseidon-only, unaudited and "not recommended for production", and its compatibility check is shape-only and binds no child proving keys, statements or public claims, so even a run of it would not show the verifier binding designs.md requires (rule 1). <!-- no-figure -->
- The command that would produce a Poseidon2 merge proxy: add `p3-poseidon2-air` at revision f98331687e47106a64ab82a77e2e1d0d66c9161b to the dev-dependencies of benchmarks/reveal/Cargo.toml, write benchmarks/reveal/tests/recursion_poseidon2.rs that derives the Poseidon2 permutations a verifier of a Poseidon2 layer proof performs (rate 15, capacity 9, a 9-element digest, as security.md states) and proves that many with that AIR at the layer parameters, and run `cargo test --release --locked --manifest-path benchmarks/reveal/Cargo.toml --test recursion_poseidon2` (not yet established).

## Architecture (c): Poseidon2 leaves, Poseidon2 aggregation

Not yet established in every figure. There is no Poseidon2 prover of the real reveal statement: the Poseidon2 proofs in this repository are of the benchmark statement only (docs/scale/phone-results.md), so there is no leaf proof whose verifier could be counted, and no merge proxy for the reason given under (b). The same missing dependencies apply, at the same revisions: a Poseidon2 AIR (`p3-poseidon2-air` at f98331687e47106a64ab82a77e2e1d0d66c9161b) and Plonky3-recursion (3a69ba61f713c8400b14eb3d8f0e52caa13512c7, on Plonky3 0.9.0-rc.2), plus a Poseidon2 prover of the real statement, which security.md notes could not carry a 128-bit collision term with the reveal AIR's 8-element in-circuit digest (modeled there). The command that would produce the leaf count is this test's derivation run on a decoded Poseidon2 reveal proof, once such a prover exists (not yet established).

- (b) Keccak leaves, Poseidon2 aggregation: not yet established
- (c) Poseidon2 leaves, Poseidon2 aggregation: not yet established

## Conversion layer versus merges

| | Conversion layer | Merges | Label |
|---|---|---|---|
| Children | one coin reveal proof | two coin reveal proofs (the first layer), then two merge proofs | modeled |
| Permutations re-proved | 13,070 | 26,140, then 40,228 | modeled |
| Trace rows of `p3-keccak-air` | 524,288 | 1,048,576 | modeled |
| Proxy at the quick size, median | 0.864547 s for 85 permutations | 1.766970 s for 170 permutations | measured (proxy) |
| One proof at the counted size, one thread | 231.020419 s | 462.040838 s | modeled |
| One proof on a 32-core machine, perfect speedup | 7.22 s | 14.44 s | modeled |
| Proofs a block | 3,500 | 3,499 | modeled |
| Machine-seconds a block | 25,267.86 | 50,521.28 | modeled |
| Trace extension alone | 82.438 GiB | 164.875 GiB | modeled |

The conversion layer as measured here wraps one leaf each. If it merges two leaves instead, as the construction of security.md has it (1,750 conversion proofs, modeled there), each conversion proof re-proves 26,140 permutations, the merge proxy's count, and costs what the merge proxy costs (modeled). In (a) the conversion and the merges then differ only in their children's shape; in (b) they differ in the in-circuit hash, which is why (b)'s conversion layer is bounded above and its merges are not yet established.

## Which records apply to each hash

Evidence must match the exact primitive (designs.md, rule 3). <!-- no-figure -->

| Hash and role here | Records that apply | Records that do not |
|---|---|---|
| Keccak-f\[1600\], 24 rounds, in the padding-free sponge of proofs/src/stark.rs (rate 17 lanes, capacity 512 bits, 4-lane digest): the leaf hashes and compressions counted above, the proxy's own commitments, and the permutation `p3-keccak-air` proves (modeled: read from the code) | This page's proxy, for its own figures only; cryptanalysis of the full Keccak-f\[1600\] permutation and the generic sponge bound at that capacity, as security.md lists | NIST SHA3-256, a different padding and domain suffix and so a different function; reduced-round Keccak results (modeled: the rule) |
| Keccak-256 with the original padding: the Fiat–Shamir transcript of the leaf and of the proxy, `HashChallenger<u8, Keccak256Hash, 32>` (modeled: read from the code) | Keccak-256 as its designers specify it, the hash of spec 01 | NIST SHA3-256 (modeled: the rule) |
| Poseidon2 over BabyBear, width 24: the aggregation hash of (b) and (c) (not yet established: nothing here runs it) | Only analysis of exactly that instance and its round numbers, which security.md leaves not yet established | The CICO and zero-test records, which are Poseidon1 over KoalaBear with t=16; any other field or width (modeled: the rule) |

The 0.303 s leanMultisig merge is not used anywhere on this page: it is leanVM verifying its own proofs over a 192-bit binary field with Keccak as a placeholder, not a Plonky3 proof of the Ghost reveal, so it says nothing about any of the three architectures (not yet established for Ghost, as workload.md records).

## What is not yet established

1. **A real recursive merge of any architecture.** No figure here is a Plonky3-recursion or leanMultisig run, and none is the cost of a recursive verifier: the proxy leaves out FRI folding, constraint evaluation and the verifier binding (not yet established). Closed by a recursion benchmark of the Ghost leaf on named hardware.
2. **The proxy at the counted sizes.** The 231.020419 s and 462.040838 s are modeled from the quick path. Closed by the full path, the command under "What was run" without `GHOST_SCALE_QUICK`, on a machine with at least 192 GiB of memory (not yet established).
3. **A counted verification of the real reveal proof.** The 13,070 is derived and recounted from the proof, not counted while `ghost-proofs` verifies (modeled). Closed by a counting hook in `ghost-proofs`, a change of proofs/ outside this piece; the transcript part is a model that leaves out step labels and sampling retries (modeled, 800 against a counted 820 on the proxy).
4. **Multi-threaded proving.** The per-machine figures divide one thread's time by 32 cores as if perfectly parallel (modeled). Closed by the full path built with the `parallel` feature of the pinned crates, which needs the rayon dependency they leave out (not yet established).
5. **Architecture (b) after its conversion layer, and its conversion time.** Closed by `p3-poseidon2-air` at f98331687e47106a64ab82a77e2e1d0d66c9161b, or Plonky3-recursion with proofs/ moved to the Plonky3 release it uses, and the command under architecture (b) (not yet established).
6. **Architecture (c) in full.** Closed by a Poseidon2 prover of the real reveal statement and the same dependencies (not yet established).
7. **The count at the bundle's parameters.** security.md asks for 92 queries; this count is at the shipped 43 (modeled). Closed by the same derivation at 92 queries (not yet established).
8. **Other arithmetizations and layer parameters.** The verdict of (a) holds for `p3-keccak-air` at the shipped leaf parameters (modeled). Whether a different Keccak-f\[1600\] AIR or other layer parameters that still meet security.md would fit the ceilings is not yet established.
