# Decision 0003: the proof system and the hash inside proofs

Status: settled from the browser benchmark results, 2026-10-17.

## Decision

Ghost's proofs are made with Plonky3, pinned to revision `f98331687e47`
(`f98331687e47106a64ab82a77e2e1d0d66c9161b`, the revision in
`benchmarks/Cargo.toml` and in every result record). The proof library and the
hash are one decision:

| Item | Settled |
|---|---|
| Library | Plonky3, revision `f98331687e47`, a hash-based STARK with no trusted setup |
| Field | BabyBear, with a degree-5 extension field for challenges (154 bits) |
| Polynomial commitment | FRI, in its hiding form, with a hiding Merkle commitment |
| Hash inside proofs and in the trees | Keccak-256 |
| Security level | The rule of [spec 09, section 4.1](../spec/09-quantum-safe-accounts.md): 129 conjectured bits from the queries alone, and at least 128 for every term of the library's own estimator (`p3-uni-stark` security parameters, `p3-security`) with grinding counted at half. Conjectured: 128 bits classical, 64 quantum. Proven: 80 bits classical, 40 quantum (a goal, not gated) |
| Zero-knowledge mode | On, in the configuration that ships, with 154-bit salts |
| Blowup | 2^3 (rate 1/8), 43 queries, 16 grinding bits on the queries and 16 before the batching challenge |

The configuration that ships is
`keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk`
(amended 2026-10-20, see "Blowup"). The benchmark records of this decision were
made with `keccak-256/hiding-fri/blowup-2^2/queries-57/grinding-q16-b0-o0/ext-5/zk`
and, for the comparison, the same at blowup 2^3.

This settles the outline's starting picks of Plonky3 and "a fast proof-friendly
hash". The library is kept; the hash is not a proof-friendly one.

## Order of the tests

A candidate had to pass soundness, zero-knowledge and the security level first.
Speed in the browser decided only among candidates that passed.

1. **Soundness.** Every one of the 418 completed proofs verified, in the
   browser and in the native build, and no run failed.
2. **Zero-knowledge.** Every counted record has zero-knowledge mode on, built
   through the hiding commitment scheme and the hiding Merkle commitment. The
   Keccak-256 trace height at blowup 2^2 is 1,024, above the library's
   zero-knowledge minimum of 134 for the openings and queries in use. A
   configuration that cannot be built in zero-knowledge mode was refused, not
   measured: Keccak-256 at blowup 2^1, because its constraint degree is 3.
3. **Security level.** Every counted record reaches 128 conjectured bits. The
   best proven figure for the same parameters is 72 bits; the target is the
   conjectured figure, and this is said wherever the number is quoted. The
   commitment hash counts at its collision resistance, 128 bits for Keccak-256.
   Since 2026-10-20 the security gate holds the configuration to spec 09,
   section 4.1, which a quantum attacker on the Fiat–Shamir hash makes
   necessary: the queries alone give at least 128 conjectured bits, and every
   estimator term, the extension-field ones included, reaches 128 with grinding
   counted at half. The configuration that ships gives 128 conjectured bits
   classical and 64 quantum, 80 proven classical and 40 proven quantum; the
   binding term is Keccak-256's collision resistance
   ([measurements](../benchmarks/reveal-parameters.md)).
4. **Native verification.** The chain verifies every proof natively, never
   inside an elliptic-curve proof. The native build verified the chosen proof
   in a median of 8.51 ms (largest 9.23 ms) at blowup 2^2. The coin reveal at
   the configuration that ships verifies in a median of 8.08 ms on the build
   machine ([measurements](../benchmarks/reveal-parameters.md)).
5. **Speed.** Only then the 10-second target.

## Hash choice

The outline picks the most-studied hash that meets the speed target, and the
benchmark plan fixed the rule before measuring: Keccak-256 is the more studied
of the two candidates, so if it meets the target on both the Mac Studio and the
emulated mid-range phone, not a real device, it is chosen over Poseidon2. It
meets it on both, so the hash is Keccak-256, inside the proofs and in the
trees.

**Passed over: Poseidon2** (over BabyBear, width 24). It also met the target,
and it is faster and smaller: at blowup 2^2 a warm median of 1.61 s on the
emulated phone against 2.77 s, a proof of about 343 KiB against about 998 KiB,
and about 13 MiB of WebAssembly memory against about 158 MiB. It was passed
over because it is the less studied hash, and the rule puts how well studied a
hash is ahead of speed once the target is met.

What the choice costs: Keccak-256 proofs are about three times as large and
take longer to verify in the browser than Poseidon2 proofs would, and they cost
the chain block space (see "Cost on the chain").

## Measured against the 10-second target

**The 10-second target is met** on the Mac Studio and on the emulated mid-range
phone, not a real device. A configuration meets it when both the median warm
proving time and the slowest cold proving time are 10 seconds or less on both,
and no run failed.

Every figure is from the single-thread WebAssembly build with SIMD, in Chrome,
with zero-knowledge mode on. The emulated phone is the same Chrome on the same
Mac Studio with the renderer process, worker included, throttled 4x by pausing
and resuming it. It is not a real device.

| Hash | Blowup | Device | Cold median / slowest | Warm median / slowest | Proof size median | Verify median (browser) | Meets target |
|---|---|---|---|---|---|---|---|
| Keccak-256 (chosen) | 2^2 | Mac Studio | 0.76 s / 0.77 s | 0.69 s / 0.72 s | 997.8 KiB | 0.01 s | yes |
| Keccak-256 (chosen) | 2^2 | Emulated mid-range phone, not a real device | 2.99 s / 3.17 s | 2.77 s / 3.09 s | 997.5 KiB | 0.01 s | yes |
| Keccak-256 | 2^3 | Mac Studio | 1.16 s / 1.20 s | 1.04 s / 1.10 s | 729.8 KiB | 0.01 s | yes |
| Keccak-256 | 2^3 | Emulated mid-range phone, not a real device | 4.91 s / 5.20 s | 4.47 s / 4.93 s | 730.4 KiB | 0.01 s | yes |

The slowest proof of the whole run was about 5.2 seconds (Keccak-256, blowup
2^3, emulated phone, a cold run). At the chosen blowup the slowest was 3.17
seconds, about a third of the target. The threaded build was not run; it is the
build a user normally gets, and the single-thread build is the slower fallback,
so the result holds for it too.

The target is not relaxed. If a later measurement misses it (see "What would
reverse this decision"), the first fallback is Poseidon2 in the same library,
which met the target with more room; if no hash in Plonky3 meets it, the proof
system is revisited as the outline requires.

## Blowup

Blowup 2^2 is the lowest that Keccak-256 can run at in zero-knowledge mode.
Blowup 2^3 also meets the target and was measured beside it:

- Proof size: 749,519 bytes instead of 1,023,438 (median, native), 26.8 percent
  smaller.
- Browser proving: about 1.6 times as long on the emulated phone (4.47 s
  against 2.77 s warm median), still under the target.
- Browser memory: 260.0 MiB instead of 157.6 MiB of WebAssembly memory.
- Native verification: 7.56 ms instead of 8.51 ms (median).

The proof is padded to one fixed length, so every private transaction uses the
same blowup.

**Amended 2026-10-20: blowup 2^3 with 43 queries.** Rate 1/4 with 57 queries
gives only 114 conjectured bits from the queries, and 120 with its grinding
counted at half, so it does not meet the rule of spec 09, section 4.1. Two
configurations reach 128 from the queries alone: rate 1/4 with 64 queries and
rate 1/8 with 43. Rate 1/4 with 64 queries makes the longest proof wider than
the proof field of spec 07 (about 1.4 MB by the same bound), which would change
the transaction format; rate 1/8 with 43 queries bounds it at 1,053,331 bytes,
inside the 1,310,720-byte field. So the blowup is 2^3. The cost is proving
time: 1.62 times as long natively for the coin reveal (median 1.35 s against
0.84 s), and proofs are about 19 percent smaller (median 957,516 bytes against
1,187,533). Whether the 10-second proving target still holds on the target
devices at this cost is measured separately; this amendment does not depend on
it, and a miss is reported against the target, not answered by lowering the
security level.

## Cost on the chain

From the native run (a Linux virtual machine on the same Mac Studio, threads
on, a high-end machine and not a typical node):

- A private transaction carries a proof padded to 1,028,144 bytes plus 164
  bytes of public inputs at blowup 2^2, or 750,859 bytes in total at 2^3.
- **At blowup 2^2 no private transaction fits in a 1 MB block**; at 2^3 one
  does. Size, not verification time, is the limit that binds: the verification
  budget of 3,000 ms per 30-second block holds 352 proofs at the median time.
- Proofs alone grow the chain by about 3.24 TB a year at 0.1 private
  transactions per second at blowup 2^2 (2.37 TB at 2^3).

The block size limit is not decided here.

## What the benchmark did not cover

- **No real phone.** The phone figures are an emulation: the CPU of the Mac
  Studio throttled 4x. They do not reproduce a phone's memory, thermal limits or
  browser build. A real mid-range phone may be slower.
- **No threaded build.** Only the single-thread WebAssembly build was run.
- **Fewer sessions than planned.** 3 to 4 sessions per configuration instead of
  5, because the run was stopped early with enough evidence.
- **One browser.** Chrome only, build 155.0.8059.80 on macOS 27.0.1.
- **No verification in the Go node.** Native verification was measured with the
  Rust verifier on one high-end machine. Verification in the Go node, and on a
  typical node, is the work of the verification path and is not measured here.
- **The fixed proof length is not proven.** Padding used the largest proof of
  10 runs; the largest length the encoding can produce was not measured.
- **The proven security figure.** Only the conjectured estimate reaches 128
  bits; the best proven figure was 72, and is 80 classical and 40 quantum at
  the configuration that ships since 2026-10-20, below the quantum target. Spec
  09 (question 3) makes the proven quantum figure a goal, not a gate.
- **The rest of a transaction.** The chain figures count only the proof and
  its public inputs, not the transaction's other fields, the encrypted note or
  the block header.

## What would reverse this decision

- A run on a real mid-range phone, or with the threaded build, misses the
  10-second target for Keccak-256.
- A flaw is found in the pinned revision's zero-knowledge, soundness or
  security estimate code, or a later revision needed for a fix fails the same
  tests.
- The Go node cannot verify the proof natively within the verification budget
  on a typical node.
- The block size limit cannot carry proofs of this size, and blowup 2^3 does
  not close the gap.
- A cryptanalytic result weakens Keccak-256 below the 128-bit level.

The sources are the [results](../benchmarks/results.md) and the
[raw records](../benchmarks/results/).
