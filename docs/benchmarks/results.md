# Browser proof benchmark results

**The 10-second target is met on both the Mac Studio and the emulated
mid-range phone, not a real device.** Every completed proof finished under 10
seconds. The slowest was about 5.2 seconds (Keccak, blowup 2^3, emulated
mid-range phone, not a real device, a cold run).

These results are measured against [the benchmark plan](plan.md). The raw
records are in [results/](results/), one file per configuration, device and
session.

## What was run

The run was stopped early because it already gave enough evidence. It has 3 to
4 sessions per configuration instead of the plan's 5, and it used the
single-thread build only; no threaded build was run. The single-thread build
is the slower fallback, so the verdict holds for the threaded build too.

- 40 session files: 12 for session 0, 10 each for sessions 1 and 2, and 8 for
  session 3.
- 420 records: 418 completed proofs and 2 refused entries. Every completed
  proof verified.
- Every record is the single-thread build with SIMD (`wasm-single`), in Chrome
  on the Mac Studio. The emulated mid-range phone, not a real device, is the
  same Chrome on the Mac Studio with 4x CPU throttling.

## Refused entries

The two refused entries are Keccak at blowup 2^1, one on the Mac Studio and
one on the emulated mid-range phone, not a real device. The harness refused
them before proving: the Keccak circuit has constraint degree 3, and in
zero-knowledge mode a blowup of 2^1 only fits degree 2 or less. The plan
foresaw this.

## Hash choice

The outline picks the most-studied hash that meets the target, and the plan
names Keccak as the more studied of the two: if Keccak meets the target on
both configurations it is chosen over Poseidon2. It does, so **the hash is
Keccak-256**.

Its lowest runnable blowup is 2^2:

- Proof size: about 1.02 MB (median 997.8 KiB).
- Verification: median about 7 ms on the Mac Studio and about 10 ms on the
  emulated mid-range phone, not a real device (mean about 31 ms, largest about
  93 ms).

At blowup 2^3 the proof is about 0.75 MB (median 729.8 KiB), and
verification is a median of about 6 ms on the Mac Studio and about 8 ms on the
emulated mid-range phone, not a real device (mean about 25 ms).

## Summary table

Produced by `benchmarks/summarize.py`:

```sh
python3 benchmarks/summarize.py --build wasm-single --min-cold 3 --min-warm 30 docs/benchmarks/results
```

The flags judge the single-thread build and accept the 3 or 4 sessions that
were run. Without them the script reports "not met", because it expects the
threaded build and the full five sessions per configuration.

| Candidate | Blowup | Build | Device | Runs (cold/warm) | Cold median / slowest | Warm median / p90 / slowest | WASM memory median / largest | Process memory median / largest | Proof size median / largest | Verify median / largest | Failed runs | Meets target |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| keccak-256 | 2^2 | wasm-single | Mac Studio | 4/40 | 0.76 s / 0.77 s | 0.69 s / 0.71 s / 0.72 s | 157.6 MiB / 157.6 MiB | 221.7 MiB / 226.4 MiB | 997.8 KiB / 1003.1 KiB | 0.01 s / 0.01 s | 0 | yes |
| keccak-256 | 2^2 | wasm-single | emulated mid-range phone, not a real device | 4/40 | 2.99 s / 3.17 s | 2.77 s / 2.99 s / 3.09 s | 157.6 MiB / 157.6 MiB | 221.8 MiB / 224.2 MiB | 997.5 KiB / 1001.5 KiB | 0.01 s / 0.09 s | 0 | yes |
| keccak-256 | 2^3 | wasm-single | Mac Studio | 4/40 | 1.16 s / 1.20 s | 1.04 s / 1.07 s / 1.10 s | 260.0 MiB / 260.0 MiB | 321.6 MiB / 322.9 MiB | 729.8 KiB / 734.4 KiB | 0.01 s / 0.01 s | 0 | yes |
| keccak-256 | 2^3 | wasm-single | emulated mid-range phone, not a real device | 4/40 | 4.91 s / 5.20 s | 4.47 s / 4.75 s / 4.93 s | 260.0 MiB / 260.0 MiB | 321.7 MiB / 323.7 MiB | 730.4 KiB / 735.7 KiB | 0.01 s / 0.09 s | 0 | yes |
| poseidon2-babybear-w24 | 2^1 | wasm-single | Mac Studio | 4/40 | 0.26 s / 0.35 s | 0.29 s / 0.46 s / 0.81 s | 8.7 MiB / 8.7 MiB | 75.9 MiB / 77.8 MiB | 603.4 KiB / 606.2 KiB | 0.04 s / 0.05 s | 0 | yes |
| poseidon2-babybear-w24 | 2^1 | wasm-single | emulated mid-range phone, not a real device | 4/40 | 1.12 s / 1.83 s | 1.10 s / 1.61 s / 2.41 s | 8.7 MiB / 8.7 MiB | 75.1 MiB / 75.6 MiB | 603.0 KiB / 606.8 KiB | 0.20 s / 0.31 s | 0 | yes |
| poseidon2-babybear-w24 | 2^2 | wasm-single | Mac Studio | 3/30 | 0.35 s / 0.55 s | 0.40 s / 0.53 s / 0.57 s | 12.5 MiB / 12.5 MiB | 76.3 MiB / 79.2 MiB | 342.2 KiB / 344.3 KiB | 0.03 s / 0.04 s | 0 | yes |
| poseidon2-babybear-w24 | 2^2 | wasm-single | emulated mid-range phone, not a real device | 3/30 | 1.62 s / 1.74 s | 1.61 s / 2.05 s / 2.22 s | 12.5 MiB / 12.5 MiB | 76.5 MiB / 78.0 MiB | 342.6 KiB / 346.4 KiB | 0.14 s / 0.22 s | 0 | yes |
| poseidon2-babybear-w24 | 2^3 | wasm-single | Mac Studio | 4/40 | 0.36 s / 0.82 s | 0.41 s / 0.59 s / 0.84 s | 10.7 MiB / 10.7 MiB | 74.8 MiB / 80.1 MiB | 245.4 KiB / 247.8 KiB | 0.03 s / 0.03 s | 0 | yes |
| poseidon2-babybear-w24 | 2^3 | wasm-single | emulated mid-range phone, not a real device | 4/40 | 1.93 s / 2.63 s | 1.71 s / 2.52 s / 3.38 s | 10.7 MiB / 10.7 MiB | 73.9 MiB / 76.0 MiB | 245.4 KiB / 248.5 KiB | 0.12 s / 0.22 s | 0 | yes |

Per configuration (both devices must meet the target):

- keccak-256, blowup 2^2, wasm-single: met
- keccak-256, blowup 2^3, wasm-single: met
- poseidon2-babybear-w24, blowup 2^1, wasm-single: met
- poseidon2-babybear-w24, blowup 2^2, wasm-single: met
- poseidon2-babybear-w24, blowup 2^3, wasm-single: met

2 record(s) without zero-knowledge mode or outside the reference devices were not counted.

The 2 records not counted are the refused Keccak blowup 2^1 entries.

Verdict: met (keccak-256 blowup 2^2, keccak-256 blowup 2^3, poseidon2-babybear-w24 blowup 2^1, poseidon2-babybear-w24 blowup 2^2, poseidon2-babybear-w24 blowup 2^3)

Security figures are conjectured estimates; the target is 128 conjectured bits, with the best proven figure recorded in each record beside it.
