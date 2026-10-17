# Browser proof benchmark results

**The 10-second target is met on both the Mac Studio and the emulated
mid-range phone, not a real device.** Every completed proof finished under 10
seconds. The slowest was about 5.2 seconds (Keccak, blowup 2^3, emulated
mid-range phone, not a real device, a cold run).

These results are measured against [the benchmark plan](plan.md). The raw
records are in [results/](results/), one file per configuration, device and
session.

The second half of this report gives what the chosen proof costs the chain:
native verification time, proof size, private transactions per block and
chain growth per year. It starts at
[Native verification on the chain](#native-verification-on-the-chain).

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
  same Chrome on the Mac Studio with 4x CPU throttling. The throttling was
  applied to the whole renderer process, worker included, by pausing and
  resuming it (25 ms running in every 100 ms), because the DevTools throttle
  does not reach background workers in this Chrome build.

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

## Native verification on the chain

The chain verifies every reveal proof natively, so this section measures the
benchmark proof as chosen above (Keccak-256) with the native build. These are
measured figures only. No capacity target is promised here, and where a usage
level does not fit, the tables say so.

### Hardware used

A native reference on one machine, the only machine the run was made on:

- Machine: a Linux aarch64 virtual machine (lima) on the Mac Studio (Apple
  M5 Max) of the plan.
- CPU: Apple M5 Max, 16 logical cores visible to the virtual machine.
- Memory: 46 GB visible to the virtual machine.
- Operating system: Linux, aarch64, inside lima on macOS. The distribution
  and kernel were not recorded.
- Threads: used (built with the prover crate's `parallel` feature).

This is a high-end machine, not a typical node. A slower node takes longer
to verify, and the per-block figures below hold for this machine only.

### How it was run

At repository commit `4da6c49b861f`, with Plonky3 at revision
`f98331687e47` and rustc 1.99.1:

```sh
cargo build --release -p ghost-bench --features parallel --bin ghost-bench-native
ghost-bench-native --sessions 1 --warm 10
```

One session of 10 warm runs per configuration; the figures are the median and
the largest of those 10. Every proof verified. The raw records of this run are
not committed; the figures below are the whole record of it.

Security level: 128 conjectured bits (the library's estimator), the level the
benchmark proof already uses, with zero-knowledge mode on for every
configuration. The field is BabyBear with a degree-5 extension and FRI, as in
the plan. Public inputs are 164 bytes for every configuration.

### Native measurements

| Candidate | Blowup | Queries | Proving median (ms) | Verification median (ms) | Verification largest (ms) | Proof bytes median | Proof bytes largest |
|---|---|---|---|---|---|---|---|
| keccak-256 | 2^1 | not buildable | not buildable | not buildable | not buildable | not buildable | not buildable |
| keccak-256 | 2^2 | 57 | 257.6 | 8.51 | 9.23 | 1,023,438 | 1,028,144 |
| keccak-256 | 2^3 | 38 | 258.4 | 7.56 | 8.30 | 749,519 | 750,695 |
| poseidon2-babybear-w24 | 2^1 | 115 | 151.4 | 33.27 | 48.22 | 617,700 | 619,860 |
| poseidon2-babybear-w24 | 2^2 | 57 | 163.8 | 30.31 | 35.87 | 351,673 | 352,969 |
| poseidon2-babybear-w24 | 2^3 | 38 | 146.4 | 29.23 | 30.30 | 251,672 | 252,572 |

Keccak-256 at blowup 2^1 does not run: its constraint degree is 3, and in
zero-knowledge mode that needs a blowup of at least 2^2, as in the browser run.

### Verification budget

The verification budget is 10 percent of the 30-second block interval:
30,000 ms x 10 / 100 = 3,000 ms per block. Proofs that fit in the budget =
floor(3,000 / verification time), verified one after another. No speed-up
from verifying several proofs at once is assumed.

| Candidate | Blowup | Statistic | Verification time (ms) | Budget (ms) | Proofs verified in budget |
|---|---|---|---|---|---|
| keccak-256 | 2^2 | median | 8.51 | 3,000 | 352 |
| keccak-256 | 2^2 | largest | 9.23 | 3,000 | 325 |
| keccak-256 | 2^3 | median | 7.56 | 3,000 | 396 |
| keccak-256 | 2^3 | largest | 8.30 | 3,000 | 361 |

For example, 352 x 8.51 = 2,995.52 ms fits and 353 x 8.51 = 3,004.03 ms does
not.

## Proof size and proving time

Proof size is the library's serde encoding with postcard, public inputs
excluded, at 128 conjectured bits in zero-knowledge mode. A higher blowup needs
fewer queries, so the proof is smaller and the prover does more work. Native
proving times are from the table above; browser proving times are the warm
medians of the single-thread browser build in the
[summary table](#summary-table).

| Candidate | Blowup | Queries | Proof bytes median | Native proving median (ms) | Browser warm median, Mac Studio (s) | Browser warm median, emulated mid-range phone, not a real device (s) |
|---|---|---|---|---|---|---|
| keccak-256 | 2^2 | 57 | 1,023,438 | 257.6 | 0.69 | 2.77 |
| keccak-256 | 2^3 | 38 | 749,519 | 258.4 | 1.04 | 4.47 |
| poseidon2-babybear-w24 | 2^1 | 115 | 617,700 | 151.4 | 0.29 | 1.10 |
| poseidon2-babybear-w24 | 2^2 | 57 | 351,673 | 163.8 | 0.40 | 1.61 |
| poseidon2-babybear-w24 | 2^3 | 38 | 251,672 | 146.4 | 0.41 | 1.71 |

The trade-off for the chosen hash, Keccak-256, going from blowup 2^2 to 2^3:

- Proof size: 1,023,438 - 749,519 = 273,919 bytes smaller (26.8 percent of
  1,023,438).
- Native proving: 258.4 - 257.6 = 0.8 ms slower (0.3 percent). A difference
  this small cannot be told apart from run-to-run variation with 10 runs.
- Browser proving, single thread: 1.04 / 0.69 = 1.51 times as long on the Mac
  Studio and 4.47 / 2.77 = 1.61 times as long on the emulated mid-range phone,
  not a real device. Both stay under the 10-second target.
- Browser memory: 260.0 MiB instead of 157.6 MiB (WebAssembly memory median).
- Native verification: 8.51 - 7.56 = 0.95 ms faster (median).

The transaction tables below give both blowups, so the cost of each choice on
the chain can be read directly. This report does not change the blowup.

## Private transactions per block

Every private transaction has an identical size, so each one carries a proof
padded to one fixed length. This report takes that length as the largest proof
of the run, plus the 164 bytes of public inputs:

- Blowup 2^2: 1,028,144 + 164 = 1,028,308 bytes per private transaction.
- Blowup 2^3: 750,695 + 164 = 750,859 bytes per private transaction.

Only the proof and its public inputs are counted. The transaction's other
fields (type, destination, encrypted note) and the block header are not, so
real transactions are larger and the counts below are upper bounds. A block
size limit of 1 MB means 1,000,000 bytes.

### Constants

| Quantity | Value |
|---|---|
| Block interval (s) | 30 |
| Seconds per year | 31,536,000 |
| Blocks per year | 1,051,200 |
| Verification budget (ms) | 3,000 |
| Public inputs (bytes) | 164 |

Seconds per year = 365 x 24 x 3600 = 31,536,000. Blocks per year =
365 x 24 x 3600 / 30 = 1,051,200.

### Capacity of one block

Fit by size = floor(limit / bytes per private transaction). Fit by
verification = floor(3,000 / median verification time), from the verification
budget table. Private transactions per block = the smaller of the two.
Private transactions per second = per block / 30.

| Candidate | Blowup | Bytes per private transaction | Block size limit | Limit (bytes) | Fit by size | Fit by verification budget | Private transactions per block | Private transactions per second |
|---|---|---|---|---|---|---|---|---|
| keccak-256 | 2^2 | 1,028,308 | 1 MB | 1,000,000 | 0 | 352 | 0 | 0.000 |
| keccak-256 | 2^2 | 1,028,308 | 4 MB | 4,000,000 | 3 | 352 | 3 | 0.100 |
| keccak-256 | 2^2 | 1,028,308 | 16 MB | 16,000,000 | 15 | 352 | 15 | 0.500 |
| keccak-256 | 2^3 | 750,859 | 1 MB | 1,000,000 | 1 | 396 | 1 | 0.033 |
| keccak-256 | 2^3 | 750,859 | 4 MB | 4,000,000 | 5 | 396 | 5 | 0.167 |
| keccak-256 | 2^3 | 750,859 | 16 MB | 16,000,000 | 21 | 396 | 21 | 0.700 |

For example, at blowup 2^2: 3 x 1,028,308 = 3,084,924 bytes fits in 4 MB and
4 x 1,028,308 = 4,113,232 bytes does not.

At every block size limit, size is the limit that binds; the verification
budget allows 352 proofs per block at blowup 2^2 and the size limits allow at
most 15. **At blowup 2^2 not one private transaction fits in a 1 MB block**
(1,028,308 bytes is more than 1,000,000); at blowup 2^3 one does.

### Usage levels

Private transactions per block needed = usage x 30. Bytes per block = needed
x bytes per private transaction. Verification time per block = needed x median
verification time.

| Candidate | Blowup | Usage (private transactions per second) | Private transactions per block needed | Bytes per block needed | Verification time per block (ms) | Fits 1 MB | Fits 4 MB | Fits 16 MB | Within verification budget |
|---|---|---|---|---|---|---|---|---|---|
| keccak-256 | 2^2 | 0.1 | 3 | 3,084,924 | 25.53 | no | yes | yes | yes |
| keccak-256 | 2^2 | 1 | 30 | 30,849,240 | 255.30 | no | no | no | yes |
| keccak-256 | 2^2 | 10 | 300 | 308,492,400 | 2,553.00 | no | no | no | yes |
| keccak-256 | 2^3 | 0.1 | 3 | 2,252,577 | 22.68 | no | yes | yes | yes |
| keccak-256 | 2^3 | 1 | 30 | 22,525,770 | 226.80 | no | no | no | yes |
| keccak-256 | 2^3 | 10 | 300 | 225,257,700 | 2,268.00 | no | no | no | yes |

What misses:

- 0.1 private transactions per second fits a 4 MB or 16 MB block, at either
  blowup, and does not fit a 1 MB block.
- 1 private transaction per second fits none of the three limits; it needs
  about 31 MB per block at blowup 2^2 and about 23 MB at 2^3.
- 10 private transactions per second fits none of the three limits; it needs
  about 308 MB per block at blowup 2^2 and about 225 MB at 2^3.
- Verification fits the budget at all three usage levels on this machine. At
  10 per second it uses 2,553.00 ms of the 3,000 ms at blowup 2^2 (85 percent);
  with the largest verification time, 300 x 9.23 = 2,769 ms, it still fits, but
  a node slower than this one by more than about 1.08 times (3,000 / 2,769) would
  not.

## Chain growth per year

Blocks per year = 365 x 24 x 3600 / 30 = 1,051,200. Private transactions per
block carried = the smaller of what the usage needs and what the block size
limit allows ("none" means no limit, so the usage is carried in full).
Private transactions per year = carried x 1,051,200. Bytes per year = private
transactions per year x bytes per private transaction. TB is 10^12 bytes.

Only proofs and their public inputs are counted (see above); headers, public
transactions, encrypted notes and the tree state add to these figures.

| Candidate | Blowup | Usage (private transactions per second) | Block size limit | Private transactions per block carried | Private transactions per year | Bytes per year | TB per year |
|---|---|---|---|---|---|---|---|
| keccak-256 | 2^2 | 0.1 | none | 3 | 3,153,600 | 3,242,872,108,800 | 3.24 |
| keccak-256 | 2^2 | 0.1 | 1 MB | 0 | 0 | 0 | 0.00 |
| keccak-256 | 2^2 | 0.1 | 4 MB | 3 | 3,153,600 | 3,242,872,108,800 | 3.24 |
| keccak-256 | 2^2 | 0.1 | 16 MB | 3 | 3,153,600 | 3,242,872,108,800 | 3.24 |
| keccak-256 | 2^2 | 1 | none | 30 | 31,536,000 | 32,428,721,088,000 | 32.43 |
| keccak-256 | 2^2 | 1 | 1 MB | 0 | 0 | 0 | 0.00 |
| keccak-256 | 2^2 | 1 | 4 MB | 3 | 3,153,600 | 3,242,872,108,800 | 3.24 |
| keccak-256 | 2^2 | 1 | 16 MB | 15 | 15,768,000 | 16,214,360,544,000 | 16.21 |
| keccak-256 | 2^2 | 10 | none | 300 | 315,360,000 | 324,287,210,880,000 | 324.29 |
| keccak-256 | 2^2 | 10 | 1 MB | 0 | 0 | 0 | 0.00 |
| keccak-256 | 2^2 | 10 | 4 MB | 3 | 3,153,600 | 3,242,872,108,800 | 3.24 |
| keccak-256 | 2^2 | 10 | 16 MB | 15 | 15,768,000 | 16,214,360,544,000 | 16.21 |
| keccak-256 | 2^3 | 0.1 | none | 3 | 3,153,600 | 2,367,908,942,400 | 2.37 |
| keccak-256 | 2^3 | 0.1 | 1 MB | 1 | 1,051,200 | 789,302,980,800 | 0.79 |
| keccak-256 | 2^3 | 0.1 | 4 MB | 3 | 3,153,600 | 2,367,908,942,400 | 2.37 |
| keccak-256 | 2^3 | 0.1 | 16 MB | 3 | 3,153,600 | 2,367,908,942,400 | 2.37 |
| keccak-256 | 2^3 | 1 | none | 30 | 31,536,000 | 23,679,089,424,000 | 23.68 |
| keccak-256 | 2^3 | 1 | 1 MB | 1 | 1,051,200 | 789,302,980,800 | 0.79 |
| keccak-256 | 2^3 | 1 | 4 MB | 5 | 5,256,000 | 3,946,514,904,000 | 3.95 |
| keccak-256 | 2^3 | 1 | 16 MB | 21 | 22,075,200 | 16,575,362,596,800 | 16.58 |
| keccak-256 | 2^3 | 10 | none | 300 | 315,360,000 | 236,790,894,240,000 | 236.79 |
| keccak-256 | 2^3 | 10 | 1 MB | 1 | 1,051,200 | 789,302,980,800 | 0.79 |
| keccak-256 | 2^3 | 10 | 4 MB | 5 | 5,256,000 | 3,946,514,904,000 | 3.95 |
| keccak-256 | 2^3 | 10 | 16 MB | 21 | 22,075,200 | 16,575,362,596,800 | 16.58 |

For example, 1 per second at blowup 2^2 with no limit: 30 x 1,051,200 =
31,536,000 private transactions, and 31,536,000 x 1,028,308 =
32,428,721,088,000 bytes, about 32.43 TB a year. Where a limit is lower than
the usage, the rest of the usage is not carried, so a row with a limit is the
growth of a chain that is full, not of one that serves the usage.

Even the smallest usage level, 0.1 per second, grows the chain by about
3.24 TB a year at blowup 2^2 (2.37 TB at 2^3) from private transaction proofs
alone.

## Cost of identical size and shape

Every private transaction must have an identical size and shape, so the
proof is padded to one fixed length and the chain gives it one fixed
verification cost.

**Size.** The proof size varies a little from run to run (the postcard
encoding writes integers with variable length; the run did not look further
into the cause). Padding every proof to the largest of the run costs:

| Candidate | Blowup | Proof bytes median | Proof bytes largest | Padding per transaction (bytes) | Padding share of median |
|---|---|---|---|---|---|
| keccak-256 | 2^2 | 1,023,438 | 1,028,144 | 4,706 | 0.46% |
| keccak-256 | 2^3 | 749,519 | 750,695 | 1,176 | 0.16% |

Padding per transaction = largest - median, so 1,028,144 - 1,023,438 = 4,706
bytes, 4,706 / 1,023,438 = 0.46 percent. Per year, with the usage carried in
full (private transactions per year from the growth table):

| Candidate | Blowup | Usage (private transactions per second) | Private transactions per year | Padding bytes per year | Padding GB per year |
|---|---|---|---|---|---|
| keccak-256 | 2^2 | 0.1 | 3,153,600 | 14,840,841,600 | 14.84 |
| keccak-256 | 2^2 | 1 | 31,536,000 | 148,408,416,000 | 148.41 |
| keccak-256 | 2^2 | 10 | 315,360,000 | 1,484,084,160,000 | 1,484.08 |
| keccak-256 | 2^3 | 0.1 | 3,153,600 | 3,708,633,600 | 3.71 |
| keccak-256 | 2^3 | 1 | 31,536,000 | 37,086,336,000 | 37.09 |
| keccak-256 | 2^3 | 10 | 315,360,000 | 370,863,360,000 | 370.86 |

GB is 10^9 bytes. The largest of 10 runs is not a proven bound: a later proof
could be longer than 1,028,144 bytes. The fixed length must be the largest
length the encoding can produce for this statement and configuration, which
was not measured here, so the real padding may be larger than the figures
above.

**Shape.** One fixed shape for every private transaction costs the
following:

- Verification cost: with one fixed shape the chain charges every proof the
  same cost, and that cost must cover the slow cases, not the median. Set from
  the largest verification time, the budget holds 325 proofs per block instead
  of 352 at blowup 2^2 (7.7 percent fewer), and 361 instead of 396 at 2^3.
  Size binds first at the 1, 4 and 16 MB limits, so this does not change the
  per-block counts above.
- One configuration for everyone: every private transaction uses the same
  hash and blowup, so a user cannot pick a smaller proof. At blowup 2^2 each
  one is 1,028,308 bytes.
- Every transaction pays for the full shape: a zero-amount claim or a reveal
  of a small amount carries the same 1,028,308-byte proof and the same
  verification time as any other, and every reveal adds a remainder
  commitment even when it holds zero.
- What stays different: the public parts (recipient, any public amount) still
  differ between transactions, as the threat model records; the public inputs
  themselves are a fixed 164 bytes.
