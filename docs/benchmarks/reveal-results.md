# Real reveal prover in the browser

**With the current reveal proof configuration (blowup 2^3, 43 queries), the
10-second target no longer holds on the emulated mid-range phone, not a real
device. It still holds on the Mac Studio.** The median warm proving time is
2.72 s on the Mac Studio and 13.15 s on the emulated mid-range phone, not a
real device; the median cold proof on the emulated phone took 15.02 s and the
slowest cold proof 17.39 s. The median warm proof misses the target by about
3 seconds and the cold proofs by 2 to 7 seconds.

The throttle in this run slowed the prover 4.8 times rather than the intended
4 times (see [Machine and browser](#machine-and-browser)). At exactly 4 times
the Mac Studio's figures, the emulated phone would still miss the target: a
warm median of about 10.9 s and a cold median of about 13.1 s.

**The threaded build of the web app's prover is not measured in the browser
yet.** It proves the same statements with the same configuration, and its
section, [Threaded build](#threaded-build-blowup-23-43-queries), holds rows
marked pending browser measurement until it is run.

This page holds two runs of the same benchmark, and the section for the
threaded build:

- [The threaded build](#threaded-build-blowup-23-43-queries): the web app's
  threaded module, the configuration unchanged; pending browser measurement.
- [The current configuration](#current-configuration-blowup-23-43-queries)
  (2026-10-21): blowup 2^3 with 43 queries, from
  [the post-quantum parameter change](reveal-parameters.md). Records in
  [reveal-results/blowup-2-3-queries-43/](reveal-results/blowup-2-3-queries-43/).
- [The earlier configuration](#earlier-configuration-blowup-22-57-queries)
  (2026-10-17): blowup 2^2 with 57 queries, which met the target. Records in
  [reveal-results/blowup-2-2-queries-57/](reveal-results/blowup-2-2-queries-57/).

The [benchmark statement results](results.md) measured the benchmark statement
of the plan. Both runs here measure the statement that ships: the coin reveal
(S1) of the `proofs/` crate, through its own `prove_coin_reveal`, with the
same method as the [benchmark plan](plan.md), on the same Mac Studio and
Chrome build. The raw records are one file per device and session.

## Threaded build: blowup 2^3, 43 queries

The single-thread prover cannot reach the target on the emulated phone at
the configuration of spec 09, section 4.1: at 4 times the Mac Studio's
figures its warm median is about 10.9 s and its cold median about 13.1 s,
and native work on the single-thread prover took off only about 12% (median
about 1,191 ms, salted 1,154 ms, against the 1,000 ms or so it would need).
About 485 to 530 ms of each native proof is the scalar Keccak-f[1600] of the
Merkle leaves (3.7 million permutations at about 131 ns) and about 275 ms the
low-degree extension. Both are work Plonky3 already splits across threads
with its `parallel` feature, so the web app now ships a threaded module
beside the single-thread one.

### What the threaded build changes

- `webapp/build.sh` builds two modules. `ghost_webapp_wasm.wasm` is the
  single-thread module as before (Rust 1.99.1, `+simd128`).
  `ghost_webapp_wasm_threads.wasm` is the same crate with its `threads`
  feature, which turns on the proofs crate's `parallel` feature: built with
  the pinned nightly toolchain (`nightly-2026-08-13`, a 1.99 nightly) and the standard
  library rebuilt for threads (`-Z build-std=std,panic_abort`), with
  `+simd128,+atomics,+bulk-memory,+mutable-globals`, on a shared memory the
  page creates (64 MiB to start, 4 GiB at most).
- The background worker loads the threaded module when the page is
  cross-origin isolated and the device reports more than one core, with up to
  8 prover threads (`navigator.hardwareConcurrency`): itself and one Web
  Worker per further thread (`webapp/src/threads.mjs`, `thread.mjs`), all on
  the one memory. Otherwise, or if the threaded module does not start, it
  loads the single-thread module.
- The hosted site sends `Cross-Origin-Embedder-Policy: require-corp` beside
  `Cross-Origin-Opener-Policy: same-origin` on every path, which makes the
  page cross-origin isolated. The page's Content-Security-Policy is
  unchanged.
- The statement, the proof and the configuration are those of the
  single-thread module: `keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk`,
  the configuration `blowup-2^3/queries-43` unchanged, which passes the
  gate of spec 09, section 4.1 (`proofs/src/stark.rs`). No post-quantum
  parameter changed. Natively, the acceptance test proves and verifies both
  reveals with the `parallel` feature on (`cargo test --release --features
  parallel --test prove_speed`).

### Threaded results

Pending browser measurement. No figure below is a measurement: each row is
filled in from the records of a run with the method of this page, and a row
counts toward the target only once its cold and warm medians are recorded.

| Statement | Build | Device | Configuration | Runs (cold/warm) | Cold median | Warm median | Meets target |
|---|---|---|---|---|---|---|---|
| coin reveal | wasm-threads | Mac Studio | blowup-2^3/queries-43 | pending browser measurement | pending browser measurement | pending browser measurement | pending browser measurement |
| coin reveal | wasm-threads | emulated mid-range phone, not a real device | blowup-2^3/queries-43 | pending browser measurement | pending browser measurement | pending browser measurement | pending browser measurement |
| salted coin reveal | wasm-threads | Mac Studio | blowup-2^3/queries-43 | pending browser measurement | pending browser measurement | pending browser measurement | pending browser measurement |
| salted coin reveal | wasm-threads | emulated mid-range phone, not a real device | blowup-2^3/queries-43 | pending browser measurement | pending browser measurement | pending browser measurement | pending browser measurement |

### How to measure the threaded build

The method is that of [the current configuration](#how-it-was-run): five
sessions per device and statement, interleaved, each a fresh tab with one
cold run and ten warm runs, 3 minutes of rest between sessions, the phone
emulated by throttling the tab's renderer process (all of its workers, the
prover threads included) and its warm median checked against 4 times the Mac
Studio's. What differs is the page: `app-reveal.html` runs the web app's own
modules, as `webapp/build.sh` ships them, through the web app's `prove` call,
on a decoy partial reveal (a throwaway key's coin of 1,000 GHOST, 250 out, a
fee of 0.001 GHOST), which is the same work as a real reveal. Each module
checks every proof in the worker before it returns it; the page does not
keep the proofs for `ghost-reveal-verify`.

```sh
benchmarks/run.sh --app --no-native
python3 benchmarks/web/serve.py --port 8000
node benchmarks/web/drive-reveal.mjs --devtools http://localhost:9222 \
  --page "http://localhost:8000/app-reveal.html?build=wasm-threads&statement=coin-reveal" \
  --sessions 1 --first-session 0 --rest 0 --mode phone \
  --commit "$(git rev-parse HEAD)" --out results/threads/coin-reveal
python3 benchmarks/summarize.py --build wasm-threads results/threads/coin-reveal
```

`statement=salted-coin-reveal` measures the salted coin reveal, into a
directory of its own; `build=wasm-single` measures the single-thread module
on the same page. The records name the build, the thread count
(`thread_count`) and the statement.

## Current configuration: blowup 2^3, 43 queries

### What was run

- The prover: `ghost_proofs::prove_coin_reveal`, unchanged, built for
  `wasm32-unknown-unknown` with SIMD from `benchmarks/reveal` at repository
  commit `67be748d1fcf`, in a dedicated background worker
  (`benchmarks/web/reveal.html`). The configuration is
  `keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk`:
  zero-knowledge mode on, 128 conjectured bits (80 proven), trace height 2,048
  before zero-knowledge padding and width 3,808.
- The witness: drawn per session from a recorded seed, with a random leaf
  position and pseudo-random siblings under a 32-level coin tree, and the
  plan's amounts (1,000 GHOST in, 250 out, a fee of 0.001 GHOST). Sessions 0,
  2 and 4 keep the remainder under the same key; sessions 1 and 3 send it to
  a new key. Zero-knowledge randomness came from `crypto.getRandomValues` on
  every run.
- Five sessions on each device, interleaved (Mac Studio, phone, phone, Mac
  Studio, and so on), each a fresh tab with one cold run and ten warm runs:
  110 proofs. 3 minutes of rest before every session after the first.
- 110 completed proofs, no failed, killed or refused run. Every proof verified
  in the worker, and **every proof also verified natively** with
  `ghost-reveal-verify` (`ghost_proofs::verify_coin_reveal`) on the aarch64
  Linux virtual machine on the same Mac Studio. Each record says so in
  `native_verified`.
- Single-thread build with SIMD only (`wasm-single`); no threaded build was
  run, as before.

### Machine and browser

| Item | Value |
|---|---|
| Machine | Mac Studio, Apple M5 Max, 64 GB; 18 logical cores reported by the browser |
| Operating system | macOS 27.0.1 |
| Browser | Google Chrome 155.0.8059.80, the Mac Studio's automation profile (the browser the session driver and browser tools use), with its extensions installed; not a fresh profile as in the earlier run |
| Repository commit | `67be748d1fcf` in every record |
| Library | Plonky3 `f98331687e47` |
| Compiler | rustc 1.99.1, `-C target-feature=+simd128`, release profile |
| CPU pressure (Compute Pressure API) | nominal in 94 of 110 records; fair in 11, serious in 4, critical in 1 |
| Load on the Mac (1-minute load average at session start) | 3.1 to 11.2: other work on the Mac and its virtual machine ran during the run |

The emulated mid-range phone, not a real device, is the same Chrome on the
same Mac Studio with the tab's renderer process, worker included, throttled by
pausing and resuming it on the Mac (`SIGSTOP` and `SIGCONT`, 25 ms running in
every 100 ms on a fixed clock), the method of the earlier run, because the
DevTools throttle still does not reach dedicated workers in this Chrome build
(`cpu_throttling_worker` is false in every record). The DevTools 4x throttle
was also set on the tab itself; the proving and verification times are taken
in the worker.

The throttle reached the worker, but slowed it more than intended: the warm
median is 13.15 / 2.72 = **4.8 times** the Mac Studio's, where the earlier
run measured 4.0 (the cold median is 4.6 times). Short calibration runs
before the measured sessions gave 4.4 times with the same 25-in-100 split and
about 4.5 times with 50 in 150 and 100 in 300 ms, so the extra slowdown is not
the cost of each pause; the likeliest cause is that the Mac was busier than in
the earlier run (the calibration runs are not committed). Read the phone figures as somewhat slower than
a 4x phone. The 4x estimates on this page are the Mac Studio's figures times 4.

### Results

Produced by `benchmarks/summarize.py`:

```sh
python3 benchmarks/summarize.py --build wasm-single docs/benchmarks/reveal-results/blowup-2-3-queries-43
```

| Candidate | Blowup | Build | Device | Runs (cold/warm) | Cold median / slowest | Warm median / p90 / slowest | WASM memory median / largest | Process memory median / largest | Proof size median / largest | Verify median / largest | Failed runs | Meets target |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| keccak-256 | 2^3 | wasm-single | Mac Studio | 5/50 | 3.28 s / 3.41 s | 2.72 s / 2.76 s / 2.79 s | 596.8 MiB / 596.8 MiB | 974.2 MiB / 975.3 MiB | 935.8 KiB / 940.1 KiB | 0.01 s / 0.02 s | 0 | yes |
| keccak-256 | 2^3 | wasm-single | emulated mid-range phone, not a real device | 5/50 | 15.02 s / 17.39 s | 13.15 s / 14.61 s / 38.70 s | 596.8 MiB / 596.8 MiB | 935.0 MiB / 938.3 MiB | 936.4 KiB / 942.9 KiB | 0.08 s / 0.20 s | 0 | no |

Verdict: met on the Mac Studio only (keccak-256 blowup 2^3).

Security figures are conjectured estimates; the target is 128 conjectured
bits, with the best proven figure (80 bits) recorded in each record beside it.

### Spread

| Device | Cold runs (s) | Warm fastest / median / slowest (s) | Warm median per session (s) | Module start-up, cold runs (ms) |
|---|---|---|---|---|
| Mac Studio | 3.11, 3.16, 3.28, 3.32, 3.41 | 2.58 / 2.72 / 2.79 | 2.76, 2.72, 2.61, 2.60, 2.75 | 13 to 29 |
| Emulated mid-range phone, not a real device | 12.11, 13.61, 15.02, 15.50, 17.39 | 9.81 / 13.15 / 38.70 | 13.70, 13.69, 14.19, 11.80, 10.70 | 10 to 90 |

Every one of the five cold proofs on the emulated phone, and 47 of its 50 warm
proofs, took more than 10 seconds. The two slowest warm proofs, 36.89 s and
38.70 s, were the last two runs of phone session 2 (CPU pressure nominal in
both records); without them the slowest warm proof is 15.21 s.

Proof size: median 958,275 bytes on the Mac Studio (smallest 952,002, largest
962,686), plus 368 bytes of public fields, within the bound of 1,053,331 bytes
and the 1,310,720-byte proof field. Verification in the worker: median
11.6 ms on the Mac Studio and 83.4 ms on the emulated phone.

### Against the earlier configuration

| | Blowup 2^2, 57 queries (2026-10-17) | Blowup 2^3, 43 queries (2026-10-21) | Ratio |
|---|---|---|---|
| Warm median, Mac Studio | 1.69 s | 2.72 s | 1.61 |
| Cold median, Mac Studio | 2.12 s | 3.28 s | 1.55 |
| Warm median, emulated phone | 6.82 s | 13.15 s | 1.93 |
| Cold median, emulated phone | 8.80 s | 15.02 s | 1.71 |
| Slowest cold, emulated phone | 8.98 s | 17.39 s | 1.94 |
| Emulated phone / Mac Studio, warm median | 4.0 | 4.8 | |
| Warm median, emulated phone at exactly 4 times the Mac Studio | 6.8 s | 10.9 s | 1.61 |
| WebAssembly memory | 358.4 MiB | 596.8 MiB | 1.67 |
| Renderer memory, Mac Studio, median | 718.6 MiB | 974.2 MiB | 1.36 |
| Proof size, median (Mac Studio) | 1,188,348 bytes | 958,275 bytes | 0.81 |
| Verify median, Mac Studio | 11.6 ms | 11.6 ms | 1.00 |

On the Mac Studio the browser prover slowed by 1.6 times, as the native
measurement of [the parameter change](reveal-parameters.md) found (1.62). The
phone emulation slowed by more, 1.9 times, because its throttle was harsher
in this run. Either way the emulated phone misses the target: at 4 times the
Mac Studio's figures, the cold median would be about 13.1 s and the warm
median about 10.9 s, against 10 s.

WebAssembly memory rose from 358 MiB to 597 MiB, and the renderer's peak to
about 1 GB on the Mac Studio. That is untested on a real mid-range phone.

### How it was run

```sh
benchmarks/run.sh --reveal --no-native
python3 benchmarks/web/serve.py --port 8000
```

The page was served from the virtual machine and opened in Chrome on the Mac
Studio at `http://localhost:8000/reveal.html`. Each session ran through the
[session driver](#the-session-driver), one session per call
(`--sessions 1 --first-session <n> --rest 0 --proofs`), in the interleaved
order above, with 180 seconds of rest between calls. Alongside each session a
watcher on the Mac, started before the driver opened its tab, found the new
renderer process of that tab (the new renderer of the browser that used more
than 1.5 s of CPU), applied the duty-cycle throttle to it for the phone
sessions from the start of the cold run, and read the renderer's
`phys_footprint_peak` (through `proc_pid_rusage`, which reports the same figure
as `footprint` without suspending the process) and CPU time while the
session ran. Its readings are in each record: `cpu_throttling`,
`process_peak_memory_bytes`, `process_memory_source`,
`renderer_cpu_seconds_in_session` and `mac_load_average_at_session_start`.
The driver touched only the tabs it opened, and the user's other tabs in that
browser were left as they were. After each session the proofs were checked
with `ghost-reveal-verify`. The proof files (about 21 MB a session) are not
committed; the records carry each proof's size and its native result.

## Earlier configuration: blowup 2^2, 57 queries

The run of 2026-10-17 measured the configuration of
[decision 0003](../decisions/0003-proof-system.md) before
[the parameter change](reveal-parameters.md):
`keccak-256/hiding-fri/blowup-2^2/queries-57/grinding-q16-b16-o0/ext-5/zk`,
128 conjectured bits (72 proven), the same trace (2,048 by 3,808). **It met
the 10-second target on both devices.** The median warm proving time was
1.69 s on the Mac Studio and 6.82 s on the emulated mid-range phone, not a
real device. The slowest proof of the run was a cold run on the emulated phone
at 8.98 s, about 1 second inside the target.

The method was the one above, with these differences: a fresh temporary
Chrome profile with no extensions; repository commit `4b96043ee2c8` in every
record (the harness commit as measured, before it was rebased onto `main`;
the rebase did not change the harness or `proofs/`); the renderer's
`footprint` peak read over ssh after each session; CPU pressure nominal in
every record. The throttle reached the worker at exactly the intended rate:
the warm median was 6.82 / 1.69 = 4.0 times the Mac Studio's.

```sh
python3 benchmarks/summarize.py --build wasm-single docs/benchmarks/reveal-results/blowup-2-2-queries-57
```

| Candidate | Blowup | Build | Device | Runs (cold/warm) | Cold median / slowest | Warm median / p90 / slowest | WASM memory median / largest | Process memory median / largest | Proof size median / largest | Verify median / largest | Failed runs | Meets target |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| keccak-256 | 2^2 | wasm-single | Mac Studio | 5/50 | 2.12 s / 2.23 s | 1.69 s / 1.74 s / 1.75 s | 358.4 MiB / 358.4 MiB | 718.6 MiB / 720.7 MiB | 1.1 MiB / 1.1 MiB | 0.01 s / 0.02 s | 0 | yes |
| keccak-256 | 2^2 | wasm-single | emulated mid-range phone, not a real device | 5/50 | 8.80 s / 8.98 s | 6.82 s / 7.37 s / 7.69 s | 358.4 MiB / 358.4 MiB | 689.1 MiB / 689.8 MiB | 1.1 MiB / 1.1 MiB | 0.02 s / 0.11 s | 0 | yes |

Verdict: met (keccak-256 blowup 2^2).

| Device | Cold runs (s) | Warm fastest / median / slowest (s) | Module start-up, cold runs (ms) |
|---|---|---|---|
| Mac Studio | 2.10, 2.10, 2.12, 2.14, 2.23 | 1.65 / 1.69 / 1.75 | 5 to 13 |
| Emulated mid-range phone, not a real device | 8.06, 8.26, 8.80, 8.82, 8.98 | 5.00 / 6.82 / 7.69 | 10 to 99 |

Proof size: median 1,188,348 bytes on the Mac Studio (largest 1,194,788),
plus 368 bytes of public fields. Verification in the worker: median 11.6 ms on
the Mac Studio and 19.8 ms on the emulated phone.

The real statement is heavier than the benchmark statement measured in
[results.md](results.md) at the same hash and blowup:

| | Benchmark statement | Real coin reveal |
|---|---|---|
| Trace height and width | 1,024 x 3,271 | 2,048 x 3,808 |
| Grinding before the batching challenge | 0 bits | 16 bits |
| Warm median, Mac Studio | 0.69 s | 1.69 s |
| Warm median, emulated phone | 2.77 s | 6.82 s |
| Slowest cold, emulated phone | 3.17 s | 8.98 s |
| WebAssembly memory | 157.6 MiB | 358.4 MiB |
| Proof size, median | 997.8 KiB | about 1,160 KiB |

## The session driver

The driver is `benchmarks/web/drive-reveal.mjs` (Node 22 or later, no
dependencies). Start Chrome yourself with a DevTools port and a fresh
profile; the driver never launches or closes the browser and closes only the
tabs it opened:

```sh
chrome --remote-debugging-port=9222 --user-data-dir="$(mktemp -d)"
python3 benchmarks/web/serve.py --port 8000
node benchmarks/web/drive-reveal.mjs --devtools http://localhost:9222 \
  --page http://localhost:8000/reveal.html --sessions 5 --mode desktop \
  --commit "$(git rev-parse HEAD)" --out results --proofs
node benchmarks/web/drive-reveal.mjs --devtools http://localhost:9222 \
  --page http://localhost:8000/reveal.html --sessions 5 --mode phone \
  --commit "$(git rev-parse HEAD)" --out results --proofs
```

For every session it opens a fresh tab, applies Chrome's own CPU throttling
with `Emulation.setCPUThrottlingRate` (1x for `desktop`, the Mac Studio; 4x
for `phone`, the emulated mid-range phone) to the tab and to the prover
worker when Chrome accepts it there, and clears network emulation (no
latency, no throughput limit: nothing but the CPU is changed). It then sets
the device, session number, warm runs and commit, starts the session, waits
for the page to finish, writes the records to
`<out>/<device>-coin-reveal-session<n>.jsonl` in the format of
[reveal-results/](reveal-results/), and closes its tab. With `--proofs` it
also writes the session's proofs for `ghost-reveal-verify`. It rests 180
seconds before every session after the first (`--rest`); run the two modes
in turn to interleave the devices. `--help` lists every option.

Each record names the throttle in `cpu_throttling`,
`cpu_throttling_rate_applied` and `cpu_throttling_worker` (whether Chrome
accepted the throttle on the worker). Both runs above used the duty-cycle
throttle as well, because the DevTools throttle did not reach the worker in
that Chrome build; with the DevTools throttle alone, check that the phone's
warm median is about 4 times the Mac Studio's before using the figures. The
driver does not read the renderer's memory peak or verify the proofs
natively: run `ghost-reveal-verify` on the `.proofs` files afterwards.

## What these runs did not cover

- **No real phone.** The phone figures are an emulation: the Mac Studio's CPU
  throttled. They do not reproduce a phone's memory, thermal limits or
  browser build. With 597 MiB of WebAssembly memory and about 1 GB for the
  renderer in the current configuration, memory on a real mid-range phone is
  untested.
- **No threaded build.** Only the single-thread build was run; the web
  app's threaded module is
  [pending browser measurement](#threaded-build-blowup-23-43-queries).
- **The proof of holding.** Its prover is compiled only for tests until the
  spent-marker set is settled (spec 02, section 13), and every public verifier
  rejects it, so it was not built for the browser or measured.
- **The salted (version 2) coin reveal.** Its trace is 16 columns wider (3,824)
  than the version 1 coin reveal measured here; it was not built for the
  browser or measured in these runs. `app-reveal.html` measures it through
  the web app's own modules.
- **One browser.** Chrome only.
