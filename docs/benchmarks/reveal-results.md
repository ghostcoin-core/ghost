# Real reveal prover in the browser

**The 10-second target is met on both the Mac Studio and the emulated
mid-range phone, not a real device, by the real coin reveal prover.** The
median warm proving time is 1.69 s on the Mac Studio and 6.82 s on the
emulated mid-range phone, not a real device. The slowest proof of the run was
a cold run on the emulated phone at 8.98 s, about 1 second inside the target.

The [earlier results](results.md) measured the benchmark statement of the
plan. This run measures the statement that ships: the coin reveal (S1) of the
`proofs/` crate, through its own `prove_coin_reveal`, in the configuration of
[decision 0003](../decisions/0003-proof-system.md). It is the same method as
the [benchmark plan](plan.md), on the same Mac Studio and Chrome build. The
raw records are in [reveal-results/](reveal-results/), one file per device
and session.

## What was run

- The prover: `ghost_proofs::prove_coin_reveal`, unchanged, built for
  `wasm32-unknown-unknown` with SIMD from `benchmarks/reveal`, in a dedicated
  background worker (`benchmarks/web/reveal.html`). The configuration is
  `keccak-256/hiding-fri/blowup-2^2/queries-57/grinding-q16-b16-o0/ext-5/zk`:
  zero-knowledge mode on, 128 conjectured bits (72 proven), trace height 2,048
  before zero-knowledge padding and width 3,808.
- The witness: drawn per session from a recorded seed, with a random leaf
  position and pseudo-random siblings under a 32-level coin tree, and the
  plan's amounts (1,000 GHOST in, 250 out, a fee of 0.001 GHOST). Sessions 0,
  2 and 4 keep the remainder under the same key; sessions 1 and 3 send it to
  a new key. Zero-knowledge randomness came from `crypto.getRandomValues` on
  every run.
- Five sessions on each device, interleaved (Mac Studio, phone, phone, Mac
  Studio, and so on), each a fresh tab with one cold run and ten warm runs:
  110 proofs. At least 3 minutes of rest before every session.
- 110 completed proofs, no failed, killed or refused run. Every proof verified
  in the worker, and **every proof also verified natively**: the driver took
  each proof and its public fields out of the page and checked them with
  `ghost-reveal-verify`, which calls `ghost_proofs::verify_coin_reveal`, on
  the aarch64 Linux virtual machine on the same Mac Studio. Each record says
  so in `native_verified`.
- Single-thread build with SIMD only (`wasm-single`); no threaded build was
  run, as in the earlier results.

### Machine and browser

| Item | Value |
|---|---|
| Machine | Mac Studio, Apple M5 Max, 64 GB; 18 logical cores reported by the browser |
| Operating system | macOS 27.0.1 |
| Browser | Google Chrome 155.0.8059.80, a fresh temporary profile with no extensions |
| Repository commit | `4b96043ee2c8` in every record: the harness commit as measured, before it was rebased onto `main`; the rebase did not change the harness or `proofs/` |
| Library | Plonky3 `f98331687e47` |
| Compiler | rustc 1.99.1, `-C target-feature=+simd128`, release profile |
| CPU pressure (Compute Pressure API) | nominal in every record |

The emulated mid-range phone, not a real device, is the same Chrome on the
same Mac Studio with the renderer process, worker included, throttled 4x by
pausing and resuming it on the Mac (25 ms running in every 100 ms), the same
method as the earlier results, because the DevTools throttle does not reach
dedicated workers in this Chrome build. The throttle reached the worker: the
warm median is 6.82 / 1.69 = 4.0 times the Mac Studio's.

## Results

Produced by `benchmarks/summarize.py`:

```sh
python3 benchmarks/summarize.py --build wasm-single docs/benchmarks/reveal-results
```

The full five cold and fifty warm runs per device are present, so the
script's default session counts apply; only the build is named, because the
threaded build was not run.

| Candidate | Blowup | Build | Device | Runs (cold/warm) | Cold median / slowest | Warm median / p90 / slowest | WASM memory median / largest | Process memory median / largest | Proof size median / largest | Verify median / largest | Failed runs | Meets target |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| keccak-256 | 2^2 | wasm-single | Mac Studio | 5/50 | 2.12 s / 2.23 s | 1.69 s / 1.74 s / 1.75 s | 358.4 MiB / 358.4 MiB | 718.6 MiB / 720.7 MiB | 1.1 MiB / 1.1 MiB | 0.01 s / 0.02 s | 0 | yes |
| keccak-256 | 2^2 | wasm-single | emulated mid-range phone, not a real device | 5/50 | 8.80 s / 8.98 s | 6.82 s / 7.37 s / 7.69 s | 358.4 MiB / 358.4 MiB | 689.1 MiB / 689.8 MiB | 1.1 MiB / 1.1 MiB | 0.02 s / 0.11 s | 0 | yes |

Verdict: met (keccak-256 blowup 2^2).

Security figures are conjectured estimates; the target is 128 conjectured
bits, with the best proven figure (72 bits) recorded in each record beside it.

### Spread

| Device | Cold runs (s) | Warm fastest / median / slowest (s) | Module start-up, cold runs (ms) |
|---|---|---|---|
| Mac Studio | 2.10, 2.10, 2.12, 2.14, 2.23 | 1.65 / 1.69 / 1.75 | 5 to 13 |
| Emulated mid-range phone, not a real device | 8.06, 8.26, 8.80, 8.82, 8.98 | 5.00 / 6.82 / 7.69 | 10 to 99 |

Proof size: median 1,188,348 bytes on the Mac Studio (largest 1,194,788),
plus 368 bytes of public fields. Verification in the worker: median 11.6 ms on
the Mac Studio and 19.8 ms on the emulated phone.

## Against the earlier figures

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

The target still holds, but with much less room: the slowest cold proof on
the emulated phone uses about 90 percent of the 10 seconds, where the
benchmark statement used about a third. A real mid-range phone may be slower
than this emulation (see below), so this margin is the figure to watch when
the statement or the configuration changes.

## How it was run

```sh
benchmarks/run.sh --reveal --no-native
python3 benchmarks/web/serve.py --port 8000
```

The page was served from the virtual machine and opened in Chrome on the Mac
Studio at `http://localhost:8000/reveal.html`. A driver on the virtual
machine opened each session in a new tab over the Chrome DevTools Protocol,
set the device and session, started the run, applied the duty-cycle throttle
for the phone sessions, read the renderer's `footprint` peak over ssh after
the session, saved the records, and took the proofs out of the page for
`ghost-reveal-verify`. The proof files (about 26 MB a session) are not
committed; the records carry each proof's size and its native result.

## What this run did not cover

- **No real phone.** The phone figures are an emulation: the Mac Studio's CPU
  throttled 4x. They do not reproduce a phone's memory, thermal limits or
  browser build. With 358 MiB of WebAssembly memory and about 690 MiB for the
  renderer, memory on a real mid-range phone is untested.
- **No threaded build.** Only the single-thread build was run.
- **The proof of holding.** Its prover is compiled only for tests until the
  spent-marker set is settled (spec 02, section 13), and every public verifier
  rejects it, so it was not built for the browser or measured.
- **One browser.** Chrome only.
