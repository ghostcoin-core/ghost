# Browser proof benchmark harness

The harness for [the benchmark plan](../docs/benchmarks/plan.md): the coin
reveal statement in Plonky3, the security gate, the correctness checks, a
browser page that measures proving inside a background worker, and the
summary that turns raw records into the results table and the verdict.

Soundness comes first. Only configurations that pass the security gate
(128 bits under the library's conjectured estimate, zero-knowledge mode on)
are built at all; speed decides among those.

## Layout

| Path | What it is |
|---|---|
| `Cargo.toml`, `Cargo.lock` | Workspace; every Plonky3 crate pinned to one revision |
| `prover/` | Package `ghost-bench`: the statement for both hash candidates, the zero-knowledge configurations, the security gate, the native runner |
| `prover/tests/correctness.rs` | The correctness checks of the plan's Method step 1 |
| `wasm/` | Package `ghost-bench-wasm`: WebAssembly exports to prove and verify in a worker |
| `web/` | The page (`index.html`, `main.js`), the worker (`worker.js`) and `serve.py`, which serves them cross-origin isolated |
| `summarize.py` | Reads records and prints the table and the verdict |
| `tests/` | Tests for `summarize.py` and `serve.py`, with a small fixture |
| `run.sh` | The one command: build, correctness checks, native reference, summary |

## The one command

```sh
benchmarks/run.sh            # build, correctness checks, native reference, summary
benchmarks/run.sh --web      # also build the browser bundle into web/pkg
```

`--web` installs the pinned `wasm-bindgen` command-line tool into
`benchmarks/.tools` on first use. Records found under
`docs/benchmarks/results/` are summarized together with the native reference;
other record files or folders can be passed as arguments. The native
reference is context only and never counts toward the target.

## Configurations

| Candidate | Hash | Blowups | Note |
|---|---|---|---|
| A | Poseidon2 over BabyBear, width 24 | 2^1, 2^2, 2^3 | Circuit of degree 2 |
| B | Keccak-256 on Plonky3's Keccak-f circuit | 2^2, 2^3 | Degree 3: zero-knowledge mode cannot fit it in a blowup of 2^1, so that configuration is refused and reported as not buildable |

The number of queries is the smallest that reaches 128 conjectured bits for
each configuration, with grinding of at most 16 bits; the gate re-checks it
before every proof made through the library interface.

## A browser session

1. Build the bundle: `benchmarks/run.sh --web`.
2. Serve it: `python3 benchmarks/web/serve.py`, then open
   `http://localhost:8000/` in a fresh Chrome profile with no extensions and
   automatic updates off.
3. For the emulated phone, open DevTools on the tab and set CPU throttling to
   4x before starting. Choose "Emulated mid-range phone, not a real device" on
   the page.
4. Choose the hash candidate, blowup and session number, then run the session
   (one cold run and ten warm runs).
5. While it runs, sample the renderer's footprint with
   `footprint -p <renderer pid>` and enter the peak on the page.
6. Download the records into `docs/benchmarks/results/`, close the tab, rest
   for at least 3 minutes, and continue with the next configuration in the
   interleaved order.

The page records the Chrome build, the logical cores, whether threads and
SIMD were available and used, the module start-up time on the cold run, the
WebAssembly memory after each proof, and the CPU pressure state when Chrome
reports it.

## Builds

The bundle built here is the single-thread build with SIMD; every record
says so (`"build": "wasm-single"`, `"threads_used": false`). The threaded
build additionally needs WebAssembly threads support in the Rust toolchain
(a nightly toolchain rebuilding the standard library with atomics) and a
thread pool in the worker. The page is already served cross-origin isolated
for it.
