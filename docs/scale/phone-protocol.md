# Protocol: the real reveal on a physical phone

This page is the procedure a person follows to measure the private reveal on a real phone with the existing browser harness (benchmarks/web/). It is part of the first stage (feasibility and security) of the scale work. The results go to phone-results.md beside it. No physical phone was reachable where this page was written, so every phone figure is **not yet established** until someone runs these steps; the emulated figures of docs/benchmarks/reveal-results.md are not phone figures and are never entered as such.

Every figure this protocol produces carries one of the labels of workload.md: **measured** (actually run, with the device named), **modeled** or **not yet established**. A record from this protocol is measured only on the physical phone it names.

## What is measured

Six runs on each phone, all on the same day, the phone named in every record:

1. The real coin reveal, threaded (the web app's threaded module), cold start after a force-quit, then repeated warm proofs.
2. The same with threads unavailable: the page served without cross-origin isolation, so the browser has no shared memory and the web app's single-thread module proves.
3. The real coin reveal on the single-thread benchmark page, the build behind the emulated single-thread record, for a like-for-like comparison.
4. The salted coin reveal, threaded, as in run 1. <!-- no-figure -->
5. The Poseidon2 equivalent statement: the benchmark statement with Poseidon2 over BabyBear, width 24. <!-- no-figure -->
6. The same benchmark statement with Keccak-256, so that run 5 has a partner of the same shape on the same phone. <!-- no-figure -->

The total browser memory of every session is read from the platform's own tool (step 3 below), not from the page: the WebAssembly memory a page can see is only part of what the browser uses.

### Proof parameters

security.md finds the parameters that would meet the requirement in the query phase (92 queries at blowup 2^3, modeled) but leaves the whole proven bound, and whether a proof at those parameters fits the proof field, **not yet established**; no prover at those parameters exists. So the chosen leaf parameters are not yet established, and this protocol measures the shipped configuration, `keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk` (blowup 2^3 with 43 queries, from proofs/src/stark.rs; its security figures are modeled in security.md). A rerun at the final parameters is not yet established: it needs a prover built at them, a Rust change outside this piece, and then these same steps.

### Which construction each run measures

The repository has two Keccak constructions, and neither is NIST SHA3-256. Every record names its construction in `hash_construction`, and the validator refuses a record whose construction does not match its statement. <!-- no-figure -->

| Run | Page | Statement | Hash construction (`hash_construction`) |
|---|---|---|---|
| 1, 2, 4 | app-reveal.html | coin reveal, salted coin reveal (the real statements of proofs/) | Keccak-f\[1600\] in the padding-free sponge of proofs/src/stark.rs for the commitments, Keccak-256 for the transcript (`keccak-f1600-padding-free-sponge`) <!-- no-figure --> |
| 3 | reveal.html | coin reveal | the same <!-- no-figure --> |
| 5 | index.html, candidate A | the benchmark statement of benchmarks/prover/ | Poseidon2 over BabyBear, width 24 (`poseidon2-babybear-width-24`) <!-- no-figure --> |
| 6 | index.html, candidate B | the benchmark statement | padded Keccak-256 of benchmarks/prover/src/keccak.rs (`keccak-256-padded`) <!-- no-figure --> |

Runs 5 and 6 are the Poseidon2 comparison on an equivalent statement: the same statement shape, the same field and blowup, with only the hash changed. They are not the real reveal. A Poseidon2 version of the real coin reveal does not exist (proofs/ proves it with Keccak only), so a Poseidon2 figure for the real statement is **not yet established**; it needs that prover, a Rust change outside this piece. Records of Poseidon1 or of KoalaBear do not stand in for run 5.

## What you need

- A physical mid-range phone. workload.md names no model for the reference phone, so which model is the reference is not yet established; use a current mid-range Android phone (for example a Samsung Galaxy A-series or Google Pixel a-series model) and name it exactly. Run several phones if you can; each is its own set of records.
- The phone on its own battery, above half charge, screen kept on, no other app open, other Chrome tabs closed, battery saver off. Let it rest at room temperature for ten minutes before the first session.
- Chrome for Android, its version read from the phone (step 1). USB debugging on (Developer options), and the phone connected to the computer by cable.
- A computer with this repository, the Rust toolchain of the repository, Node 22 or later, Python 3 and the Android platform tools (`adb`). <!-- no-figure -->
- A Safari-only phone (an iPhone) can run runs 3, 5 and 6 by hand; see "An iPhone" below. <!-- no-figure -->

## Records

One JSON line per proof, in the format `benchmarks/scale/phone_records.py` validates:

| Field | Meaning |
|---|---|
| `device_model` | The phone's exact model, as the platform reports it |
| `os` | Operating system and version |
| `browser` | Browser and full version |
| `device_kind` | `physical`; `emulated` only for an emulation, whose model must say so |
| `threads_available` | Whether the page had shared memory for threads |
| `thread_count` | Prover threads used |
| `run_kind` | `cold` or `warm` |
| `outcome` | `completed`, `failed`, `killed`, `out_of_memory` or `refused` |
| `proof_seconds` | Proving time of the run, a number; null when it did not complete |
| `peak_browser_memory_mib` | Peak memory of the whole browser during the session, in MiB, from the platform tool |
| `memory_tool` | The tool and command that read it |
| `proof_bytes` | Proof size |
| `parameters` | The configuration string the prover reports |
| `hash_candidate`, `hash_construction`, `statement` | What was proved and with which exact construction |
| `date` | The day of the run |

Raw harness files go to a scratch directory outside the repository, because the harness labels every session as the Mac Studio or the emulated phone. The converted records go to `docs/scale/phone-records/<phone>/`, one file per run and session, named `<run>-session<n>.jsonl` (for example `app-threads-session0.jsonl`). Commit them only after `validate` passes.

## Steps (Android, Chrome)

### 1. Build, serve and record the device

Build the harness and the prover modules once, then serve the page cross-origin isolated, and let the phone reach the computer's ports over the cable:

```sh
benchmarks/run.sh --web --reveal --app --no-native
python3 benchmarks/web/serve.py --port 8000
adb devices
adb reverse tcp:8000 tcp:8000
adb forward tcp:9222 localabstract:chrome_devtools_remote
mkdir -p /tmp/phone-raw
```

Read the device, operating system and browser into the session notes; these strings go into every record:

```sh
adb shell getprop ro.product.manufacturer
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell dumpsys package com.android.chrome | grep versionName
curl -s http://localhost:9222/json/version
```

### 2. Cold start after a force-quit

Before every session, force-quit Chrome and start it again on a blank page, so the first proof of the session is a cold start of the browser, the module and the prover:

```sh
adb shell am force-stop com.android.chrome
adb shell am start -n com.android.chrome/com.google.android.apps.chrome.Main -d about:blank
adb forward tcp:9222 localabstract:chrome_devtools_remote
```

Wait until the DevTools endpoint answers (the `curl` command of step 1), then start the session. Rest the phone three minutes between sessions, as the emulated runs did.

### 3. Total browser memory

The tool is Android's `dumpsys meminfo`, which reports the proportional set size (PSS) of each process. Chrome runs as several processes (the browser, the GPU process and a sandboxed renderer for the tab), and the total is the sum of every Chrome process at one moment. In a second terminal, sample them every second for the whole session:

```sh
while true; do echo "sample $(date +%s)"; adb shell dumpsys meminfo com.android.chrome | grep 'TOTAL PSS:'; sleep 1; done | tee /tmp/phone-raw/meminfo-<run>-session<n>.log
```

Stop it when the session ends, and take the peak of the per-sample sums:

```sh
awk '/^sample/ {if (t > m) m = t; t = 0; next} {t += $3} END {if (t > m) m = t; printf "%.1f MiB\n", m / 1024}' /tmp/phone-raw/meminfo-<run>-session<n>.log
```

That figure is `peak_browser_memory_mib` for every record of the session, and `memory_tool` is "Android dumpsys meminfo, TOTAL PSS of every com.android.chrome process, summed per sample, sampled every second". If your Android version prints the total differently, sum the per-process totals of Chrome yourself and write in `memory_tool` how. Sampling adds some load on the phone; sample every session the same way so the sessions compare. Android Studio's Memory Profiler is an acceptable alternative tool if it is named in `memory_tool`.

### 4. Run 1: repeated proofs, threads available

Five sessions, each a cold start (step 2) and one cold proof then ten warm proofs, the memory sampled (step 3). `--mode desktop` applies no CPU throttling, which is what a real phone needs; it labels the raw records as the Mac Studio, which the conversion (step 8) replaces:

```sh
node benchmarks/web/drive-reveal.mjs --devtools http://localhost:9222 \
  --page "http://localhost:8000/app-reveal.html?build=wasm-threads&statement=coin-reveal" \
  --sessions 1 --first-session 0 --rest 0 --mode desktop --warm 10 \
  --commit "$(git rev-parse HEAD)" --out /tmp/phone-raw/app-threads
```

Repeat with `--first-session 1` to `--first-session 4`, a force-quit and the memory sampler before each. <!-- no-figure --> A session the page refuses (for instance one core, or no isolation) is recorded as refused, never dropped.

### 5. Run 2: threads unavailable

Serve the same directory with Python's plain web server, which sends no cross-origin isolation headers, so the browser gives the page no shared memory, as an ordinary site would. Clear Chrome's cached files first (Settings, Privacy and security, Delete browsing data, Cached images and files), because this server allows caching:

```sh
python3 -m http.server 8001 --bind 127.0.0.1 --directory benchmarks/web
adb reverse tcp:8001 tcp:8001
node benchmarks/web/drive-reveal.mjs --devtools http://localhost:9222 \
  --page "http://localhost:8001/app-reveal.html?build=wasm-single&statement=coin-reveal" \
  --sessions 1 --first-session 0 --rest 0 --mode desktop --warm 10 \
  --commit "$(git rev-parse HEAD)" --out /tmp/phone-raw/app-no-threads
```

Five sessions as in step 4. Every record must show `cross_origin_isolated` and `threads_available` false; if not, the run did not test what it is for.

### 6. Runs 3 and 4: the single-thread page and the salted reveal

```sh
node benchmarks/web/drive-reveal.mjs --devtools http://localhost:9222 \
  --page http://localhost:8000/reveal.html \
  --sessions 1 --first-session 0 --rest 0 --mode desktop --warm 10 --proofs \
  --commit "$(git rev-parse HEAD)" --out /tmp/phone-raw/reveal-single
node benchmarks/web/drive-reveal.mjs --devtools http://localhost:9222 \
  --page "http://localhost:8000/app-reveal.html?build=wasm-threads&statement=salted-coin-reveal" \
  --sessions 1 --first-session 0 --rest 0 --mode desktop --warm 10 \
  --commit "$(git rev-parse HEAD)" --out /tmp/phone-raw/app-threads-salted
```

Five sessions of each. Verify the proofs of reveal.html natively afterwards with `ghost-reveal-verify` on the `.proofs` files, as the emulated runs did.

### 7. Runs 5 and 6: the Poseidon2 equivalent statement

The driver cannot choose the benchmark page's hash candidate or blowup, so these sessions are run on the phone by hand. For each session, force-quit Chrome and open the page directly:

```sh
adb shell am force-stop com.android.chrome
adb shell am start -n com.android.chrome/com.google.android.apps.chrome.Main -d http://localhost:8000/index.html
```

On the page choose candidate A (Poseidon2, BabyBear, width 24) and blowup 2^3, warm runs ten, the session number, and the repository commit; press Run session, wait for "session complete", then Download records (with the memory sampler of step 3 running). Then the same with candidate B (Keccak-256, the padded construction) at blowup 2^3. Five sessions of each, alternating A and B. The query count of each candidate is the one its record's configuration string reports. Pull the downloaded files from the phone: <!-- no-figure -->

```sh
adb shell ls /sdcard/Download
adb pull /sdcard/Download/<file> /tmp/phone-raw/bench-<candidate>/
```

### 8. Convert, validate and summarize

Convert each session's raw file with the device strings of step 1 and the memory peak of step 3, into the record directory, then validate and summarize:

```sh
python3 benchmarks/scale/phone_records.py convert --kind physical \
  --device-model "<manufacturer> <model>" --os "Android <version>" --browser "Chrome <version>" \
  --memory-mib <peak> --memory-tool "Android dumpsys meminfo, TOTAL PSS of every com.android.chrome process, summed per sample, sampled every second" \
  /tmp/phone-raw/app-threads/mac-studio-coin-reveal-session0.jsonl > docs/scale/phone-records/<phone>/app-threads-session0.jsonl
python3 benchmarks/scale/phone_records.py validate docs/scale/phone-records/<phone>/*.jsonl
python3 benchmarks/scale/phone_records.py summarize docs/scale/phone-records/<phone>/*.jsonl
```

The summary keeps every device and kind on its own row and never pools an emulated record with a physical one. Paste its table into phone-results.md, replacing the not yet established cells of that phone, with the date and the device named, and label each figure measured on that phone.

## Pass or fail

A physical row passes against the reference phone ceilings of workload.md when all of these hold (the summary's "Meets the ceilings" column):

- the proving time ceiling of workload.md, 10 s for one reveal, cold or warm (modeled: the existing target, kept as the input): the slowest cold proof and the warm median are both at most that;
- the memory ceiling of workload.md, a proposed 1 GiB for the whole tab (not yet established: a proposal for the founder): the peak browser memory of every session is at most that;
- no run failed, was killed or ran out of memory, and the full set of runs is present (five cold and fifty warm, modeled from the protocol's sessions).

Each thread mode is judged on its own. A phone that passes threaded and fails with threads unavailable passes only where shared memory exists, and the results page says so. Runs 5 and 6 are judged the same way, but they are the benchmark statement, not the reveal, so their pass or fail says how the hash compares on that phone, not whether the real reveal meets the ceiling. Until a row exists, its result is not yet established.

## An iPhone

Safari does not speak the DevTools protocol the driver uses, so on an iPhone every session is run by hand: serve with `serve.py --bind` on the computer's local address, open reveal.html or index.html in Safari on the phone, run the session, and download the records. A plain local address is not a secure context, so Safari gives the page no shared memory there: only the single-thread runs (3, 5 and 6) can be made this way, and threaded figures on an iPhone are not yet established without an HTTPS origin, which the harness does not provide. The memory tool is Xcode Instruments (Activity Monitor template) on a Mac, attached to the phone, reading the peak of Safari's WebContent and networking processes; name it in `memory_tool`. Convert with `--kind physical`, the model from Settings, General, About, and the iOS and Safari versions.

## What this protocol cannot establish

- A phone's result under thermal throttling over a long day of use: each session is short, and the rest between sessions keeps the phone cool. A sustained-use run is not yet established.
- The real reveal with Poseidon2 (no such prover) and the reveal at the final parameters (not yet chosen); both are not yet established.
- Any figure for a phone that was not run. One phone's result says nothing about another model.
