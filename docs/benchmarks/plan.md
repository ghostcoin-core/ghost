# Browser proof benchmark plan

This document fixes what the browser proof benchmark measures, on what, and how
the result is read, before anything is measured. Its purpose is to make the
10-second target in [the outline](../ghost-outline.md) mean something. It is a
specification only. A later change implements the benchmark harness against it.

Everything taken from the outline is stated as fact. Where the outline is
silent and a choice had to be made, the choice is marked **Default** and
listed again in [Defaults chosen here](#defaults-chosen-here). A later decision
may change any of them. If one changes, this document is edited first and the
benchmark is run against the edited version.

## What the outline fixes

- The reveal is one private transaction shape: one commitment in, an optional
  public amount out, and one remainder commitment.
- The coin tree has room for about four billion commitments, which is a tree
  of depth 32.
- A reveal proves membership in a recent tree state, opens one commitment,
  publishes a one-time marker, creates the remainder commitment, proves
  conservation of value including the fee, and is bound to its purpose.
- Proofs are hash-based, need no trusted setup, and come from an existing
  open-source library. The starting pick is Plonky3.
- The proof is never wrapped inside an elliptic-curve proof.
- The library's zero-knowledge mode must be on in the shipped configuration.
- The hash inside the proof is also the tree hash. It is chosen from the
  measurements below: the most-studied candidate that meets the speed target.
- The target is 10 seconds or less to prove, in a browser, on named reference
  hardware. The proof system is revisited if it is not met.
- Proofs are made in the browser in a background worker. Nothing is downloaded
  as a proving key.
- The design aims at post-quantum security within a defined threat model.

## Reference hardware and browser

One laptop and one phone. Both are real, widely sold models and are chosen to
be unremarkable on purpose: a result on a better device would not mean much.

| | Laptop | Phone |
|---|---|---|
| Model | Apple MacBook Air 13-inch (M2, 2022), model identifier Mac14,2 | Samsung Galaxy A55 5G, model SM-A556B (international version) |
| Year | 2022 (released July 2022) | 2024 (announced 11 March 2024, released 15 March 2024) |
| Processor | Apple M2, 8 cores (4 performance, 4 efficiency) | Samsung Exynos 1480, 8 cores (4 x Cortex-A78 at 2.75 GHz, 4 x Cortex-A55 at 2.0 GHz) |
| Memory | 8 GB (the base configuration) | 8 GB |
| Storage | 256 GB | 256 GB |
| Operating system | The latest macOS release on the day of the run, recorded | The latest Android release Samsung ships for the model on the day of the run, recorded |
| Browser | Google Chrome stable, version 155 (155.0.8059.40 at the time of writing) | Google Chrome for Android stable, version 155 (155.0.8059.39 at the time of writing) |

Why these:

- The A55 is Samsung's mid-range line, sold new and used in volume. The M2
  Air is the most common Apple Silicon laptop in circulation, and its base
  configuration is a plain 8 GB machine.
- Chrome is the most used browser on both platforms and has the best
  WebAssembly support, including threads and SIMD.
- **Default:** the exact models and the Chrome major version are choices made
  here, not outline decisions. Replace a model only with one in the same class,
  and say so in the results.

Rules for the machines:

- Chrome is pinned to one build for the whole run. Automatic updates are off
  while the benchmark runs, and the full build string is recorded.
- A fresh browser profile with no extensions is used. Only the benchmark tab is
  open, and it stays in the foreground with the screen on.
- Laptop: plugged in, no other applications running, lid open.
- Phone: not charging, battery between 50% and 100% at the start of each
  session, power-saving mode off, airplane mode on (nothing in the benchmark
  needs a network once the page is loaded), no other applications running.
- Thermal state is part of the result, not a nuisance. Each session starts
  after the device has rested for at least 10 minutes, and the harness records
  every run's start time so heat build-up shows in the series.

## The statement being proved

The statement is the coin reveal: the largest and most representative of the
outline's statements. It has the one fixed private shape, so every reveal costs
the same. A full reveal, a zero-amount claim and a fee that uses the whole
balance are the same statement with different witness values; they are not
separate statements.

This section fixes the size and cost shape of the statement. It does not
decide the lifecycle specification. Where the layout below (the exact fields,
their order and which values feed the marker) differs from what the lifecycle
specification later settles, the benchmark is re-run only if the number of hash
calls, the input lengths or the constraint counts change.

### Field and encoding

- **Default:** the proof field is BabyBear (prime 2^31 - 2^27 + 1), with a
  degree-5 extension field for challenges, in Plonky3's STARK stack with FRI
  as the polynomial commitment scheme.
- A digest is 8 field elements (about 248 bits).
- **Default:** an amount is 96 bits, held as four limbs of 24 bits, each limb
  range-checked. This holds about 7.9 x 10^10 whole GHOST at 18 decimals,
  well above the 21 million main emission plus any tail.
- Secrets and blinding values are 8 field elements each.

### Hash used inside the statement

- **Default (candidate A):** Poseidon2 over BabyBear, state width 24, rate 16,
  capacity 8, output the first 8 elements of the state. Plonky3 ships this
  permutation.
- **Default (candidate B):** Keccak-256, byte-oriented, using Plonky3's Keccak
  permutation circuit.
- Both are measured. The outline chooses the most-studied hash that meets the
  speed target, and Keccak is the more studied of the two. If B meets the
  target on both devices it is chosen over A; otherwise A is chosen if it
  meets the target. The decision itself is made after the measurements, not
  here.
- Every use of the hash carries its own explicit tag, as the outline requires.
  For A, a tag is placed in the capacity part of the state (one element for the
  use, one for the tree level where relevant). For B, a one-byte tag and, for
  tree nodes, a one-byte level are the first input bytes. The tags are:
  commitment, marker, tree node. (The note key is derived outside the
  statement.)
- A tree node is one permutation of the left and right child digests plus the
  tag and level. A longer input (a commitment, a marker) is absorbed 16
  elements at a time for A, and in 136-byte blocks for B.

### Public inputs

The verifier supplies or recomputes all of these. The proof is bound to them
because the library places the public values in the Fiat-Shamir transcript.

| Name | Size | Meaning |
|---|---|---|
| Tree root | 8 elements | A recent, widely shared state of the coin tree, taken from a block header |
| Marker | 8 elements | The one-time marker published by this reveal |
| Remainder commitment | 8 elements | The new commitment holding what is left |
| Public amount out | 4 limbs | The amount sent to the public destination (may be zero) |
| Fee | 4 limbs | The total fee (base fee plus the fixed private tip) as set by the chain's formula for this block. The chain checks it equals the formula; the user never chooses it |
| Binding digest | 8 elements | A tagged hash, computed by the verifier outside the proof, over the chain identifier, transaction type and version, destination address, public amount out, fee, remainder commitment and tree root |
| Type tag | 1 element | The commitment type and version; fixed to the coin type and the current version |

Purpose binding is the last two rows. The binding digest is a public value,
so a proof cannot be reused with a different destination, amount, chain or
transaction. The benchmark must include it as a real public input, because
public inputs cost transcript work and proof size.

### Witness (private inputs)

- Secret `s`, reveal secret `r`, blinding `b` of the commitment being opened.
- The commitment's version and type, content fingerprint, rule field, and
  amount `v` (four limbs).
- A Merkle path: 32 sibling digests and 32 direction bits.
- Fresh blinding `b'` for the remainder commitment, and the remainder amount
  `v'` (four limbs).

### Constraints

1. **Opening.** The input commitment `C` equals the tagged hash of
   `(s, r, b, version and type, fingerprint, rule, v)`. For the benchmark
   layout this is 8 + 8 + 8 + 1 + 8 + 4 + 4 = 41 elements plus the tag:
   3 permutations for A, 2 for B.
2. **Membership.** Starting from `C` as the leaf, apply the tagged node hash
   32 times along the path, selecting left or right by the direction bits.
   The result must equal the public tree root: 32 permutations for A and for B.
   Direction bits are range-checked to be 0 or 1.
3. **Marker.** The public marker equals the tagged hash of `(r, b)`: 16
   elements for A (1 permutation), 65 bytes for B (1 permutation). Which
   values feed the marker is the lifecycle specification's decision; what is
   fixed here is that the marker costs one short hash and is different for the
   remainder commitment, which reuses `s` and `r` with a fresh blinding.
4. **Remainder commitment.** The public remainder commitment equals the tagged
   hash of `(s, r, b', version and type, fingerprint, rule, v')`. The version
   and type, fingerprint and rule are constrained to equal those of the input,
   and `s` and `r` are the same values as in the opening (the default of the
   outline: the same Phantom Key controls the remainder). 3 permutations for A,
   2 for B.
5. **Conservation.** `v = out + v' + fee`, limb by limb with carries, with all
   amounts range-checked to 96 bits. Because `v'` cannot be negative, the fee
   plus the amount out cannot exceed the balance.
6. **Type.** The type tag is the coin type, so a data commitment can never
   satisfy this statement.

Total hash cost: 39 Poseidon2 permutations for A, and 37 Keccak permutations
for B. The remaining constraints are small (range checks, limb arithmetic,
bit selection). The trace is therefore short, but the zero-knowledge mode
raises the minimum trace height and adds random rows, so the benchmark
measures the real configuration instead of estimating from the constraint
counts.

### Witness data for the runs

- The tree is conceptual: 2^32 leaves are never built. The harness generates
  a path with pseudo-random sibling digests, a random leaf position, and the
  consistent root. Sibling values and direction bits do not change the cost but
  must differ between runs so nothing degenerate (such as all-empty subtrees)
  is measured. Seeds are recorded.
- The input amount, the amount out and the fee are fixed for the primary
  measurement: input 1,000.000000000000000000 GHOST, amount out
  250.000000000000000000 GHOST, fee 0.001000000000000000 GHOST, remainder the
  rest. These are arbitrary but realistic and use the full width of the
  limbs.
- Zero-knowledge randomness (blinding rows, salts) is freshly drawn from the
  browser's secure random source on every run. It is never seeded.

## Security level and zero-knowledge mode

- **Default target:** 128 bits of security for soundness, counted under the
  standard FRI conjecture for the chosen code rate and the extension field
  size, with the extension degree chosen so that the challenge field gives
  more than 128 bits (hence degree 5 above).
- Required: the proof-of-work grinding step is allowed up to 16 bits, and
  the rest comes from FRI queries. For a code rate of 2^-k, each query is
  counted as k bits, so the number of queries is at least `(128 - grinding)
  / k`. The harness computes this from the parameters; it does not use a
  hard-coded count.
- The primary run uses a blowup of 2^1 (rate 1/2). The harness also runs
  blowups of 2^2 and 2^3 as a sweep, because a higher blowup needs fewer
  queries (smaller proof, slower prover) and the best trade is a result, not an
  assumption.
- The result also records, next to the conjectured figure, the figure under
  the best proven bound for the same parameters, so a reader can see the gap.
  The target is the conjectured figure, and this is stated plainly wherever the
  number is quoted.
- Post-quantum: the design aims at security within the defined threat model
  in the outline. This benchmark does not prove that. It records the digest
  size, hash and field so the threat-model work can be done against exactly
  what was measured. The benchmark never uses a pairing or elliptic-curve
  step, and its proof is not wrapped.
- **Zero-knowledge mode is on for every measured configuration.** Plonky3 does
  this with a hiding polynomial commitment scheme paired with a hiding Merkle
  commitment; both must be selected, and the library does not check at compile
  time that they are. The harness therefore must:
  1. build the configuration through one function used by both the prover and
     the verifier, which uses the hiding commitment scheme and the hiding Merkle
     commitment, and fails to start if the library reports that the
     configuration is not zero-knowledge;
  2. print the library revision, the configuration name and the zero-knowledge
     flag into every result record;
  3. pass a check that two proofs of the same statement and witness, made with
     different randomness, differ in their commitments and that both verify;
  4. pass a check that the trace height used is at or above the library's
     required minimum for zero-knowledge for the number of openings and queries
     in use, and record the actual height.
- Measurements made without zero-knowledge mode are labelled "diagnostic, not
  zero-knowledge" and never count towards the target.
- The library is pinned to one exact revision for the benchmark, and the
  revision is recorded. Known problems in the zero-knowledge code of any
  revision (for instance a locking fault that can hang the prover, or a trace
  that is too short to hide its contents) are checked against the revision
  chosen before it is pinned.

## What is recorded

For every proof, in the browser, on each device:

| Quantity | Definition |
|---|---|
| Proving time | Wall-clock milliseconds, taken inside the worker with `performance.now()`, from the call that receives the witness inputs to the return of the finished proof bytes. It includes witness and trace generation, the zero-knowledge randomness, FRI commitment and queries, and grinding. It excludes page load, downloading and compiling the WebAssembly module, and moving the result to the page. These are recorded separately (below) |
| Module start-up time | Milliseconds to fetch, compile and instantiate the module in the worker, recorded for the cold run |
| Peak memory | The high-water mark of the WebAssembly linear memory in the worker (pages grown multiplied by 64 KiB), read by the harness after each proof. Also recorded: the browser's own process-level peak, from the operating system's tools (macOS `footprint` on the renderer process; on Android `dumpsys meminfo` taken while the proof runs and the largest value kept) |
| Proof size | Bytes of the proof in the library's standard serde encoding with the postcard format, public inputs excluded. Also recorded: the public inputs' size and the total |
| Verification time | Wall-clock milliseconds to verify the proof, in the same worker on the same device, from receiving the proof and public inputs to a yes or no. Also recorded once natively on the laptop, because the chain verifies natively |
| Outcome | Whether the run completed, was killed by the browser, or ran out of memory |

Also recorded on every result:

- Device, operating system, Chrome build, number of logical cores reported
  by the browser, whether threads and SIMD were available and used.
- Library revision, Rust compiler version, build flags, the hash candidate,
  the blowup, the number of queries, grinding bits, the extension degree, the
  trace height and width, and the security figures (conjectured and proven).
- Start time of the run, so thermal drift is visible. On the phone, battery
  level and the browser's reported thermal state where available.

### Builds

- **Primary build:** WebAssembly with SIMD and threads (shared memory, with
  the page served cross-origin isolated). Our own web application is able to
  ship that, so this is what a user gets.
- **Fallback build:** WebAssembly, single thread, SIMD on. Measured as well,
  because the application must still work where threads are unavailable.
- **Native reference:** the same prover built natively on the laptop, for
  context only. It does not count towards the target.

## Method

1. **Correctness before speed.** Before any timing counts, on every device and
   build, the harness verifies that: a good proof verifies; the proof fails
   when any public input is changed (root, marker, remainder commitment,
   amount, fee, binding digest); a witness that breaks conservation (value out
   exceeds value in, or the sum is off by one at a limb boundary) does not
   produce a proof that verifies; and a witness with a wrong Merkle path is
   rejected. A speed number from a build that fails any of these is discarded.
2. **Sessions.** Five sessions per device, per build, per hash candidate, per
   blowup. A session is a fresh browser tab opened on the page, so every
   session has a real cold start.
3. **Runs per session.** One cold run (the first proof after the tab opens),
   then ten warm runs back to back in the same worker. 55 proofs per
   configuration.
4. **Rest.** At least 10 minutes between sessions on the phone and 3 minutes on
   the laptop, so one session's heat does not carry into the next. The
   back-to-back warm runs inside a session are kept as they are, because a user
   who makes several reveals in a row meets the same heat.
5. **Order.** Configurations are interleaved rather than run one after another,
   so drift in room temperature or battery level does not favour one.
6. **Primary configuration.** Hash candidate A, blowup 2^1, primary build. The
   others are the sweep and are reported beside it.

## Reading the result

For every configuration the report gives, per device:

- Cold proving time: the median and the slowest of the five cold runs.
- Warm proving time: the median, the 90th percentile, and the slowest of the
  fifty warm runs.
- Peak memory, proof size and verification time: the median and the largest.
- Whether any run failed.

**Default:** the 10-second target is met for a configuration on a device when
**both** the median warm proving time **and** the slowest cold proving time are
10 seconds or less, and no run failed. The target applies to proving time as
defined above and to both devices; the laptop meeting it while the phone does
not is reported as "met on the laptop only", not as a pass. A configuration
that has zero-knowledge mode off does not count.

The report then states, in plain words, which hash candidates meet the target,
which one the outline's rule picks, and the proof size and verification time
that result in. If no candidate meets the target on both devices, the report
says so, and the proof system is revisited as the outline requires.

## Where the results go

- The harness and the raw results (one JSON record per proof, with every field
  above) are committed together with a short written report in this folder.
  Raw results are committed so anyone can recompute the summary.
- **Default:** the harness lives under `benchmarks/` at the repository root and
  the results under `docs/benchmarks/results/`. The harness has one command that
  builds, runs the correctness checks, and prints the summary.
- Every result file names the commit of this repository and the library
  revision it was produced from.

## Defaults chosen here

The outline leaves these open. Each is a default chosen for this plan that a
later decision may change.

1. Laptop: MacBook Air 13-inch (M2, 2022), 8 GB, 256 GB.
2. Phone: Samsung Galaxy A55 5G (SM-A556B, 2024), 8 GB, 256 GB.
3. Browser: Chrome stable 155 on both, pinned for the whole run.
4. Field: BabyBear with a degree-5 extension; digests of 8 elements.
5. Hash: Poseidon2 (width 24) as candidate A and Keccak-256 as candidate B;
   both measured, chosen by the outline's rule.
6. Amounts: 96 bits in four 24-bit limbs.
7. Security: 128 bits conjectured, up to 16 grinding bits, blowup 2^1 as the
   primary and 2^2 and 2^3 as a sweep; the proven figure reported beside it.
8. Benchmark layout of the commitment (41 elements plus tag) and which values
   feed the marker, used only to fix the cost shape.
9. Statistics: five sessions, one cold and ten warm runs each; the target is
   judged on the median warm time and the slowest cold time.
10. Builds: threaded and single-thread WebAssembly, both with SIMD.
11. Cooling, power and network rules for the devices.
12. Where the harness and results live in the repository.
